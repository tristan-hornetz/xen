#include <generated/autoconf.h>
#ifdef CONFIG_HVM
#include <xen/mem_access.h>
#include <xen/sched.h>
#include <xen/list.h>
#include <xen/xmalloc.h>
#include <xen/guest_access.h>
#include <xen/domain_page.h>
#include <xen/xom_seal.h>
#include <public/xen.h>
#include <asm/p2m.h>
#include <asm/event.h>
#include <asm/page.h>
#include <asm/hvm/vmx/vmx.h>
#include <asm/hvm/vmx/vmcs.h>
#include <asm/hvm/emulate.h>
#include "mm/mm-locks.h"

#define SUBPAGE_SIZE (PAGE_SIZE / (sizeof(uint32_t) << 3))
#define MAX_SUBPAGES_PER_CMD ((PAGE_SIZE - sizeof(uint8_t)) / (sizeof(xom_subpage_write_info)))

struct {
    struct list_head lhead;
    gfn_t gfn;
    union {
        uint32_t lock_status;
        uint8_t reg_clear_type;
    } info;
} typedef xom_page_info;

struct {
    uint8_t target_subpage;
    uint8_t data[SUBPAGE_SIZE];
} typedef xom_subpage_write_info;

struct {
    uint8_t num_subpages;
    xom_subpage_write_info write_info [MAX_SUBPAGES_PER_CMD];
} typedef xom_subpage_write_command;


// TODO: Replace with rbtree at some point to improve performance
static xom_page_info* get_page_info_entry(const struct list_head* const lhead, const gfn_t gfn){
    const struct list_head* next = lhead->next;

    while(next && next != lhead){
        if(((xom_page_info*)next)->gfn == gfn)
            return (xom_page_info*)next;
        next = next->next;
    }
    return NULL;
}

static int set_xom_seal(struct domain* d, gfn_t gfn, unsigned int nr_pages){
    int ret = 0;
    unsigned int i;
    struct p2m_domain *p2m;
    gfn_t c_gfn;

    p2m = p2m_get_hostp2m(d);

    if ( unlikely(!p2m) )
        return -EFAULT;

    gdprintk(XENLOG_WARNING, "Entered set_xom_seal with gfn 0x%lx for %u pages. Max mapped page is 0x%lx\n", gfn_x(gfn) , nr_pages, p2m->max_mapped_pfn);

    if (!nr_pages)
        return -EINVAL;

    if ( gfn_x(gfn) + nr_pages > p2m->max_mapped_pfn )
        return -EOVERFLOW;

    for ( i = 0; i < nr_pages; i++) {
        c_gfn = _gfn(gfn_x(gfn) + i);
        gfn_lock(p2m, c_gfn, 0);
        ret = p2m_set_mem_access_single(d, p2m, NULL, p2m_access_x, c_gfn);
        gfn_unlock(p2m, c_gfn, 0);
        if (ret < 0)
            break;
    }

    p2m->tlb_flush(p2m);
    return ret;
}

static int clear_xom_seal(struct domain* d, gfn_t gfn, unsigned int nr_pages){
    int ret = 0;
    unsigned int i;
    void* xom_page;
    struct p2m_domain *p2m;
    struct page_info *page;
    xom_page_info* page_info;
    p2m_type_t ptype;
    p2m_access_t atype;
    gfn_t c_gfn;

    p2m = p2m_get_hostp2m(d);

    if ( unlikely(!p2m) )
        return -EFAULT;

    gdprintk(XENLOG_WARNING, "Entered clear_xom_seal with gfn 0x%lx for %u pages. Max mapped page is 0x%lx\n", gfn_x(gfn) , nr_pages, p2m->max_mapped_pfn);

    if (!nr_pages)
        return -EINVAL;

    if ( gfn_x(gfn) + nr_pages > p2m->max_mapped_pfn )
        return -EOVERFLOW;


    for ( i = 0; i < nr_pages; i++ ) {
        c_gfn = _gfn(gfn_x(gfn) + i);

        gfn_lock(p2m, c_gfn, 0);
        // Check whether the provided gfn is actually an XOM page
        p2m->get_entry(p2m, c_gfn, &ptype, &atype, 0, NULL, NULL);
        if (atype != p2m_access_x){
            gfn_unlock(p2m, c_gfn, 0);
            continue;
        }

        // Map the page into our address space
        page = get_page_from_gfn(d, gfn_x(c_gfn), NULL, P2M_ALLOC);

        if (!page) {
            ret = -EINVAL;
            gfn_unlock(p2m, c_gfn, 0);
            goto exit;
        }

        if (!get_page_type(page, PGT_writable_page)) {
            put_page(page);
            gfn_unlock(p2m, c_gfn, 0);
            ret = -EPERM;
            goto exit;
        }

        // Overwrite XOM page with 0x90
        xom_page = __map_domain_page(page);
        memset(xom_page, 0x90, PAGE_SIZE);
        unmap_domain_page(xom_page);
        put_page_and_type(page);

        // Set SLAT permissions to RWX
        ret = p2m_set_mem_access_single(d, p2m, NULL, p2m_access_rwx, c_gfn);
        gfn_unlock(p2m, c_gfn, 0);

        page_info = get_page_info_entry(&d->xom_subpages, gfn);
        if(page_info){
            list_del(&page_info->lhead);
            xfree(page_info);
        }
        page_info = get_page_info_entry(&d->xom_reg_clear_pages, gfn);
        if (page_info) {
            list_del(&page_info->lhead);
            xfree(page_info);
        }
    }

exit:
    p2m->tlb_flush(p2m);
    return ret;
}

static int create_xom_subpages(struct domain* d, gfn_t gfn, unsigned int nr_pages){
    int ret = 0;
    unsigned int i;
    struct p2m_domain *p2m;
    xom_page_info* subpage_info = NULL;
    p2m_type_t ptype;
    p2m_access_t atype;
    gfn_t c_gfn;

    p2m = p2m_get_hostp2m(d);

    if ( unlikely(!p2m) )
        return -EFAULT;

    gdprintk(XENLOG_WARNING, "Entered create_subpages with gfn 0x%lx for %u (4KB!) pages. Max mapped page is 0x%lx\n", gfn_x(gfn) , nr_pages, p2m->max_mapped_pfn);

    if (!nr_pages)
        return -EINVAL;

    if ( gfn_x(gfn) + nr_pages > p2m->max_mapped_pfn )
        return -EOVERFLOW;

    for ( i = 0; i < nr_pages; i++) {
        c_gfn = _gfn(gfn_x(gfn) + i);

        subpage_info = xmalloc(xom_page_info);
        if(!subpage_info)
            return -ENOMEM;

        memset(subpage_info, 0, sizeof(*subpage_info));

        gfn_lock(p2m, c_gfn, 0);
        // Check whether the provided gfn is a XOM page already
        p2m->get_entry(p2m, c_gfn, &ptype, &atype, 0, NULL, NULL);
        if (atype == p2m_access_x){
            gfn_unlock(p2m, c_gfn, 0);
            ret = -EINVAL;
            goto exit;
        }

        // Set SLAT permissions to X
        ret = p2m_set_mem_access_single(d, p2m, NULL, p2m_access_x, c_gfn);
        gfn_unlock(p2m, c_gfn, 0);

        subpage_info->gfn = c_gfn;
        list_add(&subpage_info->lhead, &d->xom_subpages);
        subpage_info = NULL;
    }

exit:
    if(subpage_info)
        xfree(subpage_info);
    p2m->tlb_flush(p2m);
    return ret;
}

static int write_into_subpage(struct domain* d, gfn_t gfn_dest, gfn_t gfn_src){
    unsigned int i;
    char* xom_page, *write_dest;
    struct p2m_domain *p2m;
    struct page_info *page;
    xom_page_info* subpage_info;
    xom_subpage_write_command command;

    subpage_info = get_page_info_entry(&d->xom_subpages, gfn_dest);
    if(!subpage_info)
        return -EINVAL;

    p2m = p2m_get_hostp2m(d);

    if ( unlikely(!p2m) )
        return -EFAULT;

    if (gfn_x(gfn_src) > p2m->max_mapped_pfn )
        return -EOVERFLOW;

    // Copy command from gfn_src
    gfn_lock(p2m, gfn_src, 0);
    page = get_page_from_gfn(d, gfn_x(gfn_src), NULL, P2M_ALLOC);
    if(!page){
        gfn_unlock(p2m, gfn_src, 0);
        return -EINVAL;
    }
    xom_page = (char*) __map_domain_page(page);
    memcpy(&command, xom_page, sizeof(command));
    unmap_domain_page(xom_page);
    gfn_unlock(p2m, gfn_src, 0);
    put_page(page);

    gdprintk(XENLOG_WARNING, "Copying %u subpages from %lx to %lx\n", command.num_subpages, gfn_x(gfn_src), gfn_x(gfn_dest));

    // Validate command
    if(command.num_subpages > MAX_SUBPAGES_PER_CMD)
        return -EINVAL;
    for(i = 0; i < command.num_subpages; i++){
        if(command.write_info[i].target_subpage >= (PAGE_SIZE / SUBPAGE_SIZE))
            return -EINVAL;
        if(subpage_info->info.lock_status & (1 << command.write_info[i].target_subpage))
            return -EINVAL;
    }

    // Execute command
    gfn_lock(p2m, gfn_dest, 0);
    page = get_page_from_gfn(d, gfn_x(gfn_dest), NULL, P2M_ALLOC);
    if(!page){
        gfn_unlock(p2m, gfn_dest, 0);
        return -EINVAL;
    }
    if (!get_page_type(page, PGT_writable_page)) {
        put_page(page);
        gfn_unlock(p2m, gfn_dest, 0);
        return -EPERM;
    }
    xom_page = (char*) __map_domain_page(page);
    for(i = 0; i < command.num_subpages; i++){
        write_dest = xom_page + (command.write_info[i].target_subpage * SUBPAGE_SIZE);
        memcpy(write_dest, command.write_info[i].data, SUBPAGE_SIZE);
        subpage_info->info.lock_status |= 1 << command.write_info[i].target_subpage;
    }
    unmap_domain_page(xom_page);
    gfn_unlock(p2m, gfn_dest, 0);
    put_page_and_type(page);

    return 0;
}

static int map_secret_page_to_guest(struct domain* d, gfn_t gfn_dest) {
    int status;
    char* xom_page;
    struct p2m_domain *p2m;
    struct page_info *page;
    xom_page_info* subpage_info;

    status = create_xom_subpages(d, gfn_dest, 1);
    if ( status < 0 )
        return status;

    subpage_info = get_page_info_entry(&d->xom_subpages, gfn_dest);
    if(!subpage_info)
        return -EINVAL;

    p2m = p2m_get_hostp2m(d);

    gfn_lock(p2m, gfn_dest, 0);
    page = get_page_from_gfn(d, gfn_x(gfn_dest), NULL, P2M_ALLOC);
    if(!page){
        gfn_unlock(p2m, gfn_dest, 0);
        return -EINVAL;
    }
    if (!get_page_type(page, PGT_writable_page)) {
        put_page(page);
        gfn_unlock(p2m, gfn_dest, 0);
        return -EPERM;
    }
    xom_page = (char*) __map_domain_page(page);

    // Copy code for AES
    memcpy(xom_page, aes_gctr_linear, PAGE_SIZE);
    subpage_info->info.lock_status = ~0u;

    // Cleanup
    unmap_domain_page(xom_page);
    gfn_unlock(p2m, gfn_dest, 0);
    put_page_and_type(page);

    return 0;
}

static int mark_reg_clear_page(struct domain* d, gfn_t gfn, unsigned int reg_clear_type) {
    xom_page_info* page_info;
    struct p2m_domain *p2m;
    p2m_type_t ptype;
    p2m_access_t atype;

    if(!reg_clear_type || reg_clear_type > REG_CLEAR_TYPE_FULL)
        return -EINVAL;

    // A page cannot be marked twice
    page_info = get_page_info_entry(&d->xom_reg_clear_pages, gfn);
    if(page_info)
        return -EINVAL;

    // We only allow marking XOM pages
    p2m = p2m_get_hostp2m(d);
    gfn_lock(p2m, c_gfn, 0);
    p2m->get_entry(p2m, gfn, &ptype, &atype, 0, NULL, NULL);
    gfn_unlock(p2m, c_gfn, 0);
    if (atype != p2m_access_x)
        return -EINVAL;

    page_info = xmalloc(xom_page_info);
    if(!page_info)
        return -ENOMEM;

    *page_info = (xom_page_info) {
        .gfn = gfn,
        .info = {.reg_clear_type = reg_clear_type}
    };

    list_add(&page_info->lhead, &d->xom_reg_clear_pages);

    return 0;
}

int handle_xom_seal(struct vcpu* curr,
                    XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops, unsigned int count, XEN_GUEST_HANDLE_PARAM(uint) pdone) {
    int rc;
    unsigned int i;
    struct domain* d = curr->domain;
    struct mmuext_op op;

    if (!is_hvm_domain(d) || !hap_enabled(d))
        return -EOPNOTSUPP;

    for ( i = 0; i < count; i++ ) {
        if (curr->arch.old_guest_table || (i && hypercall_preempt_check())) {
            gdprintk(XENLOG_ERR, "Preempt check failed\n");
            return -ERESTART;
        }

        if (unlikely(__copy_from_guest(&op, uops, 1) != 0)) {
            gdprintk(XENLOG_ERR, "Unable to copy guest page\n");
            return -EFAULT;
        }

        spin_lock(&d->xom_page_lock);
        switch (op.cmd){
            case MMUEXT_MARK_XOM:
                rc = set_xom_seal(d, _gfn(op.arg1.mfn), op.arg2.nr_ents);
                break;
            case MMUEXT_UNMARK_XOM:
                rc = clear_xom_seal(d, _gfn(op.arg1.mfn), op.arg2.nr_ents);
                break;
            case MMUEXT_CREATE_XOM_SPAGES:
                rc = create_xom_subpages(d, _gfn(op.arg1.mfn), op.arg2.nr_ents);
                break;
            case MMUEXT_WRITE_XOM_SPAGES:
                rc = write_into_subpage(d, _gfn(op.arg1.mfn), _gfn(op.arg2.src_mfn));
                break;
            case MMUEXT_GET_SECRET_PAGE:
                rc = map_secret_page_to_guest(d, _gfn(op.arg1.mfn));
                break;
            case MMUEXT_MARK_REG_CLEAR:
                rc =  mark_reg_clear_page(d, _gfn(op.arg1.mfn), op.arg2.nr_ents);
                break;
            default:
                rc = -EOPNOTSUPP;
        }
        spin_unlock(&d->xom_page_lock);

        guest_handle_add_offset(uops, 1);
        if (rc < 0)
            return rc;
    }

    if ( unlikely(!guest_handle_is_null(pdone)) )
        copy_to_guest(pdone, &i, 1);
    return 0;
}

void free_xom_llist(struct list_head* lhead) {
    struct list_head* next = lhead->next, *last;

    while(next != lhead){
        last = next;
        next = next->next;
        xfree(last);
    }
}

static inline unsigned long gfn_of_rip(const unsigned long rip) {
    struct vcpu *curr = current;
    struct segment_register sreg;
    uint32_t pfec = PFEC_page_present | PFEC_insn_fetch | PFEC_user_mode;

    if ( unlikely(!curr || !~(uintptr_t)curr) )
        return gfn_x(INVALID_GFN);

    if ( unlikely(!curr->is_initialised) )
        return gfn_x(INVALID_GFN);

    hvm_get_segment_register(curr, x86_seg_cs, &sreg);

    return paging_gva_to_gfn(curr, sreg.base + rip, &pfec);
}

unsigned char get_reg_clear_type(const struct cpu_user_regs* const regs) {
    unsigned char ret = REG_CLEAR_TYPE_NONE;
    xom_page_info* info;
    gfn_t instr_gfn;
    struct vcpu* v = current;
    struct domain * const d = v->domain;

    if(!regs || !~(uintptr_t)regs)
        return ret;

    spin_lock(&d->xom_page_lock);
    instr_gfn = _gfn(gfn_of_rip(regs->rip));
    if ( unlikely(gfn_eq(instr_gfn, INVALID_GFN)) )
        goto out;

    info = get_page_info_entry(&d->xom_reg_clear_pages, instr_gfn);
    if(!info)
        goto out;

    ret = info->info.reg_clear_type;
out:
    spin_unlock(&d->xom_page_lock);
    return ret;
}

#endif // CONFIG_HVM

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
