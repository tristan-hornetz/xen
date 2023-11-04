#include <generated/autoconf.h>
#ifdef CONFIG_HVM
#include <xen/mem_access.h>
#include <xen/sched.h>
#include <xen/guest_access.h>
#include <public/xen.h>
#include <asm/p2m.h>
#include <asm/event.h>
#include <asm/hvm/vmx/vmcs.h>
#include "mm/mm-locks.h"

#define XOM_PAGE_SIZE 0x1000

static int set_xom_seal(struct domain* d, gfn_t gfn, unsigned int nr_pages){
    int ret = 0;
    unsigned int i;
    struct p2m_domain *p2m;
    gfn_t c_gfn;

    //gdprintk(XENLOG_WARNING, "Entered set_xom_seal, secondary controls are 0x%x, ept used is %d\n", vmx_secondary_exec_control, (vmx_secondary_exec_control & SECONDARY_EXEC_ENABLE_EPT) > 0);

    p2m = p2m_get_hostp2m(d);

    if ( unlikely(!p2m) )
        return -EFAULT;

    gdprintk(XENLOG_WARNING, "Entered set_xom_seal with gfn 0x%lx for %u pages. Max mapped page is 0x%lx\n", gfn.gfn , nr_pages, p2m->max_mapped_pfn);

    if (!nr_pages)
        return -EINVAL;

    if ( gfn.gfn + (XOM_PAGE_SIZE * nr_pages) > p2m->max_mapped_pfn )
        return -EOVERFLOW;

    for ( i = 0; i < nr_pages; i++) {
        c_gfn = _gfn(gfn.gfn + (XOM_PAGE_SIZE * i));
        gfn_lock(p2m, c_gfn, 0);
        ret = p2m_set_mem_access_single(d, p2m, NULL, p2m_access_x, c_gfn);
        gfn_unlock(p2m, c_gfn, 0);
        if (ret < 0)
            break;
    }

    p2m->tlb_flush(p2m);
    //gdprintk(XENLOG_WARNING, "Returning from set_xom_seal with ret == %d\n", ret);

    return ret;
}

static int clear_xom_seal(struct domain* d, gfn_t gfn, unsigned int nr_pages){
    int ret = 0;
    unsigned int i;
    void* xom_page;
    struct p2m_domain *p2m;
    struct page_info *page;
    p2m_type_t ptype;
    p2m_access_t atype;
    gfn_t c_gfn;

    //gdprintk(XENLOG_WARNING, "Entered clear_xom_seal\n");

    p2m = p2m_get_hostp2m(d);

    if ( unlikely(!p2m) )
        return -EFAULT;

    gdprintk(XENLOG_WARNING, "Entered clear_xom_seal with gfn 0x%lx for %u pages. Max mapped page is 0x%lx\n", gfn.gfn , nr_pages, p2m->max_mapped_pfn);

    if (!nr_pages)
        return -EINVAL;

    if ( gfn.gfn + (XOM_PAGE_SIZE * nr_pages) > p2m->max_mapped_pfn )
        return -EOVERFLOW;

    for ( i = 0; i < nr_pages; i++) {
        c_gfn = _gfn(gfn.gfn + (XOM_PAGE_SIZE * i));

        // Map the page into our address space
        page = get_page_from_gfn(d, c_gfn.gfn, NULL, P2M_ALLOC);

        if (!page) {
            ret = -EINVAL;
            goto exit;
        }

        if (!get_page_type(page, PGT_writable_page)) {
            put_page(page);
            ret = -EPERM;
            goto exit;
        }

        // Check whether the provided gfn is actually an XOM page
        p2m->get_entry(p2m, c_gfn, &ptype, &atype, 0, NULL, NULL);
        if (atype != p2m_access_x) {
            put_page(page);
            continue;
        }

        // Overwrite XOM page with 0x90
        xom_page = __map_domain_page(page);
        memset(xom_page, 0x90, PAGE_SIZE);
        unmap_domain_page(xom_page);

        // Set SLAT permissions to RWX
        gfn_lock(p2m, c_gfn, 0);
        ret = p2m_set_mem_access_single(d, p2m, NULL, p2m_access_rwx, c_gfn);
        gfn_unlock(p2m, c_gfn, 0);
        put_page(page);
    }

exit:
    p2m->tlb_flush(p2m);
    //gdprintk(XENLOG_WARNING, "Exit clear_xom_seal with ret == %d\n", ret);
    return ret;
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

        switch (op.cmd){
            case MMUEXT_MARK_XOM:
                rc = set_xom_seal(d, _gfn(op.arg1.mfn), op.arg2.nr_ents);
                break;
            case MMUEXT_UNMARK_XOM:
                rc = clear_xom_seal(d, _gfn(op.arg1.mfn), op.arg2.nr_ents);
                break;
            default:
                rc = -EOPNOTSUPP;
        }

        guest_handle_add_offset(uops, 1);
        if (rc < 0)
            return rc;
    }

    if ( unlikely(!guest_handle_is_null(pdone)) )
        copy_to_guest(pdone, &i, 1);
    return 0;
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

