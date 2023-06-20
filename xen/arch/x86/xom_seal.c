#include <xen/mem_access.h>
#include <xen/sched.h>
#include <public/xen.h>
#include <asm/p2m.h>
#include "mm/mm-locks.h"

int set_xom_seal(struct mmuext_op * op, struct vcpu *curr){
    int ret;
    const gfn_t gfn = _gfn(op->arg1.mfn);
    struct domain* d = curr->domain;
    struct p2m_domain *p2m;

    if ( !is_hvm_domain(d) || !hap_enabled(d) || !cpu_has_vmx )
        return -EOPNOTSUPP;

    p2m = p2m_get_hostp2m(d);

    if ( unlikely(!p2m) )
        return -EFAULT;

    if ( gfn.gfn > p2m->max_mapped_pfn )
        return -EINVAL;

    gfn_lock(p2m, gfn, 0);

    ret = p2m_set_mem_access_single(d, p2m, NULL, p2m_access_x, gfn);
    p2m->tlb_flush(p2m);

    gfn_unlock(p2m, gfn, 0);

    return ret;
}

int clear_xom_seal(struct mmuext_op * op, struct vcpu *curr){
    int ret;
    const gfn_t gfn = _gfn(op->arg1.mfn);
    void* xom_page;
    struct domain* d = curr->domain;
    struct p2m_domain *p2m;
    struct page_info *page;
    p2m_type_t ptype;
    p2m_access_t atype;

    if ( !is_hvm_domain(d) || !hap_enabled(d) || !cpu_has_vmx )
        return -EOPNOTSUPP;

    p2m = p2m_get_hostp2m(d);

    if ( unlikely(!p2m) )
        return -EFAULT;

    if ( gfn.gfn > p2m->max_mapped_pfn )
        return -EINVAL;

    gfn_lock(p2m, gfn, 0);
    page = get_page_from_gfn(d, gfn.gfn, NULL, P2M_ALLOC);

    if(!page){
        ret = -EINVAL;
        goto exit;
    }

    if( !get_page_type(page, PGT_writable_page) )
    {
        put_page(page);
        ret = -EPERM;
        goto exit;
    }

    p2m->get_entry(p2m, gfn, &ptype, &atype, 0, NULL, NULL);

    if (atype != p2m_access_x ){
        ret = -EADDRINUSE;
        goto exit;
    }

    xom_page = __map_domain_page(page);
    memset(xom_page, 0x90, PAGE_SIZE);
    unmap_domain_page(xom_page);

    ret = p2m_set_mem_access_single(d, p2m, NULL, p2m_access_rwx, gfn);
    p2m->tlb_flush(p2m);

exit:
    gfn_unlock(p2m, gfn, 0);
    return ret;
}

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */

