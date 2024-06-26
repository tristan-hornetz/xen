/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * arch/x86/mm/hap/guest_walk.c
 *
 * Guest page table walker
 * Copyright (c) 2007, AMD Corporation (Wei Huang)
 * Copyright (c) 2007, XenSource Inc.
 */

#include <xen/domain_page.h>
#include <xen/paging.h>
#include <xen/sched.h>
#include "private.h" /* for hap_gva_to_gfn_* */

#define _hap_gva_to_gfn(levels) hap_gva_to_gfn_##levels##_levels
#define hap_gva_to_gfn(levels) _hap_gva_to_gfn(levels)

#define _hap_p2m_ga_to_gfn(levels) hap_p2m_ga_to_gfn_##levels##_levels
#define hap_p2m_ga_to_gfn(levels) _hap_p2m_ga_to_gfn(levels)

#if GUEST_PAGING_LEVELS > CONFIG_PAGING_LEVELS
#error GUEST_PAGING_LEVELS must not exceed CONFIG_PAGING_LEVELS
#endif

#include <asm/guest_pt.h>
#include <asm/p2m.h>

unsigned long cf_check hap_gva_to_gfn(GUEST_PAGING_LEVELS)(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long gva, uint32_t *pfec)
{
    unsigned long cr3 = v->arch.hvm.guest_cr[3];
    return hap_p2m_ga_to_gfn(GUEST_PAGING_LEVELS)(v, p2m, cr3, gva, pfec, NULL);
}

unsigned long cf_check hap_p2m_ga_to_gfn(GUEST_PAGING_LEVELS)(
    struct vcpu *v, struct p2m_domain *p2m, unsigned long cr3,
    paddr_t ga, uint32_t *pfec, unsigned int *page_order)
{
    bool walk_ok;
    mfn_t top_mfn;
    void *top_map;
    p2m_type_t p2mt;
    walk_t gw;
    gfn_t top_gfn;
    struct page_info *top_page;

    /* Get the top-level table's MFN */
    top_gfn = _gfn(cr3 >> PAGE_SHIFT);

    top_page = p2m_get_page_from_gfn(p2m, top_gfn, &p2mt, NULL,
                                     P2M_ALLOC | P2M_UNSHARE);

    if ( p2m_is_paging(p2mt) )
    {
        ASSERT(p2m_is_hostp2m(p2m));
        *pfec = PFEC_page_paged;
        if ( top_page )
            put_page(top_page);
        p2m_mem_paging_populate(p2m->domain, gaddr_to_gfn(cr3));
        return gfn_x(INVALID_GFN);
    }
    if ( p2m_is_shared(p2mt) )
    {
        *pfec = PFEC_page_shared;
        if ( top_page )
            put_page(top_page);
        return gfn_x(INVALID_GFN);
    }
    if ( !top_page )
    {
        *pfec &= ~PFEC_page_present;
        goto out_tweak_pfec;
    }
    top_mfn = page_to_mfn(top_page);

    /* Map the top-level table and call the tree-walker */
    ASSERT(mfn_valid(top_mfn));
    top_map = map_domain_page(top_mfn);
#if GUEST_PAGING_LEVELS == 3
    top_map += (cr3 & ~(PAGE_MASK | 31));
#endif

    walk_ok = guest_walk_tables(v, p2m, ga, &gw, *pfec,
                                top_gfn, top_mfn, top_map);
    unmap_domain_page(top_map);
    put_page(top_page);


    if ( walk_ok )
    {
        gfn_t gfn = guest_walk_to_gfn(&gw);
        struct page_info *page;

        page = p2m_get_page_from_gfn(p2m, gfn, &p2mt, NULL,
                                     P2M_ALLOC | P2M_UNSHARE);
        if ( page )
            put_page(page);
        if ( p2m_is_paging(p2mt) )
        {
            ASSERT(p2m_is_hostp2m(p2m));
            *pfec = PFEC_page_paged;
            p2m_mem_paging_populate(p2m->domain, gfn);
            return gfn_x(INVALID_GFN);
        }
        if ( p2m_is_shared(p2mt) )
        {
            *pfec = PFEC_page_shared;
            return gfn_x(INVALID_GFN);
        }

        if ( page_order )
            *page_order = guest_walk_to_page_order(&gw);

        return gfn_x(gfn);
    }

    *pfec = gw.pfec;

 out_tweak_pfec:
    /*
     * SDM Intel 64 Volume 3, Chapter Paging, PAGE-FAULT EXCEPTIONS:
     * The PFEC_insn_fetch flag is set only when NX or SMEP are enabled.
     */
    if ( !hvm_nx_enabled(v) && !hvm_smep_enabled(v) )
        *pfec &= ~PFEC_insn_fetch;

    return gfn_x(INVALID_GFN);
}


/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
