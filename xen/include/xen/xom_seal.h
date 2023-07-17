#ifndef __XEN_XOM_SEAL_H__
#define __XEN_XOM_SEAL_H__

#ifdef CONFIG_HVM
int handle_xom_seal(struct vcpu* curr,
        XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops, unsigned int count, XEN_GUEST_HANDLE_PARAM(uint) pdone);
#else
static inline int handle_xom_seal (struct vcpu* curr,
        XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops, unsigned int count, XEN_GUEST_HANDLE_PARAM(uint) pdone){
    (void) curr;
    (void) uops;
    (void) count;
    (void) pdone;
    return -EOPNOTSUPP;
}
#endif

#endif //__XEN_XOM_SEAL_H__

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */

