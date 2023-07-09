#ifndef __XEN_XOM_SEAL_H__
#define __XEN_XOM_SEAL_H__

int set_xom_seal(struct domain* d, gfn_t gfn);
int clear_xom_seal(struct domain* d, gfn_t gfn);
int handle_xom_seal(struct vcpu* curr,
        XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops, unsigned int count, XEN_GUEST_HANDLE_PARAM(uint) pdone);

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

