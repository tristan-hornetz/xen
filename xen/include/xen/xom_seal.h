#ifndef __XEN_XOM_SEAL_H__
#define __XEN_XOM_SEAL_H__

int set_xom_seal(struct mmuext_op * op, struct vcpu *curr);
int clear_xom_seal(struct mmuext_op * op, struct vcpu *curr);

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

