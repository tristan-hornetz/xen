#ifndef __XEN_XOM_SEAL_H__
#define __XEN_XOM_SEAL_H__

#define XOM_TYPE_NONE       0
#define XOM_TYPE_PAGE       1
#define XOM_TYPE_SUBPAGE    2


#ifdef CONFIG_HVM
int handle_xom_seal(struct vcpu* curr,
        XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops, unsigned int count, XEN_GUEST_HANDLE_PARAM(uint) pdone);
void free_xen_subpages(struct list_head* lhead);
unsigned char get_xom_type(const struct cpu_user_regs* regs);

#else
static inline int handle_xom_seal (struct vcpu* curr,
        XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops, unsigned int count, XEN_GUEST_HANDLE_PARAM(uint) pdone){
    (void) curr;
    (void) uops;
    (void) count;
    (void) pdone;
    return -EOPNOTSUPP;
}

static inline void free_xen_subpages(struct list_head* lhead) {(void)lhead;}
static inline unsigned char get_xom_type(const struct cpu_user_regs* regs) {(void) regs; return XOM_TYPE_NONE;}

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

