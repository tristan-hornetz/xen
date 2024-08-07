#ifndef __XEN_XOM_SEAL_H__
#define __XEN_XOM_SEAL_H__

#define REG_CLEAR_TYPE_NONE     0
#define REG_CLEAR_TYPE_VECTOR   1
#define REG_CLEAR_TYPE_FULL     2

// Do not call without backing up SSE registers !!
extern void aes_gctr_linear(void *icb, void* x, void *y, unsigned int num_blocks);

#ifdef CONFIG_HVM
int handle_xom_seal(struct vcpu* curr,
        XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops, unsigned int count, XEN_GUEST_HANDLE_PARAM(uint) pdone);
void free_xom_info(struct rb_root *root);
unsigned char get_reg_clear_type(const struct cpu_user_regs* regs);

#else
static inline int handle_xom_seal (struct vcpu* curr,
        XEN_GUEST_HANDLE_PARAM(mmuext_op_t) uops, unsigned int count, XEN_GUEST_HANDLE_PARAM(uint) pdone){
    (void) curr;
    (void) uops;
    (void) count;
    (void) pdone;
    return -EOPNOTSUPP;
}

static inline void free_xom_info(struct rb_root *root) {(void)root;}
static inline unsigned char get_reg_clear_type(const struct cpu_user_regs* regs) {(void) regs; return REG_CLEAR_TYPE_NONE;}

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

