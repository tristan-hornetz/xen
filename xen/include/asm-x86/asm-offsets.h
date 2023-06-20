/*
 * DO NOT MODIFY.
 *
 * This file was auto-generated from asm-offsets.s
 *
 */

#ifndef __ASM_OFFSETS_H__
#define __ASM_OFFSETS_H__

#define UREGS_r15 0 /* offsetof(struct cpu_user_regs, r15) */
#define UREGS_r14 8 /* offsetof(struct cpu_user_regs, r14) */
#define UREGS_r13 16 /* offsetof(struct cpu_user_regs, r13) */
#define UREGS_r12 24 /* offsetof(struct cpu_user_regs, r12) */
#define UREGS_rbp 32 /* offsetof(struct cpu_user_regs, rbp) */
#define UREGS_rbx 40 /* offsetof(struct cpu_user_regs, rbx) */
#define UREGS_r11 48 /* offsetof(struct cpu_user_regs, r11) */
#define UREGS_r10 56 /* offsetof(struct cpu_user_regs, r10) */
#define UREGS_r9 64 /* offsetof(struct cpu_user_regs, r9) */
#define UREGS_r8 72 /* offsetof(struct cpu_user_regs, r8) */
#define UREGS_rax 80 /* offsetof(struct cpu_user_regs, rax) */
#define UREGS_rcx 88 /* offsetof(struct cpu_user_regs, rcx) */
#define UREGS_rdx 96 /* offsetof(struct cpu_user_regs, rdx) */
#define UREGS_rsi 104 /* offsetof(struct cpu_user_regs, rsi) */
#define UREGS_rdi 112 /* offsetof(struct cpu_user_regs, rdi) */
#define UREGS_error_code 120 /* offsetof(struct cpu_user_regs, error_code) */
#define UREGS_entry_vector 124 /* offsetof(struct cpu_user_regs, entry_vector) */
#define UREGS_rip 128 /* offsetof(struct cpu_user_regs, rip) */
#define UREGS_cs 136 /* offsetof(struct cpu_user_regs, cs) */
#define UREGS_eflags 144 /* offsetof(struct cpu_user_regs, rflags) */
#define UREGS_rsp 152 /* offsetof(struct cpu_user_regs, rsp) */
#define UREGS_ss 160 /* offsetof(struct cpu_user_regs, ss) */
#define UREGS_kernel_sizeof 168 /* offsetof(struct cpu_user_regs, es) */

#define VCPU_processor 4 /* offsetof(struct vcpu, processor) */
#define VCPU_domain 16 /* offsetof(struct vcpu, domain) */
#define VCPU_vcpu_info 8 /* offsetof(struct vcpu, vcpu_info) */
#define VCPU_trap_bounce 1456 /* offsetof(struct vcpu, arch.pv.trap_bounce) */
#define VCPU_thread_flags 896 /* offsetof(struct vcpu, arch.flags) */
#define VCPU_event_addr 1384 /* offsetof(struct vcpu, arch.pv.event_callback_eip) */
#define VCPU_event_sel 1400 /* offsetof(struct vcpu, arch.pv.event_callback_cs) */
#define VCPU_syscall_addr 1400 /* offsetof(struct vcpu, arch.pv.syscall_callback_eip) */
#define VCPU_syscall32_addr 1408 /* offsetof(struct vcpu, arch.pv.syscall32_callback_eip) */
#define VCPU_syscall32_sel 1424 /* offsetof(struct vcpu, arch.pv.syscall32_callback_cs) */
#define VCPU_syscall32_disables_events 1428 /* offsetof(struct vcpu, arch.pv.syscall32_disables_events) */
#define VCPU_sysenter_addr 1416 /* offsetof(struct vcpu, arch.pv.sysenter_callback_eip) */
#define VCPU_sysenter_sel 1426 /* offsetof(struct vcpu, arch.pv.sysenter_callback_cs) */
#define VCPU_sysenter_disables_events 1429 /* offsetof(struct vcpu, arch.pv.sysenter_disables_events) */
#define VCPU_trap_ctxt 1168 /* offsetof(struct vcpu, arch.pv.trap_ctxt) */
#define VCPU_kernel_sp 1312 /* offsetof(struct vcpu, arch.pv.kernel_sp) */
#define VCPU_kernel_ss 1304 /* offsetof(struct vcpu, arch.pv.kernel_ss) */
#define VCPU_iopl 1484 /* offsetof(struct vcpu, arch.pv.iopl) */
#define VCPU_guest_context_flags 1160 /* offsetof(struct vcpu, arch.pv.vgc_flags) */
#define VCPU_cr3 2856 /* offsetof(struct vcpu, arch.cr3) */
#define VCPU_arch_msrs 3416 /* offsetof(struct vcpu, arch.msrs) */
#define VCPU_nmi_pending 960 /* offsetof(struct vcpu, arch.async_exception_state[(1)-1].pending) */
#define VCPU_mce_pending 962 /* offsetof(struct vcpu, arch.async_exception_state[(2)-1].pending) */
#define VCPU_nmi_old_mask 961 /* offsetof(struct vcpu, arch.async_exception_state[(1)-1].old_mask) */
#define VCPU_mce_old_mask 963 /* offsetof(struct vcpu, arch.async_exception_state[(2)-1].old_mask) */
#define VCPU_async_exception_mask 964 /* offsetof(struct vcpu, arch.async_exception_mask) */
#define VCPU_TRAP_NMI 1 /* VCPU_TRAP_NMI */
#define VCPU_TRAP_MCE 2 /* VCPU_TRAP_MCE */
#define _VGCF_syscall_disables_events 4 /* _VGCF_syscall_disables_events */

#define VCPU_svm_vmcb_pa 1480 /* offsetof(struct vcpu, arch.hvm.svm.vmcb_pa) */
#define VCPU_svm_vmcb 1472 /* offsetof(struct vcpu, arch.hvm.svm.vmcb) */

#define VCPU_vmx_launched 1516 /* offsetof(struct vcpu, arch.hvm.vmx.launched) */
#define VCPU_vmx_realmode 1738 /* offsetof(struct vcpu, arch.hvm.vmx.vmx_realmode) */
#define VCPU_vmx_emulate 1739 /* offsetof(struct vcpu, arch.hvm.vmx.vmx_emulate) */
#define VCPU_vm86_seg_mask 1742 /* offsetof(struct vcpu, arch.hvm.vmx.vm86_segment_mask) */
#define VCPU_hvm_guest_cr2 1040 /* offsetof(struct vcpu, arch.hvm.guest_cr[2]) */

#define VCPU_nhvm_guestmode 1960 /* offsetof(struct vcpu, arch.hvm.nvcpu.nv_guestmode) */
#define VCPU_nhvm_p2m 2192 /* offsetof(struct vcpu, arch.hvm.nvcpu.nv_p2m) */
#define VCPU_nsvm_hap_enabled 2148 /* offsetof(struct vcpu, arch.hvm.nvcpu.u.nsvm.ns_hap_enabled) */

#define VCPUINFO_upcall_pending 0 /* offsetof(struct vcpu_info, evtchn_upcall_pending) */
#define VCPUINFO_upcall_mask 1 /* offsetof(struct vcpu_info, evtchn_upcall_mask) */

#define CPUINFO_guest_cpu_user_regs 0 /* offsetof(struct cpu_info, guest_cpu_user_regs) */
#define CPUINFO_verw_sel 204 /* offsetof(struct cpu_info, verw_sel) */
#define CPUINFO_current_vcpu 208 /* offsetof(struct cpu_info, current_vcpu) */
#define CPUINFO_per_cpu_offset 216 /* offsetof(struct cpu_info, per_cpu_offset) */
#define CPUINFO_cr4 224 /* offsetof(struct cpu_info, cr4) */
#define CPUINFO_xen_cr3 232 /* offsetof(struct cpu_info, xen_cr3) */
#define CPUINFO_pv_cr3 240 /* offsetof(struct cpu_info, pv_cr3) */
#define CPUINFO_shadow_spec_ctrl 248 /* offsetof(struct cpu_info, shadow_spec_ctrl) */
#define CPUINFO_xen_spec_ctrl 252 /* offsetof(struct cpu_info, xen_spec_ctrl) */
#define CPUINFO_last_spec_ctrl 253 /* offsetof(struct cpu_info, last_spec_ctrl) */
#define CPUINFO_spec_ctrl_flags 254 /* offsetof(struct cpu_info, spec_ctrl_flags) */
#define CPUINFO_root_pgt_changed 255 /* offsetof(struct cpu_info, root_pgt_changed) */
#define CPUINFO_use_pv_cr3 256 /* offsetof(struct cpu_info, use_pv_cr3) */
#define CPUINFO_sizeof 264 /* sizeof(struct cpu_info) */

#define TRAPINFO_eip 8 /* offsetof(struct trap_info, address) */
#define TRAPINFO_cs 2 /* offsetof(struct trap_info, cs) */
#define TRAPINFO_flags 1 /* offsetof(struct trap_info, flags) */
#define TRAPINFO_sizeof 16 /* sizeof(struct trap_info) */

#define TRAPBOUNCE_error_code 0 /* offsetof(struct trap_bounce, error_code) */
#define TRAPBOUNCE_flags 4 /* offsetof(struct trap_bounce, flags) */
#define TRAPBOUNCE_cs 6 /* offsetof(struct trap_bounce, cs) */
#define TRAPBOUNCE_eip 8 /* offsetof(struct trap_bounce, eip) */

#define VCPUMSR_spec_ctrl_raw 0 /* offsetof(struct vcpu_msrs, spec_ctrl.raw) */

#define IRQSTAT_shift 7 /* ilog2(sizeof(irq_cpustat_t)) */
#define IRQSTAT_softirq_pending 0 /* offsetof(irq_cpustat_t, __softirq_pending) */

#define CPUINFO_features 12 /* offsetof(struct cpuinfo_x86, x86_capability) */

#define MB_flags 0 /* offsetof(multiboot_info_t, flags) */
#define MB_cmdline 16 /* offsetof(multiboot_info_t, cmdline) */
#define MB_mem_lower 4 /* offsetof(multiboot_info_t, mem_lower) */

#define MB2_fixed_sizeof 8 /* sizeof(multiboot2_fixed_t) */
#define MB2_fixed_total_size 0 /* offsetof(multiboot2_fixed_t, total_size) */
#define MB2_tag_type 0 /* offsetof(multiboot2_tag_t, type) */
#define MB2_tag_size 4 /* offsetof(multiboot2_tag_t, size) */
#define MB2_load_base_addr 8 /* offsetof(multiboot2_tag_load_base_addr_t, load_base_addr) */
#define MB2_mem_lower 8 /* offsetof(multiboot2_tag_basic_meminfo_t, mem_lower) */
#define MB2_efi64_st 8 /* offsetof(multiboot2_tag_efi64_t, pointer) */
#define MB2_efi64_ih 8 /* offsetof(multiboot2_tag_efi64_ih_t, pointer) */

#define DOMAIN_vm_assist 544 /* offsetof(struct domain, vm_assist) */

#endif
