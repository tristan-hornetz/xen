#if 0
.if 0
#endif
#ifndef __ASM_MACROS_H__
#define __ASM_MACROS_H__
asm ( ".include \"/root/xen/xen/include/asm-x86/asm-macros.h\"" );
#endif /* __ASM_MACROS_H__ */
#if 0
.endif
.macro vmrun
    .byte 0x0f, 0x01, 0xd8
.endm
.macro stgi
    .byte 0x0f, 0x01, 0xdc
.endm
.macro clgi
    .byte 0x0f, 0x01, 0xdd
.endm
.macro INDIRECT_BRANCH insn:req arg:req
    .if 1 == 1
        $done = 0
        .irp reg, ax, cx, dx, bx, bp, si, di, 8, 9, 10, 11, 12, 13, 14, 15
        .ifeqs "\arg", "%r\reg"
            \insn __x86_indirect_thunk_r\reg
            $done = 1
           .exitm
        .endif
        .endr
        .if $done != 1
            .error "Bad register arg \arg"
        .endif
    .else
        \insn *\arg
    .endif
.endm
.macro INDIRECT_CALL arg:req
    INDIRECT_BRANCH call \arg
.endm
.macro INDIRECT_JMP arg:req
    INDIRECT_BRANCH jmp \arg
.endm
.macro guest_access_mask_ptr ptr:req, scratch1:req, scratch2:req
    mov $((((((256 >> 8) * 0xffff000000000000) | (256 << 39))) + (1 << 39)*16) - 1), \scratch1
    mov $~0, \scratch2
    cmp \ptr, \scratch1
    rcr $1, \scratch2
    and \scratch2, \ptr
.endm
.macro altinstruction_entry orig repl feature orig_len repl_len pad_len
    .long \orig - .
    .long \repl - .
    .word \feature
    .byte \orig_len
    .byte \repl_len
    .byte \pad_len
    .byte 0
.endm
.macro mknops nr_bytes
    .nops \nr_bytes, 9
.endm
.macro ALTERNATIVE oldinstr, newinstr, feature
    .L\@_orig_s: \oldinstr; .L\@_orig_e: .L\@_diff = (.L\@_repl_e\()1 - .L\@_repl_s\()1) - (.L\@_orig_e - .L\@_orig_s); mknops ((-(.L\@_diff > 0)) * .L\@_diff); .L\@_orig_p:
    .pushsection .altinstructions, "a", @progbits
    altinstruction_entry .L\@_orig_s, .L\@_repl_s1, \feature, (.L\@_orig_e - .L\@_orig_s), (.L\@_repl_e\()1 - .L\@_repl_s\()1), (.L\@_orig_p - .L\@_orig_e)
    .section .discard, "a", @progbits
    .byte (.L\@_orig_p - .L\@_orig_s)
    .byte 0xff + (.L\@_repl_e\()1 - .L\@_repl_s\()1) - (.L\@_orig_p - .L\@_orig_s)
    .section .altinstr_replacement, "ax", @progbits
    .L\@_repl_s\()1: \newinstr; .L\@_repl_e\()1:
    .popsection
.endm
.macro ALTERNATIVE_2 oldinstr, newinstr1, feature1, newinstr2, feature2
    .L\@_orig_s: \oldinstr; .L\@_orig_e: .L\@_diff = (((.L\@_repl_e\()1 - .L\@_repl_s\()1)) ^ ((((.L\@_repl_e\()1 - .L\@_repl_s\()1)) ^ ((.L\@_repl_e\()2 - .L\@_repl_s\()2))) & -(-(((.L\@_repl_e\()1 - .L\@_repl_s\()1)) < ((.L\@_repl_e\()2 - .L\@_repl_s\()2)))))) - (.L\@_orig_e - .L\@_orig_s); mknops ((-(.L\@_diff > 0)) * .L\@_diff); .L\@_orig_p:
    .pushsection .altinstructions, "a", @progbits
    altinstruction_entry .L\@_orig_s, .L\@_repl_s1, \feature1, (.L\@_orig_e - .L\@_orig_s), (.L\@_repl_e\()1 - .L\@_repl_s\()1), (.L\@_orig_p - .L\@_orig_e)
    altinstruction_entry .L\@_orig_s, .L\@_repl_s2, \feature2, (.L\@_orig_e - .L\@_orig_s), (.L\@_repl_e\()2 - .L\@_repl_s\()2), (.L\@_orig_p - .L\@_orig_e)
    .section .discard, "a", @progbits
    .byte (.L\@_orig_p - .L\@_orig_s)
    .byte 0xff + (.L\@_repl_e\()1 - .L\@_repl_s\()1) - (.L\@_orig_p - .L\@_orig_s)
    .byte 0xff + (.L\@_repl_e\()2 - .L\@_repl_s\()2) - (.L\@_orig_p - .L\@_orig_s)
    .section .altinstr_replacement, "ax", @progbits
    .L\@_repl_s\()1: \newinstr1; .L\@_repl_e\()1:
    .L\@_repl_s\()2: \newinstr2; .L\@_repl_e\()2:
    .popsection
.endm
.macro DO_SPEC_CTRL_COND_IBPB maybexen:req
    .if \maybexen
        testb $SCF_entry_ibpb, STACK_CPUINFO_FIELD(spec_ctrl_flags)(%r14)
        jz .L\@_skip
        testb $3, UREGS_cs(%rsp)
    .else
        testb $SCF_entry_ibpb, CPUINFO_xen_spec_ctrl(%rsp)
    .endif
    jz .L\@_skip
    mov $MSR_PRED_CMD, %ecx
    mov $PRED_CMD_IBPB, %eax
    wrmsr
    jmp .L\@_done
.L\@_skip:
    lfence
.L\@_done:
.endm
.macro DO_OVERWRITE_RSB tmp=rax
    mov $16, %ecx
    mov %rsp, %\tmp
.L\@_fill_rsb_loop:
    .irp n, 1, 2
    call .L\@_insert_rsb_entry_\n
.L\@_capture_speculation_\n:
    pause
    lfence
    jmp .L\@_capture_speculation_\n
.L\@_insert_rsb_entry_\n:
    .endr
    sub $1, %ecx
    jnz .L\@_fill_rsb_loop
    mov %\tmp, %rsp
    mov $1, %ecx
    rdsspd %ecx
    cmp $1, %ecx
    je .L\@_shstk_done
    mov $64, %ecx
    incsspd %ecx
.L\@_shstk_done:
.endm
.macro DO_SPEC_CTRL_COND_VERW
    testb $SCF_verw, CPUINFO_spec_ctrl_flags(%rsp)
    jz .L\@_verw_skip
    verw CPUINFO_verw_sel(%rsp)
.L\@_verw_skip:
.endm
.macro DO_SPEC_CTRL_ENTRY maybexen:req
    mov $MSR_SPEC_CTRL, %ecx
    xor %edx, %edx
    .if \maybexen
        xor %eax, %eax
        testb $3, UREGS_cs(%rsp)
        setnz %al
        not %eax
        and %al, STACK_CPUINFO_FIELD(spec_ctrl_flags)(%r14)
        movzbl STACK_CPUINFO_FIELD(xen_spec_ctrl)(%r14), %eax
    .else
        andb $~(1 << 0), CPUINFO_spec_ctrl_flags(%rsp)
        movzbl CPUINFO_xen_spec_ctrl(%rsp), %eax
    .endif
    wrmsr
.endm
.macro DO_SPEC_CTRL_EXIT_TO_XEN
    xor %edx, %edx
    testb $SCF_use_shadow, STACK_CPUINFO_FIELD(spec_ctrl_flags)(%rbx)
    jz .L\@_skip
    mov STACK_CPUINFO_FIELD(shadow_spec_ctrl)(%rbx), %eax
    mov $MSR_SPEC_CTRL, %ecx
    wrmsr
.L\@_skip:
.endm
.macro DO_SPEC_CTRL_EXIT_TO_GUEST
    mov %eax, CPUINFO_shadow_spec_ctrl(%rsp)
    orb $SCF_use_shadow, CPUINFO_spec_ctrl_flags(%rsp)
    mov $MSR_SPEC_CTRL, %ecx
    xor %edx, %edx
    wrmsr
.endm
.macro SPEC_CTRL_ENTRY_FROM_INTR_IST
    movzbl STACK_CPUINFO_FIELD(spec_ctrl_flags)(%r14), %ebx
    test $SCF_ist_ibpb, %bl
    jz .L\@_skip_ibpb
    mov $MSR_PRED_CMD, %ecx
    mov $PRED_CMD_IBPB, %eax
    wrmsr
.L\@_skip_ibpb:
    test $SCF_ist_rsb, %bl
    jz .L\@_skip_rsb
    DO_OVERWRITE_RSB
.L\@_skip_rsb:
    test $SCF_ist_sc_msr, %bl
    jz .L\@_skip_msr_spec_ctrl
    xor %eax, %eax
    testb $3, UREGS_cs(%rsp)
    setnz %al
    not %eax
    and %al, STACK_CPUINFO_FIELD(spec_ctrl_flags)(%r14)
    mov $MSR_SPEC_CTRL, %ecx
    movzbl STACK_CPUINFO_FIELD(xen_spec_ctrl)(%r14), %eax
    wrmsr
UNLIKELY_DISPATCH_LABEL(\@_serialise):
    .subsection 1
.L\@_skip_msr_spec_ctrl:
    lfence
    UNLIKELY_END(\@_serialise)
.endm
.macro SPEC_CTRL_EXIT_TO_XEN_IST
    testb $SCF_ist_sc_msr, STACK_CPUINFO_FIELD(spec_ctrl_flags)(%rbx)
    jz .L\@_skip
    DO_SPEC_CTRL_EXIT_TO_XEN
.L\@_skip:
.endm
#endif
