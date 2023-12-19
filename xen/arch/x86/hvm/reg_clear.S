.file "reg_clear.S"

.text
.globl is_reg_clear_magic
is_reg_clear_magic:
    // Prologue
    push %rbp
    mov %rsp, %rbp
    sub $0x20, %rsp
    and $0xfffffffffffffff0, %rsp
    movaps %xmm14, (%rsp)

    mov $0x002121657361656c, %rax
    push %rax
    mov $0x50654d7261656c43, %rax
    push %rax
    movaps (%rsp), %xmm14
    add $0x10, %rsp

    // Check if xmm14 and xmm15 are equal
    xor %rax, %rax
    pxor %xmm15, %xmm14
    ptest %xmm14, %xmm14
    jnz is_reg_clear_magic_exit
    inc %al
is_reg_clear_magic_exit:

    // Epilogue
    movaps (%rsp), %xmm14

    leave
    ret

.globl clear_sse_regs
clear_sse_regs:
    clear_sse_regs:
    pxor   %xmm0, %xmm0
    pxor   %xmm1, %xmm1
    pxor   %xmm2, %xmm2
    pxor   %xmm3, %xmm3
    pxor   %xmm4, %xmm4
    pxor   %xmm5, %xmm5
    pxor   %xmm6, %xmm6
    pxor   %xmm7, %xmm7
    pxor   %xmm8, %xmm8
    pxor   %xmm9, %xmm9
    pxor   %xmm10, %xmm10
    pxor   %xmm11, %xmm11
    pxor   %xmm12, %xmm12
    pxor   %xmm13, %xmm13
    pxor   %xmm14, %xmm14
    pxor   %xmm15, %xmm15
    ret

.globl clear_avx_regs
clear_avx_regs:
    vzeroall
    ret

.globl clear_avx512_regs
clear_avx512_regs:
    vzeroall
    vpxorq   %zmm16, %zmm16, %zmm16
    vpxorq   %zmm17, %zmm17, %zmm17
    vpxorq   %zmm18, %zmm18, %zmm18
    vpxorq   %zmm19, %zmm19, %zmm19
    vpxorq   %zmm20, %zmm20, %zmm20
    vpxorq   %zmm21, %zmm21, %zmm21
    vpxorq   %zmm22, %zmm22, %zmm22
    vpxorq   %zmm23, %zmm23, %zmm23
    vpxorq   %zmm24, %zmm24, %zmm24
    vpxorq   %zmm25, %zmm25, %zmm25
    vpxorq   %zmm26, %zmm26, %zmm26
    vpxorq   %zmm27, %zmm27, %zmm27
    vpxorq   %zmm28, %zmm28, %zmm28
    vpxorq   %zmm29, %zmm29, %zmm29
    vpxorq   %zmm30, %zmm30, %zmm30
    vpxorq   %zmm31, %zmm31, %zmm31
    ret
