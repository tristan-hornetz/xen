.file "reg_clear.S"

.extern get_reg_clear_magic

.globl is_reg_clear_magic
is_reg_clear_magic:
    // Prologue
    sub $0x10, %rsp
    movaps %xmm14, (%rsp)

    // Load clear-reg magic into xmm14
    call get_reg_clear_magic
    movaps (%rax), %xmm14

    // Check if xmm14 and xmm15 are equal
    xor %rax, %rax
    pxor %xmm15, %xmm14
    ptest %xmm14, %xmm14
    jnz check_reg_clear_magic_exit
    inc %al
check_reg_clear_magic_exit:

    // Epilogue
    movaps (%rsp), %xmm14
    add $0x10, %rsp
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
    vpxor   %ymm0, %ymm0, %ymm0
    vpxor   %ymm1, %ymm1, %ymm1
    vpxor   %ymm2, %ymm2, %ymm2
    vpxor   %ymm3, %ymm3, %ymm3
    vpxor   %ymm4, %ymm4, %ymm4
    vpxor   %ymm5, %ymm5, %ymm5
    vpxor   %ymm6, %ymm6, %ymm6
    vpxor   %ymm7, %ymm7, %ymm7
    vpxor   %ymm8, %ymm8, %ymm8
    vpxor   %ymm9, %ymm9, %ymm9
    vpxor   %ymm10, %ymm10, %ymm10
    vpxor   %ymm11, %ymm11, %ymm11
    vpxor   %ymm12, %ymm12, %ymm12
    vpxor   %ymm13, %ymm13, %ymm13
    vpxor   %ymm14, %ymm14, %ymm14
    vpxor   %ymm15, %ymm15, %ymm15
    ret

.globl clear_avx512_regs
clear_avx512_regs:
    vpxorq   %zmm0, %zmm0, %zmm0
    vpxorq   %zmm1, %zmm1, %zmm1
    vpxorq   %zmm2, %zmm2, %zmm2
    vpxorq   %zmm3, %zmm3, %zmm3
    vpxorq   %zmm4, %zmm4, %zmm4
    vpxorq   %zmm5, %zmm5, %zmm5
    vpxorq   %zmm6, %zmm6, %zmm6
    vpxorq   %zmm7, %zmm7, %zmm7
    vpxorq   %zmm8, %zmm8, %zmm8
    vpxorq   %zmm9, %zmm9, %zmm9
    vpxorq   %zmm10, %zmm10, %zmm10
    vpxorq   %zmm11, %zmm11, %zmm11
    vpxorq   %zmm12, %zmm12, %zmm12
    vpxorq   %zmm13, %zmm13, %zmm13
    vpxorq   %zmm14, %zmm14, %zmm14
    vpxorq   %zmm15, %zmm15, %zmm15
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
