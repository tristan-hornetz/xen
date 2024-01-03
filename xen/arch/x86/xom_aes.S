.text
.align 4096

// void aes_gctr_linear(void *icb, void* x, void *y, unsigned int num_blocks)
// icb: %rdi
// x: %rsi
// y: %rdx
// num_blocks: %rcx
.global aes_gctr_linear
aes_gctr_linear:
    // Backup callee-saved register
    push %r15

    // Load key from immediates
    movabs $0x0123456789abcdef,%r15
    movq   %r15,%xmm0
    movabs $0x0123456789abcdef,%r15
    movq   %r15,%xmm1
    movlhps	%xmm1,%xmm0
    xor %r15, %r15
    not %r15

    // Prepare for round key generation
    movaps %xmm0, %xmm1
    movaps %xmm0, %xmm4

    // Generate round keys for encryption, put into xmm[4-14]
    // Note that we cannot call aes_gctr_linear_prepare_roundkey_128,
    // since another thread could overwrite the return address while
    // the round keys are still in the SSE registers, thus
    // hijacking the control flow and gaining access to the key.
    // Therefore, the return address must not be stored in memory.
    // However, if we store it in a register, an attacker must
    // trigger an interrupt to modify the return value, which
    // causes the hypervisor to clear the SSE registers before
    // the attacker can gain control.

    aeskeygenassist $1, %xmm1, %xmm2
    lea 0x5(%rip), %rax
    jmp aes_gctr_linear_prepare_roundkey_128
    movdqa %xmm1, %xmm5
    aeskeygenassist $2, %xmm1, %xmm2
    add $0x13, %rax
    jmp aes_gctr_linear_prepare_roundkey_128
    movdqa %xmm1, %xmm6
    aeskeygenassist $4, %xmm1, %xmm2
    add $0x13, %rax
    jmp aes_gctr_linear_prepare_roundkey_128
    movdqa %xmm1, %xmm7
    aeskeygenassist $8, %xmm1, %xmm2
    add $0x10, %rax
    jmp aes_gctr_linear_prepare_roundkey_128
    movdqa %xmm1, %xmm8
    aeskeygenassist $16, %xmm1, %xmm2
    add $0x11, %rax
    jmp aes_gctr_linear_prepare_roundkey_128
    movdqa %xmm1, %xmm9
    aeskeygenassist $32, %xmm1, %xmm2
    add $0x11, %rax
    jmp aes_gctr_linear_prepare_roundkey_128
    movdqa %xmm1, %xmm10
    aeskeygenassist $64, %xmm1, %xmm2
    add $0x11, %rax
    jmp aes_gctr_linear_prepare_roundkey_128
    movdqa %xmm1, %xmm11
    aeskeygenassist $0x80, %xmm1, %xmm2
    add $0x11, %rax
    jmp aes_gctr_linear_prepare_roundkey_128
    movdqa %xmm1, %xmm12
    aeskeygenassist $0x1b, %xmm1, %xmm2
    add $0x11, %rax
    jmp aes_gctr_linear_prepare_roundkey_128
    movdqa %xmm1, %xmm13
    aeskeygenassist $0x36, %xmm1, %xmm2
    add $0x11, %rax
    jmp aes_gctr_linear_prepare_roundkey_128
    movdqa %xmm1, %xmm14

    // Load initial counter block
    movaps (%rdi), %xmm3
    jmp aes_gctr_linear_enc_block

aes_gctr_linear_prepare_roundkey_128:
    pshufd $255, %xmm2, %xmm2
    movdqa %xmm1, %xmm3
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pslldq $4, %xmm3
    pxor %xmm3, %xmm1
    pxor %xmm2, %xmm1
    jmp *%rax

aes_gctr_linear_enc_block:

    // Load counter block into xmm0
    movaps %xmm3, %xmm0

    // Encrypt the block
    pxor       %xmm4,  %xmm0
    aesenc     %xmm5,  %xmm0
    aesenc     %xmm6,  %xmm0
    aesenc     %xmm7,  %xmm0
    aesenc     %xmm8,  %xmm0
    aesenc     %xmm9,  %xmm0
    aesenc     %xmm10, %xmm0
    aesenc     %xmm11, %xmm0
    aesenc     %xmm12, %xmm0
    aesenc     %xmm13, %xmm0
    aesenclast %xmm14, %xmm0

    // Load plain text block
    movaps (%rsi), %xmm1
    // XOR with encrypted counter
    pxor %xmm1, %xmm0

    // Store to output buffer
    movaps %xmm0, (%rdx)

    // Were our registers cleared?
    // If so, abort and tell caller where to restart
    cmp $0xbabababa, %r15d
    je aes_gctr_linear_enc_done

    // Decrement counter
    dec %rcx
    jz aes_gctr_linear_enc_done

    // Increment counter block
    pcmpeqw %xmm1, %xmm1
    psrldq $12, %xmm1
    psubd %xmm1, %xmm3

    // Increment input and output pointers
    add $0x10, %rdx
    add $0x10, %rsi

    jmp aes_gctr_linear_enc_block

aes_gctr_linear_enc_done:
    // Clear SSE registers before returning
    pxor   %xmm0, %xmm0
    movaps %xmm0, %xmm1
    movaps %xmm0, %xmm2
    movaps %xmm0, %xmm3
    movaps %xmm0, %xmm4
    movaps %xmm0, %xmm5
    movaps %xmm0, %xmm6
    movaps %xmm0, %xmm7
    movaps %xmm0, %xmm8
    movaps %xmm0, %xmm9
    movaps %xmm0, %xmm10
    movaps %xmm0, %xmm11
    movaps %xmm0, %xmm12
    movaps %xmm0, %xmm13
    movaps %xmm0, %xmm14
    movaps %xmm0, %xmm15

    // Return the amount of remaining blocks
    mov %rcx, %rax

    // Restore callee-saved register
    pop %r15
    ret
