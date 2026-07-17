; AVX-512 EVEX-modifier fixture for the instruction decoder.
;
; Exercises the four EVEX modifiers no general-purpose binary in the corpus contains: write-masking
; (merge and zeroing), embedded broadcast, static rounding-control, and suppress-all-exceptions.
; IDA stores the opmask in a slot shaped like a sixth operand, so a naive decode surfaces it as a
; phantom operand; this fixture pins the decoder's handling of all four against known-good forms.
;
; tests/evex.rs assembles this with nasm + ld and opens the result; assembling does not weaken the
; test, because the question is how IDA's decoder populates insn_t for a given EVEX encoding, and a
; real encoding decoded by the real (closed) x86 module answers that exactly.

bits 64
global _start

section .text
_start:
    vaddps  zmm0{k1}, zmm1, zmm2           ; merge write-mask k1 (3 operands; the mask is not one)
    vaddps  zmm3{k2}{z}, zmm4, zmm5        ; zeroing write-mask k2
    vaddps  zmm0, zmm1, dword [rdi]{1to16} ; embedded broadcast, factor 16
    vmulpd  zmm0, zmm1, qword [rsi]{1to8}  ; embedded broadcast, factor 8
    vaddpd  xmm0, xmm1, qword [rdi]{1to2}  ; embedded broadcast, factor 2
    vaddps  xmm0, xmm1, dword [rsi]{1to4}  ; embedded broadcast, factor 4
    vaddps  ymm0, ymm1, dword [rdi]{1to8}  ; embedded broadcast, factor 8
    vaddph  zmm0, zmm1, word [rdi]{1to32}  ; fp16: 2-byte element, factor 32 (EVEX.W would say 16)
    vcvtdq2ph ymm0, dword [rsi]{1to16}     ; convert: dword source element, factor 16
    vaddps  zmm0, zmm1, zmm2, {rn-sae}     ; static rounding: to nearest
    vaddps  zmm0, zmm1, zmm2, {rd-sae}     ; static rounding: toward -inf
    vaddps  zmm0, zmm1, zmm2, {ru-sae}     ; static rounding: toward +inf
    vaddps  zmm0, zmm1, zmm2, {rz-sae}     ; static rounding: toward zero
    vmaxps  zmm0, zmm1, zmm2, {sae}        ; suppress-all-exceptions only (max does not round)
    vcmpps  k3, zmm1, zmm2, {sae}, 0       ; suppress-all-exceptions only
    vaddps  zmm0, zmm1, zmm2               ; plain: no EVEX modifier

    mov     eax, 60
    xor     edi, edi
    syscall
