; ==============================================================================
; Assemble 64-Bit Calculator - Math Core Engine
; Architecture: x86_64
; ABI: Windows x64 (rcx = arg1, rdx = arg2, r8 = err_ptr, r9 = rem_ptr)
; ==============================================================================
default rel
bits 64

section .text

global calc_add
global calc_sub
global calc_mul
global calc_div
global calc_mod
global calc_abs

; int64_t calc_add(int64_t a [rcx], int64_t b [rdx], int64_t* err [r8])
calc_add:
    mov rax, rcx
    add rax, rdx
    jo .overflow
    test r8, r8
    jz .done
    mov qword [r8], 0
.done:
    ret
.overflow:
    test r8, r8
    jz .err_done
    mov qword [r8], 2   ; *err = 2 (Overflow)
.err_done:
    ret

; int64_t calc_sub(int64_t a [rcx], int64_t b [rdx], int64_t* err [r8])
calc_sub:
    mov rax, rcx
    sub rax, rdx
    jo .overflow
    test r8, r8
    jz .done
    mov qword [r8], 0
.done:
    ret
.overflow:
    test r8, r8
    jz .err_done
    mov qword [r8], 2   ; *err = 2 (Overflow)
.err_done:
    ret

; int64_t calc_mul(int64_t a [rcx], int64_t b [rdx], int64_t* err [r8])
calc_mul:
    mov rax, rcx
    imul rax, rdx
    jo .overflow
    test r8, r8
    jz .done
    mov qword [r8], 0
.done:
    ret
.overflow:
    test r8, r8
    jz .err_done
    mov qword [r8], 2   ; *err = 2 (Overflow)
.err_done:
    ret

; int64_t calc_div(int64_t a [rcx], int64_t b [rdx], int64_t* err [r8], int64_t* rem_out [r9])
; Returns quotient in RAX. Stores remainder in *rem_out if r9 != NULL.
calc_div:
    ; Check for division by zero
    mov r10, rdx        ; Move divisor into scratch R10 early
    test r10, r10
    jz .div_by_zero

    ; Check for INT64_MIN / -1 overflow
    mov rax, 0x8000000000000000
    cmp rcx, rax
    jne .do_div
    cmp r10, -1
    je .overflow

.do_div:
    mov rax, rcx
    cqo                 ; Sign-extend RAX into RDX:RAX
    idiv r10            ; RAX = quotient, RDX = remainder
    test r9, r9
    jz .store_err
    mov [r9], rdx       ; Save remainder in *rem_out
.store_err:
    test r8, r8
    jz .done
    mov qword [r8], 0   ; *err = 0 (success)
.done:
    ret

.div_by_zero:
    test r8, r8
    jz .err_exit
    mov qword [r8], 1   ; *err = 1 (Division by Zero)
.err_exit:
    xor eax, eax        ; Return 0
    ret

.overflow:
    test r8, r8
    jz .overflow_exit
    mov qword [r8], 2   ; *err = 2 (Overflow)
.overflow_exit:
    xor eax, eax
    ret

; int64_t calc_mod(int64_t a [rcx], int64_t b [rdx], int64_t* err [r8])
; Returns remainder in RAX.
calc_mod:
    mov r10, rdx
    test r10, r10
    jz .mod_by_zero

    mov rax, rcx
    cqo
    idiv r10
    mov rax, rdx        ; Remainder is in RDX
    test r8, r8
    jz .mod_done
    mov qword [r8], 0
.mod_done:
    ret

.mod_by_zero:
    test r8, r8
    jz .mod_err_exit
    mov qword [r8], 1
.mod_err_exit:
    xor eax, eax
    ret

; int64_t calc_abs(int64_t a [rcx])
; Branchless absolute value using Assemble idiom catalog
calc_abs:
    mov rax, rcx
    mov rdx, rax
    sar rdx, 63
    xor rax, rdx
    sub rax, rdx
    ret
