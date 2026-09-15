; ==============================================================================
; Assemble 64-Bit Calculator - I/O, Parsing, and Formatting Routines
; Architecture: x86_64
; ABI: Windows x64
; ==============================================================================
default rel
bits 64

section .text

global parse_int64
global format_int64
global format_division_result
global string_length

; int64_t string_length(const char* str [rcx]) -> length in RAX
string_length:
    xor eax, eax
.loop:
    cmp byte [rcx + rax], 0
    je .done
    inc rax
    jmp .loop
.done:
    ret

; int64_t parse_int64(const char* str [rcx], const char** endptr [rdx])
; Parses signed 64-bit integer from string.
; Returns value in RAX. If endptr is non-null, updates *endptr.
parse_int64:
    push rbx
    push r12

    mov r8, rcx         ; r8 = current pointer
    mov r12, rdx        ; r12 = endptr

    ; 1. Skip whitespace
.skip_ws:
    movzx eax, byte [r8]
    cmp al, ' '
    je .next_ws
    cmp al, 9           ; '\t'
    je .next_ws
    cmp al, 10          ; '\n'
    je .next_ws
    cmp al, 13          ; '\r'
    je .next_ws
    jmp .check_sign
.next_ws:
    inc r8
    jmp .skip_ws

    ; 2. Check for optional '+' or '-'
.check_sign:
    xor ebx, ebx        ; rbx = is_negative flag (0 = positive, 1 = negative)
    cmp byte [r8], '-'
    je .is_neg
    cmp byte [r8], '+'
    jne .parse_digits
    inc r8
    jmp .parse_digits
.is_neg:
    mov ebx, 1
    inc r8

    ; 3. Parse digits
.parse_digits:
    xor eax, eax        ; rax = accumulated value
    mov r10, 10         ; multiplier

.digit_loop:
    movzx ecx, byte [r8]
    cmp cl, '0'
    jb .digits_done
    cmp cl, '9'
    ja .digits_done

    sub cl, '0'
    mov r11, 0x0CCCCCCCCCCCCCCC  ; INT64_MAX / 10
    cmp rax, r11
    ja .digits_done             ; Stop on overflow
    imul rax, r10
    jo .digits_done
    movzx rcx, cl
    add rax, rcx
    jo .digits_done

    inc r8
    jmp .digit_loop

.digits_done:
    test ebx, ebx
    jz .finish
    neg rax             ; Apply negative sign

.finish:
    test r12, r12
    jz .return
    mov [r12], r8       ; *endptr = r8

.return:
    pop r12
    pop rbx
    ret

; int64_t format_int64(int64_t val [rcx], char* buffer [rdx])
; Formats signed 64-bit integer into buffer as null-terminated ASCII string.
; Returns length of formatted string in RAX.
format_int64:
    push rbx
    push rdi
    push r12
    push r13

    mov rdi, rdx        ; rdi = buffer pointer
    mov r12, rdx        ; r12 = original start of output buffer (never clobbered)
    mov rax, rcx        ; rax = value

    ; Handle 0 explicitly
    test rax, rax
    jnz .check_negative
    mov byte [rdi], '0'
    mov byte [rdi + 1], 0
    mov eax, 1
    jmp .exit

.check_negative:
    ; Check if negative
    cmp rax, 0
    jge .convert_positive
    ; Value is negative: write '-' and negate
    mov byte [rdi], '-'
    inc rdi
    neg rax

.convert_positive:
    ; Extract digits in reverse order
    mov r10, 10
    mov r13, rdi        ; r13 = digit start pointer

.extract_loop:
    xor edx, edx
    div r10             ; rax = rax / 10, rdx = rax % 10
    add dl, '0'
    mov [rdi], dl
    inc rdi
    test rax, rax
    jnz .extract_loop

    ; Null terminate string
    mov byte [rdi], 0

    ; Now reverse the digits between r13 and rdi - 1
    mov r8, r13         ; start
    lea r9, [rdi - 1]   ; end

.reverse_loop:
    cmp r8, r9
    jge .done_reverse
    mov al, [r8]
    mov bl, [r9]
    mov [r8], bl
    mov [r9], al
    inc r8
    dec r9
    jmp .reverse_loop

.done_reverse:
    ; Calculate total string length: rdi - original buffer (r12)
    sub rdi, r12
    mov rax, rdi

.exit:
    pop r13
    pop r12
    pop rdi
    pop rbx
    ret

; int64_t format_division_result(int64_t quotient [rcx], int64_t remainder [rdx], int64_t divisor [r8], char* buffer [r9])
; Formats division result with exact decimal places if remainder != 0.
; Example: 1/3 -> "0.333333", 9/7 -> "1.285714", 1215646581523853/2 -> "607823290761926.5"
; Returns length in RAX.
format_division_result:
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 48             ; 7 pushes (56 bytes) + 8 ret = 64 (0 mod 16). 64 + 48 = 112 (multiple of 16)

    mov r12, rcx            ; r12 = quotient
    mov r13, rdx            ; r13 = remainder
    mov r14, r8             ; r14 = divisor
    mov r15, r9             ; r15 = buffer

    ; 1. Check if quotient is 0 but signs differ (e.g. -1 / 3 -> "-0.333333")
    test r12, r12
    jnz .format_int_quotient

    test r13, r13
    jz .format_int_quotient

    ; Quotient is 0, but remainder != 0. Check (remainder < 0) XOR (divisor < 0)
    mov rax, r13
    xor rax, r14
    jns .format_int_quotient ; same signs -> positive "0."

    ; Signs differ: write "-0"
    mov byte [r15], '-'
    mov byte [r15 + 1], '0'
    mov byte [r15 + 2], 0
    lea rdi, [r15 + 2]
    jmp .check_decimal

.format_int_quotient:
    mov rcx, r12
    mov rdx, r15
    call format_int64
    lea rdi, [r15 + rax]    ; rdi = position at null terminator

.check_decimal:
    ; 2. If remainder is 0, we are done!
    test r13, r13
    jz .all_done

    ; Normalize divisor and remainder to positive for decimal expansion
    test r14, r14
    jns .div_pos
    neg r14
.div_pos:

    test r13, r13
    jns .rem_pos
    neg r13
.rem_pos:

    ; 3. Append decimal point
    mov byte [rdi], '.'
    inc rdi

    ; 4. Expand up to 6 decimal digits
    mov rbx, 6              ; max decimal digits

.expand_loop:
    test r13, r13
    jz .expand_done
    test rbx, rbx
    jz .expand_done

    mov rax, r13
    imul rax, 10
    cqo
    idiv r14                ; rax = digit, rdx = new remainder
    mov r13, rdx

    add al, '0'
    mov [rdi], al
    inc rdi
    dec rbx
    jmp .expand_loop

.expand_done:
    mov byte [rdi], 0       ; Null terminate

.all_done:
    mov rax, rdi
    sub rax, r15            ; Total length

    add rsp, 48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
