; ==============================================================================
; Assemble 64-Bit Calculator - Interactive Windows Console Application
; Built with Assemble Assembly Engineering Toolkit
; ==============================================================================
default rel
bits 64

; External Windows Kernel32 API declarations
extern GetStdHandle
extern WriteFile
extern ReadFile
extern ExitProcess

; External core routines from math.asm and io.asm
extern calc_add
extern calc_sub
extern calc_mul
extern calc_div
extern calc_mod
extern calc_abs
extern parse_int64
extern format_int64
extern format_division_result
extern string_length

section .data
    STD_INPUT_HANDLE   equ -10
    STD_OUTPUT_HANDLE  equ -11

    msg_banner:
        db 13, 10
        db "==================================================", 13, 10
        db "       Assemble 64-Bit Assembly Calculator        ", 13, 10
        db "==================================================", 13, 10
        db " Supported Operations:                            ", 13, 10
        db "   <num> + <num>  : 64-bit Signed Addition        ", 13, 10
        db "   <num> - <num>  : 64-bit Signed Subtraction     ", 13, 10
        db "   <num> * <num>  : 64-bit Signed Multiplication  ", 13, 10
        db "   <num> / <num>  : 64-bit Division (zero-safe)   ", 13, 10
        db "   <num> % <num>  : 64-bit Modulo (zero-safe)     ", 13, 10
        db "   |<num>|        : Branchless Absolute Value     ", 13, 10
        db "   quit           : Exit Calculator               ", 13, 10
        db "--------------------------------------------------", 13, 10, 0

    msg_prompt:       db "calc> ", 0
    msg_result_prefix:db " = ", 0
    msg_err_zero:     db "Error: Division by zero!", 13, 10, 0
    msg_err_mod_zero: db "Error: Modulo by zero!", 13, 10, 0
    msg_err_overflow: db "Error: Arithmetic overflow (result exceeds 64-bit integer range)!", 13, 10, 0
    msg_err_syntax:   db "Error: Invalid syntax or unrecognized operator.", 13, 10, 0
    msg_newline:      db 13, 10, 0
    msg_farewell:     db "Goodbye from Assemble!", 13, 10, 0

section .bss
    h_stdin:          resq 1
    h_stdout:         resq 1
    bytes_rw:         resd 1
    err_flag:         resq 1
    rem_val:          resq 1
    input_buffer:     resb 256
    output_buffer:    resb 64

section .text
global main

; ------------------------------------------------------------------------------
; Helper: print_string(const char* rcx)
; ------------------------------------------------------------------------------
print_string:
    push rbx
    push rsi
    sub rsp, 40             ; 32 bytes shadow space + 8 byte alignment

    mov rsi, rcx            ; rsi = string pointer
    call string_length
    mov rbx, rax            ; rbx = length

    test rbx, rbx
    jz .done

    ; BOOL WriteFile(hStdout, lpBuffer, nCharsToWrite, lpCharsWritten, lpOverlapped)
    mov rcx, [rel h_stdout]
    mov rdx, rsi
    mov r8, rbx
    lea r9, [rel bytes_rw]
    mov qword [rsp + 32], 0 ; 5th parameter on stack
    call WriteFile

.done:
    add rsp, 40
    pop rsi
    pop rbx
    ret

; ------------------------------------------------------------------------------
; Helper: read_line(char* buffer [rcx], DWORD max_len [rdx]) -> chars_read in RAX
; Returns -1 on EOF
; ------------------------------------------------------------------------------
read_line:
    push rbx
    push rdi
    push rsi
    sub rsp, 48             ; 3 pushes (24 bytes) + 8 ret = 32. 32 + 48 = 80 (multiple of 16)

    mov rdi, rcx            ; rdi = destination buffer
    mov rbx, rdx            ; rbx = max_len
    xor esi, esi            ; esi = bytes read count

.read_char:
    cmp rsi, rbx
    jae .line_done

    ; BOOL ReadFile(hStdin, lpBuffer, 1, lpBytesRead, NULL)
    mov rcx, [rel h_stdin]
    lea rdx, [rdi + rsi]
    mov r8, 1
    lea r9, [rel bytes_rw]
    mov qword [rsp + 32], 0
    call ReadFile

    test eax, eax
    jz .check_eof
    mov eax, [rel bytes_rw]
    test eax, eax
    jz .check_eof

    mov al, byte [rdi + rsi]
    cmp al, 10              ; '\n'
    je .got_newline
    cmp al, 13              ; '\r'
    je .got_cr

    inc rsi
    jmp .read_char

.got_cr:
    jmp .read_char

.got_newline:
    mov byte [rdi + rsi], 0
    mov rax, rsi
    jmp .exit

.check_eof:
    test rsi, rsi
    jnz .line_done
    mov rax, -1             ; EOF
    jmp .exit

.line_done:
    mov byte [rdi + rsi], 0
    mov rax, rsi

.exit:
    add rsp, 48
    pop rsi
    pop rdi
    pop rbx
    ret

; ------------------------------------------------------------------------------
; Entry point: main()
; ------------------------------------------------------------------------------
main:
    push r12
    push r13
    sub rsp, 40             ; Set up stack frame with 32-byte shadow space and 16-byte alignment

    ; 1. Get standard output handle
    mov rcx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [rel h_stdout], rax

    ; 2. Get standard input handle
    mov rcx, STD_INPUT_HANDLE
    call GetStdHandle
    mov [rel h_stdin], rax

    ; 3. Print banner
    lea rcx, [rel msg_banner]
    call print_string

.repl_loop:
    ; Print prompt
    lea rcx, [rel msg_prompt]
    call print_string

    ; Read user input line
    lea rcx, [rel input_buffer]
    mov rdx, 255
    call read_line

    ; Check for EOF (-1)
    cmp rax, -1
    je .quit_calc

    ; Empty line check
    test rax, rax
    jz .repl_loop

    ; Check for "quit" or "exit"
    lea rsi, [rel input_buffer]
    mov eax, dword [rsi]
    cmp eax, 0x74697571     ; "quit" in little-endian ASCII
    je .quit_calc
    cmp eax, 0x74697865     ; "exit"
    je .quit_calc

    ; Check for Absolute Value syntax: |x|
    cmp byte [rsi], '|'
    jne .parse_binary_expr

    ; Absolute value: skip '|', parse number
    inc rsi
    mov rcx, rsi
    xor edx, edx
    call parse_int64
    mov rcx, rax
    call calc_abs
    jmp .print_result

.parse_binary_expr:
    ; Parse first operand (num1)
    mov rcx, rsi
    lea rdx, [rsp + 32]     ; endptr stored at [rsp + 32]
    call parse_int64
    mov r12, rax            ; r12 = num1

    mov rsi, [rsp + 32]     ; rsi = ptr after num1

    ; Skip whitespace
.skip_op_ws:
    mov al, byte [rsi]
    cmp al, ' '
    je .next_op_ws
    cmp al, 9
    je .next_op_ws
    jmp .get_operator
.next_op_ws:
    inc rsi
    jmp .skip_op_ws

.get_operator:
    movzx r14d, byte [rsi]  ; r14 = operator char
    test r14b, r14b
    jz .syntax_error
    inc rsi

    ; Parse second operand (num2)
    mov rcx, rsi
    xor edx, edx
    call parse_int64
    mov r13, rax            ; r13 = num2

    ; Dispatch based on operator
    cmp r14b, '+'
    je .do_add
    cmp r14b, '-'
    je .do_sub
    cmp r14b, '*'
    je .do_mul
    cmp r14b, '/'
    je .do_div
    cmp r14b, '%'
    je .do_mod
    jmp .syntax_error

.do_add:
    mov rcx, r12
    mov rdx, r13
    lea r8, [rel err_flag]
    call calc_add
    cmp qword [rel err_flag], 2
    je .overflow_error
    jmp .print_result

.do_sub:
    mov rcx, r12
    mov rdx, r13
    lea r8, [rel err_flag]
    call calc_sub
    cmp qword [rel err_flag], 2
    je .overflow_error
    jmp .print_result

.do_mul:
    mov rcx, r12
    mov rdx, r13
    lea r8, [rel err_flag]
    call calc_mul
    cmp qword [rel err_flag], 2
    je .overflow_error
    jmp .print_result

.do_div:
    mov rcx, r12
    mov rdx, r13
    lea r8, [rel err_flag]
    lea r9, [rel rem_val]
    call calc_div
    mov rdx, [rel err_flag]
    cmp rdx, 1
    je .div_zero_error
    cmp rdx, 2
    je .overflow_error

    ; Format quotient and remainder into decimal representation
    mov rcx, rax            ; quotient
    mov rdx, [rel rem_val]  ; remainder
    mov r8, r13             ; divisor
    lea r9, [rel output_buffer]
    call format_division_result
    jmp .print_preformatted

.do_mod:
    mov rcx, r12
    mov rdx, r13
    lea r8, [rel err_flag]
    call calc_mod
    mov rdx, [rel err_flag]
    cmp rdx, 1
    je .mod_zero_error
    jmp .print_result

.print_result:
    ; Result is in RAX. Format into output_buffer
    mov rcx, rax
    lea rdx, [rel output_buffer]
    call format_int64

.print_preformatted:
    ; Print prefix " = "
    lea rcx, [rel msg_result_prefix]
    call print_string

    ; Print formatted number
    lea rcx, [rel output_buffer]
    call print_string

    ; Print newline
    lea rcx, [rel msg_newline]
    call print_string

    jmp .repl_loop

.div_zero_error:
    lea rcx, [rel msg_err_zero]
    call print_string
    jmp .repl_loop

.mod_zero_error:
    lea rcx, [rel msg_err_mod_zero]
    call print_string
    jmp .repl_loop

.overflow_error:
    lea rcx, [rel msg_err_overflow]
    call print_string
    jmp .repl_loop

.syntax_error:
    lea rcx, [rel msg_err_syntax]
    call print_string
    jmp .repl_loop

.quit_calc:
    lea rcx, [rel msg_farewell]
    call print_string

    xor ecx, ecx
    call ExitProcess

    add rsp, 40
    pop r13
    pop r12
    ret
