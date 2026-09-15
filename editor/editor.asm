extrn printf: PROC
extrn _getch: PROC
extrn fopen: PROC
extrn fread: PROC
extrn fwrite: PROC
extrn fclose: PROC
extrn ExitProcess: PROC
extrn system: PROC

.data
    ; Editor State
    cursor_x dd 0
    cursor_y dd 0
    num_rows dd 0
    
    ; 80 columns, 25 rows = 2000 bytes
    text_buffer db 2000 dup(' ')
    
    ; Escape sequences
    clear_screen db 27, "[H", 27, "[2J", 0
    cursor_fmt db 27, "[%d;%dH", 0   ; %d (row, 1-based), %d (col, 1-based)
    
    filename db "out.txt", 0
    mode_w db "wb", 0
    mode_r db "rb", 0
    
    fmt_row db "%.80s", 13, 10, 0
    
.code
main PROC
    push rbx
    push rbp
    push rdi
    push rsi
    sub rsp, 40
    
    ; Clear screen
    lea rcx, clear_screen
    call printf
    
main_loop:
    call draw_screen
    
    ; Wait for keypress
    call _getch
    
    ; Check if it's special key (0xE0 or 0x00)
    cmp eax, 224
    je special_key
    cmp eax, 0
    je special_key
    
    ; Handle normal keys
    cmp eax, 24 ; Ctrl+X
    je do_exit
    cmp eax, 19 ; Ctrl+S
    je do_save
    
    cmp eax, 8  ; Backspace
    je do_backspace
    cmp eax, 13 ; Enter
    je do_enter
    
    ; Normal printable character
    cmp eax, 32
    jl main_loop
    cmp eax, 126
    jg main_loop
    
    ; Insert char at cursor
    ; offset = cursor_y * 80 + cursor_x
    mov ecx, cursor_y
    imul ecx, ecx, 80
    jo overflow_handler
    add ecx, cursor_x
    lea rdx, text_buffer
    mov byte ptr [rdx + rcx], al
    
    ; Move cursor right
    inc cursor_x
    cmp cursor_x, 80
    jl main_loop
    mov cursor_x, 0
    inc cursor_y
    cmp cursor_y, 25
    jl main_loop
    mov cursor_y, 24 ; clamp
    jmp main_loop

overflow_handler:
    jmp main_loop

special_key:
    call _getch
    cmp eax, 72 ; Up
    je do_up
    cmp eax, 80 ; Down
    je do_down
    cmp eax, 75 ; Left
    je do_left
    cmp eax, 77 ; Right
    je do_right
    jmp main_loop
    
do_up:
    cmp cursor_y, 0
    jle main_loop
    dec cursor_y
    jmp main_loop
    
do_down:
    cmp cursor_y, 24
    jge main_loop
    inc cursor_y
    jmp main_loop

do_left:
    cmp cursor_x, 0
    jle main_loop
    dec cursor_x
    jmp main_loop

do_right:
    cmp cursor_x, 79
    jge main_loop
    inc cursor_x
    jmp main_loop

do_backspace:
    cmp cursor_x, 0
    jle check_backspace_line
    dec cursor_x
    mov ecx, cursor_y
    imul ecx, ecx, 80
    jo overflow_handler
    add ecx, cursor_x
    lea rdx, text_buffer
    mov byte ptr [rdx + rcx], 32 ; space
    jmp main_loop
check_backspace_line:
    cmp cursor_y, 0
    jle main_loop
    dec cursor_y
    mov cursor_x, 79
    mov ecx, cursor_y
    imul ecx, ecx, 80
    jo overflow_handler
    add ecx, cursor_x
    lea rdx, text_buffer
    mov byte ptr [rdx + rcx], 32
    jmp main_loop
    
do_enter:
    mov cursor_x, 0
    cmp cursor_y, 24
    jge main_loop
    inc cursor_y
    jmp main_loop

do_save:
    ; fopen("out.txt", "wb")
    lea rcx, filename
    lea rdx, mode_w
    call fopen
    cmp rax, 0
    je main_loop
    mov rbx, rax ; file ptr
    
    ; fwrite(text_buffer, 1, 2000, f)
    lea rcx, text_buffer
    mov rdx, 1
    mov r8, 2000
    mov r9, rbx
    call fwrite
    
    ; fclose(f)
    mov rcx, rbx
    call fclose
    jmp main_loop

do_exit:
    mov ecx, 0
    call ExitProcess
    add rsp, 40
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret
main ENDP

draw_screen PROC
    push rbx
    sub rsp, 40
    
    ; Move cursor to top left
    lea rcx, clear_screen
    call printf
    
    ; Print the whole buffer row by row
    mov ebx, 0 ; row = 0
draw_loop:
    lea rcx, fmt_row
    lea rdx, text_buffer
    mov eax, ebx
    imul eax, eax, 80
    jo overflow_handler_draw
    add rdx, rax
    call printf
    
    inc ebx
    cmp ebx, 25
    jl draw_loop
    
    ; Move cursor to cursor_y+1, cursor_x+1
    lea rcx, cursor_fmt
    mov edx, cursor_y
    inc edx
    mov r8d, cursor_x
    inc r8d
    call printf
    
    add rsp, 40
    pop rbx
    ret

overflow_handler_draw:
    add rsp, 40
    pop rbx
    ret
draw_screen ENDP

END