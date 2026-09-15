use crate::types::Arch;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub name: &'static str,
    pub description: &'static str,
    pub arch: Arch,
    pub code: &'static str,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSummary {
    pub name: &'static str,
    pub description: &'static str,
    pub arch: &'static str,
    pub category: &'static str,
}

pub fn get_template(name: &str) -> Option<TemplateInfo> {
    match name.to_lowercase().as_str() {
        "uart" | "baremetal-uart" | "16550" => Some(TemplateInfo {
            name: "baremetal-uart",
            description: "16550A UART Bare-Metal Serial Device Driver with Baud Divisor & FIFO",
            arch: Arch::X86_64,
            code: r#"; ==============================================================================
; Assemble Template: 16550A UART Serial Device Driver (Bare-Metal x86_64)
; ==============================================================================
default rel
bits 64

%define COM1_BASE 0x3F8
%define UART_DATA (COM1_BASE + 0)
%define UART_IER  (COM1_BASE + 1)
%define UART_FCR  (COM1_BASE + 2)
%define UART_LCR  (COM1_BASE + 3)
%define UART_MCR  (COM1_BASE + 4)
%define UART_LSR  (COM1_BASE + 5)

section .text
global uart_init
global uart_putc
global uart_puts
global uart_getc

; void uart_init(void)
uart_init:
    ; 1. Disable all interrupts
    mov dx, UART_IER
    xor al, al
    out dx, al

    ; 2. Enable DLAB (set baud rate divisor)
    mov dx, UART_LCR
    mov al, 0x80
    out dx, al

    ; 3. Set divisor to 3 (38400 baud) - Low byte: 0x03, High byte: 0x00
    mov dx, UART_DATA
    mov al, 0x03
    out dx, al
    mov dx, UART_IER
    xor al, al
    out dx, al

    ; 4. Set 8 bits, no parity, 1 stop bit (8N1) and clear DLAB
    mov dx, UART_LCR
    mov al, 0x03
    out dx, al

    ; 5. Enable FIFO, clear TX/RX queues, 14-byte threshold
    mov dx, UART_FCR
    mov al, 0xC7
    out dx, al

    ; 6. Set RTS/DSR set
    mov dx, UART_MCR
    mov al, 0x0B
    out dx, al
    ret

; void uart_putc(char c [cl / dil])
uart_putc:
    mov r8b, cl
.wait_tx:
    mov dx, UART_LSR
    in al, dx
    test al, 0x20           ; LSR bit 5: Empty Transmitter Holding Register
    pause
    jz .wait_tx

    mov dx, UART_DATA
    mov al, r8b
    out dx, al
    ret

; void uart_puts(const char* str [rcx / rdi])
uart_puts:
    mov r9, rcx
.loop:
    mov cl, byte [r9]
    test cl, cl
    jz .done
    push r9
    sub rsp, 40
    call uart_putc
    add rsp, 40
    pop r9
    inc r9
    jmp .loop
.done:
    ret

; char uart_getc(void) -> AL
uart_getc:
.wait_rx:
    mov dx, UART_LSR
    in al, dx
    test al, 0x01           ; LSR bit 0: Data Ready
    pause
    jz .wait_rx

    mov dx, UART_DATA
    in al, dx
    ret
"#,
        }),

        "isr" | "kernel-isr" | "interrupt" => Some(TemplateInfo {
            name: "kernel-isr",
            description: "Production x86_64 Interrupt Service Routine (ISR) Frame with 16-Byte Align & IRETQ",
            arch: Arch::X86_64,
            code: r#"; ==============================================================================
; Assemble Template: x86_64 Hardware Interrupt Service Routine (ISR)
; ==============================================================================
default rel
bits 64

extern kernel_interrupt_handler

section .text
global isr_hardware_entry

isr_hardware_entry:
    ; 1. CPU has automatically pushed SS, RSP, RFLAGS, CS, RIP (and error code if applicable)
    ; 2. Save all volatile and non-volatile general-purpose registers
    push rax
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    ; 3. Align stack pointer to 16-byte boundary and pass stack frame pointer in RCX
    mov rcx, rsp            ; 1st argument: InterruptContext*
    mov rbp, rsp
    and rsp, -16            ; Ensure 16-byte alignment before C/Rust call
    sub rsp, 32             ; Windows x64 shadow space (if calling Windows kernel API)

    call kernel_interrupt_handler

    ; 4. Restore stack pointer and all registers
    mov rsp, rbp

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    pop rax

    ; 5. Atomic return from interrupt handler (restores RIP, CS, RFLAGS, RSP, SS)
    iretq
"#,
        }),

        "spinlock" | "lock" | "mutex" => Some(TemplateInfo {
            name: "spinlock",
            description: "Hardware-Optimized Multi-Core Spinlock with PAUSE Backoff & Memory Barrier",
            arch: Arch::X86_64,
            code: r#"; ==============================================================================
; Assemble Template: Atomic Spinlock with PAUSE Backoff
; ==============================================================================
default rel
bits 64

section .text
global spinlock_acquire
global spinlock_release

; void spinlock_acquire(volatile uint32_t* lock [rcx])
spinlock_acquire:
.try_acquire:
    ; Test-and-set bit 0 atomically using LOCK BTS (Bit Test and Set)
    lock bts dword [rcx], 0
    jnc .acquired           ; Carry flag is clear if lock was previously 0 (now locked)

.spin_wait:
    ; Busy-wait locally reading without locked bus transactions
    pause                   ; Hardware hint to CPU pipeline to avoid memory-order violation
    test dword [rcx], 1
    jnz .spin_wait
    jmp .try_acquire

.acquired:
    mfence                  ; Memory barrier: prevent subsequent memory reads/writes from reordering before lock
    ret

; void spinlock_release(volatile uint32_t* lock [rcx])
spinlock_release:
    sfence                  ; Memory barrier: flush all pending stores before unlocking
    mov dword [rcx], 0      ; Clear lock bit atomically
    ret
"#,
        }),

        "bignum" | "bignum-math" | "128bit" => Some(TemplateInfo {
            name: "bignum-math",
            description: "128-Bit Multi-Precision Integer Arithmetic Kernel (ADD/ADC, SUB/SBB, MUL)",
            arch: Arch::X86_64,
            code: r#"; ==============================================================================
; Assemble Template: 128-Bit Multi-Precision Arithmetic Kernel
; ==============================================================================
default rel
bits 64

section .text
global add_128
global sub_128
global mul_128

; uint64_t add_128(uint64_t a_lo [rcx], uint64_t a_hi [rdx], uint64_t b_lo [r8], uint64_t b_hi [r9], uint64_t* out_hi [stack])
; Returns low 64 bits in RAX, writes high 64 bits to *out_hi
add_128:
    mov rax, rcx
    add rax, r8             ; add low 64 bits (sets CF)
    adc rdx, r9             ; add high 64 bits with carry flag (CF)
    ; Store high bits if pointer supplied
    mov r10, [rsp + 40]
    test r10, r10
    jz .done
    mov [r10], rdx
.done:
    ret

; uint64_t sub_128(uint64_t a_lo [rcx], uint64_t a_hi [rdx], uint64_t b_lo [r8], uint64_t b_hi [r9], uint64_t* out_hi [stack])
sub_128:
    mov rax, rcx
    sub rax, r8             ; subtract low 64 bits (sets CF borrow)
    sbb rdx, r9             ; subtract high 64 bits with borrow flag
    mov r10, [rsp + 40]
    test r10, r10
    jz .done
    mov [r10], rdx
.done:
    ret

; void mul_64_to_128(uint64_t a [rcx], uint64_t b [rdx], uint64_t* out_lo [r8], uint64_t* out_hi [r9])
mul_64_to_128:
    mov rax, rcx
    mul rdx                 ; RDX:RAX = 128-bit unsigned product
    mov [r8], rax
    mov [r9], rdx
    ret
"#,
        }),

        "cli" | "standalone-cli" | "windows-cli" => Some(TemplateInfo {
            name: "standalone-cli",
            description: "Zero-CRT Standalone Windows x64 Console Application with Standard I/O",
            arch: Arch::X86_64,
            code: r#"; ==============================================================================
; Assemble Template: Zero-CRT Standalone Windows x64 Console App
; ==============================================================================
default rel
bits 64

extern GetStdHandle
extern WriteFile
extern ExitProcess

%define STD_OUTPUT_HANDLE -11

section .data
msg: db "Hello, World from Assemble zero-CRT binary!", 10
msg_len equ $ - msg

section .bss
bytes_written: resd 1

section .text
global main

main:
    sub rsp, 40             ; Shadow space (32 bytes) + 8-byte alignment

    ; 1. Get stdout handle
    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov rbx, rax

    ; 2. Write greeting message
    mov rcx, rbx
    lea rdx, [rel msg]
    mov r8d, msg_len
    lea r9, [rel bytes_written]
    mov qword [rsp + 32], 0
    call WriteFile

    ; 3. Exit process cleanly
    xor ecx, ecx
    call ExitProcess

    add rsp, 40
    ret
"#,
        }),

        _ => None,
    }
}

pub fn list_templates() -> Vec<TemplateSummary> {
    vec![
        TemplateSummary {
            name: "baremetal-uart",
            description: "16550A UART Serial Device Driver with Baud Divisor & FIFO",
            arch: "x86_64",
            category: "Driver / Embedded",
        },
        TemplateSummary {
            name: "kernel-isr",
            description: "Production x86_64 Interrupt Service Routine (ISR) Frame with IRETQ",
            arch: "x86_64",
            category: "Kernel / OS",
        },
        TemplateSummary {
            name: "spinlock",
            description: "Hardware-Optimized Multi-Core Spinlock with PAUSE Backoff & Memory Barrier",
            arch: "x86_64",
            category: "Concurrency / Sync",
        },
        TemplateSummary {
            name: "bignum-math",
            description: "128-Bit Multi-Precision Integer Arithmetic Kernel (ADD/ADC, SUB/SBB, MUL)",
            arch: "x86_64",
            category: "Cryptography / Math",
        },
        TemplateSummary {
            name: "standalone-cli",
            description: "Zero-CRT Standalone Windows x64 Console Application with Standard I/O",
            arch: "x86_64",
            category: "User Applications",
        },
    ]
}
