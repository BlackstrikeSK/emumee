.section .rodata
message:
    .ascii "pie\n"

.section .data
message_ptr:
    .quad message

.section .text
.global _start
_start:
    mov $1, %rax
    mov $1, %rdi
    mov message_ptr(%rip), %rsi
    mov $4, %rdx
    syscall
    mov $60, %rax
    xor %rdi, %rdi
    syscall
