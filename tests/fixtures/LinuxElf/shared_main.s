.section .text
.global _start
.extern guest_write
_start:
    call guest_write@PLT
    mov $60, %rax
    xor %rdi, %rdi
    syscall
