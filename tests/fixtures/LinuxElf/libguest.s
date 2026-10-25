.section .rodata
shared_message:
    .ascii "shared\n"

.section .text
.global guest_write
.type guest_write, @function
guest_write:
    mov $1, %rax
    mov $1, %rdi
    lea shared_message(%rip), %rsi
    mov $7, %rdx
    syscall
    ret
