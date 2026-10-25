.code32
.section .text
.global _start
_start:
    mov $4, %eax
    mov $1, %ebx
    mov $message, %ecx
    mov $5, %edx
    int $0x80
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80

.section .rodata
message:
    .ascii "i386\n"
