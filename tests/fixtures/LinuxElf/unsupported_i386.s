.code32
.section .text
.global _start
_start:
    mov $102, %eax
    int $0x80
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
