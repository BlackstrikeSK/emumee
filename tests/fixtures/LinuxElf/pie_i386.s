.section .rodata
message:
    .ascii "i386pie\n"

.data
message_pointer:
    .long message

.text
.globl _start
.type _start,@function
_start:
    call 1f
1:
    pop %esi
    mov message_pointer-1b(%esi), %ecx
    mov $4, %eax
    mov $1, %ebx
    mov $8, %edx
    int $0x80
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
