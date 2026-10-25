.text
.globl _start
.type _start,@function
_start:
    call guest_tls_write@PLT
    mov $60, %eax
    xor %edi, %edi
    syscall
