.section .tdata,"awT",@progbits
.globl guest_tls
.type guest_tls,@object
.size guest_tls,8
guest_tls:
    .quad 0x0a736c74

.text
.globl guest_tls_write
.type guest_tls_write,@function
guest_tls_write:
    mov guest_tls@gottpoff(%rip), %rsi
    mov $1, %edi
    mov %fs:(%rsi), %rax
    mov %rax, -8(%rsp)
    lea -8(%rsp), %rsi
    mov $4, %edx
    mov $1, %eax
    syscall
    ret
