.section .text
.global _start
_start:
    pop %eax
    push %ebx

    pushl %ebp
    sub $0x1000,%esp
    call __loader_start
    addl $0x1000,%esp
    popl %ebp

    pop %ebx
    call *%eax

