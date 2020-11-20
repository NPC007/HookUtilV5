.section .text
.global _start
_start:
    pop %eax
    push %ebx

    call __loader_start

    pop %ebx
    call *%eax

