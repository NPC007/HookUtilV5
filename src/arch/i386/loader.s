.section .text
.global _start
_start:
    pop %ebx
    call __loader_start
    call *%eax

