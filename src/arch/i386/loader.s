.section .text
.global _start
_start:
    call __loader_start
    jmp *%eax

