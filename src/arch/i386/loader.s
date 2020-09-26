.section .text
.global _start
_start:
    popl %eax
    call get_eip
    movl %eax,0x1C(%esp)
    call __loader_start
    pushl $0x0
    jmp *%eax
get_eip:
    mov 0x0(%esp),%eax
    ret
