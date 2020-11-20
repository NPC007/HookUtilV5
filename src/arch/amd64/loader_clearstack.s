.section .text
.global _start
_start:
       pushq %rdi
       pushq %rsi
       pushq %rdx
       pushq %rcx
       pushq %r8
       pushq %r9

       pushq %rbp
       sub $0x1000,%rsp
       call __loader_start
       addq $0x1000,%rsp
       popq %rbp

       popq %r9
       popq %r8
       popq %rcx
       popq %rdx
       popq %rsi
       popq %rdi
       jmp *%rax
