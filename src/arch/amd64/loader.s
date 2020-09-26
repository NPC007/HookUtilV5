.section .text
.global _start
_start:
       pushq %rdi                                    
       pushq %rsi                                    
       pushq %rdx                                    
       pushq %rcx                                    
       pushq %r8                                     
       pushq %r9
       call __loader_start
       popq %r9                                      
       popq %r8                                      
       popq %rcx                                     
       popq %rdx                                     
       popq %rsi                                     
       popq %rdi
       jmp *%rax
