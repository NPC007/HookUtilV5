/*
section .text
     xor ecx, ecx
     mul ecx
     push ecx
     push 0x68732f2f   ;; hs//
     push 0x6e69622f   ;; nib/
     mov ebx, esp
     mov al, 11
     int 0x80
     */

void _start(){
    __asm__ __volatile__("xor %ecx,%ecx");
    __asm__ __volatile__("mul %ecx");
    __asm__ __volatile__("pushl %ecx");
    __asm__ __volatile__("pushl $0x68732f2f");
    __asm__ __volatile__("pushl $0x6e69622f");
    __asm__ __volatile__("movl %esp,%ebx");
    __asm__ __volatile__("movb $0xb,%al");
    __asm__ __volatile__("int $0x80");
}
