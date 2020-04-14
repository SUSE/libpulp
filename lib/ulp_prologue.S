/* Prevent the stack from being needlessly set to executable.  */
.section .note.GNU-stack,"",%progbits

.section .text,"ax",@progbits

.global __ulp_prologue
.type	__ulp_prologue,@function
__ulp_prologue:
    pushq  %rsi
    pushq  %rdx
    pushq  %rcx
    pushq  %r8
    pushq  %r9
    call   *__ulp_manage_universes@GOTPCREL(%rip)
    popq   %r9
    popq   %r8
    popq   %rcx
    popq   %rdx
    popq   %rsi
    popq   %rdi
    jmp    *%r11
