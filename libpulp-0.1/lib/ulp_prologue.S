.global __ulp_prologue
.type	__ulp_prologue,@function
__ulp_prologue:
    call   *__ulp_manage_universes@GOTPCREL(%rip)
    popq   %rdi
    jmp    *%r11
