
# Emulates x86_64 push and pop instructions.
.macro push reg
    stdu    \reg -16(r1)
.endm

.macro pop reg
    ld      \reg, 0(r1)
    addi    r1, r1, 16
.endm
