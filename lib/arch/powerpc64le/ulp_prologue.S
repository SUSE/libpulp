#
# libpulp - User-space Livepatching Library
#
# Copyright (C) 2020-2021 SUSE Software Solutions GmbH
#
# This file is part of libpulp.
#
# libpulp is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# libpulp is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with libpulp.  If not, see <http://www.gnu.org/licenses/>.
#

# Emulates x86_64 push and pop instructions.
.macro push reg
    stdu    \reg -16(%r1)
.endm

.macro pop reg
    ld      \reg, 0(%r1)
    addi    %r1, %r1, 16
.endm

#.data
#
#msg:    .string "__ulp_prologue called\n"
#        length = . - msg

.section .text,"ax"

.global __ulp_prologue
.type   __ulp_prologue,@function
__ulp_prologue:
    .cfi_startproc
#    li      %r3, 1                # stdout file descriptor
#    lis     %r4, msg@highest      # load 64-bit buffer address
#    ori     %r4, %r4, msg@higher
#    rldicr  %r4, %r4, 32, 31
#    oris    %r4, %r4, msg@h
#    ori     %r4, %r4, msg@l
#    li      %r5, length           # buffer length
#    sc
#
#    li      %r0, 1                # _exit(2)
#    li      %r3, 0                # return success
#    sc

    ## Save parameters registers.
    #push      %r4
    #push      %r5
    #push      %r6
    #push      %r7
    #push      %r8
    #push      %r9
    #push      %r10

    ## Build call stack
    ## FIXME: Is this really necessary?
    #mflr      %r0            # Save LR
    #std       %r0, 16(%r1)    # Save top of stack
    #stdu      %r1, -32(%r1)  # create 32 bytes additionally for the stack and backchain

    ## call function
    #bl        *__ulp_manage_universes@GOTPCREL(%pc)
    #ori       %r0, %r0, 0     # Required NOP for function call.

    ## Destroy stack.
    #addi      %r1, %r1, 32
    #ld        %r0, 16(%r1)
    #mtlr      %r0

    #pop       %r10
    #pop       %r9
    #pop       %r8
    #pop       %r7
    #pop       %r6
    #pop       %r5
    #pop       %r4

    #jmp       *%f0
    .cfi_endproc
