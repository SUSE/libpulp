/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2018 SUSE Linux GmbH
 *
 *  This file is part of libpulp.
 *
 *  libpulp is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libpulp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libpulp.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  Author: Joao Moreira <jmoreira@suse.de>
 */

.section .ulp.track,"ax",@progbits
.local	__ulp_trm
.type	__ulp_trm,@function

.align 8
__ulp_trm:
    // check if lib was already entered
    mov	    __ulp_ret@gottpoff(%rip), %r11
    cmp	    $0x0, %fs:(%r11)
    jnz	    __ulp_trm_epilogue

    push    %r10

    // load and save original return address
    mov	    0x10(%rsp), %r10
    mov	    %r10, %fs:(%r11)

    // modify return address
    leaq    __ulp_trm_return(%rip), %r10
    movq    %r10, 0x10(%rsp)
    pop	    %r10

__ulp_trm_epilogue:
    ret

.align  8
.local  __ulp_trm_return
.type   __ulp_trm_return,@function

__ulp_trm_return:
    mov	    __ulp_ret@gottpoff(%rip), %r10
    mov	    %fs:(%r10), %r11
    movl    $0x0, %fs:(%r10)
    jmp	    *%r11

.align  8
.local	__ulp_get_flag
.type	__ulp_get_flag,@function

__ulp_get_flag:
    nop
    nop
    xor	    %rax, %rax
    mov	    __ulp_flag@gottpoff(%rip), %r10
    mov	    %fs:(%r10), %rax
    int3

.section .tdata,"awT",@progbits
.align  16

.type   __ulp_ret, @object
.size   __ulp_ret, 8
.global __ulp_ret
__ulp_ret:
.word   0x0

.type   __ulp_flag, @object
.size   __ulp_flag, 8
.global __ulp_flag
__ulp_flag:
.word 0x0
