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
.local	__ulp_entry
.type	__ulp_entry,@function


.align 8
.ifdef LOCAL_EXEC
__ulp_entry:
    // check if this is library entrance
    movq    __ulp_ret@gottpoff(%rip), %r11
    cmp     $0x0, %fs:(%r11)
    jnz     __ulp_entry_bypass

    // migrate to new universe if there is a pending patch
    // TODO: verify if comparing then setting to zero if pending performs
    // better then simply always setting to zero
    push %r10
    movq    __ulp_pending@gottpoff(%rip), %r10
    //movq    %fs:(%r10), %rax
    cmp     $0x1, %fs:(%r10)
    jne     __ulp_call_function
    movq    $0x0, %fs:(%r10)

   // call original function
__ulp_call_function:
    pop     %r10
    push    8(%rsp)
    pop     %fs:(%r11)
    pop     %r11
    addq    $0x8, %rsp
    call    *%r11
    mov     __ulp_ret@gottpoff(%rip), %r11
    push    %fs:(%r11)
    movq    $0x0, %fs:(%r11)
    ret

__ulp_entry_bypass:
    pop     %r11
    jmp     *%r11

.else

__ulp_entry:
    // check if this is library entrance
    pushq   %rdi
    pushq   %rax
    leaq    __ulp_ret@tlsld(%rip), %rdi
    call    __tls_get_addr@PLT
    cmp     $0x0, __ulp_ret@dtpoff(%rax)
    jnz     __ulp_entry_bypass

    movq    %rax, %r11

    // migrate to new universe
    // we are always setting to zero, irrespectively of what was there before.
    // TODO: check if cmp 1 + set to 0 is better then simply always set to 0

    leaq    __ulp_pending@tlsld(%rip), %rdi
    call    __tls_get_addr@PLT
    movq    $0x0, __ulp_pending@dtpoff(%rax)

   // call original function
__ulp_call_function:
    popq    %rax
    popq    %rdi
    push    8(%rsp)
    pop     __ulp_ret@dtpoff(%r11)
    pop     %r11
    addq    $0x8, %rsp
    call    *%r11

    pushq   %rdi
    pushq   %rax
    leaq    __ulp_ret@tlsld(%rip), %rdi
    call    __tls_get_addr@PLT
    movq     __ulp_ret@dtpoff(%rax), %r11
    movq    $0x0, __ulp_ret@dtpoff(%rax)
    popq    %rax
    popq    %rdi
    pushq   %r11
    retq

__ulp_entry_bypass:
    pop     %rax
    pop     %rdi
    pop     %r11
    jmp     *%r11

.endif

// TODO: check if visibility of these symbols below are ok
.align  8
.global __ulp_get_pending
.type   __ulp_get_pending,@function
__ulp_get_pending:
    pushq   %rdi
    pushq   %rax
    leaq    __ulp_pending@tlsld(%rip), %rdi
    call    __tls_get_addr@PLT
    movq    __ulp_pending@dtpoff(%rax), %r11
    popq   %rax
    popq   %rdi
    retq

.global __ulp_set_pending
.type   __ulp_set_pending,@function
__ulp_set_pending:
    nop
    nop
    pushq   %rdi
    pushq   %rax
    leaq    __ulp_pending@tlsld(%rip), %rdi
    call    __tls_get_addr@PLT
    movq    $0x1, __ulp_pending@dtpoff(%rax)
    popq    %rax
    popq    %rdi

.global __ulp_loop
.type   __ulp_loop,@function
__ulp_loop:
    nop
    nop
    jmp	    __ulp_loop

.section .tbss,"awT",@nobits
.align  8

.type   __ulp_ret, @object
.size   __ulp_ret, 8
.global __ulp_ret
__ulp_ret:
.zero   0x8

.type   __ulp_pending, @object
.size   __ulp_pending, 8
.global __ulp_pending
__ulp_pending:
.zero	0x8
