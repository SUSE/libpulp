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

.weak   __ulp_global_universe
.local	__ulp_entry
.type	__ulp_entry,@function
.align 8

__ulp_entry:
    // check if this is library entrance
    pushq   %r10
    pushq   %r9
    pushq   %r8
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
    pushq   %rdi
    pushq   %rax
    leaq    __ulp_ret@tlsld(%rip), %rdi
    call    __tls_get_addr@PLT
    cmp     $0x0, __ulp_ret@dtpoff(%rax)
    jnz     __ulp_entry_bypass

    movq    %rax, %r11

    // Migrate to new universe:
    // - always set __ulp_thread_universe = __ulp_global_universe.
    // - comparing __ulp_thread_universe with __ulp_global_universe pior to
    // setting it, would require loading the __ulp_thread_universe value, then
    // cmp, then jne. Instead of that, we always update the value and end with
    // one movq instruction in place of the load, cmp, jne, movq sequence.
    // - the above should be properly benchmarked.

    leaq    __ulp_thread_universe@tlsld(%rip), %rdi
    call    __tls_get_addr@PLT
    movq    __ulp_global_universe@GOTPCREL(%rip), %rdi
    movq    (%rdi), %rdi
    movq    %rdi, __ulp_thread_universe@dtpoff(%rax)

   // call original function
__ulp_call_function:
    popq    %rax
    popq    %rdi
    popq    %rcx
    popq    %rdx
    popq    %rsi
    popq    %r8
    popq    %r9
    popq    %r10
    push    8(%rsp)
    pop     __ulp_ret@dtpoff(%r11)
    pop     %r11
    addq    $0x8, %rsp
    call    *%r11

    pushq   %r10
    pushq   %r9
    pushq   %r8
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
    pushq   %rdi
    pushq   %rax
    leaq    __ulp_ret@tlsld(%rip), %rdi
    call    __tls_get_addr@PLT
    movq     __ulp_ret@dtpoff(%rax), %r11
    movq    $0x0, __ulp_ret@dtpoff(%rax)
    popq    %rax
    popq    %rdi
    popq    %rcx
    popq    %rdx
    popq    %rsi
    popq    %r8
    popq    %r9
    popq    %r10
    pushq   %r11
    retq

__ulp_entry_bypass:
    popq    %rax
    popq    %rdi
    popq    %rcx
    popq    %rdx
    popq    %rsi
    popq    %r8
    popq    %r9
    popq    %r10
    pop     %r11
    jmp     *%r11

//.global __ulp_get_universe
//.type   __ulp_get_universe,@function
//__ulp_get_universe:
//    pushq   %rdx
//    pushq   %rcx
//    pushq   %rdi
//    pushq   %rax
//    leaq    __ulp_ret@tlsld(%rip), %rdi
//    call    __tls_get_addr@PLT
//    movq    __ulp_ret@dtpoff(%rax), %r11
//    cmp     $0x0, __ulp_ret@dtpoff(%rax)
//    popq    %rax
//    popq    %rdi
//    popq    %rcx
//    popq    %rdx
//    retq

.global __ulp_loop
.type   __ulp_loop,@function
__ulp_loop:
    nop
    nop
    jmp	    __ulp_loop

.section .data
.align 8
.type __ulp_global_universe, @object
.size __ulp_global_universe, 8
__ulp_global_universe:
.zero 0x8

.section .tbss,"awT",@nobits
.align  8

.type   __ulp_ret, @object
.size   __ulp_ret, 8
.global __ulp_ret
__ulp_ret:
.zero   0x8

.global __ulp_thread_universe
.type   __ulp_thread_universe, @object
.size   __ulp_thread_universe, 8
__ulp_thread_universe:
.zero	0x8
