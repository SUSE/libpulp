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

/* Prevent the stack from being needlessly set to executable.  */
.section .note.GNU-stack,"",%progbits

.section .ulp.track,"ax",@progbits

// A weak symbol for __ulp_global_universe is needed so that __ulp_entry
// can reference it via GOT, however, there should be no definition,
// hence no object, for it in this file.  Otherwise, when linking with
// -Bsymbolic, the GOT reference becomes a reference to the local object
// and the intended, external object in libulp.so will not be reachable.
//
// This works if libulp.so is LD_PRELOAD'ed, because the GOT entry will
// be filled in during relocation, which makes the address of the global
// counter (__ulp_global_universe) available to __ulp_entry.  As well as
// it works if libulp isn't PRELOAD'ed, because then the GOT entry will
// be left zeroed out, which __ulp_entry tests for, and regular
// execution of the library happens.
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

    // Find the address of the thread-local (TLS) counter.
    leaq    __ulp_thread_universe@tlsld(%rip), %rdi
    call    __tls_get_addr@PLT
    // Check if the address of the global counter has been filled in the
    // GOT entry during initialization (only happens when libulp.so has
    // been LD_PRELOAD'ed).  In case it has, read the contents.
    // Otherwise, the uninitialized value, zero, can be used directly.
    movq    __ulp_global_universe@GOTPCREL(%rip), %rdi
    test    %rdi, %rdi
    jz      __ulp_thread_counter_update
    movq    (%rdi), %rdi
__ulp_thread_counter_update:
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

.global __ulp_get_local_universe
.type   __ulp_get_local_universe,@function
__ulp_get_local_universe:
    nop
    nop
    // If the thread is not within the library, the current local
    // universe value is meaningless, because the thread universe will
    // be updated upon the next library entrance.  Thus, return a
    // special code (all digits zeroed).
    leaq    __ulp_ret@tlsld(%rip), %rdi
    call    __tls_get_addr@PLT
    cmp     $0x0, __ulp_ret@dtpoff(%rax)
    jnz     __ulp_get_local_universe_value
    mov     $-1, %rax
    int3
__ulp_get_local_universe_value:
    // Read the thread universe into %rax.
    leaq    __ulp_thread_universe@tlsld(%rip), %rdi
    call    __tls_get_addr@PLT
    movq    __ulp_thread_universe@dtpoff(%rax), %rax
    int3

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
