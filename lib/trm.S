/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2020 SUSE Software Solutions GmbH
 *
 *  This file is part of libpulp.
 *
 *  libpulp is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  libpulp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libpulp.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Prevent the stack from being needlessly set to executable.  */
.section .note.GNU-stack,"",%progbits

.section .ulp.track,"ax",@progbits

// A weak symbol for __ulp_global_universe is needed so that __ulp_entry
// can reference it via GOT, however, there should be no definition,
// hence no object, for it in this file.  Otherwise, when linking with
// -Bsymbolic, the GOT reference becomes a reference to the local object
// and the intended, external object in libpulp.so will not be reachable.
//
// This works if libpulp.so is LD_PRELOAD'ed, because the GOT entry will
// be filled in during relocation, which makes the address of the global
// counter (__ulp_global_universe) available to __ulp_entry.  As well as
// it works if libpulp isn't PRELOAD'ed, because then the GOT entry will
// be left zeroed out, which __ulp_entry tests for, and regular
// execution of the library happens.
.weak   __ulp_global_universe

.local	__ulp_entry
.type	__ulp_entry,@function
.align 8

// Track library entrance
__ulp_entry:
#ifndef HAVE___LIBPULP_TLS_GET_ADDR
    pushq   %r10
    pushq   %r9
    pushq   %r8
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
#endif
    pushq   %rdi
    pushq   %rax
    leaq    __ulp_ret@tlsld(%rip), %rdi
#ifndef HAVE___LIBPULP_TLS_GET_ADDR
    call    __tls_get_addr@PLT
#else
    call    __libpulp_tls_get_addr@PLT
#endif

    // If not library entrance, skip universe update code and jump to
    // the target function directly, as if this detour had not happened.
    cmp     $0x0, __ulp_ret@dtpoff(%rax)
    jnz     __ulp_entry_bypass

    // Otherwise, move the return address to __ulp_ret, update the local
    // universe, and call the target function. When it returns, restore
    // __ulp_ret, and return to the call site. Notice that the original
    // call becomes two calls in this situation.

    // Save the address of the TLS block so it can be used further down
    // to update __ulp_ret.
    movq    %rax, %r11

    // Update the local counter, but first make sure that the address of
    // the global counter has been filled in the GOT entry during
    // initialization (only happens when libulp.so has been loaded). In
    // case it has, read the contents; otherwise, the uninitialized
    // value, zero, can be used directly.
    movq    __ulp_global_universe@GOTPCREL(%rip), %rdi
    test    %rdi, %rdi
    jz      __ulp_thread_counter_update
    movq    (%rdi), %rdi
__ulp_thread_counter_update:
    // The "local dynamic TLS model" allows reusing the result of the
    // previous call to __tls_get_addr (when the address of __ulp_ret
    // was determined) to access other thread-specific variables in the
    // same compilation unit (e.g. __ulp_thread_universe).
    movq    %rdi, __ulp_thread_universe@dtpoff(%rax)

    // Call target function
    popq    %rax
    popq    %rdi
#ifndef HAVE___LIBPULP_TLS_GET_ADDR
    popq    %rcx
    popq    %rdx
    popq    %rsi
    popq    %r8
    popq    %r9
    popq    %r10
#endif
    // Save the original return address into __ulp_ret.
    push    8(%rsp)
    pop     __ulp_ret@dtpoff(%r11)
    // The address of the target function has been pushed onto the stack
    // by the trampoline in the .ulp section, so pop it.
    pop     %r11
    // Remove the return address from the stack (it has been pushed by
    // the original call into the target function and copied into
    // __ulp_ret (above)), so parameters are in the right place.
    addq    $0x8, %rsp
    call    *%r11

#ifndef HAVE___LIBPULP_TLS_GET_ADDR
    pushq   %r10
    pushq   %r9
    pushq   %r8
    pushq   %rsi
    pushq   %rdx
    pushq   %rcx
#endif
    pushq   %rdi
    pushq   %rax
    leaq    __ulp_ret@tlsld(%rip), %rdi
#ifndef HAVE___LIBPULP_TLS_GET_ADDR
    call    __tls_get_addr@PLT
#else
    call    __libpulp_tls_get_addr@PLT
#endif
    movq     __ulp_ret@dtpoff(%rax), %r11
    movq    $0x0, __ulp_ret@dtpoff(%rax)
    popq    %rax
    popq    %rdi
#ifndef HAVE___LIBPULP_TLS_GET_ADDR
    popq    %rcx
    popq    %rdx
    popq    %rsi
    popq    %r8
    popq    %r9
    popq    %r10
#endif
    pushq   %r11
    retq

__ulp_entry_bypass:
    popq    %rax
    popq    %rdi
#ifndef HAVE___LIBPULP_TLS_GET_ADDR
    popq    %rcx
    popq    %rdx
    popq    %rsi
    popq    %r8
    popq    %r9
    popq    %r10
#endif
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

// The __ulp_ret_local_universe function must be in the .text section,
// otherwise, trying to find its address with dlsym (during live patch
// application) fails silently (it returns a non-NULL value, but not the
// address of __ulp_ret_local_universe).
.section .text
.align 8

.global __ulp_ret_local_universe
.type   __ulp_ret_local_universe,@function
__ulp_ret_local_universe:
    leaq    __ulp_thread_universe@tlsld(%rip), %rdi
    call    __tls_get_addr@PLT
    movq    __ulp_thread_universe@dtpoff(%rax), %rax
    ret

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
