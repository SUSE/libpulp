/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020-2021 SUSE Software Solutions GmbH
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

.section .text,"ax",@progbits

.global __ulp_prologue
.type	__ulp_prologue,@function
__ulp_prologue:

    // When a function gets live patched, the padding area before its
    // entry point gets updated with a trampoline that: 1. saves the
    // contents of %rdi on the stack; 2. writes a hardcoded value (an
    // index for the universe handling routine); 3. then jumps here.
    // Since it used the stack, call frame information is broken, which
    // leads to unreliable backtracing in gdb, so update the cfi:
    .cfi_startproc
    .cfi_adjust_cfa_offset 8

    // Save registers, then call __ulp_manage_universes
    pushq  %rsi
    .cfi_adjust_cfa_offset 8
    pushq  %rdx
    .cfi_adjust_cfa_offset 8
    pushq  %rcx
    .cfi_adjust_cfa_offset 8
    pushq  %r8
    .cfi_adjust_cfa_offset 8
    pushq  %r9
    .cfi_adjust_cfa_offset 8
    call   *__ulp_manage_universes@GOTPCREL(%rip)
    popq   %r9
    .cfi_adjust_cfa_offset -8
    popq   %r8
    .cfi_adjust_cfa_offset -8
    popq   %rcx
    .cfi_adjust_cfa_offset -8
    popq   %rdx
    .cfi_adjust_cfa_offset -8
    popq   %rsi
    .cfi_adjust_cfa_offset -8
    popq   %rdi
    .cfi_adjust_cfa_offset -8

    // __ulp_manage_universes saves the address of the target function
    // in %r11, before returning.
    jmp    *%r11
    .cfi_endproc
