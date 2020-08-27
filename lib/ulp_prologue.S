/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020 SUSE Software Solutions GmbH
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
