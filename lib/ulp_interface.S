/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2020 SUSE Linux GmbH
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

.align  8
__ulp_testlocks:
    nop
    nop
    push    %rsp
    and     $0xfffffffffffffff0, %rsp
    call    __ulp_do_testlocks@PLT
    pop     %rsp
    int3

__ulp_trigger:
    nop
    nop
    push    %rsp
    and     $0xfffffffffffffff0, %rsp
    call    __ulp_apply_patch@PLT
    pop     %rsp
    int3

/* this can be optimized to return the address directly */
__ulp_get_path_buffer:
    nop
    nop
    push    %rsp
    and     $0xfffffffffffffff0, %rsp
    call    __ulp_get_path_buffer_addr@PLT
    pop     %rsp
    int3

__ulp_check_patched:
    nop
    nop
    push   %rsp
    and    $0xfffffffffffffff0, %rsp
    call   __ulp_check_applied_patch@PLT
    pop    %rsp
    int3

__ulp_get_global_universe:
    nop
    nop
    push   %rsp
    and    $0xfffffffffffffff0, %rsp
    call   __ulp_get_global_universe_value@PLT
    pop    %rsp
    int3

__ulp_loop:
    nop
    nop
    jmp	    __ulp_loop
