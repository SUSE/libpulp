/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2021 SUSE Software Solutions GmbH
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

/*
 * The functions below are the entry points into libpulp, which are
 * accessed from libpulp's tools, such as the trigger tool. After
 * ptracing into all threads, the tools modify the program counter so
 * that it points to the third instruction in each of the functions
 * below, i.e. right after the sequence of two nops. These two nops are
 * skipped not because they must not be executed, but to account for
 * syscall restarting by the kernel (which subtracts two from the
 * program counter, so that, on regular syscalls, the syscall
 * instructions gets executed again; in libpulp's case, the two nops get
 * executed, without side-effects).
 */

__ulp_trigger:
    nop
    nop
    call    __ulp_apply_patch@PLT
    int3

__ulp_check_patched:
    nop
    nop
    call   __ulp_check_applied_patch@PLT
    int3

__ulp_get_global_universe:
    nop
    nop
    call   __ulp_get_global_universe_value@PLT
    int3
