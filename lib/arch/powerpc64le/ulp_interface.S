/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2024 SUSE Software Solutions GmbH
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
 * accessed from libpulp's tools, such as the trigger tool. The two
 * nops here is to take into account syscall restarting by the kernel.
 */

.global __ulp_revert_all
    nop
    nop
__ulp_revert_all:
    nop
    nop
    addis   2, 12, .TOC.-__ulp_revert_all@ha
    addi    2, 2,  .TOC.-__ulp_revert_all@l
    mflr    %r0
    std     %r0,16(%r1)
    stdu    %r1,-32(%r1)
    bl      __ulp_revert_patches_from_lib
    nop
    addi    %r1,%r1,32
    ld      %r0,16(%r1)
    mtlr    %r0
    trap

.globl __ulp_trigger
.type  __ulp_trigger, @function
    nop
    nop
__ulp_trigger:
    nop
    nop
    addis   2, 12, .TOC.-__ulp_trigger@ha
    addi    2, 2,  .TOC.-__ulp_trigger@l
    #.localentry     __ulp_trigger,.-__ulp_trigger
    mflr    %r0
    std     %r0,16(%r1)
    stdu    %r1,-32(%r1)
    bl      __ulp_apply_patch
    nop
    addi    %r1,%r1,32
    ld      %r0,16(%r1)
    mtlr    %r0
    trap

.global __ulp_check_patched
    nop
    nop
__ulp_check_patched:
    nop
    nop
    addis   2, 12, .TOC.-__ulp_check_patched@ha
    addi    2, 2,  .TOC.-__ulp_check_patched@l
    mflr    %r0
    std     %r0,16(%r1)
    stdu    %r1,-32(%r1)
    bl      __ulp_check_applied_patch
    nop
    addi    %r1,%r1,32
    ld      %r0,16(%r1)
    mtlr    %r0
    trap

.global __ulp_get_global_universe
    nop
    nop
__ulp_get_global_universe:
    nop
    nop
    addis   2, 12, .TOC.-__ulp_get_global_universe@ha
    addi    2, 2,  .TOC.-__ulp_get_global_universe@l
    mflr    %r0
    std     %r0,16(%r1)
    stdu    %r1,-32(%r1)
    bl      __ulp_get_global_universe_value
    nop
    addi    %r1,%r1,32
    ld      %r0,16(%r1)
    mtlr    %r0
    trap


.global __ulp_enable_or_disable_patching
    nop
    nop
__ulp_enable_or_disable_patching:
    nop
    nop
    addis   2, 12, .TOC.-__ulp_enable_or_disable_patching@ha
    addi    2, 2,  .TOC.-__ulp_enable_or_disable_patching@l
    mflr    %r0
    std     %r0,16(%r1)
    stdu    %r1,-32(%r1)
    bl      ulp_enable_or_disable_patching
    nop
    addi    %r1,%r1,32
    ld      %r0,16(%r1)
    mtlr    %r0
    trap
