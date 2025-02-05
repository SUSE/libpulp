/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2025 SUSE Software Solutions GmbH
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

#include "arch/powerpc64le/arch_common.h"

.file	"ulp_prologue.S"
.machine power8
.abiversion 2
.section	".text"
.align 2
.p2align 4,,15

# ulp_stack_helper
.globl   ulp_stack_helper
.type    ulp_stack_helper, @function

.section        ".text"
.align 2
.p2align 4,,15

# Trampoline routine
.globl   trampoline_routine
.type    trampoline_routine, @function
trampoline_routine:
	.cfi_startproc

  # Concatenate two registers from prologue.
  rldimi %r6, %r5, 32, 0

  # Move the target function ptr to control register so we can free r6.
  mtctr %r6

  # Load the ulp_stack into r5 through r13 (thread local storage ptr)
  addis %r5, %r13, ulp_stack@tprel@ha
  addi  %r5, %r5,  ulp_stack@tprel@l

  # Load real_size
  ld    %r6, ULP_STACK_REAL_SIZE(%r5)   # Load real_size (allocated by mmap)
  ld    %r5, ULP_STACK_USED_SIZE(%r5)   # Load used_size (currently in use)

  # Check if we have space.
  cmpd %cr0, %r6, %r5
  ble   %cr0, .Lexpand_ulp_stack

.Lcontinue_ulp_prologue:

  # Reload the ulp_stack into r5 through r13 (thread local storage ptr)
  addis %r5, %r13, ulp_stack@tprel@ha
  addi  %r5, %r5,  ulp_stack@tprel@l

  # Load used_size
  ld    %r6, ULP_STACK_USED_SIZE(%r5)

  # Update top_of_stack in the struct field.
  addi  %r6, %r6, 16
  std   %r6, ULP_STACK_USED_SIZE(%r5)    # Store new used size value.

  # Load stack ptr
  ld    %r5, ULP_STACK_PTR(%r5)

  # Store TOC
  add   %r5, %r5, %r6  # ulp_stack + used_size

  # At this point, %r5 points to 16 bytes ahead of the slot where we shall
  # save TOC.  Hence we have to subtract 16 bytes of the storing location,
  # as pictured in this diagram.
  #                              %r5 --+
  # +----------------------------------v
  # | TOC1 | LR1 || ... || _8b_ | _8b_ |
  # +----------------------------------+
  std   %r2, -16(%r5)  # store in *(ulp_stack + used_size - 16)
  mflr  %r2
  std   %r2, -8(%r5)   # store in *(ulp_stack + used_size - 8)

  # Restore registers
  ld    %r5, -8(%r1)  # Restore register.
  ld    %r6, -16(%r1) # Restore register.

  # Jump to target function
  mfctr %r12
  bctrl

  # Load the ulp_stack into r5 through r13 (thread local storage ptr)
  addis %r5, %r13, ulp_stack@tprel@ha
  addi  %r5, %r5,  ulp_stack@tprel@l

  # Deference ulp_stack.
  ld    %r6, ULP_STACK_USED_SIZE(%r5)
  addi  %r6, %r6, -16   # Sub 16 bytes because the first entry stores the top of stack, and we need to store 2 longs.
  std   %r6, ULP_STACK_USED_SIZE(%r5)     # Store new used_size value.

  # Load ulp_stack ptr field.
  ld    %r5, ULP_STACK_PTR(%r5)

  # Restore saved data.
  ld    %r2, 0(%r5)     # Restore TOC
  ld    %r8, 8(%r5)     # Restore LR
  mtlr  %r8             # Load LR

  # Return execution to caller.
  blr

.Lexpand_ulp_stack:

  # Save all volatile registers
  # r5 & r6 are designated temp regs, having data already on stack.
  # After return from expand_ulp_stack, both regs construct values
  # before use.
  std   %r2,  -24(%r1)
  std   %r3,  -32(%r1)
  std   %r4,  -40(%r1)
  std   %r7,  -48(%r1)
  std   %r8,  -56(%r1)
  std   %r9,  -64(%r1)
  std   %r10, -72(%r1)
  std   %r11, -80(%r1)
  std   %r12, -88(%r1)
  mfctr %r3
  std   %r3,  -96(%r1)
  mflr  %r3,
  std   %r3,  -104(%r1)

  # As per ppc64le ABIv2, the minimum stack frame is of 32 bytes and
  # additional 8 bytes padding is needed for alignment in stack frame.
  # The regs stored in redzone must have this 32+8 bytes padding to form
  # auxiliary stack frame before calling ulp_stack_helper which will
  # have its own proper stack frame.

  # Move stack register
  addi  %r1, %r1, -(104 + 32 + 8) # 32 + 8 for padding

  # Fix TOC.  %r12 must be pointing to the address of trampoline_routine.
  addis %r2,%r12, .TOC.-trampoline_routine@ha
  addi  %r2,%r2 , .TOC.-trampoline_routine@l

  # Call C helper routine.
  bl ulp_stack_helper
  nop

  # Restore stack register.
  addi  %r1, %r1, (104 + 32 + 8)

  # Restore registers
  ld    %r3,  -104(%r1)
  mtlr  %r3
  ld    %r3,  -96(%r1)
  mtctr %r3
  ld    %r12, -88(%r1)
  ld    %r11, -80(%r1)
  ld    %r10, -72(%r1)
  ld    %r9,  -64(%r1)
  ld    %r8,  -56(%r1)
  ld    %r7,  -48(%r1)
  ld    %r4,  -40(%r1)
  ld    %r3,  -32(%r1)
  ld    %r2,  -24(%r1)

  b     .Lcontinue_ulp_prologue

	.long 0
	.byte 0,0,0,0,0,0,0,0
	.cfi_endproc
	.size	trampoline_routine,.-trampoline_routine

	.globl ulp_prologue
	.type  ulp_prologue, @function
ulp_prologue:
	.cfi_startproc
  std   %r5, -8(%r1)  # Save one register used as function parameter
  std   %r6, -16(%r1) # Save

  # Compute absolute address of trampoline routine
  lis   %r5,  trampoline_routine@highest     #0x1122
  ori   %r5,  %r5, trampoline_routine@higher #0x3344
  lis   %r12, trampoline_routine@high        #0x5566
  ori   %r12, %r12, trampoline_routine@l      #0x7788

  # Concatenate two registers
  rldimi %r12, %r5, 32, 0

  # Move to control register
  mtctr %r12

  # Compute absolute address of target function 0x1122334455667788
  lis   %r5,      0x1122
  ori   %r5, %r5, 0x3344
  lis   %r6,      0x5566
  ori   %r6, %r6, 0x7788

  # Jump to trampoline_routine
  bctr

  # Execution is returned to the caller by the trampoline_routine, not here.
  # so no blr is necessary here.

ulp_prologue_end = .
	.long 0
	.byte 0,0,0,0,0,0,0,0
	.cfi_endproc
.LFE0:
	.size ulp_prologue,.-ulp_prologue
ulp_prologue_padding_end = .

.section      ".data"
.align        2
.type         ulp_prologue_size, @object
.size         ulp_prologue_size, 4

.global ulp_prologue_size
ulp_prologue_size:
  .long     ulp_prologue_end - ulp_prologue

# Declare a space in thread local storage for the ulp stack.
# This datastructure layout is pictured below:
# bytes:      8          16          24        32
# +-----------+-----------+-----------+---------+
# | real_size | used_size | stack_ptr | padding |
# +-----------+-----------+-----------+---------+
#
# The macros in powerpc64le/arch_common.h defines how such fields shall
# be accessed in a clean way.  For ASM, the pointer to this structure
# shall be passed as a parameter to the macro, and for C it should be
# used as a index for a C array. For example:
#
# ASM:
# ld  %dst, ULP_STACK_REAL_SIZE(%r5)
#
# C:
# ulp_stack[ULP_STACK_REAL_SIZE];
#
# Now the stack_ptr field in above array holds reference to the actual
# stack "ulp_stack"(provisioned by mmap). The used_size field indicates
# the memory used (in bytes) by the entries pushed on the stack, and
# real_size indicates the total memory allocated for the stack. Stack
# overflow occurs when used_size >= real_size. In this case, the size
# of the stack is increased (i.e. realloc'ed) to a larger value.
#
# This is the layout of this stack:
# bytes: 8     16     24     32      used_size           real_size
# +------------------------------------------------------+
# | TOC1 | LR1 || TOC2 | LR2 || ... || TOCn | LRn || ... |
# +------------------------------------------------------+
#
# On each redirection, the TOC and LR registers are pushed in this stack
# (8 bytes per pointer, hence 16 bytes in total).

.section  .tbss,"awT",@nobits
.align 4
.type ulp_stack, @object
.size ulp_stack, 32   # 3 unsigned longs, 1 padding.
.global ulp_stack
ulp_stack:
  .zero 32

.section	.note.GNU-stack,"",@progbits
