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

# __tls_get_addr
.globl   __tls_get_addr
.type    __tls_get_addr, @function

.section        ".text"
.align 2
.p2align 4,,15

# Trampoline routine
.globl   trampoline_routine
.type    trampoline_routine, @function
trampoline_routine:
  .cfi_startproc

  # The address in LR is in the caller's prologue.  Move it to r6, so
  # we can access the new function pointer stored in the prologue.
  mflr  %r6
  ld    %r6, (ulp_prologue_new_function_addr - .prologue_load_pc)(%r6)

  # Move the target function ptr to control register so we can free r6.
  mtctr %r6

  # Reload LR which we saved on %r5
  mtlr  %r5

  # Save all volatile registers
  # r5 & r6 are designated temp regs, having data already on stack.
  # After return from expand_ulp_stack, both regs construct values
  # before use.
  std   %r2,  -24(%r1)
  std   %r3,  -32(%r1)
  std   %r12, -40(%r1)
  mflr  %r2
  std   %r2,  -48(%r1)

  # Move stack register
  addi  %r1, %r1, -(48 + 32 + 8) # 32 + 8 for padding

  # Fix TOC.  %r12 must be pointing to the address of trampoline_routine.
  addis %r2,%r12, .TOC.-trampoline_routine@ha
  addi  %r2,%r2 , .TOC.-trampoline_routine@l

  # Load ulp_stack
  addis %r3, %r2, ulp_stack@got@tlsgd@ha
  addi  %r3, %r3, ulp_stack@got@tlsgd@l

  # Get address of ulp_stack
  bl    __tls_get_addr(ulp_stack@tlsgd)
  nop

  # Load ulp_stack attributes
  ld    %r6, ULP_STACK_REAL_SIZE(%r3)     # Load real_size (allocated by mmap)
  ld    %r5, ULP_STACK_USED_SIZE(%r3)     # Load used_size

  # Check if we have space
  cmpd  %cr0, %r6, %r5
  ble   %cr0, .Lexpand_ulp_stack

.Lcontinue_ulp_prologue:

  # Here we must ensure that %r3 points to ulp_stack.  If we are here from
  # the .Lexpand_ulp_stack, then r3 will point to it because
  # ulp_stack_helper returned it.

  # Load used_size
  ld    %r6, ULP_STACK_USED_SIZE(%r3)

  # Update top_of_stack in the struct field.
  addi  %r6, %r6, 16
  std   %r6, ULP_STACK_USED_SIZE(%r3)    # Store new used size value.

  # Load stack ptr
  ld    %r5, ULP_STACK_PTR(%r3)

  # Store TOC
  add   %r5, %r5, %r6  # ulp_stack_ptr + used_size

  # Restore stack register.
  addi  %r1, %r1, (48 + 32 + 8)

  # Load original LR
  ld    %r2, -48(%r1)
  mtlr  %r2

  # Load original TOC
  ld    %r6, -24(%r1)

  # At this point, %r5 points to 16 bytes ahead of the slot where we shall
  # save TOC.  Hence we have to subtract 16 bytes of the storing location,
  # as pictured in this diagram.
  #                              %r5 --+
  # +----------------------------------v
  # | TOC1 | LR1 || ... || _8b_ | _8b_ |
  # +----------------------------------+
  std   %r6, -16(%r5)  # store in *(ulp_stack + used_size - 16)
  std   %r2, -8(%r5)   # store in *(ulp_stack + used_size - 8)


  # Restore registers
  ld    %r5, -8(%r1)   # Restore register.
  ld    %r6, -16(%r1)  # Restore register.
 #ld    %r2,  -24(%r1) # r2 was already loaded
  ld    %r3,  -32(%r1)
  ld    %r12, -40(%r1)

  # jump to target function
  mfctr %r12
  bctrl

  # Save return registers and ones used by __get_tls_addr.
  std   %r3,  -8(%r1)
  std   %r12, -16(%r1)

  # Move stack register
  addi  %r1, %r1, -(16 + 32 + 8) # 32 + 8 for padding

  # Do a trick to load PC into LR register.
  bl    .return_to_caller
.return_to_caller:
  mflr  %r12

  # Get the function address.
  addi  %r12, %r12, trampoline_routine - .return_to_caller

  # Fix TOC.  %r12 must be pointing to the address of trampoline_routine.
  addis %r2,%r12, .TOC.-trampoline_routine@ha
  addi  %r2,%r2 , .TOC.-trampoline_routine@l

  # Load ulp_stack
  addis %r3, %r2, ulp_stack@got@tlsgd@ha
  addi  %r3, %r3, ulp_stack@got@tlsgd@l

  # Get address of ulp_stack
  bl    __tls_get_addr(ulp_stack@tlsgd)
  nop

  # Deference ulp_stack.
  ld    %r6, ULP_STACK_USED_SIZE(%r3)
  addi  %r6, %r6, -16   # Sub 16 bytes because the first entry stores the top of stack, and we need to store 2 longs.
  std   %r6, ULP_STACK_USED_SIZE(%r3)     # Store new used_size value.

  # Load ulp_stack ptr field.
  ld    %r5, ULP_STACK_PTR(%r3)

  # Point to the top of stack but two, these two entries are popped in
  # previous step and accessed in next step (stack size decremented before access).
  add   %r5, %r5, %r6  # ulp_stack + used_size

  # Restore saved data.
  ld    %r2, 0(%r5)     # Restore TOC
  ld    %r8, 8(%r5)     # Restore LR
  mtlr  %r8             # Load LR

  # Restore used registers
  addi  %r1, %r1, (16 + 32 + 8) # 32 + 8 for padding
  ld    %r3,  -8(%r1)
  ld    %r12, -16(%r1)

  # Return.
  blr

.Lexpand_ulp_stack:

  # Save all volatile registers
  # r5 & r6 are designated temp regs, having data already on stack.
  # r0, r2 & r12 is as well in this slow path.
  # After return from expand_ulp_stack, both regs construct values
  # before use.
  std   %r4,  -8(%r1)
  std   %r7,  -16(%r1)
  std   %r8,  -24(%r1)
  std   %r9,  -32(%r1)
  std   %r10, -40(%r1)
  std   %r11, -48(%r1)
  mfctr %r4
  std   %r4,  -56(%r1)
  mflr  %r4,
  std   %r4,  -64(%r1)

  # Setup stack frame
  addi  %r1, %r1, -(64 + 32 + 8)

  # Call C helper routine.
  bl    ulp_stack_helper
  nop

  # Restore stack frame
  addi %r1, %r1, (64 + 32 + 8)

  # Load back registers.
  ld    %r7,  -16(%r1)
  ld    %r8,  -24(%r1)
  ld    %r9,  -32(%r1)
  ld    %r10, -40(%r1)
  ld    %r11, -48(%r1)
  ld    %r4,  -56(%r1)
  mtctr %r4
  ld    %r4,  -64(%r1)
  mtlr  %r4
  ld    %r4,  -8(%r1)

  # Continue execution
  b     .Lcontinue_ulp_prologue

	.long 0
	.byte 0,0,0,0,0,0,0,0
	.cfi_endproc
	.size	trampoline_routine,.-trampoline_routine

# The following function needs to be placed in .data, as it is a template to be
# copied in the prologue of tha patched function.  Placing this in .data avoids
# text relocations.
.section        ".data"
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
  ori   %r12, %r12, trampoline_routine@l     #0x7788

  # Concatenate two registers
  rldimi %r12, %r5, 32, 0

  # Move to control register
  mtctr %r12

  # Save LR into R5, as getting the PC will clobber it.
  mflr  %r5

  # Load PC into LR
  bl    .prologue_load_pc
.prologue_load_pc:

  # Jump to trampoline_routine
  bctr

  # Execution is returned to the caller by the trampoline_routine, not here.
  # so no blr is necessary here.

  # Variable holding the address of the new function.  Note that this prologue
  # is copied to the target's function prologue, hence this must not be accessed
  # directly.
.global ulp_prologue_new_function_addr
.type   ulp_prologue_new_function_addr, @object
.size   ulp_prologue_new_function_addr, 8
ulp_prologue_new_function_addr:
  .zero 8

ulp_prologue_end = .
	.long 0
	.byte 0,0,0,0,0,0,0,0
	.cfi_endproc
.LFE0:
	.size ulp_prologue,.-ulp_prologue
ulp_prologue_padding_end = .

.section      ".rodata"
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
