/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2023 SUSE Software Solutions GmbH
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

#define _GNU_SOURCE

#include <stddef.h>
#include <string.h>

#include "config.h"
#include "error.h"
#include "insn_queue_lib.h"
#include "msg_queue.h"
#include "ulp.h"
//#include "arch/powerpc64le/common.h"

/* clang-format off */

/** Offset of the data entry in the ulp_prologue.  */
#define ULP_DATA_OFFSET 6
static char ulp_prologue[ULP_NOPS_LEN] = {
  0x22, 0x11, 0xc0, 0x3d,     //lis     r14,1122
  0x44, 0x33, 0xce, 0x61,     //ori     r14,r14,0x3344
  0xc6, 0x07, 0xce, 0x79,     //sldi    r14,r14,32
  0x66, 0x55, 0xce, 0x65,     //oris    r14,r14,0x5566
  0x88, 0x77, 0xce, 0x61,     //ori     r14,r14,0x7788
  0xa6, 0x03, 0xc9, 0x7d,     //mtctr   r14
  0x10, 0x00, 0x01, 0xf8,     //std     r0,16(r1)
  0xe1, 0xff, 0x21, 0xf8,     //stdu    r1,-32(r1)
  0x18, 0x00, 0x41, 0xf8,     //std     r2,24(r1)
  0x20, 0x04, 0x80, 0x4e,     //bctr
  0x20, 0x00, 0x80, 0x4e,     //blr
};

static const unsigned char gNop[] = { 0x00, 0x00, 0x00, 0x60 };

/* clang-format on */

/** @brief Write new function address into data prologue of  `old_fentry`.
 *
 *  This function replaces the `<data>` section in prologue `old_fentry`
 *  with a pointer to the new function given by `manager`, which will
 *  replace the to be patched function.
 *
 *  @param old_fentry Pointer to prologue of to be replaced function
 *  @param manager Address of new function.
 */
void
ulp_patch_addr_absolute(void *old_fentry, void *manager)
{
  char manager_bytes[8];

  /* Copy the address to a memory buffer to avoid unaligned accesses.  */
  memcpy(manager_bytes, manager, sizeof(void*));

  /* Assemble the absolute address in the instructions.  Little endian, so
     bytes are inverted.  */
  char *dst = (char *)old_fentry + ULP_DATA_OFFSET;

  insnq_insert_write(&dst[0], sizeof(char), &manager_bytes[7]);
  insnq_insert_write(&dst[1], sizeof(char), &manager_bytes[6]);

  insnq_insert_write(&dst[4], sizeof(char), &manager_bytes[5]);
  insnq_insert_write(&dst[5], sizeof(char), &manager_bytes[4]);

  insnq_insert_write(&dst[12], sizeof(char), &manager_bytes[3]);
  insnq_insert_write(&dst[13], sizeof(char), &manager_bytes[2]);

  insnq_insert_write(&dst[16], sizeof(char), &manager_bytes[1]);
  insnq_insert_write(&dst[17], sizeof(char), &manager_bytes[0]);
}

/** @brief Copy the ulp proglogue layout into the function to be patched's
 * prologue
 *
 * This function copies the new code prologue into the old function prologue
 * in order to redirect the execution to the new function.
 *
 */
static void
ulp_patch_prologue_layout(void *old_fentry, const char *prologue, int len)
{
  insnq_insert_write(old_fentry, len, prologue);
}

/** @brief skip the ulp prologue.
 *
 * When a function gets live patch, the nops at its entry point get replaced
 * with a backwards-jump to a small segment of code that redirects execution to
 * the new version of the function. However, when all live patches to said
 * function are deactivated (because the live patches have been reversed), the
 * need for the backwards-jump is gone.
 *
 * The following function replaces the backwards-jump with nops, thus making
 * the target function look like it did at the beginning of execution, i.e.
 * without live patches.
 *
 * @param fentry        Address to write the prologue to.
 */
void
ulp_skip_prologue(void *fentry)
{
  /* Assemble the absolute address in the instructions.  Little endian, so
     bytes are inverted.  */
  char *dst = (char *)fentry + ULP_DATA_OFFSET;
  for (int i = 0; i < ULP_NOPS_LEN; i++) {
    memcpy(dst, gNop, sizeof(gNop));
    dst += sizeof(gNop);
  }
}

/** @brief Actually patch the old function with the new function
 *
 * This function will finally patch the old function pointed by `old_faddr`
 * with the one pointed by `new_faddr`, replacing the ulp NOP prologue with
 * the intended content to redirect to the new function.
 *
 * @param old_faddr     Address of the old function.
 * @param new_faddr     Address of the new function.
 * @param enable        False to disable the redirection to the new function.
 *
 * @return              0 if success, error code otherwise.
 */
int
ulp_patch_addr(void *old_faddr, void *new_faddr, int enable)
{
  unsigned char *dst = (unsigned char *) old_faddr;

  /* Check if we have a stack frame setup.  */
  unsigned char *old_faddr_bytes = (unsigned char *) old_faddr;
  if (old_faddr_bytes[2] == 0x40 && old_faddr_bytes[3] == 0x3c && // lis 42,CONST
      old_faddr_bytes[6] == 0x42 && old_faddr_bytes[7] == 0x38) { // addi r2,r2,CONST
    dst += 8; // Account for the stackframe instructions.
  }

  /* Check for the NOP prologue.  */
  if (memcmp(dst, gNop, sizeof(gNop)) != 0) {
    WARN("Function at addr %lx is not livepatchable",
         (unsigned long)old_faddr);
    return ENOPATCHABLE;
  }

  if (enable) {
    ulp_patch_prologue_layout(dst, ulp_prologue, ULP_NOPS_LEN);
    ulp_patch_addr_absolute(dst, new_faddr);
  } else {
    ulp_skip_prologue(dst);
  }

  return 0;
}


void save_to_register(void *target)
{
  (void) target;
/*
  asm (
    "mr %0, %%r31;"
    :
    : "r" (target)
    :
  );
*/
}
