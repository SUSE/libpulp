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
#include <limits.h>

#include "config.h"
#include "error.h"
#include "msg_queue.h"
#include "ulp.h"

/* clang-format off */

/** Size of each instructions, in bytes.  */
#define INSN_SIZE 4

static unsigned char ulp_prologue[INSN_SIZE * PRE_NOPS_LEN] = {
  0x22, 0x11, 0x80, 0x3d,    // lis     r12,0x1122
  0xa6, 0x02, 0x08, 0x7c,    // mflr    r0
  0x44, 0x33, 0x8c, 0x61,    // ori     r12,r12,0x3344
  0xc6, 0x07, 0x8c, 0x79,    // sldi    r12,r12,32
  0x66, 0x55, 0x8c, 0x65,    // oris    r12,r12,0x5566
  0x10, 0x00, 0x01, 0xf8,    // std     r0,16(r1)
  0xe1, 0xff, 0x21, 0xf8,    // stdu    r1,-32(r1)
  0x88, 0x77, 0x8c, 0x61,    // ori     r12,r12,0x7788
  0x18, 0x00, 0x41, 0xf8,    // std     r2,24(r1)
  0xa6, 0x03, 0x89, 0x7d,    // mtctr   r12
  0x21, 0x04, 0x80, 0x4e,    // bctrl
  0x18, 0x00, 0x41, 0xe8,    // ld      r2,24(r1)
  0x20, 0x00, 0x21, 0x38,    // addi    r1,r1,32
  0x10, 0x00, 0x01, 0xe8,    // ld      r0,16(r1)
  0xa6, 0x03, 0x08, 0x7c,    // mtlr    r0
  0x20, 0x00, 0x80, 0x4e,    // blr
};

/** The NOP instruction.  */
static const unsigned char gNop[] = { 0x00, 0x00, 0x00, 0x60 };

/** Generate a branch (b) instruction according to offset.  */
static uint32_t
generate_branch_to_prologue(int32_t offset)
{
  return (offset & 0x00FFFFFF) | (0x4B << 24);
}

#define WITH_OFFSET(x) (-(INSN_SIZE * PRE_NOPS_LEN + (offset)))
#define WITHOUT_OFFSET WITH_OFFSET(0)

/* clang-format on */

/** @brief Copy the ulp prologue layout into the function to be patched's
 * prologue
 *
 * This function copies the new code prologue into the old function prologue
 * in order to redirect the execution to the new function.
 *
 */
static void
ulp_patch_prologue_layout(void *old_fentry, void *new_fentry, const unsigned char *prologue, int len)
{
  (void) len;

  /* Create a copy of the prologue.  */
  unsigned char prolog[INSN_SIZE*PRE_NOPS_LEN];
  _Static_assert(sizeof(prolog) == sizeof(ulp_prologue),
                 "Prologue sizes do not match");
  memcpy(prolog, prologue, sizeof(prolog));

  unsigned char new_fentry_bytes[sizeof(void*)];
  memcpy(new_fentry_bytes, &new_fentry, sizeof(new_fentry_bytes));

  /* Patch the code with the address of the function we want to be redirected.  */
  prolog[0]  = new_fentry_bytes[6];
  prolog[1]  = new_fentry_bytes[7];
  prolog[8]  = new_fentry_bytes[4];
  prolog[9]  = new_fentry_bytes[5];
  prolog[16] = new_fentry_bytes[2];
  prolog[17] = new_fentry_bytes[3];
  prolog[28] = new_fentry_bytes[0];
  prolog[29] = new_fentry_bytes[1];

  /* Point to the prologue.  */
  char *fentry_prologue = old_fentry - INSN_SIZE * PRE_NOPS_LEN;
  memwrite(fentry_prologue, prolog, INSN_SIZE * PRE_NOPS_LEN);
}

/** @brief Get the offset of the NOP instruction.
 *
 * Some function do not have a global entry point prologue, that means
 * the NOP instruction is placed at the same address as the calling point.
 * We have to figure out which case we are handling.
 */
static int
get_branch_offset(void *fentry)
{
  int valid_offsets[] = {
    0, // NOP located at the calling point.
    8, // func with global entry point, NOP is located 8 bytes after it.
  };

  for (unsigned i = 0; i < ARRAY_LENGTH(valid_offsets); i++) {
    int offset = valid_offsets[i];
    void *fpos = (void *) ((char *)fentry + offset);

    /* Generate a branch instruction to the begining of the NOP prologue.  */
    uint32_t branch = generate_branch_to_prologue(WITH_OFFSET(offset));

    /* There are two cases we must check:
        - Function not livepatched: have a NOP insn here.
        - Function is livepatched: have a B (branch) insn here.  */
    if (memcmp(fpos, gNop, sizeof(gNop)) == 0 ||
        memcmp(fpos, &branch, sizeof(branch)) == 0) {
      return offset;
    }
  }

  /* Not valid.  */
  return -INT_MAX;
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
static int
ulp_skip_prologue(void *fentry)
{
  int offset = get_branch_offset(fentry);
  if (offset < 0) {
    return ENOPATCHABLE;
  }

  unsigned char *dst = (unsigned char *)fentry + get_branch_offset(fentry);
  memwrite(dst, gNop, sizeof(gNop));

  return 0;
}

/** @brief Insert the backwards jump to the NOP prologue.
 *
 * When a function gets live patch, the nops at its entry point get replaced
 * with a backwards-jump to a small segment of code that redirects execution to
 * the new version of the function. This function does exactly this.
 *
 * @param fentry        Address to write the prologue to.
 */
static int
ulp_patch_addr_trampoline(void *old_fentry)
{
  int offset = get_branch_offset(old_fentry);
  if (offset < 0) {
    return ENOPATCHABLE;
  }

  uint32_t branch = generate_branch_to_prologue(WITH_OFFSET(offset));
  char *dst = (char *)old_fentry + offset;
  memwrite(dst, &branch, sizeof(branch));

  return 0;
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

  int ret = 0;

  if (enable) {
    ulp_patch_prologue_layout(dst, new_faddr, ulp_prologue, INSN_SIZE * ULP_NOPS_LEN);
    ret = ulp_patch_addr_trampoline(dst);
  } else {
    ret = ulp_skip_prologue(dst);
  }

  return ret;
}
