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

#include "hash.h"
#include "config.h"
#include "error.h"
#include "insn_queue_lib.h"
#include "msg_queue.h"
#include "ulp.h"

/* clang-format off */

static unsigned char ulp_prologue[ULP_NOPS_LEN] = {
  0x02, 0x10, 0x40, 0x3c,    // lis     r2,4098
  0x00, 0x7f, 0x42, 0x38,    // addi    r2,r2,32512
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

static const unsigned char gNop[] = { 0x00, 0x00, 0x00, 0x60 };

/* clang-format on */

static hash_t insn_memory = NULL;


/** @brief Copy the ulp proglogue layout into the function to be patched's
 * prologue
 *
 * This function copies the new code prologue into the old function prologue
 * in order to redirect the execution to the new function.
 *
 */
static void
ulp_patch_prologue_layout(void *old_fentry, void *new_fentry, const unsigned char *prologue, int len)
{
  /* Create a copy of the prologue.  */
  unsigned char prolog[ULP_NOPS_LEN];
  memcpy(prolog, prologue, len);

  unsigned char new_fentry_bytes[sizeof(void*)];
  memcpy(new_fentry_bytes, &new_fentry, sizeof(new_fentry_bytes));

  /* Remember what instructions was there when patching.  */
  if (hash_get_entry(insn_memory, old_fentry) == NULL) {
    void *value;
    memcpy(&value, old_fentry, 8);
    hash_insert_single(&insn_memory, old_fentry, value);
  }

  prolog[8]  = new_fentry_bytes[6];
  prolog[9]  = new_fentry_bytes[7];
  prolog[16]  = new_fentry_bytes[4];
  prolog[17]  = new_fentry_bytes[5];
  prolog[24] = new_fentry_bytes[2];
  prolog[25] = new_fentry_bytes[3];
  prolog[36] = new_fentry_bytes[0];
  prolog[37] = new_fentry_bytes[1];

  insnq_insert_write(old_fentry, len, prolog);
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
  unsigned char prolog[ULP_NOPS_LEN];

  struct hash_entry *entry = hash_get_entry(insn_memory, fentry);
  libpulp_assert(entry);

  memcpy(prolog, &entry->value, 8);

  /* Assemble the absolute address in the instructions.  Little endian, so
     bytes are inverted.  */
  unsigned char *dst = prolog + 8;
  while (dst - prolog < ULP_NOPS_LEN) {
    libpulp_assert(dst - prolog < ULP_NOPS_LEN);
    memcpy(dst, gNop, sizeof(gNop));
    dst += sizeof(gNop);
  }

  insnq_insert_write(fentry, ULP_NOPS_LEN, prolog);
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
  if (insn_memory == NULL) {
    insn_memory = hash_table_create(0);
  }

  unsigned char *dst = (unsigned char *) old_faddr;

  if (enable) {
    ulp_patch_prologue_layout(dst, new_faddr, ulp_prologue, ULP_NOPS_LEN);
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
