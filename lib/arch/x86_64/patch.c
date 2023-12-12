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
#include "arch/x86_64/common.h"

/** Intel endbr64 instruction optcode.  */
static const uint8_t insn_endbr64[] = {INSN_ENDBR64};

/* clang-format off */

/** Offset of the data entry in the ulp_prologue.  */
#define ULP_DATA_OFFSET 6           // ------------------------------+
                                    //                               |
static char ulp_prologue[ULP_NOPS_LEN] = { //                               |
  // Preceding nops                                                  |
  0xff, 0x25, 0, 0, 0, 0,           // jmp     0x0(%rip) <-------+   |
  0, 0, 0, 0, 0, 0, 0, 0,           // <data>  &__ulp_prolog     | <-+
  // Function entry is here                                      |
  0xeb, -(PRE_NOPS_LEN + 2)         // jmp ----------------------+
  // (+2 because the previous jump consumes 2 bytes.
};

#define ULP_NOPS_LEN_ENDBR64    (ULP_NOPS_LEN + 4)

/** Offset of the data entry in the ulp_prologue.  */
static char ulp_prologue_endbr64[ULP_NOPS_LEN_ENDBR64] = {
  // Preceding nops
  0xff, 0x25, 0, 0, 0, 0,           // jmp     0x0(%rip) <-------+
  0, 0, 0, 0, 0, 0, 0, 0,           // <data>  &__ulp_prolog     |
  // Function entry is here                                      |
  INSN_ENDBR64,                     // endbr64                   |
  0xeb, -(PRE_NOPS_LEN + 2 + 4)     // jmp ----------------------+
  // (+2 because the previous jump consumes 2 bytes.
};
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
  char *dst = (char *)old_fentry + ULP_DATA_OFFSET;
  insnq_insert_write(dst, sizeof(void *), &manager);
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
  static const char insn_nop2[] = { 0x66, 0x90 };
  int bias = 0;
  if (memcmp(fentry, insn_endbr64, sizeof(insn_endbr64)) == 0)
    bias += sizeof(insn_endbr64);

  /* Do not jump backwards on function entry (0x6690 is a nop on x86). */
  insnq_insert_write((char *)fentry + bias, sizeof(insn_nop2), insn_nop2);
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
  void *addr;

  int ulp_nops_len;
  const char *prologue;

  const unsigned char *as_bytes = old_faddr;

  /* Check if the first instruction of old_function is endbr64.  In this
     case, we have to handle things differently.  */
  if (memcmp(old_faddr, insn_endbr64, sizeof(insn_endbr64)) == 0) {
    ulp_nops_len = ULP_NOPS_LEN_ENDBR64;
    prologue = ulp_prologue_endbr64;
    as_bytes += sizeof(insn_endbr64);
  }
  else {
    ulp_nops_len = ULP_NOPS_LEN;
    prologue = ulp_prologue;
  }

  /* Check if we have the two NOP sequence or a JMP ref8 insn.  Else we might
     be attempting to patch a non-livepatchable function.  */

  if (!(as_bytes[0] == 0xEB ||
        (as_bytes[1] == 0x90 &&
         (as_bytes[0] == 0x90 || as_bytes[0] == 0x66)))) {
    WARN("Function at addr %lx is not livepatchable",
         (unsigned long)old_faddr);
    return ENOPATCHABLE;
  }

  /* Find the starting address of the pages containing the nops. */
  addr = old_faddr - PRE_NOPS_LEN;

  /* Actually patch the prologue. */
  if (enable) {
    ulp_patch_prologue_layout(addr, prologue, ulp_nops_len);
    ulp_patch_addr_absolute(addr, new_faddr);
  }
  else {
    ulp_skip_prologue(old_faddr);
  }

  return 0;
}


void save_to_register(void *target)
{
  asm (
    "movq %0, %%r11;"
    :
    : "r" (target)
    :
  );
}
