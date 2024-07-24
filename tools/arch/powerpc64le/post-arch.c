/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2021-2023 SUSE Software Solutions GmbH
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


#include <libelf.h>
#include <assert.h>
#include <string.h>
#include <gelf.h>
#include <link.h>

#include "ulp_common.h"
#include "post.h"
#include "ptrace.h"

/*
 * On POWER all instructions are 4 bytes long, so there is no need
 * to do anything in the `ulp post` command.
 */
void
merge_nops_at_addr(Elf64_Addr addr, size_t amount)
{
  (void) addr;
  (void) amount;
}

/** @brief Check if function at `sym_address` has the NOP preamble.
 *
 * Functions that are livepatchable has ULP_NOPS_LEN - PRE_NOPS_LEN at the
 * beginning of the function. Check the existence of this preamble.
 *
 * @param sym_address  Address of function in target process.
 * @param pid          Pid of the target process.
 *
 * @return  True if preamble exists, false if not.
 */
bool
check_preamble(ElfW(Addr) sym_address, pid_t pid)
{
  unsigned char bytes[12]; // 3 instructions

  if (read_memory((char *)bytes, sizeof(bytes), pid, sym_address)) {
    /* In case it was unable to read the symbol due to permission error, just
     * warn in debug output.  */
    DEBUG("Unable to read symbol preamble at address %lx in process %d",
          sym_address, pid);
    return false;
  }

  const unsigned char nop[] = { 0x00, 0x00, 0x00, 0x60 };

  /* Check if first or third insn is a NOP..  */
  if (memcmp(bytes, nop, sizeof(nop)) == 0 ||
      memcmp(bytes + 8, nop, sizeof(nop)) == 0) {
    return true;
  }
  return false;
}
