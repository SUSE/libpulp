/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2021 SUSE Software Solutions GmbH
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

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libelf.h>

#include "arguments.h"
#include "config.h"
#include "post.h"
#include "ulp_common.h"

Elf *elf;

/** Arch-specific.  */
void merge_nops_at_addr(Elf64_Addr addr, size_t amount);

/*
 * Finds and returns the section identified by NAME. Returns NULL if no
 * such section is found. Exits in error if the string table containing
 * sections names is not found.
 */
Elf_Scn *
find_section_by_name(Elf *elf, const char *name)
{
  char *str;
  size_t string_table;

  Elf_Scn *result;
  Elf_Scn *section;
  Elf64_Shdr *shdr;

  if (elf_getshdrstrndx(elf, &string_table) == -1)
    errx(1, "Unable to find the string table.\n");

  /* Iterate over all sections */
  result = NULL;
  section = NULL;
  while ((section = elf_nextscn(elf, section)) != NULL) {
    shdr = elf64_getshdr(section);

    str = elf_strptr(elf, string_table, shdr->sh_name);
    if (strcmp(name, str) == 0) {
      result = section;
      break;
    }
  }

  return result;
}

/*
 * Iterates over all entries in the __patchable_function_entries
 * section, finds the entry points of the functions they refer to, then
 * replaces sequences of multiple nop instruction with multi-byte nops.
 */
static void
nops_fixup(void)
{
  Elf_Scn *scn;
  Elf_Data *data;
  Elf64_Shdr *shdr;
  Elf64_Addr addr;

  scn = find_section_by_name(elf, "__patchable_function_entries");
  if (scn == NULL)
    return;
  data = elf_getdata(scn, NULL);
  shdr = elf64_getshdr(scn);
  assert(data);
  assert(shdr);

  /* Iterate over the entries in __patchable_function_entries. */
  for (Elf64_Xword i = 0; i < shdr->sh_size; i += sizeof(Elf64_Addr)) {
    addr = *(Elf64_Addr *)(data->d_buf + i);

    /*
     * Each entry in the __patchable_function_entries section points to
     * the start of the nop padding added at the prologue of functions
     * compiled with -fpatchable-function-entries. However, only the
     * nops that lay after the function entry point should be merged, so
     * skip the preceding nops.
     */
    addr += PRE_NOPS_LEN;

    merge_nops_at_addr(addr, (ULP_NOPS_LEN - PRE_NOPS_LEN));
  }
}

int
run_post(struct arguments *arguments)
{
  int fd;
  Elf_Scn *scn;

  fd = open(arguments->args[0], O_RDWR);
  if (fd == -1)
    errx(EXIT_FAILURE, "Unable to open file '%s'.\n", arguments->args[0]);

  elf_version(EV_CURRENT);
  elf = elf_begin(fd, ELF_C_RDWR, NULL);

  /* Do not let libelf change the layout of the elf file. */
  assert(elf_flagelf(elf, ELF_C_SET, ELF_F_LAYOUT));

  /* Sanity check. */
  scn = find_section_by_name(elf, "__patchable_function_entries");
  if (scn == NULL)
    errx(EXIT_FAILURE,
         "Section __patchable_function_entries not found.\n"
         "(Binary not built with -fpatchable-function-entry?)\n");

  nops_fixup();

  /* Actually update the binary. */
  if (elf_update(elf, ELF_C_WRITE) == -1)
    errx(EXIT_FAILURE, "Error writing back to the Elf file.\n"
                       "(Elf file probably corrupted).\n");

  elf_end(elf);
  close(fd);

  return 0;
}
