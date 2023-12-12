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

#include "ulp_common.h"
#include "post.h"
#include "arch/x86_64/common.h"

extern Elf *elf;

/*
 * Merges AMOUNT nop instruction at the function at ADDR.
 *
 * NOTE: This is an x86_64 specific function.
 */
void
merge_nops_at_addr(Elf64_Addr addr, size_t amount)
{
  Elf_Scn *scn;
  Elf_Data *data;
  Elf64_Shdr *shdr;
  Elf64_Sym *sym;
  Elf64_Off offset;

  /* Nothing to merge. */
  if (amount < 2)
    return;

  if (amount > 2) {
    WARN("Merging more than 2 nops is not implemented.\n");
    return;
  }

  /* Use the .symtab if available, otherwise, the .dynsym. */
  scn = find_section_by_name(elf, ".symtab");
  if (scn == NULL)
    scn = find_section_by_name(elf, ".dynsym");
  if (scn == NULL)
    return;
  data = elf_getdata(scn, NULL);
  shdr = elf64_getshdr(scn);
  assert(data);
  assert(shdr);

  /* Iterate over the entries in the selected symbols section. */
  for (Elf64_Xword i = 0; i < shdr->sh_size; i += sizeof(Elf64_Sym)) {
    sym = (Elf64_Sym *)(data->d_buf + i);
    if (sym->st_value == addr) {

      /* Symbol found. Get its containing section. */
      scn = elf_getscn(elf, sym->st_shndx);
      assert(scn);
      data = elf_getdata(scn, NULL);
      shdr = elf64_getshdr(scn);
      assert(data);
      assert(shdr);

      /* Merge two nops into a two-bytes, single one. */
      offset = addr - shdr->sh_addr;
      uint8_t *func_addr = data->d_buf + offset;
      static const char insn_endbr64[] = { INSN_ENDBR64 };

      /* Check if instruction is actually an endbr64.  In that case we must
         take that into account.  */
      if (memcmp(func_addr, insn_endbr64, sizeof(insn_endbr64)) == 0)
        func_addr += sizeof(insn_endbr64);

      /* Assert that the insn is actually a NOP.  */
      assert(func_addr[1] == 0x90 &&
             (func_addr[0] == 0x90 || func_addr[0] == 0x66));

      /* Merge two NOPs.  */
      *func_addr = 0x66;
      elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
      elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
      return;
    }
  }
}
