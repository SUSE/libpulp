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

#include "config.h"

Elf *elf;

/*
 * Finds and returns the section identified by NAME. Returns NULL if no
 * such section is found. Exits in error if the string table containing
 * sections names is not found.
 */
Elf_Scn *
find_section_by_name(char *name)
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
 * Searches for a symbol named NAME. Returns a pointer to the Elf64_Sym
 * record that represents that symbol, or NULL if the symbol has not
 * been found.
 */
Elf64_Sym *
find_symbol_by_name(char *name)
{
  char *str;
  size_t entry_size;
  Elf_Scn *scn;
  Elf_Data *data;
  Elf64_Shdr *shdr;
  Elf64_Sym *sym;

  /* Use the .symtab if available, otherwise fallback to the .dynsym. */
  scn = find_section_by_name(".symtab");
  if (scn == NULL)
    scn = find_section_by_name(".dynsym");
  assert(scn);

  /* Iterate over the entries in the selected symbol table. */
  data = elf_getdata(scn, NULL);
  shdr = elf64_getshdr(scn);
  assert(data);
  assert(shdr);
  entry_size = sizeof(Elf64_Sym);
  for (size_t i = 0; i < shdr->sh_size; i += entry_size) {
    sym = (Elf64_Sym *)(data->d_buf + i);
    str = elf_strptr(elf, shdr->sh_link, sym->st_name);
    if (strcmp(name, str) == 0) {
      return sym;
    }
  }

  /* Symbol not found, return NULL. */
  return NULL;
}

/*
 * Searches for a symbol named NAME. Returns its address. Exits the
 * program in error if the symbol has not been found.
 */
Elf64_Addr
find_symbol_addr_by_name(char *name)
{
  Elf64_Sym *sym;

  sym = find_symbol_by_name(name);

  if (sym == NULL)
    errx(EXIT_FAILURE, "Unable to find symbol '%s'.\n", name);

  return sym->st_value;
}

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
    fprintf(stderr, "Merging more than 2 nops is not implemented.\n");
    return;
  }

  /* Use the .symtab if available, otherwise, the .dynsym. */
  scn = find_section_by_name(".symtab");
  if (scn == NULL)
    scn = find_section_by_name(".dynsym");
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
      *(uint8_t *)(data->d_buf + offset) = 0x66;
      elf_flagdata(data, ELF_C_SET, ELF_F_DIRTY);
      elf_flagscn(scn, ELF_C_SET, ELF_F_DIRTY);
      return;
    }
  }
}

int
is_patchable(Elf64_Sym *sym)
{
  Elf_Scn *scn;
  Elf_Data *data;
  Elf64_Addr addr;
  Elf64_Addr entry;
  size_t entry_size;
  int bind, type;

  /* Only FUNCTIONS, either GLOBAL or WEAK, are patchable. */
  bind = ELF64_ST_BIND(sym->st_info);
  type = ELF64_ST_TYPE(sym->st_info);
  if (!(type == STT_FUNC && (bind == STB_GLOBAL || bind == STB_WEAK)))
    return 0;

  /* Start of the nop padding area for SYM. */
  addr = sym->st_value - PRE_NOPS_LEN;

  /*
   * SYM has padding nops *only if* ADDR is an entry in
   * __patchable_function_entries.
   */
  scn = find_section_by_name("__patchable_function_entries");
  assert(scn);
  data = elf_getdata(scn, NULL);
  assert(data);
  entry_size = sizeof(Elf64_Addr);
  for (size_t i = 0; i < data->d_size; i += entry_size) {
    entry = *(Elf64_Addr *)(data->d_buf + i);
    if (addr == entry)
      return 1;
  }

  return 0;
}

/*
 * Iterates over all entries in the __patchable_function_entries
 * section, finds the entry points of the functions they refer to, then
 * replaces sequences of multiple nop instruction with multi-byte nops.
 */
void
nops_fixup(void)
{
  Elf_Scn *scn;
  Elf_Data *data;
  Elf64_Shdr *shdr;
  Elf64_Addr addr;

  scn = find_section_by_name("__patchable_function_entries");
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
main(int argc, char **argv)
{
  int fd;
  Elf_Scn *scn;

  if (argc != 2)
    errx(EXIT_FAILURE, "Usage: %s <library.so>", argv[0]);

  fd = open(argv[1], O_RDWR);
  if (fd == -1)
    errx(EXIT_FAILURE, "Unable to open file '%s'.\n", argv[1]);

  elf_version(EV_CURRENT);
  elf = elf_begin(fd, ELF_C_RDWR, NULL);

  /* Do not let libelf change the layout of the elf file. */
  assert(elf_flagelf(elf, ELF_C_SET, ELF_F_LAYOUT));

  /* Sanity check. */
  scn = find_section_by_name("__patchable_function_entries");
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
