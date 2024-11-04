/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2024 SUSE Software Solutions GmbH
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

/* Small parser for elf, not depending on larger libraries such as libelf
 * and with very small memory footprint.  No allocation on the heap is done
 * in this library.
 */

/* This file is not needed if we are compiling without gdb interface.  */
#ifdef ENABLE_GDB_INTERFACE

#include <elf.h>

/** Maximum size of the Section String Table.  */
#define STRTBL_SIZE_MAX       0x500

/** Typedefs so we can adjust according to architecture.  */
typedef Elf64_Ehdr Elf_Ehdr;
typedef Elf64_Shdr Elf_Shdr;
typedef Elf64_Half Elf_Half;
typedef Elf64_Off  Elf_Off;

/** Read the Elf File Header.  */
Elf_Ehdr *Elf_Parse_Ehdr(Elf_Ehdr *ehdr, int fd);

/** Get an ELF section by its name.
  *
  * OBS: use `readelf -S <file>` to show section names.
  */
Elf_Shdr *Elf_Get_Shdr_By_Name(Elf_Shdr *shdr, const char *name, int fd,
                               const Elf_Ehdr *ehdr, const char strtbl[]);


/** Get an ELF section by its index.
  *
  * OBS: use `readelf -S <file>` to show section index [<idx>].
  */
Elf_Shdr *Elf_Get_Shdr(Elf_Shdr *shdr, Elf_Half index,
                       int fd, const Elf_Ehdr *ehdr);

/** Get the section string table.  */
long Elf_Load_Strtbl(char strtbl[STRTBL_SIZE_MAX], const Elf_Ehdr *ehdr, int fd);

/** Load Section into `dest` buffer.  */
long Elf_Load_Section(unsigned dest_size, unsigned char *dest,
                      const Elf_Shdr *shdr, int fd);

/** ----- ELF functions related to ULP ----- .  */

/** Get the .ulp section from the given ELF file.  */
long Get_ULP_Section(unsigned dest_size, unsigned char *dest, const char *file);

/** Get the .ulp.rev section from the given ELF file.  */
long Get_ULP_REV_Section(unsigned dest_size, unsigned char *dest, const char *file);

#endif //ENABLE_GDB_INTERFACE
