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

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "error.h"
#include "minielf.h"
#include "ulp_common.h"

#define debug(...) DEBUG(__VA_ARGS__)
#define warn(...)  WARN(__VA_ARGS__)

/** Ban memory allocation functions.  This module should never allocate memory
    in the heap.  */
#pragma GCC poison malloc calloc free

/** Read the Elf File Header.  */
Elf_Ehdr *Elf_Parse_Ehdr(Elf_Ehdr *ehdr, int fd)
{
  /* Go to begining of file.  */
  lseek(fd, 0L, SEEK_SET);

  ssize_t n = read(fd, ehdr, sizeof(Elf_Ehdr));

  if (n != sizeof(Elf_Ehdr)) {
    warn("Invalid ELF file: invalid size");
    return NULL;
  }

  /* Check if the header makes sense.  */
  if (memcmp(&ehdr->e_ident, ELFMAG, SELFMAG) != 0) {
    warn("Invalid ELF file: invalid magic number");
    return NULL;
  }

  return ehdr;
}

/** Get an ELF section by its name.
  *
  * OBS: use `readelf -S <file>` to show section names.
  */
Elf_Shdr *Elf_Get_Shdr_By_Name(Elf_Shdr *shdr, const char *name, int fd,
                               const Elf_Ehdr *ehdr, const char strtbl[])
{
  /* Make sure it will fit the buffer.  */
  libpulp_assert(ehdr->e_shentsize == sizeof(Elf_Shdr));

  /* Go to offset.  */
  lseek(fd, ehdr->e_shoff, SEEK_SET);

  for (Elf_Half i = 0; i < ehdr->e_shnum; i++) {
    /* Load the header.  */
    ssize_t n = read(fd, shdr, ehdr->e_shentsize);

    if (n != ehdr->e_shentsize) {
      warn("Invalid ELF file: invalid size\n");
      return NULL;
    }

    /* Check if name matches.  */
    if (strcmp(name, &strtbl[shdr->sh_name]) == 0) {
      return shdr;
    }
  }

  return NULL;
}

/** Get an ELF section by its index.
  *
  * OBS: use `readelf -S <file>` to show section index [<idx>].
  */
Elf_Shdr *Elf_Get_Shdr(Elf_Shdr *shdr, Elf_Half index,
                       int fd, const Elf_Ehdr *ehdr)
{
  /* Make sure it will fit the buffer.  */
  libpulp_assert(ehdr->e_shentsize == sizeof(Elf_Shdr));

  /* Go to offset.  */
  lseek(fd, ehdr->e_shoff, SEEK_SET);

  for (Elf_Half i = 0; i < ehdr->e_shnum; i++) {
    /* Load the header.  */
    ssize_t n = read(fd, shdr, ehdr->e_shentsize);

    if (n != ehdr->e_shentsize) {
      warn("Invalid ELF file: invalid size");
      return NULL;
    }

    /* Check if index matches.  */
    if (index == i) {
      return shdr;
    }
  }

  return NULL;
}

/** Get the section string table.  */
long Elf_Load_Strtbl(char strtbl[STRTBL_SIZE_MAX], const Elf_Ehdr *ehdr, int fd)
{
  /* Make sure it will fit the buffer.  */
  libpulp_assert(ehdr->e_shentsize == sizeof(Elf_Shdr));

  /* Declare a section for us to store and iterate.  */
  Elf_Shdr shdr;
  Elf_Shdr *p_shdr = Elf_Get_Shdr(&shdr, ehdr->e_shstrndx, fd, ehdr);

  /* Make sure we are in the correct section.  */
  if (p_shdr == NULL) {
      warn("Invalid ELF file: no section string table");
      return 0L;
  }

  if (shdr.sh_size > STRTBL_SIZE_MAX) {
      warn("Unable to load section string table: size larger than buffer");
      return 0L;
  }

  /* Go to offset.  */
  lseek(fd, shdr.sh_offset, SEEK_SET);

  /* Load the strtbl.  */
  ssize_t n = read(fd, strtbl, shdr.sh_size);

  if ((size_t)n != shdr.sh_size) {
    warn("Unable to load section string table: file size mismatch.\n");
    return 0L;
  }

  return shdr.sh_size;
}

/** Load Section into `dest` buffer.  */
long Elf_Load_Section(unsigned dest_size, unsigned char *dest,
                             const Elf_Shdr *shdr, int fd)
{
  /* Check if dest can hold the section.  */
  if (shdr->sh_size > dest_size) {
    warn("Unable to load section: buffer too small");
    return 0L;
  }

  /* Go to offset.  */
  lseek(fd, shdr->sh_offset, SEEK_SET);

  /* Load the section.  */
  ssize_t n = read(fd, dest, shdr->sh_size);

  if ((size_t)n != shdr->sh_size) {
    warn("Unable to load section string table: read size mismatch");
    return 0L;
  }

  return shdr->sh_size;
}

/** Load the .ulp section of livepatch of `file` into the buffer.  */
static int
Get_Elf_Section(unsigned dest_size, unsigned char *dest,
                const char *section_name, const char *file)
{
  /* Open ELF file.  */
  int elf_fd = open(file, O_RDONLY);
  if (elf_fd < 0) {
    warn("Unable to open file %s: %s", file, strerror(errno));
    return ENOENT;
  }

  /* Load ELF file header.  */
  Elf_Ehdr ehdr;
  Elf_Ehdr *p_ehdr = Elf_Parse_Ehdr(&ehdr, elf_fd);
  if (p_ehdr == NULL) {
    warn("File is not an ELF object.");

    close(elf_fd);
    return EINVAL;
  }

  /* Load ELF section string table.  */
  char strtbl[STRTBL_SIZE_MAX];
  Elf_Load_Strtbl(strtbl, &ehdr, elf_fd);

  /* Load section header from the ELF file.  */
  Elf_Shdr ulp_shdr;
  Elf_Shdr *p_ulp_shdr = Elf_Get_Shdr_By_Name(&ulp_shdr, section_name,
                                              elf_fd, &ehdr, strtbl);

  if (p_ulp_shdr == NULL) {
    warn("Section %s not found.", section_name);

    close(elf_fd);
    return EINVAL;
  }

  /* Load ELF section into dest.  */
  long x = Elf_Load_Section(dest_size, dest, &ulp_shdr, elf_fd);
  if (x == 0) {
    close(elf_fd);
    return EINVAL;
  }

  close(elf_fd);
  return 0;
}

int
Get_ULP_Section(unsigned dest_size, unsigned char *dest, const char *file)
{
  return Get_Elf_Section(dest_size, dest, ".ulp", file);
}

int
Get_ULP_REV_Section(unsigned dest_size, unsigned char *dest, const char *file)
{
  return Get_Elf_Section(dest_size, dest, ".ulp.rev", file);
}
