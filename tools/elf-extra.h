/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2019-2022 SUSE Software Solutions GmbH
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

#include <gelf.h>
#include <libelf.h>
#include <link.h>

/* Extra ELF functions.  */

Elf_Scn *get_elfscn_by_name(Elf *elf, const char *name);

Elf_Scn *get_elf_section(Elf *, ElfW(Word) sht_type);

Elf *load_elf(const char *path, int *fd);

void unload_elf(Elf **, int *fd);

int embed_patch_metadata_into_elf(Elf *elfinput, const char *elf_path,
                                  const char *metadata,
                                  const char *section_name);
