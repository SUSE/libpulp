/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2021 SUSE Software Solutions GmbH
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

#ifndef PACKER_H
#define PACKER_H

#include <gelf.h>
#include <stdio.h>
#include <unistd.h>

#include "ulp_common.h"

struct arguments;
struct ulp_so_info;
struct argp_option;

void unload_elf(Elf **elf, int *fd);

Elf *load_elf(const char *obj, int *fd);

Elf_Scn *get_dynsym(Elf *elf);

Elf_Scn *get_symtab(Elf *elf);

Elf_Scn *get_build_id_note(Elf *elf);

int get_object_metadata(Elf *elf, struct ulp_object *obj);

int get_target_addrs(struct ulp_so_info *, struct ulp_object *);

int create_patch_metadata_file(struct ulp_metadata *ulp, const char *filename);

int add_dependency(struct ulp_metadata *ulp, struct ulp_dependency *dep,
                   const char *filename);

int get_build_id(Elf_Scn *s, char *buildid_buf, unsigned *len);

int get_elf_buildid(Elf *elf, char *buf, unsigned *len);

void *get_symbol_addr(Elf *elf, Elf_Scn *s, const char *search);

int run_packer(struct arguments *);

struct argp_option *get_command_option_packer(void);

#endif /* PACKER_H */
