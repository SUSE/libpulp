/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017 SUSE Linux GmbH
 *
 *  This file is part of libpulp.
 *
 *  libpulp is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libpulp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libpulp.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  Author: Joao Moreira <jmoreira@suse.de>
 */

#include <stdio.h>
#include <gelf.h>
#include <unistd.h>
#include "ulp_common.h"

void usage(char *name);

void free_metadata(struct ulp_metadata *ulp);

void unload_elf(Elf **elf, int *fd);

Elf *load_elf(char *obj, int *fd);

Elf_Scn *get_symtab(Elf *elf);

Elf_Scn *get_build_id_note(Elf *elf);

int get_ulp_elf_metadata(Elf *elf, struct ulp_object *obj,
    struct ulp_metadata *ulp);

int get_object_metadata(Elf *elf, struct ulp_object *obj);

int get_elf_tgt_addrs(Elf *elf, struct ulp_object *obj, Elf_Scn *st);

int create_patch_metadata_file(struct ulp_metadata *ulp);

int add_dependency(struct ulp_metadata *ulp, struct ulp_dependency *dep,
    char *filename);

int parse_description(char *filename, struct ulp_metadata *ulp);

int get_build_id(Elf_Scn *s, struct ulp_object *obj);

void *get_symbol_addr(Elf *elf, Elf_Scn *s, char *search);

int generate_random_patch_id(struct ulp_metadata *ulp);
