/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2018 SUSE Linux GmbH
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

#include <link.h>
#include <bfd.h>

struct ulp_process
{
    int pid;

    Elf64_Addr load_bias;

    struct ulp_thread *threads;

    struct ulp_dynobj *dynobj_main;
    struct ulp_dynobj *dynobj_libulp;
    struct ulp_dynobj *dynobjs;
};

struct ulp_thread
{
    int tid;
    struct user_regs_struct context;
    int consistent;
    struct ulp_thread *next;
};

struct ulp_dynobj
{
    char *filename;
    struct link_map link_map;
    asymbol **symtab;
    int symtab_len;

    Elf64_Addr loop;
    Elf64_Addr trigger;
    Elf64_Addr check;
    Elf64_Addr path_buffer;
    Elf64_Addr state;

    struct ulp_dynobj *next;
};

struct ulp_addresses
{
    Elf64_Addr loop;
    Elf64_Addr trigger;
    Elf64_Addr path_buffer;
    Elf64_Addr check;
    Elf64_Addr state;
};

int parse_file_symtab(struct ulp_dynobj *obj, char needed);

int dig_main_link_map(struct ulp_process *process);

int parse_threads(struct ulp_process *process);

Elf64_Addr get_loaded_symbol_addr(struct ulp_dynobj *obj, char *sym);

int dig_load_bias(struct ulp_process *process);

int parse_main_dynobj(struct ulp_process *process);

int parse_libs_dynobj(struct ulp_process *process);

struct link_map *parse_lib_dynobj(struct ulp_process *process,
                                  struct link_map *link_map_addr);

int initialize_data_structures(struct ulp_process *process);

int hijack_threads(struct ulp_process *process);

int set_id_buffer(struct ulp_process *process, unsigned char *patch_id);

int set_path_buffer(struct ulp_process *process, char *path);

int restore_threads(struct ulp_process *process);

int load_patch_info(char *livepatch);

int check_patch_sanity();
