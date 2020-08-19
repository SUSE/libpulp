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

#include "ptrace.h"

struct ulp_process
{
    int pid;

    Elf64_Addr load_bias;

    struct ulp_thread *threads;

    struct ulp_dynobj *dynobj_main;
    struct ulp_dynobj *dynobj_libpulp;
    struct ulp_dynobj *dynobj_targets;
    struct ulp_dynobj *dynobj_patches;
    struct ulp_dynobj *dynobj_others;

    unsigned long global_universe;

    struct ulp_process *next;
};

struct ulp_thread
{
    int tid;
    struct user_regs_struct context;
    int consistent;
    struct ulp_thread *next;
};

struct thread_state
{
    int tid;
    unsigned long universe;

    struct thread_state *next;
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
    Elf64_Addr global;
    Elf64_Addr local;
    Elf64_Addr testlocks;

    struct thread_state *thread_states;

    struct ulp_dynobj *next;
};

struct ulp_addresses
{
    Elf64_Addr loop;
    Elf64_Addr trigger;
    Elf64_Addr path_buffer;
    Elf64_Addr check;
    Elf64_Addr state;
    Elf64_Addr global;
    Elf64_Addr local;
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

int testlocks(struct ulp_process *process);

int patch_applied(struct ulp_process *process, unsigned char *patch_id);

int apply_patch(struct ulp_process *process, char *metadata);

int restore_threads(struct ulp_process *process);

int read_global_universe (struct ulp_process *process);

unsigned long read_local_universe (struct ulp_process *process,
                                   struct ulp_dynobj *library,
                                   struct ulp_thread *thread);

int read_local_universes (struct ulp_process *process);

int load_patch_info(char *livepatch);

int check_patch_sanity();
