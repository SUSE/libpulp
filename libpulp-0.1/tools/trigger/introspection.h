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
    int main;
    struct link_map link_map;
    asymbol **symtab;
    int symtab_len;

    Elf64_Addr loop;
    Elf64_Addr trigger;
    Elf64_Addr consistency;
    Elf64_Addr check;
    Elf64_Addr path_buffer;
    Elf64_Addr set_pending;

    struct ulp_dynobj *next;
};

struct ulp_addresses
{
    Elf64_Addr loop;
    Elf64_Addr trigger;
    Elf64_Addr path_buffer;
    Elf64_Addr check;
    Elf64_Addr set_pending;
};

typedef struct ulp_process ulp_process;
typedef struct ulp_thread ulp_threads;
typedef struct ulp_dynobj ulp_dynobj;
typedef struct ulp_addresses ulp_addresses;

int parse_file_symtab(ulp_dynobj *obj);

asymbol **get_main_symtab();

int get_main_symtab_length();

int dig_main_link_map(struct link_map *main_link_map);

int parse_threads(int pid);

Elf64_Addr get_loaded_symbol_addr(struct ulp_dynobj *obj, char *sym);

int dig_load_bias(struct ulp_dynobj *obj);

int parse_main_dynobj(char *objname);

int is_main_object_parsed();

struct link_map *parse_lib_dynobj(struct link_map *link_map_addr);

struct link_map get_link_map(char *name);

int initialize_data_structures(int pid, char *livepatch);

int hijack_threads(int set_pending);

int set_id_buffer(char *patch_id, struct ulp_thread *t);

int set_path_buffer(char *path, struct ulp_thread *t);

int check_thread_consistency(char *path);

int restore_threads();

int check_consistency(char *path);

int load_patch_info(char *livepatch);

int check_patch_sanity();
