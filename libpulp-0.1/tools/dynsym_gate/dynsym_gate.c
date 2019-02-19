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
#include <stddef.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <gelf.h>
#include <string.h>
#include <stdbool.h>
#include <err.h>
#include "../../include/ulp_common.h"

#define TRM_LEN 16
#define ENTRY_LEN 8

typedef struct
{
    Elf_Scn *sec;
    Elf64_Shdr *shdr;
    int len;
    void *offset;
    Elf_Data *data;
} elf_section;

static const char trm_entry_layout[TRM_LEN] =
{
    0xe8, 0, 0, 0, 0,	/* call ulp_entry   */
    0xe9, 0, 0, 0, 0,	/* jmp plt entry    */
    0x90, 0x90, 0x90, 0x90, 0x90, 0x88
};

static const char trm_cet_entry_layout[TRM_LEN] =
{
    0x4c, 0x8d, 0x1d, 0, 0, 0, 0,
    0x41, 0x53,
    0xe9, 0, 0, 0, 0, 0x90, 0x90

};

Elf *gelf;

Elf *load_elf(char *obj, int *fd)
{
    Elf *elf;

    *fd = open(obj, O_RDWR);
    if (*fd == -1) 	errx(EXIT_FAILURE, "File open error.");

    elf = elf_begin(*fd, ELF_C_RDWR, NULL);
    if (!elf) {
	close(*fd);
	errx(EXIT_FAILURE, "Elf begin error.");
    }
    return elf;
}

void unload_elf(Elf **elf, int *fd)
{
    if (elf) elf_end(*elf);
    if (fd > 0) close(*fd);
    *fd = 0;
    *elf = NULL;
}

int32_t compute_branch(void *org, void *dst, int entry, int instr_offset)
{
    ptrdiff_t offset = (org + (entry * TRM_LEN)) - dst + instr_offset;
    if (org > dst) offset = -offset;

    // offsets beyond 32 bits are not yet sypported
    if (offset > INT32_MAX || offset < INT32_MIN)
	return 0;

    return (int32_t) offset;
}

void write_trm_cet_entry(elf_section stub, int32_t branch, uint32_t target,
	uint32_t count)
{
	void *ptr = stub.data->d_buf;
	ptr = ptr + (count * TRM_LEN);
	memcpy(ptr, trm_cet_entry_layout, TRM_LEN);
	memcpy(ptr + 3, &target, 4);
	memcpy(ptr + 10, &branch, 4);
}

void write_trm_entry(elf_section stub, int32_t offset, int32_t branch,
	uint32_t count)
{
    void *ptr = stub.data->d_buf;
    ptr = ptr + (count * TRM_LEN);
    memcpy(ptr, trm_entry_layout, TRM_LEN);
    memcpy(ptr + 1, &offset, 4);
    memcpy(ptr + 6, &branch, 4);
}

void write_padding_nops(elf_section text, uint64_t fct_offset)
{
    void *ptr = text.data->d_buf;
    ptr = ptr + fct_offset;
    memset(ptr, 0x90, PRE_NOPS_LEN + 2);
    memset(ptr + PRE_NOPS_LEN, 0x66, 1);
}

int whitelisted(char *sym_name)
{
	if (strcmp(sym_name, "__ulp_get_pending")==0) return 1;
	return 0;
}

int main(int argc, char **argv) {
    elf_version(EV_CURRENT);

    Elf_Scn *s = NULL;
    GElf_Shdr sh;
    size_t shstrndx, nr;
    int i, fd;
    Elf64_Sym *sym;
    char *sym_name, *str;
    int bind, type;
    void * trm_offset = NULL;
    int32_t ulp_offset, fct_offset, count = 0;
    elf_section dynsym, symtab, stubs, text, patchable;

    fd = 0;
    gelf = load_elf(argv[1], &fd);

    if (elf_getshdrnum(gelf, &nr))
	errx(EXIT_FAILURE, "elf_getshdrnum: %s", elf_errmsg(-1));

    if (elf_getshdrstrndx(gelf, &shstrndx))
	errx(EXIT_FAILURE, "elf_getshdrstrndx: %s", elf_errmsg(-1));

    // TODO: add section type checks besides name comparison below
    for (i = 0; i < nr; i++) {
	s = elf_getscn(gelf, i);
	if (!s)	errx(EXIT_FAILURE, "elf_getscn: %s", elf_errmsg(-1));

	if (!gelf_getshdr(s, &sh))
	    errx(EXIT_FAILURE, "elf_getshdr: %s", elf_errmsg(-1));

	str = elf_strptr(gelf, shstrndx, sh.sh_name);
	if (strcmp(str, ".dynsym")==0) {
	    dynsym.sec = s;
	    dynsym.shdr = elf64_getshdr(s);
	    dynsym.len = (int) sh.sh_size / sizeof(Elf64_Sym);
	    dynsym.offset = (void *) sh.sh_offset;
	    dynsym.data = elf_getdata(dynsym.sec, NULL);
	}
	if (strcmp(str, ".symtab")==0) {
	    symtab.sec = s;
	    symtab.shdr = elf64_getshdr(s);
	    symtab.len = (int) sh.sh_size / sizeof(Elf64_Sym);
	    symtab.offset = (void *) sh.sh_offset;
	    symtab.data = elf_getdata(symtab.sec, NULL);
	}
	if (strcmp(str, ".ulp")==0) {
	    stubs.sec = s;
	    stubs.shdr = elf64_getshdr(s);
	    stubs.offset = (void *) sh.sh_offset;
	    stubs.data = elf_getdata(stubs.sec, NULL);
	}
        if (strcmp(str, ".text")==0) {
            text.sec = s;
            text.shdr = elf64_getshdr(s);
            text.offset = (void *) sh.sh_offset;
            text.data = elf_getdata(text.sec, NULL);
        }
	if (strcmp(str, "__patchable_function_entries")==0) {
            patchable.sec = s;
            patchable.shdr = elf64_getshdr(s);
            patchable.offset = (void *) sh.sh_offset;
            patchable.data = elf_getdata(patchable.sec, NULL);
            patchable.len = (int) sh.sh_size / sizeof(void *);
            // the __patchable_function_entries section keeps relocation
            // information of patchable entries. by subtracting these from the
            // .text section offset, we get the position of the patchable entry
            // in the .text data buffer.
        }
    }

    for (i = 0; i < symtab.len; i++) {
	sym = (Elf64_Sym *)(symtab.data->d_buf + (i * sizeof(Elf64_Sym)));
	sym_name = elf_strptr(gelf, symtab.shdr->sh_link, sym->st_name);
	bind = ELF64_ST_BIND(sym->st_info);
	type = ELF64_ST_TYPE(sym->st_info);
	if (strcmp(sym_name, "__ulp_entry")==0) {
	    trm_offset = (void *) sym->st_value;
	}
    }
    if (!trm_offset) errx(EXIT_FAILURE, "Elf has not __ulp_trm function\n");

    for (i = 0; i < dynsym.len; i++) {
	sym = (Elf64_Sym *) (dynsym.data->d_buf + i * sizeof(Elf64_Sym));
	sym_name = elf_strptr(gelf, dynsym.shdr->sh_link, sym->st_name);
	if (whitelisted(sym_name)) continue;
	bind = ELF64_ST_BIND(sym->st_info);
	type = ELF64_ST_TYPE(sym->st_info);
	if (type == 2 && bind == 1 && sym->st_shndx != 0) {
	    ulp_offset = -(compute_branch(stubs.offset, trm_offset, count, 14));
	    fct_offset = compute_branch(stubs.offset, (void *) sym->st_value,
		    count, 7);
            write_trm_cet_entry(stubs, ulp_offset, fct_offset, count);
	    sym->st_value = (Elf64_Addr) stubs.offset + (count * 16);
	    count++;
	}
    }

    for (i = 0; i < patchable.len; i++) {
      uint64_t offset = * (uint64_t *) (patchable.data->d_buf + (i * 8));
      write_padding_nops(text, offset - (uint64_t) text.offset);
    }

    if (count > 0) {
	elf_flagehdr(gelf, ELF_C_SET, ELF_F_DIRTY | ELF_F_LAYOUT);
	elf_flagscn(dynsym.sec, ELF_C_SET, ELF_F_DIRTY | ELF_F_LAYOUT);
	elf_flagscn(text.sec, ELF_C_SET, ELF_F_DIRTY | ELF_F_LAYOUT);
	elf_flagelf(gelf, ELF_C_SET, ELF_F_DIRTY | ELF_F_LAYOUT);
	if (elf_update(gelf, ELF_C_WRITE) < 0)
	    errx(EXIT_FAILURE , "elf_update(): %s", elf_errmsg( -1));
	fprintf(stderr, "Elf file succesfully updated.\n");
    }

    unload_elf(&gelf, &fd);
    return 0;
}
