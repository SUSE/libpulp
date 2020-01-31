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

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <gelf.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "../../include/packer.h"

void usage(char *name)
{
    fprintf(stderr, "Usage: %s <descr.txt> <target.so> [output file]", name);
    fprintf(stderr, " * <descr.txt>: Text-file with patch description.\n");
    fprintf(stderr, " * <target.so>: .so with to-be-patched function.\n");
    fprintf(stderr, " * [output file] (optional): write to output file,\n");
    fprintf(stderr, "   instead of to the standard, hardcoded path.\n\n");
    fprintf(stderr, "   descr.txt format:\n\n");
    fprintf(stderr, "   absolute path to patch.so\n");
    fprintf(stderr, "   tgt_func1:patch_func1\n");
    fprintf(stderr, "   tgt_func2:patch_func2\n");
    fprintf(stderr, " * <tgt_func>: Function to be patched\n");
    fprintf(stderr, " * <patch_func>: Function that will replace tgt_func\n");
    fprintf(stderr, " * Each line describes a function to be patched\n");
    fprintf(stderr, " * Patches are to the object listed in the previous line \
	    started with a '@' and should be to a single shared object\n");
}

void free_metadata(struct ulp_metadata *ulp)
{
    struct ulp_object *obj;
    struct ulp_unit *unit, *next_unit;
    if (!ulp) return;
    obj = ulp->objs;
    if (obj) {
	unit = obj->units;
	while (unit) {
	    next_unit = unit->next;
	    free(unit->old_fname);
	    free(unit->new_fname);
	    free(unit);
	    unit = next_unit;
	}
	free(obj->name);
	free(obj->build_id);
	free(obj);
    }
}

void unload_elf(Elf **elf, int *fd)
{
    if (fd > 0) close(*fd);
    if (elf) elf_end(*elf);
    *fd = 0;
    *elf = NULL;
}

Elf *load_elf(char *obj, int *fd)
{
    Elf *elf;

    *fd = open(obj, O_RDONLY);
    if (*fd == -1) {
	err(0, "Error opening %s", obj);
	return NULL;
    }

    elf = elf_begin(*fd, ELF_C_READ, NULL);
    if (!elf) {
	err(0, "Error invoking elf_begin()");
	close(*fd);
	return NULL;
    }
    return elf;
}

Elf_Scn *get_symtab(Elf *elf) {
    int i;
    size_t nsecs;
    Elf_Scn *s;
    GElf_Shdr sh;

    if (elf_getshdrnum(elf, &nsecs)) {
	err(0, "Error invoking elf_getshdrnum()");
	return NULL;
    }

    for (i = 0; i < nsecs; i++) {
	s = elf_getscn(elf, i);
	if (!s) {
	    err(0, "Error invoking elf_getscn()");
	    return NULL;
	}
	gelf_getshdr(s, &sh);

	if (sh.sh_type == SHT_SYMTAB) {
	    return s;
	}
    }
    return NULL;
}

Elf_Scn *get_build_id_note(Elf *elf) {
    int i;
    size_t nsecs, shstrndx;
    Elf_Scn *s;
    GElf_Shdr sh;
    char *sec_name;

    if (elf_getshdrnum(elf, &nsecs)) {
	err(1, "Error invoking elf_getshdrnum()");
    }

    for (i = 0; i < nsecs; i++) {
	s = elf_getscn(elf, i);
	if (!s) {
	    err(1, "Error invoking elf_getscn()");
	}
	gelf_getshdr(s, &sh);

	if (sh.sh_type == SHT_NOTE) {
	    elf_getshdrstrndx(elf, &shstrndx);
	    sec_name = elf_strptr(elf, shstrndx, sh.sh_name);
	    if (strcmp(sec_name, ".note.gnu.build-id") == 0) return s;
	}
    }
    return NULL;
}

int get_ulp_elf_metadata(Elf *elf, struct ulp_object *obj,
	struct ulp_metadata *ulp)
{

    Elf_Scn *symtab;
    symtab = get_symtab(elf);
    if (!symtab) {
	WARN("Unable to get .symtab section (stripped binary?).");
	return 0;
    }

    if (!get_object_metadata(elf, obj)) {
	WARN("Unable to get object metadata.");
	return 0;
    }

    if (!get_elf_tgt_addrs(elf, obj, symtab)) {
	WARN("Unable to get target addresses.");
	return 0;
    }

    return 1;
}

int get_object_metadata(Elf *elf, struct ulp_object *obj)
{
    Elf_Scn *s;
    s = get_build_id_note(elf);
    if (!s) return 0;
    if (!get_build_id(s, obj)) return 0;
    return 1;
}

int get_elf_tgt_addrs(Elf *elf, struct ulp_object *obj, Elf_Scn *st)
{
    struct ulp_unit *unit;
    unit = obj->units;

    while (unit != NULL) {
	unit->old_faddr = get_symbol_addr(elf, st, unit->old_fname);
	unit = unit->next;
    }
    return 1;
}

int create_patch_metadata_file(struct ulp_metadata *ulp, char *filename)
{
    FILE *file;
    struct ulp_unit *unit;
    struct ulp_object *obj;
    struct ulp_dependency *dep;
    uint32_t c;
    uint8_t type = 1;

    if (filename == NULL)
        file = fopen(OUT_PATCH_NAME, "w");
    else
        file = fopen(filename, "w");
    if (!file) {
	WARN("unable to open output metadata file.");
	return 0;
    };

    /* Patch type -> 1 means patch, 2 means revert-patch */
    fwrite(&type, sizeof(uint8_t), 1, file);

    /* Patch id (first 32b) */
    fwrite(ulp->patch_id, sizeof(char), 32, file);
    c = strlen(ulp->so_filename);
    /* patch .so filename length */
    fwrite(&c, sizeof(uint32_t), 1, file);
    /* patch .so filename */
    fwrite(ulp->so_filename, sizeof(char), c, file);

    obj = ulp->objs;
    /* object build id length */
    fwrite(&obj->build_id_len, sizeof(uint32_t), 1, file);
    /* object build id */
    fwrite(obj->build_id, sizeof(char), obj->build_id_len, file);

    if (!obj->name) {
	WARN("to be patched object has no name\n");
	return 0;
    }
    c = strlen(obj->name);
    /* object name length */
    fwrite(&c, sizeof(uint32_t), 1, file);
    /* object name */
    fwrite(obj->name, sizeof(char), c, file);

    /* number of units appended to object */
    fwrite(&obj->nunits, sizeof(uint32_t), 1, file);

    for (unit = obj->units; unit != NULL; unit = unit->next) {
	c = strlen(unit->old_fname);
	/* to-be-patched function name length */
	fwrite(&c, sizeof(uint32_t), 1, file);
	/* to-be-patched function name */
	fwrite(unit->old_fname, sizeof(char), c, file);

	c = strlen(unit->new_fname);
	/* patch function name length */
	fwrite(&c, sizeof(uint32_t), 1, file);
	/* patch function name */
	fwrite(unit->new_fname, sizeof(char), c, file);

	/* to-be-patched function addrs */
	fwrite(&unit->old_faddr, sizeof(void *), 1, file);
    }

    fwrite(&ulp->ndeps, sizeof(uint32_t), 1, file);

    for(dep = ulp->deps; dep != NULL; dep = dep->next) {
	fwrite(&dep->dep_id, sizeof(char), 32, file);
    }

    return 1;
}

int add_dependency(struct ulp_metadata *ulp, struct ulp_dependency *dep,
	char *filename)
{
    FILE *file;
    uint8_t patch_type;

    file = fopen(filename, "r");
    if (!file) {
	WARN("Unable to open dependency file %s.", filename);
	return 0;
    }

    if (fread(&patch_type, sizeof(uint8_t), 1, file) < 1) {
	WARN("Unable to read dependency patch type.");
	return 0;
    }

    if (patch_type != 1) {
	WARN("Incorrect dependency patch type %x.", patch_type);
	return 0;
    }

    if (fread(&dep->dep_id, sizeof(char), 32, file) < 32) {
	WARN("Unable to read depedency build id.");
	return 0;
    }

    if (!ulp->deps) ulp->ndeps = 1;
    else ulp->ndeps++;

    dep->next = ulp->deps;
    ulp->deps = dep;
    return 1;
}

int parse_description(char *filename, struct ulp_metadata *ulp)
{
    struct ulp_unit *unit, *last_unit;
    struct ulp_dependency *dep;
    FILE *file;
    char *first;
    char *second;
    size_t len = 0;
    int i, n;

    /* zero the entire structure before filling */
    memset(ulp, 0, sizeof(struct ulp_metadata));

    file = fopen(filename, "r");
    if (!file) {
	WARN("Unable to open description file.");
	return 0;
    }

    first = NULL;
    second = NULL;
    last_unit = NULL;
    len = 0;

    n = getline(&first, &len, file);
    if (n <= 0) {
	WARN("Unable to parse description.");
	return 0;
    }

    ulp->so_filename = calloc(n, sizeof(char));
    if (!ulp->so_filename) {
	WARN("Unable to allocate memory for patch so filename.");
	return 0;
    }
    strcpy(ulp->so_filename, first);

    if (!ulp->so_filename) {
	WARN("Unable to retrieve so filename from description.");
	return 0;
    }
    if (ulp->so_filename[n-1] == '\n') ulp->so_filename[n-1] = '\0';
    free(first);
    first = NULL;
    len = 0;

    n = getline(&first, &len, file);
    while (n > 0 && first[0] == '*') {
	dep = calloc(1, sizeof(struct ulp_dependency));
	if (!dep) {
	    WARN("Unable to allocate memory for dependency.");
	    return 0;
	}
	if (first[n-1] == '\n') first[n-1] = '\0';
	if(!add_dependency(ulp, dep, &first[1])) {
	    WARN("Unable to add dependency to livepatch metadata.");
	    return 0;
	}

	free(first);
	first = NULL;
	len = 0;
	n = getline(&first, &len, file);
    }

    while (n > 0) {
	/* if this is another object */
	if (first[0] == '@') {
	    if (ulp->objs) {
		WARN("libpulp patches 1 shared object per patch\n");
		return 0;
	    }

	    ulp->objs =  calloc(1, sizeof(struct ulp_object));
	    if (!ulp->objs) {
		WARN("Unable to allocate memory for parsing ulp object.");
		return 0;
	    }
	    if (first[n-1] == '\n') first[n-1] = '\0';
	    ulp->objs->name = strdup(&first[1]);
	    ulp->objs->nunits = 0;
	    last_unit = NULL;
	} else {
	    if (!ulp->objs) {
		WARN("Patch description does not define shared object for patching.");
		return 0;
	    }

	    /* else, this is new function to-be-patched in last found object */
	    if (first[n-1] == '\n') first[n-1] = '\0';

	    /* find old/new function name separator */
	    for (i = 0; i < len; i++) {
		if (first[i] == ':') {
		    first[i] = '\0';
		    second = &first[i+1];
		}
	    }

	    if (!second) {
		WARN("Invalid input description.");
		return 0;
	    }

	    /* allocate and fill patch unit */
	    unit = calloc(1, sizeof(struct ulp_unit));
	    if (!unit) {
		WARN("Unable to allocate memory for parsing ulp units.");
		return 0;
	    }

	    unit->old_fname = strdup(first);
	    if (!unit->old_fname) {
		WARN("Unable to allocate memory for parsing ulp units.");
		return 0;
	    }

	    unit->new_fname = strdup(second);
	    if (!unit->old_fname) {
		WARN("Unable to allocate memory for parsing ulp units.");
		return 0;
	    }

	    if (!last_unit) {
		ulp->objs->units = unit;
	    } else {
		last_unit->next = unit;
	    }
	    ulp->objs->nunits++;
	    last_unit = unit;
	}

	/* get new line */
	free(first);
	first = NULL;
	second = NULL;
	len = 0;
	n = getline(&first, &len, file);
    }
    return 1;
}

int get_build_id(Elf_Scn *s, struct ulp_object *obj) {
    GElf_Nhdr nhdr;
    Elf_Data *d;
    size_t namep, descp;
    int found = 0;
    size_t offset= 0, n;

    d = elf_getdata(s, NULL);
    if (!d) {
	WARN("Unable to find pointer to build id header.");
	return 0;
    }

    for(; (n = gelf_getnote(d, offset, &nhdr, &namep, &descp) > 0); offset = n)
    {
	if (nhdr.n_type == NT_GNU_BUILD_ID) {
	    found = 1;
	    break;
	}
    }

    if (!found) {
	WARN("Unable to note with expected build id type.");
	return 0;
    }

    obj->build_id = calloc(1, sizeof(char) * nhdr.n_descsz);
    if (!obj->build_id) {
	WARN("Unable to allocate memory for build id.");
	return 0;
    }
    memcpy(obj->build_id, d->d_buf + descp, nhdr.n_descsz);
    obj->build_id_len = nhdr.n_descsz;
    return 1;
}

void *get_symbol_addr(Elf *elf, Elf_Scn *s, char *search){
    int nsyms, i;
    char *sym_name;
    Elf_Data *data;
    GElf_Shdr sh;
    GElf_Sym sym;

    gelf_getshdr(s, &sh);

    nsyms = sh.sh_size / sh.sh_entsize;
    data = elf_getdata(s, NULL);
    if (!data) {
	WARN("Unable to get section data.");
	return 0;
    }

    for (i = 0; i < nsyms; i++) {
	gelf_getsym(data, i, &sym);
	sym_name = elf_strptr(elf, sh.sh_link, sym.st_name);
	if(strcmp(sym_name, search) == 0)
	    return (void *) sym.st_value;
    }
    return 0;
}

int generate_random_patch_id(struct ulp_metadata *ulp)
{
    int r;
    r = open("/dev/urandom", 'r');
    if (read(r, &ulp->patch_id, 32) < 0) {
	WARN("Error generating patch id.");
	close(r);
	return 0;
    }
    close(r);
    return 1;
}

int main(int argc, char **argv)
{
    struct ulp_metadata ulp;
    Elf *target_elf = NULL;
    int fd;
    char *filename = NULL;

    memset(&ulp, 0, sizeof(ulp));

    if (argc < 3) {
	usage(argv[0]);
	return 1;
    }

    if (argc > 3) {
	filename = strndup(argv[3], NAME_MAX);
    }

    elf_version(EV_CURRENT);

    if (!parse_description(argv[1], &ulp)) {
	WARN("Unable to parse patch description from %s.", argv[1]);
	goto main_error;
    }

    fd = 0;
    target_elf = load_elf(argv[2], &fd);
    if (!target_elf) goto main_error;
    if (!get_ulp_elf_metadata(target_elf, ulp.objs, &ulp)) goto main_error;
    unload_elf(&target_elf, &fd);

    if (!generate_random_patch_id(&ulp)) goto main_error;
    if (!create_patch_metadata_file(&ulp, filename))
        goto main_error;

    free_metadata(&ulp);
    return 0;

main_error:
    unload_elf(&target_elf, &fd);
    free_metadata(&ulp);
    return 1;
}
