/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2019-2020 SUSE Software Solutions GmbH
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



#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <gelf.h>
#include <libgen.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include "packer.h"

void usage(char *name)
{
    fprintf(stderr, "Usage: %s <ulp metadata file> [output filename]\n",
            name);
}

int write_reverse_patch(struct ulp_metadata *ulp, char *filename)
{
    FILE *file;
    char type = 2;
    struct ulp_object *obj;
    int c;

    if (filename == NULL)
	file = fopen(OUT_REVERSE_NAME, "w");
    else
	file = fopen(filename, "w");
    if (!file) {
	WARN("unable to open output metadata file.");
	return 0;
    };

    /* Patch type -> 2 means revert-patch */
    fwrite(&type, sizeof(uint8_t), 1, file);

    /* Patch id (32b) */
    fwrite(&ulp->patch_id, sizeof(char), 32, file);
    /* patch .so filename */
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

    fclose(file);
    return 1;
}

struct ulp_metadata *parse_metadata(char *filename, struct ulp_metadata *ulp)
{
    FILE *file;
    struct ulp_object *obj;
    uint32_t c;

    file = fopen(filename, "rb");
    if (!file) {
        WARN("Unable to open metadata file: %s.", filename);
        return NULL;
    }

    if (fread(&ulp->type, sizeof(uint8_t), 1, file) < 1) {
        WARN("Unable to read patch type.");
        return NULL;
    }

    if (ulp->type != 1) {
        WARN("Provided file is not a user space live patch\n");
        return NULL;
    }

    if (fread(&ulp->patch_id, sizeof(char), 32, file) < 32) {
        WARN("Unable to read patch id.");
        return NULL;
    }

    if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
	WARN("Unable to read so filename length.");
	return NULL;
    }
    ulp->so_filename = calloc(c + 1, sizeof(char));
    if (!ulp->so_filename) {
	WARN("Unable to allocate so filename buffer.");
	return NULL;
    }
    if (fread(ulp->so_filename, sizeof(char), c, file) < c) {
	WARN("Unable to read so filename first.");
	return NULL;
    }

    obj = calloc(1, sizeof(struct ulp_object));
    if (!obj) {
	WARN("Unable to allocate memory for the patch objects.");
	return NULL;
    }
    obj->units = NULL;

    if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
	WARN("Unable to read build id length (ulp).");
	return NULL;
    }
    obj->build_id_len = c;

    obj->build_id = calloc(c, sizeof(char));
    if (!obj->build_id) {
	WARN("Unable to allocate build id buffer.");
	return NULL;
    }
    if (fread(obj->build_id, sizeof(char), c, file) < c) {
	WARN("Unable to read build id (ulp).");
	return NULL;
    }
    obj->build_id_check = 0;

    if (fread(&c, sizeof(uint32_t), 1, file) < 1) {
	WARN("Unable to read object name length.");
	return NULL;
    }
    ulp->objs = obj;

    /* shared object: fill data + read patching units */
    obj->name = calloc(c + 1, sizeof(char));
    if (!obj->name) {
	WARN("Unable to allocate object name buffer.");
	return NULL;
    }
    if (fread(obj->name, sizeof(char), c, file) < c) {
	WARN("Unable to read object name.");
	return NULL;
    }
    fclose(file);
    return ulp;
}

int main(int argc, char **argv)
{
    struct ulp_metadata ulp;
    char *filename = NULL;

    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (argc > 2) {
        filename = strndup(argv[2], NAME_MAX);
    }

    if (!parse_metadata(argv[1], &ulp)) {
        WARN("Error parsing ulp metadata.\n");
        return 1;
    }

    if (!write_reverse_patch(&ulp, filename)) {
        WARN("Error gerenating reverse live patch.\n");
        return 2;
    }
    return 0;
}
