/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2019-2021 SUSE Software Solutions GmbH
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

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arguments.h"
#include "elf-extra.h"
#include "error_common.h"
#include "introspection.h"
#include "packer.h"
#include "revert.h"

static int
write_reverse_patch(struct ulp_metadata *ulp, const char *filename)
{
  FILE *file;
  char type = 2;
  struct ulp_object *obj;
  int c;
#if 0
  if (filename == NULL)
    file = fopen(OUT_REVERSE_NAME, "w");
  else
    file = fopen(filename, "w");
  if (!file) {
    WARN("unable to open output metadata file.");
    return 0;
  };
#endif

  const char *tmp_path = create_path_to_tmp_file();
  file = fopen(tmp_path, "w");

  if (!file) {
    WARN("unable to open output metadata temp file to %s: %s.", tmp_path,
         strerror(errno));
    return 0;
  };

  /* Patch type -> 2 means revert-patch */
  fwrite(&type, sizeof(uint8_t), 1, file);

  /* Patch id (32b) */
  fwrite(&ulp->patch_id, sizeof(char), 32, file);

  /* Don't write these informations yet.  This will be written when extracting
     the metadata from the livepatch container.  But keep the code here so that
     someone reading this code knows that more information will be added into
     the metadata file.  */
#if 0
  /* patch .so filename */
  c = strlen(ulp->so_filename) + 1;
  /* patch .so filename length */
  fwrite(&c, sizeof(uint32_t), 1, file);
  /* patch .so filename */
  fwrite(ulp->so_filename, sizeof(char), c, file);
#endif

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
  if (embed_patch_metadata_into_elf(NULL, filename, tmp_path, ".ulp.rev")) {
    WARN("Unable to embed patch metadata into %s", filename);
    remove(tmp_path);
    return 0;
  }

  remove(tmp_path);
  return 1;
}

static struct ulp_metadata *
parse_metadata(const char *filename, struct ulp_metadata *ulp)
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

int
run_reverse(struct arguments *arguments)
{
  struct ulp_metadata ulp = { 0 };
  const char *container = arguments->args[0];
  char *tmp_metadata;

  tmp_metadata = extract_ulp_from_so_to_disk(container, false);
  if (!tmp_metadata) {
    WARN("Unable to extract .ulp section from %s: %s", container,
         strerror(errno));
    return 1;
  }

  if (!parse_metadata(tmp_metadata, &ulp)) {
    WARN("Error parsing ulp metadata.\n");
    return 1;
  }

  if (!write_reverse_patch(&ulp, container)) {
    WARN("Error gerenating reverse live patch.\n");
    remove(tmp_metadata);
    free(tmp_metadata);
    return 2;
  }
  free_metadata(&ulp);
  remove(tmp_metadata);
  free(tmp_metadata);
  return 0;
}
