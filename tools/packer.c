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

#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libgen.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "arguments.h"
#include "config.h"
#include "introspection.h"
#include "md4.h"
#include "packer.h"
#include "ulp_common.h"

void
free_metadata(struct ulp_metadata *ulp)
{
  struct ulp_object *obj;
  struct ulp_unit *unit, *next_unit;
  struct ulp_reference *ref, *next_ref;
  if (!ulp)
    return;

  free(ulp->so_filename);

  for (ref = ulp->refs; ref != NULL; ref = next_ref) {
    free(ref->target_name);
    free(ref->reference_name);
    next_ref = ref->next;
    free(ref);
  }
  ulp->refs = NULL;

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

void
unload_elf(Elf **elf, int *fd)
{
  if (*fd > 0)
    close(*fd);
  if (elf)
    elf_end(*elf);
  *fd = 0;
  *elf = NULL;
}

Elf *
load_elf(const char *obj, int *fd)
{
  Elf *elf;

  *fd = open(obj, O_RDONLY);
  if (*fd == -1) {
    WARN("error opening %s: %s", obj, strerror(errno));
    return NULL;
  }

  elf = elf_begin(*fd, ELF_C_READ, NULL);
  if (!elf) {
    WARN("error invoking elf_begin()");
    close(*fd);
    return NULL;
  }
  return elf;
}

static Elf_Scn *
get_elf_section(Elf *elf, ElfW(Word) sht_type)
{
  size_t i, nsecs;
  Elf_Scn *s;
  GElf_Shdr sh;

  if (elf_getshdrnum(elf, &nsecs)) {
    WARN("error invoking elf_getshdrnum()");
    return NULL;
  }

  for (i = 0; i < nsecs; i++) {
    s = elf_getscn(elf, i);
    if (!s) {
      WARN("error invoking elf_getscn()");
      return NULL;
    }
    gelf_getshdr(s, &sh);

    if (sh.sh_type == sht_type) {
      return s;
    }
  }
  return NULL;
}

Elf_Scn *
get_dynsym(Elf *elf)
{
  return get_elf_section(elf, SHT_DYNSYM);
}

Elf_Scn *
get_symtab(Elf *elf)
{
  return get_elf_section(elf, SHT_SYMTAB);
}

Elf_Scn *
get_build_id_note(Elf *elf)
{
  size_t i, nsecs, shstrndx;
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
      if (strcmp(sec_name, ".note.gnu.build-id") == 0)
        return s;
    }
  }
  return NULL;
}

int
get_ulp_elf_metadata(const char *filename, struct ulp_object *obj)
{
  int fd, ret;
  Elf *elf;
  Elf_Scn *dynsym;
  Elf_Scn *symtab = NULL;

  fd = 0;
  elf = load_elf(filename, &fd);
  if (!elf) {
    WARN("Unable to load elf file: %s", filename);
    return 0;
  }

  dynsym = get_dynsym(elf);
  if (!dynsym) {
    WARN("Unable to get .dynsym section.");
    ret = 0;
    goto clean_elf;
  }

  /* Symtab support should be optional. A linux binary can have it stripped. */
  symtab = get_symtab(elf);

  if (!get_object_metadata(elf, obj)) {
    WARN("Unable to get object metadata.");
    ret = 0;
    goto clean_elf;
  }

  if (!get_elf_tgt_addrs(elf, obj, dynsym, symtab)) {
    WARN("Unable to get target addresses.");
    ret = 0;
    goto clean_elf;
  }

  ret = 1;

clean_elf:
  unload_elf(&elf, &fd);
  return ret;
}

int
get_object_metadata(Elf *elf, struct ulp_object *obj)
{
  Elf_Scn *s;
  s = get_build_id_note(elf);
  if (!s)
    return 0;
  if (!get_build_id(s, obj))
    return 0;
  return 1;
}

int
get_elf_tgt_addrs(Elf *elf, struct ulp_object *obj, Elf_Scn *st1, Elf_Scn *st2)
{
  struct ulp_unit *unit;

  for (unit = obj->units; unit != NULL; unit = unit->next) {
    /* First look at dynsym. This section is always present in binary.  */
    unit->old_faddr = get_symbol_addr(elf, st1, unit->old_fname);
    if (unit->old_faddr == NULL && st2 != NULL) {
      /* In case we couldn't find the symbol there, look in the symtab, if
       * available.  */
      unit->old_faddr = get_symbol_addr(elf, st2, unit->old_fname);
    }
  }
  return 1;
}

int
create_patch_metadata_file(struct ulp_metadata *ulp, const char *filename)
{
  FILE *file;
  struct ulp_unit *unit;
  struct ulp_object *obj;
  struct ulp_dependency *dep;
  struct ulp_reference *ref;
  uint32_t c;
  uint8_t type = 1;

  if (filename == NULL)
    file = stdout;
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
  c = strlen(ulp->so_filename) + 1;
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
    fclose(file);
    return 0;
  }
  c = strlen(obj->name) + 1;
  /* object name length */
  fwrite(&c, sizeof(uint32_t), 1, file);
  /* object name */
  fwrite(obj->name, sizeof(char), c, file);

  /* number of units appended to object */
  fwrite(&obj->nunits, sizeof(uint32_t), 1, file);

  for (unit = obj->units; unit != NULL; unit = unit->next) {
    c = strlen(unit->old_fname) + 1;
    /* to-be-patched function name length */
    fwrite(&c, sizeof(uint32_t), 1, file);
    /* to-be-patched function name */
    fwrite(unit->old_fname, sizeof(char), c, file);

    c = strlen(unit->new_fname) + 1;
    /* patch function name length */
    fwrite(&c, sizeof(uint32_t), 1, file);
    /* patch function name */
    fwrite(unit->new_fname, sizeof(char), c, file);

    /* to-be-patched function addrs */
    fwrite(&unit->old_faddr, sizeof(void *), 1, file);
  }

  fwrite(&ulp->ndeps, sizeof(uint32_t), 1, file);

  for (dep = ulp->deps; dep != NULL; dep = dep->next) {
    fwrite(&dep->dep_id, sizeof(char), 32, file);
  }

  fwrite(&ulp->nrefs, sizeof(uint32_t), 1, file);

  for (ref = ulp->refs; ref != NULL; ref = ref->next) {
    uint32_t len;
    len = strlen(ref->target_name) + 1;
    fwrite(&len, sizeof(len), 1, file);
    fwrite(ref->target_name, sizeof(char), len, file);
    len = strlen(ref->reference_name) + 1;
    fwrite(&len, sizeof(len), 1, file);
    fwrite(ref->reference_name, sizeof(char), len, file);
    fwrite(&ref->target_offset, sizeof(ref->target_offset), 1, file);
    fwrite(&ref->patch_offset, sizeof(ref->patch_offset), 1, file);
    fwrite(&ref->tls, sizeof(ref->tls), 1, file);
    fflush(file);
  }

  fclose(file);
  return 1;
}

int
add_dependency(struct ulp_metadata *ulp, struct ulp_dependency *dep,
               const char *filename)
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

  if (!ulp->deps)
    ulp->ndeps = 1;
  else
    ulp->ndeps++;

  dep->next = ulp->deps;
  ulp->deps = dep;
  return 1;
}

int
parse_description(const char *filename, struct ulp_metadata *ulp)
{
  struct ulp_unit *unit, *last_unit;
  struct ulp_dependency *dep;
  struct ulp_reference *ref;
  FILE *file;
  char *first;
  char *second;
  char *third;
  size_t len = 0;
  int n;

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

  ulp->so_filename = calloc(n + 1, sizeof(char));
  if (!ulp->so_filename) {
    WARN("Unable to allocate memory for patch so filename.");
    return 0;
  }
  strcpy(ulp->so_filename, first);

  if (!ulp->so_filename) {
    WARN("Unable to retrieve so filename from description.");
    return 0;
  }
  if (ulp->so_filename[n - 1] == '\n')
    ulp->so_filename[n - 1] = '\0';
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
    if (first[n - 1] == '\n')
      first[n - 1] = '\0';
    if (!add_dependency(ulp, dep, &first[1])) {
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

      ulp->objs = calloc(1, sizeof(struct ulp_object));
      if (!ulp->objs) {
        WARN("Unable to allocate memory for parsing ulp object.");
        return 0;
      }
      if (first[n - 1] == '\n')
        first[n - 1] = '\0';
      ulp->objs->name = strdup(&first[1]);
      ulp->objs->nunits = 0;
      last_unit = NULL;
    }
    else {
      if (!ulp->objs) {
        WARN("Patch description does not define shared object for patching.");
        return 0;
      }

      /* else, this is new function to-be-patched in last found object */
      if (first[n - 1] == '\n')
        first[n - 1] = '\0';

      /* Lines starting with # are static data references */
      if (first[0] == '#') {

        ref = calloc(1, sizeof(struct ulp_reference));
        if (!ref) {
          WARN("Unable to allocate memory");
          return 0;
        }

        if (first[1] == '%') {
          ref->tls = true;
        }
        else {
          ref->tls = false;
        }

        third = first + 1;
        second = strchr(third, ':');
        *second = '\0';
        ref->target_name = strdup(third);

        third = second + 1;
        second = strchr(third, ':');
        *second = '\0';
        ref->reference_name = strdup(third);

        third = second + 1;
        second = strchr(third, ':');
        *second = '\0';
        ref->target_offset = (intptr_t)strtol(third, NULL, 16);

        third = second + 1;
        ref->patch_offset = (intptr_t)strtol(third, NULL, 16);

        ref->next = ulp->refs;
        ulp->refs = ref;
        ulp->nrefs++;
      }

      /*
       * Lines not starting with # contain the names of replacement and
       * replaced functions.
       */
      else {

        /* find old/new function name separator */
        first = strtok(first, ":");
        second = strtok(NULL, ":");

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
        }
        else {
          last_unit->next = unit;
        }
        ulp->objs->nunits++;
        last_unit = unit;
      }
    }

    /* get new line */
    free(first);
    first = NULL;
    second = NULL;
    len = 0;
    n = getline(&first, &len, file);
  }
  free(first);
  return 1;
}

int
get_build_id(Elf_Scn *s, struct ulp_object *obj)
{
  GElf_Nhdr nhdr;
  Elf_Data *d;
  size_t namep, descp;
  int found = 0;
  size_t offset = 0, n;

  d = elf_getdata(s, NULL);
  if (!d) {
    WARN("Unable to find pointer to build id header.");
    return 0;
  }

  for (; (n = gelf_getnote(d, offset, &nhdr, &namep, &descp) > 0);
       offset = n) {
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

int
parse_build_id(Elf_Scn *s, char **result, int *length)
{
  GElf_Nhdr nhdr;
  Elf_Data *d;
  size_t namep, descp;
  int found = 0;
  size_t offset = 0, n;

  d = elf_getdata(s, NULL);
  if (!d) {
    WARN("Unable to find pointer to build id header.");
    return 1;
  }

  for (; (n = gelf_getnote(d, offset, &nhdr, &namep, &descp) > 0);
       offset = n) {
    if (nhdr.n_type == NT_GNU_BUILD_ID) {
      found = 1;
      break;
    }
  }

  if (!found) {
    WARN("Unable to find note with expected build id type.");
    return 1;
  }

  *result = (d->d_buf + descp);
  *length = nhdr.n_descsz;

  return 0;
}

void *
get_symbol_addr(Elf *elf, Elf_Scn *s, const char *search)
{
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
    if (strcmp(sym_name, search) == 0)
      return (void *)sym.st_value;
  }
  return 0;
}

int
write_patch_id(struct ulp_metadata *ulp, const char *description,
               const char *livepatch)
{
  int half;
  int total;
  int retcode;
  int length;

  char *input;
  FILE *fp;
  uint8_t *digest;

  Elf *elf;
  Elf_Scn *note;
  int fd;
  char *id;

  _Static_assert((sizeof(ulp->patch_id) % 2) == 0,
                 "Patch ID length must be a multiple of two");
  total = sizeof(ulp->patch_id);
  half = total / 2;

  /* Initialize the patch id with zeroes. */
  memset(ulp->patch_id, 0, total);

  /* Find the build ID of LIVEPATCH. */
  elf = load_elf(livepatch, &fd);
  if (elf == NULL) {
    WARN("error opening %s with libelf", livepatch);
    return 1;
  }
  note = get_build_id_note(elf);
  if (note == NULL) {
    WARN("error finding the build id section of %s", livepatch);
    return 1;
  }
  retcode = parse_build_id(note, &id, &length);
  if (retcode) {
    WARN("error parsing the build id for %s", livepatch);
    return 1;
  }

  /* Write the build id as the first half of the patch id. */
  if (length > half)
    length = half;
  memcpy(ulp->patch_id, id, length);

  unload_elf(&elf, &fd);

  /* Read the whole DESCRIPTION File into memory to use as digest input. */
  fp = fopen(description, "r");
  if (fp == NULL) {
    WARN("error opening %s: %s", description, strerror(errno));
    return 1;
  }
  retcode = fseek(fp, 0, SEEK_END);
  if (retcode == -1) {
    WARN("error seeking %s: %s", description, strerror(errno));
    return 1;
  }
  length = ftell(fp);
  if (length == -1) {
    WARN("error checking length of %s: %s", description, strerror(errno));
    return 1;
  }
  rewind(fp);
  input = malloc(length);
  if (input == NULL) {
    WARN("unable to allocate memory: %s", strerror(errno));
    return 1;
  }
  retcode = fread(input, 1, length, fp);
  if (retcode != length) {
    WARN("error reading description file to memory: %s", strerror(errno));
    return 1;
  }

  /* Generate a digest out of the description file. */
  digest = MD4(input, length);
  if (digest == NULL) {
    WARN("error generating message digest from description file");
    return 1;
  }

  /* Write the digest as the second half of the patch id. */
  if (MD4_LENGTH > half)
    length = half;
  else
    length = MD4_LENGTH;
  memcpy(ulp->patch_id + half, digest, length);
  free(input);
  free(digest);

  return 0;
}

int
run_packer(struct arguments *arguments)
{
  struct ulp_metadata ulp;
  const char *description = arguments->args[0];

  /* Set the verbosity level in the common introspection infrastructure. */
  ulp_verbose = arguments->verbose;
  ulp_quiet = arguments->quiet;

  memset(&ulp, 0, sizeof(ulp));

  elf_version(EV_CURRENT);

  DEBUG("parsing the description file (%s).", description);
  if (!parse_description(description, &ulp)) {
    WARN("unable to parse description file (%s).", description);
    goto main_error;
  }

  /* Select source of the target library filename. */
  if (arguments->library == NULL) {
    arguments->library = ulp.objs->name;
    DEBUG("path to target library taken from the description file.");
  }
  else {
    DEBUG("path to target library taken from the command-line.");
  }
  DEBUG("target library: %s.", arguments->library);

  if (!get_ulp_elf_metadata(arguments->library, ulp.objs)) {
    WARN("unable to parse target library.");
    goto main_error;
  }

  if (arguments->livepatch == NULL) {
    arguments->livepatch = ulp.so_filename;
    DEBUG("path to live patch taken from the description file.");
  }
  else {
    DEBUG("path to live patch taken from the command-line.");
  }
  DEBUG("live patch: %s.", arguments->livepatch);

  if (write_patch_id(&ulp, description, arguments->livepatch)) {
    WARN("unable to generate live patch ID.");
    goto main_error;
  }

  if (!create_patch_metadata_file(&ulp, arguments->metadata))
    goto main_error;

  free_metadata(&ulp);
  WARN("metadata file generated successfully.");
  return 0;

main_error:
  free_metadata(&ulp);
  WARN("metadata file generation failed.");
  return 1;
}
