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

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <gelf.h>
#include <libgen.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "arguments.h"
#include "config.h"
#include "elf-extra.h"
#include "introspection.h"
#include "md4.h"
#include "packer.h"
#include "terminal_colors.h"
#include "ulp_common.h"

static int get_elf_tgt_ref_addrs(Elf *, struct ulp_reference *, Elf_Scn *,
                                 Elf_Scn *);

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
  return get_elfscn_by_name(elf, ".note.gnu.build-id");
}

int
get_ulp_elf_metadata(const char *filename, struct ulp_metadata *ulp)
{
  int fd, ret;
  Elf *elf;
  Elf_Scn *dynsym;
  Elf_Scn *symtab = NULL;
  struct ulp_object *obj = ulp->objs;
  struct ulp_reference *ref = ulp->refs;

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

  if (!get_elf_tgt_ref_addrs(elf, ref, dynsym, symtab)) {
    WARN("Unable to get target reference addresses.");
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

/** @brief Get offsets of symbols in target library
 *
 * This function gather the address of all to-be-patched functions in the
 * target library.
 *
 * @param elf     The target library elf object.
 * @param obj     Chain of objects.
 * @param st1     Symbol table 1, usually .dymsym.
 * @param st2     Symbol table 2, usually .symtab if present.
 *
 * @return 1
 */
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

/** @brief Get offsets of references to symbol in target library
 *
 * When the user doesn't specify the offset of the target symbol in the target
 * library when using the # syntax, try to find it by looking into the target
 * library symbols.
 *
 * @param elf     The target library elf object.
 * @param ref     Chain of references.
 * @param st1     Symbol table 1, usually .dymsym.
 * @param st2     Symbol table 2, usually .symtab if present.
 *
 * @return 1
 */
static int
get_elf_tgt_ref_addrs(Elf *elf, struct ulp_reference *ref, Elf_Scn *st1,
                      Elf_Scn *st2)
{

  while (ref != NULL) {
    if (ref->target_offset == 0) {
      ref->target_offset =
          (uintptr_t)get_symbol_addr(elf, st1, ref->target_name);
      if (ref->target_offset == 0 && st2 != NULL) {
        /* In case we couldn't find the symbol there, look in the symtab, if
         * available.  */
        ref->target_offset =
            (uintptr_t)get_symbol_addr(elf, st2, ref->target_name);
      }
    }
    ref = ref->next;
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
    WARN("unable to open output metadata file: %s", strerror(errno));
    return 0;
  };

  /* Patch type -> 1 means patch, 2 means revert-patch */
  fwrite(&type, sizeof(uint8_t), 1, file);

  /* Patch id (first 32b) */
  fwrite(ulp->patch_id, sizeof(char), 32, file);

  /* Don't write these informations yet.  This will be written when extracting
     the metadata from the livepatch container.  But keep the code here so that
     someone reading this code knows that more information will be added into
     the metadata file.  */
#if 0
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

/** Struct to denote a location in the file.  Used for better error messages.
 */
typedef struct
{
  unsigned line;
  unsigned col;
} location_t;

static const char *parse_filename;
static location_t loc;

/** @brief Print a beautiful error message to the user
 *
 * This function tries to print error messages in the .dsc file as beautiful as
 * GCC 5.0+ does.
 *
 * @param loc      Location of the problem.
 * @param fmt      Reason of error.
 **/

static void
parse_error(location_t loc, const char *fmt, ...)
{
  va_list arglist;
  unsigned i, j;
  FILE *parse_file;

  char *line = NULL;
  size_t line_size;
  size_t len;

  change_color(TERM_COLOR_BOLD);
  printf("%s:%d:%d: ", parse_filename, loc.line, loc.col);
  change_color(TERM_COLOR_RED);
  printf("error: ");
  change_color(TERM_COLOR_RESET);

  va_start(arglist, fmt);
  vprintf(fmt, arglist);
  va_end(arglist);
  putchar('\n');
  parse_file = fopen(parse_filename, "r");
  if (!parse_file) {
    printf("ERROR WHILE PRINTING ERROR MESSAGE: %s\n", strerror(errno));
    return;
  }

  assert(loc.line > 0 && loc.col > 0);

  for (i = 0; i < loc.line; i++) {
    len = getline(&line, &line_size, parse_file);
  }

  if (i > 0) {
    for (j = 0; j < (loc.col - 1) && j < len; j++) {
      putchar(line[j]);
    }

    unsigned redchars = 0;
    change_color(TERM_COLOR_RED);
    for (; j < len; j++) {
      if (line[j] == ':') {
        if (line[loc.col - 1] == ':') {
          putchar(line[j]);
          redchars++;
          j++;
        }
        break;
      }
      else if (line[j] != '\n') {
        putchar(line[j]);
        redchars++;
      }
    }
    change_color(TERM_COLOR_RESET);

    for (; j < len; j++) {
      if (line[j] != '\n')
        putchar(line[j]);
    }

    putchar('\n');

    for (j = 0; j < (loc.col - 1) && j < len; j++) {
      putchar(' ');
    }

    change_color(TERM_COLOR_RED);
    putchar('^');
    for (j = 1; j < redchars; j++) {
      putchar('~');
    }
    change_color(TERM_COLOR_RESET);
  }

  free(line);
  putchar('\n');
  fclose(parse_file);
}

static void
segfault_handler(int signum)
{
  if (signum != SIGSEGV) {
    return;
  }

  parse_error(loc, "internal error parsing %s: received SIGSEGV",
              parse_filename);
  exit(1);
}

/** Struct containing informations about a shared-link library (.so). */
struct shared_object
{
  /** The path to the .so.  */
  const char *path;

  /** Elf object in memory.  */
  Elf *elf;

  /** Opened file descriptor.  */
  int fd;

  /** Dynsym object.  */
  Elf_Scn *dynsym;

  /** Symtab object.  */
  Elf_Scn *symtab;
};

/** @brief Checks if symbol `sym` exists in shared object `so`
 *
 * @param so   The shared object.
 * @param sym  Symbol to query
 *
 * @return true if exists, false if not.
 **/
static bool
symbol_exists(struct shared_object *so, const char *sym)
{
  if (!get_symbol_addr(so->elf, so->dynsym, sym)) {
    if (so->symtab) {
      if (!get_symbol_addr(so->elf, so->symtab, sym)) {
        return 0;
      }
    }
    else {
      return 0;
    }
  }

  return true;
}

/** @brief Parse description .dsc file.
 *
 * This function parses the livepatch description files in dsc format, as
 * specified by the programmer, and construct the ulp object.
 *
 * @param filename           Path to .dsc file.
 * @param ulp                Pointer to ulp object
 * @param container_override Use the following container file instead of the
 * one provided in the .dsc file
 * @param target_override    Use the following target file instead of the one
 *                           provided in .dsc file.
 *
 */

static int
parse_description(const char *filename, struct ulp_metadata *ulp,
                  const char *container_override, const char *target_override)
{
  struct ulp_unit *unit, *last_unit;
  struct ulp_dependency *dep;
  struct ulp_reference *ref;
  char *first = NULL;
  char *second = NULL;
  char *third = NULL;
  FILE *parse_file;
  size_t len = 0;
  int n, ret;

  struct shared_object container, target;

  memset(&container, 0, sizeof(container));
  memset(&target, 0, sizeof(target));

  loc.line = 0;
  loc.col = 0;
  parse_filename = filename;

  /* Install a SIGSEGV handler in case this parser crashes, so the user at
     least get some kind of error message.  */
  signal(SIGSEGV, segfault_handler);

  /* zero the entire structure before filling */
  memset(ulp, 0, sizeof(struct ulp_metadata));

  parse_file = fopen(filename, "r");
  if (!parse_file) {
    WARN("Unable to open description file.");
    ret = 0;
    goto dsc_clean;
  }

  first = NULL;
  second = NULL;
  last_unit = NULL;
  len = 0;

  n = getline(&first, &len, parse_file);
  loc.line++;
  loc.col = 1;
  if (n <= 0) {
    WARN("Unable to parse description file: is empty");
    ret = 0;
    goto dsc_clean;
  }

  if (container_override) {
    ulp->so_filename = strdup(container_override);
  }
  else {
    ulp->so_filename = calloc(n + 1, sizeof(char));
    if (!ulp->so_filename) {
      parse_error(loc, "unable to allocate memory for patch so filename");
      ret = 0;
      goto dsc_clean;
    }
    strcpy(ulp->so_filename, first);

    if (!ulp->so_filename) {
      parse_error(loc, "unable to retrieve so filename from description");
      ret = 0;
      goto dsc_clean;
    }
    if (ulp->so_filename[n - 1] == '\n')
      ulp->so_filename[n - 1] = '\0';
  }

  FILE *file_check = fopen(ulp->so_filename, "r");
  if (!file_check) {
    parse_error(loc, "livepatch container file not found");
    ret = 0;
    goto dsc_clean;
  }
  fclose(file_check);

  free(first);
  first = NULL;
  len = 0;

  container.path = ulp->so_filename;
  container.elf = load_elf(container.path, &container.fd);
  container.dynsym = get_dynsym(container.elf);
  container.symtab = get_symtab(container.elf);

  n = getline(&first, &len, parse_file);
  loc.line++;
  loc.col = 1;
  while (n > 0 && first[0] == '*') {
    dep = calloc(1, sizeof(struct ulp_dependency));
    if (!dep) {
      parse_error(loc, "unable to allocate memory for dependency.");
      ret = 0;
      goto dsc_clean;
    }
    if (first[n - 1] == '\n')
      first[n - 1] = '\0';
    if (!add_dependency(ulp, dep, &first[1])) {
      parse_error(loc, "unable to add dependency to livepatch metadata.");
      ret = 0;
      goto dsc_clean;
    }

    free(first);
    first = NULL;
    len = 0;
    n = getline(&first, &len, parse_file);
    loc.line++;
    loc.col = 1;
  }

  while (n > 0) {
    /* if this is another object */
    if (first[0] == '@') {
      if (ulp->objs) {
        parse_error(loc, "duplicated target object. Libpulp patches 1 shared "
                         "object per patch\n");
        ret = 0;
        goto dsc_clean;
      }

      ulp->objs = calloc(1, sizeof(struct ulp_object));
      if (!ulp->objs) {
        parse_error(loc, "unable to allocate memory for parsing ulp object.");
        ret = 0;
        goto dsc_clean;
      }
      if (first[n - 1] == '\n')
        first[n - 1] = '\0';

      if (target_override)
        ulp->objs->name = strdup(target_override);
      else
        ulp->objs->name = strdup(&first[1]);
      ulp->objs->nunits = 0;
      last_unit = NULL;

      target.path = ulp->objs->name;
      target.elf = load_elf(target.path, &target.fd);
      target.dynsym = get_dynsym(target.elf);
      target.symtab = get_symtab(target.elf);
    }
    else {
      if (!ulp->objs) {
        parse_error(
            loc,
            "patch description does not define shared object for patching.");
        ret = 0;
        goto dsc_clean;
      }

      /* else, this is new function to-be-patched in last found object */
      if (first[n - 1] == '\n')
        first[n - 1] = '\0';

      /* Lines starting with # are static data references */
      if (first[0] == '#') {
        loc.col = 2;
        ref = calloc(1, sizeof(struct ulp_reference));
        if (!ref) {
          parse_error(loc, "unable to allocate memory");
          ret = 0;
          goto dsc_clean;
        }

        if (first[1] == '%') {
          ref->tls = true;
          loc.col++;
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

        /* Check if the user manually specified the offsets.  */
        if (second == NULL) {
          ref->reference_name = strdup(third);

          if (!symbol_exists(&target, ref->target_name)) {
            parse_error(loc, "symbol %s is not present in %s",
                        ref->target_name, target.path);
            ret = 0;
            goto dsc_clean;
          }

          loc.col += strlen(ref->target_name) + 1;

          if (!symbol_exists(&container, ref->reference_name)) {
            parse_error(loc, "symbol %s is not present in %s",
                        ref->reference_name, container.path);
            ret = 0;
            goto dsc_clean;
          }
        }
        else {
          *second = '\0';
          ref->reference_name = strdup(third);

          third = second + 1;

          second = strchr(third, ':');
          *second = '\0';
          ref->target_offset = (intptr_t)strtol(third, NULL, 16);

          third = second + 1;
          ref->patch_offset = (intptr_t)strtol(third, NULL, 16);
        }

        ref->next = ulp->refs;
        ulp->refs = ref;
        ulp->nrefs++;
      }

      /*
       * Lines not starting with # contain the names of replacement and
       * replaced functions.
       */
      else {

        if (first[strlen(first) - 1] == ':') {
          loc.col = strlen(first);
          parse_error(loc, "expected target variable or offset");
          ret = 0;
          goto dsc_clean;
        }

        /* find old/new function name separator */
        first = strtok(first, ":");
        second = strtok(NULL, ":");

        if (!symbol_exists(&target, first)) {
          parse_error(loc, "symbol %s is not present in %s", first,
                      target.path);
          ret = 0;
          goto dsc_clean;
        }

        if (!second) {
          parse_error(loc, "expected ':' token and target variable or offset");
          ret = 0;
          goto dsc_clean;
        }

        loc.col = (ssize_t)(second - first) + 1;
        if (*second == '\0') {
          parse_error(loc, "expected target variable or offset");
          ret = 0;
          goto dsc_clean;
        }

        if (!symbol_exists(&container, second)) {
          parse_error(loc, "symbol %s is not present in %s", second,
                      container.path);
          ret = 0;
          goto dsc_clean;
        }

        /* allocate and fill patch unit */
        unit = calloc(1, sizeof(struct ulp_unit));
        if (!unit) {
          parse_error(loc, "unable to allocate memory for parsing ulp units.");
          ret = 0;
          goto dsc_clean;
        }

        unit->old_fname = strdup(first);
        if (!unit->old_fname) {
          parse_error(loc, "unable to allocate memory for parsing ulp units.");
          ret = 0;
          goto dsc_clean;
        }

        unit->new_fname = strdup(second);
        if (!unit->old_fname) {
          parse_error(loc, "unable to allocate memory for parsing ulp units.");
          ret = 0;
          goto dsc_clean;
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
    n = getline(&first, &len, parse_file);
    loc.line++;
    loc.col = 1;
  }
  ret = 1;
dsc_clean:
  fclose(parse_file);
  parse_file = NULL;
  if (first)
    free(first);
  signal(SIGSEGV, SIG_DFL);
  if (container.elf)
    unload_elf(&container.elf, &container.fd);
  if (target.elf)
    unload_elf(&target.elf, &target.fd);
  return ret;
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

int
run_packer(struct arguments *arguments)
{
  struct ulp_metadata ulp;
  const char *description = arguments->args[0];
  int ret = 0;

  /* Set the verbosity level in the common introspection infrastructure. */
  ulp_verbose = arguments->verbose;
  ulp_quiet = arguments->quiet;

  memset(&ulp, 0, sizeof(ulp));

  elf_version(EV_CURRENT);

  DEBUG("parsing the description file (%s).", description);
  if (!parse_description(description, &ulp, arguments->livepatch,
                         arguments->library)) {
    ret = 1;
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

  if (!get_ulp_elf_metadata(arguments->library, &ulp)) {
    WARN("unable to parse target library.");
    ret = 1;
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
    ret = 1;
    goto main_error;
  }

  const char *tmp_path = create_path_to_tmp_file();

  if (!create_patch_metadata_file(&ulp, tmp_path)) {
    ret = 1;
    goto main_error;
  }

  if (embed_patch_metadata_into_elf(NULL, arguments->livepatch, tmp_path,
                                    ".ulp")) {
    ret = 1;
    goto tmpfile_clean;
  }

  remove(tmp_path);

  if (!write_reverse_patch(&ulp, arguments->livepatch)) {
    WARN("Error gerenating reverse live patch.\n");
    ret = 1;
    goto tmpfile_clean;
  }

tmpfile_clean:
  remove(tmp_path);

main_error:
  free_metadata(&ulp);
  if (ret == 0) {
    WARN("metadata successfully embedded into livepatch container");
  }
  else {
    WARN("metadata file generation failed.");
  }
  return ret;
}
