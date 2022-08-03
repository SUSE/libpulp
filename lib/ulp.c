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

#define _GNU_SOURCE
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "config.h"
#include "error.h"
#include "interpose.h"
#include "msg_queue.h"
#include "ulp.h"

/* ulp data structures */
struct ulp_patching_state __ulp_state = { 0, NULL };
char __ulp_metadata_buffer[ULP_METADATA_BUF_LEN] = { 0 };
struct ulp_metadata *__ulp_metadata_ref = NULL;
struct ulp_detour_root *__ulp_root = NULL;

/* clang-format off */

/** Intel endbr64 instruction optcode.  */
static const uint8_t insn_endbr64[] = {INSN_ENDBR64};

/** Offset of the data entry in the ulp_prologue.  */
#define ULP_DATA_OFFSET 6           // ------------------------------+
                                    //                               |
char ulp_prologue[ULP_NOPS_LEN] = { //                               |
  // Preceding nops                                                  |
  0xff, 0x25, 0, 0, 0, 0,           // jmp     0x0(%rip) <-------+   |
  0, 0, 0, 0, 0, 0, 0, 0,           // <data>  &__ulp_prolog     | <-+
  // Function entry is here                                      |
  0xeb, -(PRE_NOPS_LEN + 2)         // jmp ----------------------+
  // (+2 because the previous jump consumes 2 bytes.
};

/** Offset of the data entry in the ulp_prologue.  */
char ulp_prologue_endbr64[ULP_NOPS_LEN_ENDBR64] = {
  // Preceding nops
  0xff, 0x25, 0, 0, 0, 0,           // jmp     0x0(%rip) <-------+
  0, 0, 0, 0, 0, 0, 0, 0,           // <data>  &__ulp_prolog     |
  // Function entry is here                                      |
  INSN_ENDBR64,                     // endbr64                   |
  0xeb, -(PRE_NOPS_LEN + 2 + 4)     // jmp ----------------------+
  // (+2 because the previous jump consumes 2 bytes.
};
/* clang-format on */

unsigned int __ulp_root_index_counter = 0;
unsigned long __ulp_global_universe = 0;

extern void __ulp_prologue();

__attribute__((constructor)) void
begin(void)
{
  __ulp_state.load_state = 1;
  msgq_push("libpulp loaded...\n");
}

/** @brief Revert all live patches associated with library `lib_name`
 *
 * The user may have applied a series of live patches on a library named
 * `lib_name` in the program. This function will revert every patch so
 * that all functions are reverted into their original state.
 *
 * @param lib_name Base name of the library.
 * @return 0 on success, anything else on failure.
 */
static int
revert_all_patches_from_lib(const char *lib_name)
{
  struct ulp_applied_patch *patch = __ulp_state.patches;
  struct ulp_applied_patch *next;

  const char *lib_basename = get_basename(lib_name);

  int ret = 0;

  /* Paranoid: check if the path buffer didn't overflow.  */
  if ((ptrdiff_t)(lib_basename - lib_name) >= ULP_PATH_LEN) {
    WARN("Path buffer overflow, aborting revert...");
    return EOVERFLOW;
  }

  while (patch) {
    next = patch->next;
    if (!strncmp(lib_basename, patch->lib_name, ULP_PATH_LEN)) {
      ret = ulp_can_revert_patch(patch->patch_id);
      if (ret) {
        break;
      }

      ret = ulp_revert_patch(patch->patch_id);
    }

    patch = next;
  }

  return ret;
}

/** @brief Entry point for libulp -- remove all patches associated with lib.
 *
 * This function is called from ulp_interface.S `__ulp_revert_all` assembly
 * routine that is called from the `trigger` ulp tool, which have set the
 * library name parameter in the path buffer.
 *
 * @return 0 on success, anything else on failure.
 */
int
__ulp_revert_patches_from_lib()
{
  int result;

  /*
   * If the target process is busy within functions from the malloc or
   * dlopen implementations, applying a live patch could lead to a
   * deadlock, thus give up.
   */
  if (__ulp_asunsafe_trylock())
    return EAGAIN;
  __ulp_asunsafe_unlock();

  /* Otherwise, try to apply the live patch. */
  result = revert_all_patches_from_lib(__ulp_metadata_buffer);

  /*
   * Live patching could fail for a couple of different reasons, thus
   * check the result and return either zero for success or one for
   * failures (except for EAGAIN above).
   */
  return result;
}

/* libpulp interfaces for livepatch trigger */
int
__ulp_apply_patch()
{
  int result;

  /* If libpulp is in an error state, we cannot continue.  */
  if (libpulp_is_in_error_state())
    return get_libpulp_error_state();

  /*
   * If the target process is busy within functions from the malloc or
   * dlopen implementations, applying a live patch could lead to a
   * deadlock, thus give up.
   */
  if (__ulp_asunsafe_trylock())
    return EAGAIN;
  __ulp_asunsafe_unlock();

  /* Otherwise, try to apply the live patch. */
  result = load_patch();

  /*
   * Live patching could fail for a couple of different reasons, thus
   * check the result and return either zero for success or whatever
   * error happened internally.
   */
  return result;
}

void
__ulp_print()
{
  fprintf(stderr, "ULP DEBUG PRINT MSG\n");
}

int
__ulp_check_applied_patch()
{
  struct ulp_applied_patch *patch;

  /* If libpulp is in an error state, we cannot continue.  */
  if (libpulp_is_in_error_state())
    return 0;

  patch = ulp_get_applied_patch((unsigned char *)__ulp_metadata_buffer);
  if (patch)
    return 1;
  else
    return 0;
}

unsigned long
__ulp_get_global_universe_value()
{
  return __ulp_global_universe;
}

/* TODO: unloading needs further testing */
int
unload_handlers(struct ulp_metadata *ulp)
{
  int status = 1;
  if (ulp->so_handler && dlclose(ulp->so_handler)) {
    WARN("Error unloading patch so handler: %s", ulp->so_filename);
    status = 0;
  }
  return status;
}

void *
load_so_symbol(char *fname, void *handle)
{
  void *func;
  char *error;

  func = dlsym(handle, fname);
  error = dlerror();
  if (error) {
    WARN("Unable to load function %s: %s.", fname, error);
    return NULL;
  }

  return func;
}

int
load_so_handlers(struct ulp_metadata *ulp)
{
  ulp->so_handler = load_so(ulp->so_filename);

  if (!ulp->so_handler) {
    WARN("Unable to load patch dl handler.");
    unload_handlers(ulp);
    return 0;
  }

  return 1;
}

int
unload_metadata(struct ulp_metadata *ulp)
{
  free_metadata(ulp);
  __ulp_metadata_ref = NULL;
  return 0;
}

struct ulp_metadata *
load_metadata(int *err)
{
  struct ulp_metadata *ulp;
  if (__ulp_metadata_ref) {
    *err = 0;
    return __ulp_metadata_ref;
  }

  ulp = calloc(1, sizeof(struct ulp_metadata));
  if (!ulp) {
    WARN("Unable to allocate memory for ulp metadata");
    *err = errno;
    return NULL;
  }

  __ulp_metadata_ref = ulp;
  *err = parse_metadata(ulp);
  if (*err) {
    unload_metadata(ulp);
    WARN("Error in metadata load: %s.", libpulp_strerror(*err));
    return NULL;
  };

  *err = 0;
  return ulp;
}

int
read_data(int from, void *to, size_t count, int line)
{
  size_t done;
  ssize_t ret;

  for (done = 0;;) {
    errno = 0;
    ret = read(from, to + done, count - done);
    if (ret == 0)
      break; /* EOF or read called with count set to zero. */
    else if (ret > 0) {
      done += ret;
      if (done == count)
        break; /* Done. */
      else
        continue; /* More to read. */
    }
    else if (errno == EINTR || errno == EAGAIN) {
      continue; /* Try again. */
    }
    else {
      WARN("Error in call to read()");
      return 1;
    }
  }
  if (done != count) {
    WARN("line %d: Not enough data to read()", line);
    return 1;
  }

  return 0;
}

/*
 * Read one line from FD into BUF, which must be pre-allocated and large
 * enough to hold LEN characteres. The offset into FD is advanced by the
 * amount of bytes read.
 *
 * Returns -1 on error, 0 on End-of-file, or the amount of bytes read.
 */
int
read_line(int fd, char *buf, size_t len)
{
  char *ptr;
  int retcode;
  size_t offset;

  /* Read one byte at a time, until a newline is found. */
  offset = 0;
  while (offset < len) {
    ptr = buf + offset;

    /* Read one byte. */
    retcode = read(fd, ptr, 1);

    /* Error with read syscall. */
    if (retcode == -1) {
      if (errno == EINTR || errno == EAGAIN)
        continue;
      else
        return -1;
    }

    /* Stop at EOF or EOL. */
    if (retcode == 0 || *ptr == '\n') {
      return offset;
    }

    offset++; /* Reading one byte at a time. */
  }

  /* EOL not found. */
  return -1;
}

void *
load_so(char *obj)
{
  void *patch_obj;

  patch_obj = dlopen(obj, RTLD_LAZY);
  if (!patch_obj) {
    WARN("Unable to load shared object %s: %s.", obj, dlerror());
    return NULL;
  }

  return patch_obj;
}

/** @brief Parse metadata file in __ulp_metadata_buffer.
 *
 * When trigger command is issued, the metadata is written in
 * __ulp_metadata_buffer. Parse this metadata.
 *
 * @param ulp  The metadata output object
 * @return 0   0 if success, anything else if failure.
 */
int
parse_metadata(struct ulp_metadata *ulp)
{
  /* Initialize pointer and counter to keep track of metadata buffer parsing.
   */
  void *src = __ulp_metadata_buffer;
  size_t meta_size = ULP_METADATA_BUF_LEN;
  int ret;

  ret = parse_metadata_from_mem(ulp, src, meta_size);

  if (ret != ENONE || ulp->type == 2)
    goto metadata_clean;

  ret = check_patch_sanity(ulp);
  if (ret)
    goto metadata_clean;

  if (!load_so_handlers(ulp)) {
    ret = errno;
    goto metadata_clean;
  }

metadata_clean:
  memset(src, 0, ULP_METADATA_BUF_LEN);
  return ret;
}

int
load_patch()
{
  struct ulp_metadata *ulp = NULL;
  struct ulp_applied_patch *patch_entry;
  int patch;
  int ret = 0;

  ulp = load_metadata(&ret);
  if (ulp == NULL)
    return ret;

  patch = ulp->type;

  switch (patch) {
    case 1: /* apply patch */
      patch_entry = ulp_state_update(ulp);
      if (!patch_entry) {
        ret = ESTATE;
        break;
      }

      ret = ulp_apply_all_units(ulp);
      if (ret) {
        WARN("FATAL ERROR while applying patch units\n");
        libpulp_exit(ret);
      }

      goto load_patch_success;

    case 2: /* revert patch */
      ret = ulp_can_revert_patch(ulp->patch_id);
      if (ret) {
        break;
      }

      ret = ulp_revert_patch(ulp->patch_id);
      if (ret) {
        WARN("Unable to revert patch.");
        break;
      }

      goto load_patch_success;

    default: /* load patch metadata error */
      if (!patch) {
        WARN("load patch metadata error");
        ret = ENOMETA;
      }
      else {
        WARN("Unknown load metadata status");
        ret = EUNKNOWN;
      }
  }

load_patch_success:
  unload_metadata(ulp);
  return ret;
}

int
ulp_can_revert_patch(const unsigned char *id)
{
  int i;
  struct ulp_applied_patch *patch, *applied_patch;
  struct ulp_dependency *dep;

  /* check if patch exists */
  applied_patch = ulp_get_applied_patch(id);
  if (!applied_patch) {
    WARN("Can't revert because patch was not applied");
    return ENOTAPPLIED;
  }

  /* check if someone depends on the patch */
  for (patch = __ulp_state.patches; patch != NULL; patch = patch->next) {
    for (dep = patch->deps; dep != NULL; dep = dep->next) {
      if (memcmp(dep->dep_id, id, 32) == 0) {
        msgq_push("Can't revert. Dependency:\n   PATCH 0x");
        for (i = 0; i < 32; i++) {
          msgq_push("%x ", id[i]);
        }
        msgq_push("\n");
        return EDEPEND;
      }
    }
  }

  return 0;
}

struct ulp_detour_root *
get_detour_root_by_index(unsigned int idx)
{
  struct ulp_detour_root *r;
  r = __ulp_root;

  if (r == NULL)
    return NULL;
  for (r = __ulp_root; r != NULL && r->index != idx; r = r->next) {
  };

  return r;
}

struct ulp_detour_root *
get_detour_root_by_address(void *addr)
{
  struct ulp_detour_root *r;
  r = __ulp_root;

  if (r == NULL)
    return NULL;
  for (r = __ulp_root; r != NULL && r->patched_addr != addr; r = r->next) {
  };

  return r;
}

struct ulp_detour_root *
push_new_root()
{
  struct ulp_detour_root *root, *root_aux;

  root = calloc(1, sizeof(struct ulp_detour_root));
  if (!root) {
    WARN("unable to allocate memory for ulp detour root");
    return NULL;
  }

  // since above we use calloc, the if/else below shouldn't be needed
  if (!__ulp_root)
    root_aux = NULL;
  else
    root_aux = __ulp_root;
  __ulp_root = root;
  root->next = root_aux;

  return root;
}

int
ulp_apply_all_units(struct ulp_metadata *ulp)
{
  int retcode;
  void *old_fun, *new_fun;
  void *patch_so = ulp->so_handler;
  struct ulp_object *obj = ulp->objs;
  struct ulp_unit *unit;
  struct ulp_detour_root *root;
  struct ulp_reference *ref;

  __ulp_global_universe++;

  /* only shared objs have units, this loop never runs for main obj */
  unit = obj->units;
  while (unit) {
    old_fun = get_loaded_symbol_addr(get_basename(obj->name), unit->old_fname,
                                     unit->old_faddr);
    if (!old_fun)
      return ENOOLDFUNC;

    new_fun = load_so_symbol(unit->new_fname, patch_so);
    if (!new_fun)
      return ENONEWFUNC;

    root = get_detour_root_by_address(old_fun);
    if (!root) {
      root = push_new_root();
      if (!root)
        return EUNKNOWN;

      root->index = get_next_function_index();
      root->patched_addr = old_fun;
    }

    if (!(push_new_detour(__ulp_global_universe, ulp->patch_id, root,
                          new_fun))) {
      WARN("error setting ulp data structure\n");
      return EUNKNOWN;
    }

    if ((retcode = ulp_patch_addr(old_fun, new_fun, true)) > 0) {
      WARN("error patching address %p", old_fun);
      return retcode;
    }

    unit = unit->next;
  }

  /*
   * Each live patch loads a new shared object into the target process. If the
   * live patch references static data from the target library, the references
   * must be fixed so that they point to the actual address where the target
   * library has been loaded, so find the base address.
   *
   * XXX: The metadata file and its corresponding data structures within
   *      libpulp seem to allow more than one live patch object per live patch.
   *      However, the implementation is incomplete, so assume that there is a
   *      single object, and access ulp->objs directly.
   */
  struct link_map map_data;
  struct link_map *map_ptr;
  uintptr_t target_base;
  int tls_idx;
  uintptr_t patch_base;
  const char *target_basename = get_basename(ulp->objs->name);

  target_base = (uintptr_t)get_loaded_library_base_addr(target_basename);
  tls_idx = get_loaded_library_tls_index(target_basename);
  if (target_base == 0xFF) {
    WARN("Unable to find target library load address of %s", target_basename);
    return ENOADDRESS;
  }

  map_ptr = &map_data;
  memset(map_ptr, 0, sizeof(struct link_map));
  retcode = dlinfo(ulp->so_handler, RTLD_DI_LINKMAP, &map_ptr);
  if (retcode == -1) {
    WARN("Error in call to dlinfo: %s", dlerror());
    return EUNKNOWN;
  }
  if (map_ptr->l_addr == 0) {
    WARN("Unable to find target library load address: %s", dlerror());
    return ENOADDRESS;
  }
  patch_base = map_ptr->l_addr;

  /* Now patch static data references in the live patch object */
  ref = ulp->refs;
  while (ref) {
    uintptr_t patch_address;
    if (ref->patch_offset == 0) {
      /* In case the user did not specify the patch offset, try to find the
         symbol's address by its name.  */
      patch_address =
          (uintptr_t)load_so_symbol(ref->reference_name, ulp->so_handler);
      ref->patch_offset = patch_address - patch_base;
    }
    else {
      patch_address = patch_base + ref->patch_offset;
    }
    if (ref->tls) {
      tls_index ti = { .ti_module = tls_idx, .ti_offset = ref->target_offset };
      memcpy((void *)patch_address, &ti, sizeof(ti));
    }
    else {
      uintptr_t target_address = target_base + ref->target_offset;
      memcpy((void *)patch_address, &target_address, sizeof(void *));
    }
    ref = ref->next;
  }

  return 0;
}

struct ulp_applied_patch *
ulp_state_update(struct ulp_metadata *ulp)
{
  struct ulp_applied_patch *a_patch, *prev_patch = NULL;
  struct ulp_applied_unit *a_unit, *prev_unit = NULL;
  struct ulp_object *obj;
  struct ulp_unit *unit;
  struct ulp_dependency *dep, *a_dep;
  const char *basename_target;

  a_patch = calloc(1, sizeof(struct ulp_applied_patch));
  if (!a_patch) {
    WARN("Unable to allocate memory to update ulp state.");
    return 0;
  }

  memcpy(a_patch->patch_id, ulp->patch_id, 32);

  a_patch->lib_name = strndup(get_basename(ulp->objs->name), ULP_PATH_LEN);
  if (!a_patch->lib_name) {
    WARN("Unable to allocate filename buffer state.");
    return 0;
  }

  a_patch->container_name = strndup(ulp->so_filename, ULP_PATH_LEN);
  if (!a_patch->container_name) {
    WARN("Unable to allocate filename buffer state.");
    return 0;
  }

  for (dep = ulp->deps; dep != NULL; dep = dep->next) {
    a_dep = calloc(1, sizeof(struct ulp_dependency));
    if (!a_dep) {
      WARN("Unable to allocate memory to ulp state dependency.");
      return 0;
    }

    *a_dep = *dep;
    a_dep->next = a_patch->deps;
    a_patch->deps = a_dep;
  }

  obj = ulp->objs;
  unit = obj->units;

  basename_target = get_basename(obj->name);

  /* only shared objs have units, this loop never runs for main obj */
  while (unit != NULL) {
    a_unit = calloc(1, sizeof(struct ulp_applied_unit));
    if (!a_unit) {
      WARN("Unable to allocate memory to update ulp state (unit).");
      return 0;
    }

    a_unit->patched_addr = get_loaded_symbol_addr(
        basename_target, unit->old_fname, unit->old_faddr);
    if (!a_unit->patched_addr) {
      WARN("Symbol %s not found in %s.", unit->old_fname, basename_target);
      return 0;
    }

    a_unit->target_addr = load_so_symbol(unit->new_fname, ulp->so_handler);
    if (!a_unit->target_addr) {
      return 0;
    }

    memcpy(a_unit->overwritten_bytes, a_unit->patched_addr, 14);

    if (a_patch->units == NULL) {
      a_patch->units = a_unit;
      prev_unit = a_unit;
    }
    else {
      prev_unit->next = a_unit;
      prev_unit = a_unit;
    }
    unit = unit->next;
  }

  /* leave last on top of list to optmize revert */
  prev_patch = __ulp_state.patches;
  __ulp_state.patches = a_patch;
  a_patch->next = prev_patch;

  return a_patch;
}

/*
 * Retrieves the memory protection bits of the page containing ADDR and
 * returns it. If errors ocurred, return -1.
 */
int
memory_protection_get(uintptr_t addr)
{
  char line[LINE_MAX];
  char *str;
  char *end;
  int fd;
  int result;
  int retcode;
  uintptr_t addr1;
  uintptr_t addr2;

  fd = open("/proc/self/maps", O_RDONLY);
  if (fd == -1)
    return -1;

  /* Iterate over /proc/self/maps lines. */
  result = -1;
  for (;;) {

    /* Read one line. */
    retcode = read_line(fd, line, LINE_MAX);
    if (retcode <= 0)
      break;

    /* Parse the address range in the current line. */
    str = line;
    addr1 = strtoul(str, &end, 16);
    str = end + 1; /* Skip the dash used in the range output. */
    addr2 = strtoul(str, &end, 16);

    /* Skip line if target address not within range. */
    if (addr < addr1 || addr >= addr2)
      continue;

    /* Otherwise, parse the memory protection bits. */
    result = 0;
    if (*(end + 1) == 'r')
      result |= PROT_READ;
    if (*(end + 2) == 'w')
      result |= PROT_WRITE;
    if (*(end + 3) == 'x')
      result |= PROT_EXEC;
    break;
  }

  close(fd);
  return result;
}

int
check_patch_sanity(struct ulp_metadata *ulp)
{
  int ret;
  if (!check_build_id(ulp))
    return EBUILDID;
  ret = check_patch_dependencies(ulp);
  if (ret)
    return ret;
  if (ulp_get_applied_patch(ulp->patch_id)) {
    return EAPPLIED;
  }

  return 0;
}

int
check_patch_dependencies(struct ulp_metadata *ulp)
{
  struct ulp_applied_patch *patch;
  struct ulp_dependency *dep;

  for (dep = ulp->deps; dep != NULL; dep = dep->next) {
    for (patch = __ulp_state.patches; patch != NULL; patch = patch->next) {
      if (memcmp(patch->patch_id, dep->dep_id, 32) == 0) {
        dep->patch_id_check = 1;
        break;
      }
    }
  }

  for (dep = ulp->deps; dep != NULL; dep = dep->next) {
    if (dep->patch_id_check == 0) {
      WARN("Patch does not match dependencies.");
      return EDEPEND;
    }
  }
  return 0;
}

int
compare_build_ids(struct dl_phdr_info *info,
                  size_t __attribute__((unused)) size, void *data)
{
  int i;
  char *note_ptr, *build_id_ptr, *note_sec;
  uint32_t note_type, build_id_len, name_len, sec_size, next = 0;
  struct ulp_metadata *ulp;
  ulp = (struct ulp_metadata *)data;

  /* algorithm goes as follows:
   * 1 - check every object inside ulp_metadata
   * 1.1 - if object is main, match loaded object whose name length is 0
   * 1.2 - else, match ulp object and loaded object names
   * 2 - check every phdr for loaded object and match all PT_NOTE
   * 3 - trespass PT_NOTE searching for NT_GNU_BUILD_ID
   * 3.1 - once found, match contents with ulp object build id
   * 3.2 - if match, mark ulp object as checked and break dl_iterate (return 1)
   * 3.3 - else, continue looking for the library by returning 0
   *
   * Algorithm assumes that objects will only have one NT_GNU_BUILD_ID entry
   */

  for (i = 0; i < info->dlpi_phnum; i++) {
    if (info->dlpi_phdr[i].p_type != PT_NOTE)
      continue;

    note_sec = (char *)(info->dlpi_phdr[i].p_vaddr + info->dlpi_addr);
    sec_size = info->dlpi_phdr[i].p_memsz;

    for (note_ptr = note_sec, note_type = (uint32_t) * (note_ptr + 8);
         note_type != NT_GNU_BUILD_ID && note_ptr < note_sec + sec_size;
         note_ptr = note_sec + next, note_type = (uint32_t) * (note_ptr + 8)) {

      build_id_len = (uint32_t) * (note_ptr + 4);
      name_len = (uint32_t)*note_ptr;

      /* fix paddings */
      build_id_len += build_id_len % 4;
      name_len += name_len % 4;

      next = next + build_id_len + name_len + 12;
    }

    /* could not fid the build id in the note section, go to next sec */
    if (note_type != NT_GNU_BUILD_ID)
      continue;

    build_id_len = (uint32_t) * (note_ptr + 4);
    build_id_len += build_id_len % 4;
    if (build_id_len != ulp->objs->build_id_len)
      return 0;

    /* we compute, but currently do not check note names */
    name_len = (uint32_t)*note_ptr;
    name_len += name_len % 4;

    build_id_ptr = note_ptr + 12 + name_len;
    if (memcmp(ulp->objs->build_id, build_id_ptr, build_id_len) == 0) {
      ulp->objs->build_id_check = 1;
      return 1;
    }
    else {
      return 0;
    }
  }
  return 0;
}

int
all_build_ids_checked(struct ulp_metadata *ulp)
{
  if (!ulp->objs->build_id_check) {
    WARN("Could not match patch target build id %s.", ulp->objs->name);
    return 0;
  }
  return 1;
}

int
check_build_id(struct ulp_metadata *ulp)
{
  dl_iterate_phdr(compare_build_ids, ulp);
  if (!all_build_ids_checked(ulp))
    return 0;
  return 1;
}

static void
ulp_patch_prologue_layout(void *old_fentry, const char *prologue, int len)
{
  memcpy(old_fentry, prologue, len);
}

/*
 * When a function gets live patch, the nops at its entry point get replaced
 * with a backwards-jump to a small segment of code that redirects execution to
 * the new version of the function. However, when all live patches to said
 * function are deactivated (because the live patches have been reversed), the
 * need for the backwards-jump is gone.
 *
 * The following function replaces the backwards-jump with nops, thus making
 * the target function look like it did at the beginning of execution, i.e.
 * without live patches.
 */
void
ulp_skip_prologue(void *fentry)
{
  static const char insn_nop2[] = { 0x66, 0x90 };
  int bias = 0;
  if (memcmp(fentry, insn_endbr64, sizeof(insn_endbr64)) == 0)
    bias += sizeof(insn_endbr64);

  /* Do not jump backwards on function entry (0x6690 is a nop on x86). */
  memcpy(fentry + bias, insn_nop2, sizeof(insn_nop2));
}

void
__ulp_manage_universes(unsigned long idx)
{
  struct ulp_detour_root *root;
  struct ulp_detour *d;
  void *target;

  root = get_detour_root_by_index((unsigned int)idx);
  if (!root) {
    WARN("FATAL ERROR While Live Patching.");
    libpulp_exit(-1);
  }

  target = NULL;

  // since universes are kept in order, this is a top-down search
  for (d = root->detours; d != NULL; d = d->next) {
    if (d->active) {
      target = d->target_addr;
      break;
    }
  }
  if (!target)
    target = root->patched_addr + 2;

  /* clang-format off */
  asm (
    "movq %0, %%r11;"
    :
    : "r" (target)
    :
  );
  /* clang-format on */
}

unsigned int
get_next_function_index()
{
  return __ulp_root_index_counter++;
}

unsigned int
push_new_detour(unsigned long universe, unsigned char *patch_id,
                struct ulp_detour_root *root, void *new_faddr)
{
  struct ulp_detour *detour, *detour_aux;

  detour = calloc(1, sizeof(struct ulp_detour));
  if (!detour) {
    WARN("Unable to acllocate memory for ulp detour");
    return 0;
  }

  detour_aux = root->detours;
  root->detours = detour;
  detour->next = detour_aux;
  detour->target_addr = new_faddr;
  detour->universe = universe;
  detour->active = 1;
  memcpy(detour->patch_id, patch_id, 32);

  return 1;
}

/** @brief Write new function address into data prologue of  `old_fentry`.
 *
 *  This function replaces the `<data>` section in prologue `old_fentry`
 *  with a pointer to the new function given by `manager`, which will
 *  replace the to be patched function.
 *
 *  @param old_fentry Pointer to prologue of to be replaced function
 *  @param manager Address of new function.
 */
void
ulp_patch_addr_absolute(void *old_fentry, void *manager)
{
  memcpy(old_fentry + ULP_DATA_OFFSET, &manager, sizeof(void *));
}

int
ulp_patch_addr(void *old_faddr, void *new_faddr, int enable)
{
  void *addr;
  unsigned long page_size;
  uintptr_t page_mask;
  uintptr_t page1;
  uintptr_t page2;
  int prot1;
  int prot2;

  int ulp_nops_len;
  const char *prologue;

  const unsigned char *as_bytes = old_faddr;

  /* Check if the first instruction of old_function is endbr64.  In this
     case, we have to handle things differently.  */
  if (memcmp(old_faddr, insn_endbr64, sizeof(insn_endbr64)) == 0) {
    ulp_nops_len = ULP_NOPS_LEN_ENDBR64;
    prologue = ulp_prologue_endbr64;
    as_bytes += sizeof(insn_endbr64);
  }
  else {
    ulp_nops_len = ULP_NOPS_LEN;
    prologue = ulp_prologue;
  }

  /* Check if we have the two NOP sequence or a JMP ref8 insn.  Else we might
     be attempting to patch a non-livepatchable function.  */

  if (!(as_bytes[0] == 0xEB ||
        (as_bytes[1] == 0x90 &&
         (as_bytes[0] == 0x90 || as_bytes[0] == 0x66)))) {
    WARN("Function at addr %lx is not livepatchable",
         (unsigned long)old_faddr);
    return ENOPATCHABLE;
  }

  /*
   * The size of the nop padding area is supposed to be a lot smaller
   * than the typical size of a memory page. Even so, when the entry
   * point to the target function is at an address close to a page
   * boundary, the padding area may span two pages. This function is
   * able to handle at most one page cross.
   */
  page_size = getpagesize();
  page_mask = ~(page_size - 1);
  if ((unsigned long)ulp_nops_len > page_size) {
    WARN("Nop padding area unexpectedly large.");
    return 0;
  }

  /* Find the starting address of the pages containing the nops. */
  addr = old_faddr - PRE_NOPS_LEN;

  page1 = (uintptr_t)addr;
  page2 = (uintptr_t)(addr + ulp_nops_len - 1);
  page1 = page1 & page_mask;
  page2 = page2 & page_mask;

  /* Retrieve the current set of protection bits. */
  prot1 = memory_protection_get(page1);
  prot2 = memory_protection_get(page2);
  if (prot1 == -1 || prot2 == -1) {
    WARN("Memory protection read error");
    return ENOADDRESS;
  }

  /* Set the writable bit on affected pages. */
  if (mprotect((void *)page1, page_size, prot1 | PROT_WRITE)) {
    WARN("Memory protection set error (1st page)");
    return errno;
  }
  if (mprotect((void *)page2, page_size, prot2 | PROT_WRITE)) {
    WARN("Memory protection set error (2nd page)");
    return errno;
  }

  /* Actually patch the prologue. */
  if (enable) {
    ulp_patch_prologue_layout(addr, prologue, ulp_nops_len);
    ulp_patch_addr_absolute(addr, new_faddr);
  }
  else {
    ulp_skip_prologue(old_faddr);
  }

  /* Restore the previous access protection. */
  if (mprotect((void *)page1, page_size, prot1)) {
    WARN("Memory protection restore error (1st page)");
    return errno;
  }
  if (mprotect((void *)page2, page_size, prot2)) {
    WARN("Memory protection restore error (2nd page)");
    return errno;
  }

  return 0;
}

struct ulp_applied_patch *
ulp_get_applied_patch(const unsigned char *id)
{
  struct ulp_applied_patch *patch;

  for (patch = __ulp_state.patches; patch != NULL; patch = patch->next)
    if (memcmp(patch->patch_id, id, 32) == 0)
      return patch;

  return NULL;
}

int
ulp_revert_patch(unsigned char *id)
{
  struct ulp_applied_patch *patch;

  __ulp_global_universe++;
  patch = ulp_get_applied_patch(id);

  if (ulp_revert_all_units(id)) {
    if (!ulp_state_remove(patch)) {
      WARN("Problem updating state. Program may be inconsistent.");
      return ESTATE;
    }
  }

  return 0;
}

int
ulp_state_remove(struct ulp_applied_patch *rm_patch)
{
  struct ulp_applied_patch *patch;
  struct ulp_applied_unit *unit, *next_unit;
  struct ulp_dependency *dep, *next_dep;
  int found = 0;

  /* take it out from applied patches list */
  if (__ulp_state.patches == rm_patch) {
    found = 1;
    __ulp_state.patches = rm_patch->next;
  }
  else {
    for (patch = __ulp_state.patches; patch != NULL; patch = patch->next) {
      if (patch == rm_patch) {
        found = 1;
        patch->next = rm_patch->next;
        break;
      }
    }
  }

  if (!found)
    return 0;

  /* free all units from it */
  for (unit = rm_patch->units; unit != NULL; unit = next_unit) {
    next_unit = unit->next;
    free(unit);
  }

  /* free all deps from it */
  for (dep = rm_patch->deps; dep != NULL; dep = next_dep) {
    next_dep = dep->next;
    free(dep);
  }

  free((void *)rm_patch->lib_name);

  /* free it */
  free(rm_patch);

  return 1;
}

int
ulp_revert_all_units(unsigned char *patch_id)
{
  struct ulp_detour_root *r;
  struct ulp_detour *d;
  struct ulp_detour *d2;
  struct ulp_detour *dactive;

  for (r = __ulp_root; r != NULL; r = r->next)
    for (d = r->detours; d != NULL; d = d->next)
      if (memcmp(d->patch_id, patch_id, 32) == 0) {

        /* Deactivate this patch. */
        d->active = 0;

        /* Find the most recent live patch that is active. */
        dactive = NULL;
        for (d2 = r->detours; d2 != NULL; d2 = d2->next) {
          if (d2->active) {
            dactive = d2;
            /* Newest elements of the list come first. */
            break;
          }
        }

        /* Update the function prologue. */
        if (dactive == NULL) {
          ulp_patch_addr(r->patched_addr, NULL, false);
        }
        else {
          ulp_patch_addr(r->patched_addr, dactive->target_addr, true);
        }
      }

  return 1;
}

/* these are here for debugging reasons :) */
void
dump_ulp_patching_state(void)
{
  struct ulp_applied_patch *a_patch;
  struct ulp_applied_unit *a_unit;
  struct ulp_dependency *dep;
  int i;

  fprintf(stderr, "----- ULP state dump -----\n");
  fprintf(stderr, "__ulp_state address: %lx\n", (unsigned long)&__ulp_state);

  for (a_patch = __ulp_state.patches; a_patch != NULL;
       a_patch = a_patch->next) {
    fprintf(stderr, "* libname: %s\n", a_patch->lib_name);
    fprintf(stderr, "* container: %s\n", a_patch->container_name);
    fprintf(stderr, "* PATCH 0x");
    for (i = 0; i < 32; i++) {
      fprintf(stderr, "%x.", a_patch->patch_id[i]);
    }
    fprintf(stderr, "\n");
    for (dep = a_patch->deps; dep != NULL; dep = dep->next) {
      fprintf(stderr, "* DEPENDs 0x");
      for (i = 0; i < 32; i++) {
        fprintf(stderr, "%x.", dep->dep_id[i]);
      }
      fprintf(stderr, "\n");
    }

    for (a_unit = a_patch->units; a_unit != NULL; a_unit = a_unit->next)
      fprintf(stderr, "** %p %p\n", a_unit->patched_addr, a_unit->target_addr);
  }
  fprintf(stderr, "----- End of dump ------\n");
}

void
dump_ulp_detours(void)
{
  struct ulp_detour_root *r;
  struct ulp_detour *d;
  int i;
  fprintf(stderr, "====== ULP Roots ======\n");
  for (r = __ulp_root; r != NULL; r = r->next) {
    fprintf(stderr, "* ROOT:\n");
    fprintf(stderr, "* Index: %d\n", r->index);
    fprintf(stderr, "* Patched addr: %p\n", r->patched_addr);
    fprintf(stderr, "----- ULP DETOURS -----\n");
    for (d = r->detours; d != NULL; d = d->next) {
      fprintf(stderr, "  * DETOUR:\n");
      fprintf(stderr, "  * Universe: %ld\n", d->universe);
      fprintf(stderr, "  * Target addr: %p\n", d->target_addr);
      fprintf(stderr, "  * Active: ");
      if (d->active)
        fprintf(stderr, "yep\n");
      else
        fprintf(stderr, "nop\n");
      fprintf(stderr, "  * Patch ID: ");
      for (i = 0; i < 16; i++)
        fprintf(stderr, "%x.", d->patch_id[i]);
      fprintf(stderr, "\n              ");
      for (i = 16; i < 32; i++)
        fprintf(stderr, "%x.", d->patch_id[i]);
      fprintf(stderr, "\n========================\n");
    }
  }
}
