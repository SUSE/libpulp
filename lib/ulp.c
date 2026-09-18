/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2026 SUSE Software Solutions GmbH
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
#include <fcntl.h>
#include <limits.h>
#include <link.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "arch_common.h"
#include "config.h"
#include "error.h"
#include "insn_queue_lib.h"
#include "interpose.h"
#include "symbol_loader.h"
#include "msg_queue.h"
#include "ulp.h"
#include "ulp_detour.h"

/* ulp data structures */
extern struct ulp_patching_state __ulp_state;
extern struct ulp_detour_root *__ulp_root;

char __ulp_metadata_buffer[ULP_METADATA_BUF_LEN] = { 0 };

/* current libpulp version.  */
const char __ulp_version[] = VERSION;

unsigned long __ulp_global_universe = 0;

int load_patch(void);

__attribute__((constructor)) void
begin(void)
{
  __ulp_state.load_state = 1;
  msgq_push("libpulp loaded...\n");
}

/** @brief Release resources allocated by libpulp.
 *
 * Once the execution of the process ends, release all resources took by
 * libpulp.
 */
__attribute__((destructor)) void
end(void)
{
  struct ulp_applied_patch *patch = __ulp_state.patches;

  /* First, revert all livepatches.  */
  while (patch) {
    struct ulp_applied_patch *next_patch = patch->next;

    dlclose(patch->so_handler); // Close the livepatch .so handler.
    if (ulp_can_revert_patch(patch->patch_id) == 0) {
      ulp_revert_patch(patch->patch_id);
    }

    patch = next_patch;
  }

  __ulp_state.patches = NULL;

  /* Now release the detours.  */
  struct ulp_detour_root *root = __ulp_root;

  while (root) {
    struct ulp_detour_root *root_next = root->next;
    struct ulp_detour *detour = root->detours;

    while (detour != NULL) {
      struct ulp_detour *detour_next = detour->next;

      /* Zero object.  */
      memset(detour, 0, sizeof(*detour));

      /* Release detour.  */
      FREE_AND_NULLIFY(detour);

      detour = detour_next;
    }

    /* Lets zero out the root object.  */
    memset(root, 0, sizeof(*root));

    /* Release detour_root.  */
    FREE_AND_NULLIFY(root);

    /* Go to next.  */
    root = root_next;
  }

  /* Set the root object as NULL.  */
  __ulp_root = NULL;
}

/** @brief Write into memory bypassing memory protections
 *
 * The process may be launched with mprotect through seccomp, which
 * will block certain addresses to be written.  This function
 * circunvent this by queuing up an instruction to the ulp insn queue
 * for the `ulp` tool to process later.
 *
 * @param dest    Destination address
 * @param src     Source address
 * @param n       number of bytes
 * @return dest on success, NULL if error.
 */
void *
memwrite(void *dest, const void *src, size_t n)
{
  error_t e = insnq_insert_write(dest, n, src);
  if (e != ENONE) {
    return NULL;
  }

  return dest;
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

  /* If libpulp is in an error state, we cannot continue.  */
  if (libpulp_is_in_error_state())
    return get_libpulp_error_state();

  /* If the instruction queue is in an weird state, we cannot continue.  */
  if (insnq_ensure_emptiness())
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

  /* If the instruction queue is in an weird state, we cannot continue.  */
  if (insnq_ensure_emptiness())
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

/** @brief Get ULP global universe.
 *
 * Every time a patch is applied or reverted, the global universe counter is
 * incremented.
 *
 * @return current global universe counter.
 */
unsigned long
__ulp_get_global_universe_value()
{
  return __ulp_global_universe;
}

/*
 * Read one line from FD into BUF, which must be pre-allocated and large
 * enough to hold LEN characteres. The offset into FD is advanced by the
 * amount of bytes read.
 *
 * @return  -1 on error, 0 on End-of-file, or the amount of bytes read.
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

/** @brief Load patch from metadata buffer and apply its content.
 *
 * When a livepatch is issued, this function will parse the patch from the
 * patch buffer and apply its content, either revert or apply.
 *
 * @return 0 if success, anything else if error.
 */
int
load_patch(void)
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

/* @brief Retrieves the memory protection bits of the page containing ADDR.
 *
 * @param addr    Address of the page.
 * @return        If errors ocurred, return -1.
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

/** @brief Get patched address of function with universe index = idx.
 *
 * This function will get the function address (plus 2) of the function whose
 * universe index equals `idx`. Every time a function is livepatched or
 * reverted this index number increases. It will save this address in register
 * r11.
 */
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
}

/** @brief Remove applied patch and its units.
 *
 * If a patch removal is issued, this function will remove the patch from the
 * patch list and also every unit that is associated with it.
 *
 * @brief id    Patch id to remove.
 *
 * @return      0 if success, ESTATE if error.
 *
 */
int
ulp_revert_patch(unsigned char *id)
{
  __ulp_global_universe++;

  if (ulp_revert_all_units(id)) {
    if (!ulp_state_remove(id)) {
      WARN("Problem updating state. Program may be inconsistent.");
      return ESTATE;
    }
  }

  return 0;
}

/** @brief Enable or disable livepatching in this process.
 *
 * This function enables or disables livepatching according to libpulp's error
 * state. If libpulp is not in a error state, it sets it to EUSRBLOCKED, which
 * flags that the user requested this process to not be livepatched anymore.
 * In case current state is EUSRBLOCKED, it sets to ENONE, thus re-enabling
 * livepatching.
 *
 * If libpulp is in an error state outside of EUSRBLOCKED or ENONE, then
 * changing this state is blocked as it is in a real error state, thus
 * patching is blocked.
 *
 * @return error state after change.
 **/
int
ulp_enable_or_disable_patching(void)
{
  ulp_error_t state = get_libpulp_error_state();

  switch (state) {
    case ENONE:
      /* Block livepatching.  */
      set_libpulp_error_state(EUSRBLOCKED);
      break;

    case EUSRBLOCKED:
      /* Unblock livepatching.  */
      set_libpulp_error_state(ENONE);
      break;

    default:
      /* Libpulp is in an error state and we can not continue.  */
      break;
  }

  /* Return the current state.  */
  return get_libpulp_error_state();
}
