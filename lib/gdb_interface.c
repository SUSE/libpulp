/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2024 SUSE Software Solutions GmbH
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

/* Small interface that allows livepatches to be applied or reverted
 * within gdb.  */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <string.h>
#include <sys/types.h>
#include <link.h>

#include "config.h"
#include "ulp_common.h"
#include "ulp.h"
#include "minielf.h"
#include "error_common.h"
#include "insn_queue_lib.h"

extern char __ulp_metadata_buffer[ULP_METADATA_BUF_LEN];

int
inject_lp_path(const char *path, long metadata_size)
{
  /* FIXME: This is absurdly awkward.  */

  /* Copy the final metadata into final_meta buffer.  Things works here as
   * follows:
   *
   * 1. Copy the first 1 + 32 bytes containing the patch type and patch id.
   * 2. Copy the size of the path to the livepatch container file.
   * 3. Copy the path to the livepatch container file.
   * 4. Copy the remaining metadata stuff.
   *
   * We do it in this way so we don't have to carry the path to the patch
   * container with the patch. This info can be retrieved from the path to
   * patch and avoid problems regarding the application running in another path
   * than the ulp tool.
   *
   * See introspection.c: 1868.
   * */

  long metadata_left = 1 + 32;
  long metadata_right = metadata_size - metadata_left;


  char *head = &__ulp_metadata_buffer[metadata_left];

  uint32_t path_size = strlen(path) + 1;
  uint32_t path_object_size = sizeof(uint32_t) + path_size;

  /* Check if it will still fit the metadata buffer.  */
  if (metadata_size + path_object_size > ULP_METADATA_BUF_LEN) {
    /* Won't fit.  */
    return ENOMEM;
  }

  /* Shift right so it fits.  */
  memmove(head + path_object_size, head, metadata_right);

  /* Inject the path.  */
  memcpy(head, &path_size, sizeof(uint32_t));
  head += sizeof(uint32_t);

  memcpy(head, path, path_size);
  head += path_object_size;

  return 0;
}

int
gdb_ulp_apply(const char *path)
{
  int ret;

  /* Prepare the ULP metadata buffer.  */
  memset(__ulp_metadata_buffer, '\0', ULP_METADATA_BUF_LEN);

  /* Load the .ulp section into the metadata buffer.  */
  long len = Get_ULP_Section(ULP_METADATA_BUF_LEN, (void*)__ulp_metadata_buffer, path);
  if (len < 0) {
    /* Invalid.  */
    return (int) -len;
  }

  if (inject_lp_path(path, len)) {
    return EINVALIDULP;
  }

  /* Trigger the livepatch.  */
  if ((ret = __ulp_apply_patch()) != 0) {
    return ret;
  }

  /* Process instruction queue.  */
  if ((ret = insnq_interpret_from_lib()) != 0) {
    return ret;
  }

  return 0;
}


int
gdb_ulp_revert(const char *path)
{
  int ret;
  /* Prepare the ULP metadata buffer.  */
  memset(__ulp_metadata_buffer, '\0', ULP_METADATA_BUF_LEN);

  /* Load the .ulp section into the metadata buffer.  */
  long len = Get_ULP_REV_Section(ULP_METADATA_BUF_LEN, (void *)__ulp_metadata_buffer, path);
  if (len < 0) {
    /* Invalid.  */
    return (int) -len;
  }

  if (inject_lp_path(path, len)) {
    return EINVALIDULP;
  }

  /* Trigger the livepatch.  */
  if ((ret = __ulp_apply_patch()) != 0) {
    return ret;
  }

  /* Process instruction queue.  */
  if ((ret = insnq_interpret_from_lib()) != 0) {
    return ret;
  }

  return 0;
}
