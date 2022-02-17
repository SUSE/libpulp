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
#include <errno.h>
#include <fcntl.h>
#include <libelf.h>
#include <stdio.h>
#include <unistd.h>

#include "arguments.h"
#include "config.h"
#include "introspection.h"
#include "livepatchable.h"
#include "msg_queue.h"
#include "post.h"
#include "ulp_common.h"

int
run_livepatchable(struct arguments *arguments)
{
  int ret = 0;
  int fd;

  /* Set the verbosity level in the common introspection infrastructure. */
  ulp_verbose = arguments->verbose;
  ulp_quiet = arguments->quiet;

  fd = open(arguments->args[0], 0);
  if (fd == -1)
    errx(EXIT_FAILURE, "Unable to open file '%s': %s.\n", arguments->args[0],
         strerror(errno));

  elf_version(EV_CURRENT);
  Elf *elf = elf_begin(fd, ELF_C_READ, NULL);

  struct Elf_Scn *scn =
      find_section_by_name(elf, "__patchable_function_entries");
  if (scn == NULL) {
    WARN("file '%s' is not livepatchable: Missing "
         "__patchable_function_entries section.",
         arguments->args[0]);
    ret = 1;
  }
  else {
    WARN("file '%s' is livepatchable.", arguments->args[0]);
    ret = 0;
  }

  elf_end(elf);
  close(fd);

  return ret;
}
