/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020-2021 SUSE Software Solutions GmbH
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

#include <sys/mman.h>
#include <stdlib.h>

/* This function is here for messing with seccomp.  Seccomp disables
   mmap with EXEC | WRITE attributes, so if we call it we should get
   a memory allocation error with ENOPERM.  */

__attribute__((constructor))
static void initialize(void)
{
  void *page = mmap(NULL, 128, PROT_EXEC | PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  /* Check if we got the page.  */
  if (page == (void *) -1L || page == NULL) {
    /* We did not get the page, abort.  */
    abort();
  }

  /* Clean memory.  */
  munmap(page, 128);
}

int
baker_dozen(void)
{
  return 13;
}
