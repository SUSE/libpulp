/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2021 SUSE Software Solutions GmbH
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

#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) static void
init(void)
{
  char message1[] = "malloc returned NULL\n";
  char message2[] = "malloc returned Non-NULL\n";
  void *result;
  ssize_t retcode __attribute__((unused));

  /*
   * Libpulp interposes several functions from libc, such as malloc, but
   * it doesn't actually reimplement them. Instead, during process
   * startup, libpulp finds the original addresses of the functions, and
   * saves; afterwards, it uses these addresses to redirect calls made
   * from the program (or from other libraries). However, this only
   * works if libpulp's initialization happens before other constructors
   * try to access the interposed functions. The following call to
   * malloc tries to detect if other constructors also try to access
   * malloc before libpulp gets a chance to initialize itself.
   */
  result = malloc(1);
  if (result == NULL)
    retcode = write(STDOUT_FILENO, message1, sizeof(message1));
  else
    retcode = write(STDOUT_FILENO, message2, sizeof(message2));
}
