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

#include <err.h>
#include <stdlib.h>

#include <libaccess.h>

static char **ulpr_banner = NULL;
static char *ulpr_string = "String from live patch";

void
new_banner_set(__attribute__((unused)) char *new)
{
  if (ulpr_banner == NULL)
    errx(EXIT_FAILURE, "Live patch data references not initialized");

  *ulpr_banner = ulpr_string;
}

/*
 * Touch ulpr_banner so that it does not get optimized away or placed into
 * read-only sections.
 */
void
banner_disturb(void)
{
  ulpr_banner++;
}
