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
#include <stdio.h>
#include <stdlib.h>

#include "../include/ulp_common.h"

// ti is overriden in the livepatching process.  It must not be declared static
// else the compiler may remove the variable because it is unreferenced.
tls_index ti = { 0 };
static char *ulpr_string = "String from live patch";

void *__tls_get_addr(tls_index *);

#define SWAP(a,b) { typeof(a) _t = (a); (a) = (b); (b) = _t; }

void
new_banner_set(__attribute__((unused)) char *new)
{
  if (ti.ti_module == 0 && ti.ti_offset == 0)
    errx(EXIT_FAILURE, "Live patch data references not initialized");

  char **ulpr_banner = __tls_get_addr(&ti);
  printf("module: %lx, offset: %lx\n", ti.ti_module, ti.ti_offset);
  printf("addr: 0x%lx\n", (unsigned long)ulpr_banner);
  *ulpr_banner = ulpr_string;
}
