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

#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>

#include "ulp_common.h"

/* ULP Structures */

/* libpulp livepatching interfaces */
int __ulp_apply_patch();

void __ulp_print();

/* functions */
void *memwrite(void *dest, const void *src, size_t n);

int ulp_revert_patch(unsigned char *id);
