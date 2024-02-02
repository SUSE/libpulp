/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2021-2023 SUSE Software Solutions GmbH
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


#include <libelf.h>
#include <assert.h>
#include <string.h>

#include "ulp_common.h"
#include "post.h"

/*
 * On POWER all instructions are 4 bytes long, so there is no need
 * to do anything in the `ulp post` command.
 */
void
merge_nops_at_addr(Elf64_Addr addr, size_t amount)
{
  (void) addr;
  (void) amount;
}
