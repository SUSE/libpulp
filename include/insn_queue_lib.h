/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2023 SUSE Software Solutions GmbH
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

#ifndef INSNQ_TOOL_H
#define INSNQ_TOOL_H

#include "insn_queue.h"

void *insnq_get_writable_area(insn_queue_t *, size_t insn_size);

ulp_error_t insnq_insert_print(const char *string);

ulp_error_t insnq_insert_write(void *addr, int n, const void *bytes);

int insnq_ensure_emptiness(void);

/* Not necessary if compiling without gdb interface.  */
#ifdef ENABLE_GDB_INTERFACE

/** Interpret the global instruction queue from process side.  */
int insnq_interpret_from_lib(void);

#endif //ENABLE_GDB_INTERFACE

#endif
