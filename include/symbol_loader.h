/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2025 SUSE Software Solutions GmbH
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

#include <pthread.h>

void *get_loaded_symbol_addr_size(const char *, const char *, void *, size_t *);

#define get_loaded_symbol_addr(x, y, z) get_loaded_symbol_addr_size(x, y, z, NULL)

void *get_loaded_library_base_addr(const char *);

int get_loaded_library_tls_index(const char *);

void get_ld_global_locks(pthread_mutex_t **l_lock, pthread_mutex_t **w_lock);
