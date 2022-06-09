/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2022 SUSE Software Solutions GmbH
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

#ifndef _LD_RTLD
#define _LD_RTLD

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>

#if __GLIBC__ == 2 && __GLIBC_MINOR__ < 35
struct r_debug_extended
{
  struct r_debug base;
  struct r_debug_extended *r_next;
};
#endif

typedef struct
{
  pthread_mutex_t mutex;
} __rtld_lock_recursive_t;

#define __rtld_lock_define_recursive(CLASS, NAME) \
  CLASS __rtld_lock_recursive_t NAME;

#define DL_NNS 16
#define EXTERN

/* clang-format off */

/**
 * Incomplete declaration of rtld_global, taken out from glibc's
 * sysdeps/generic/ldsodefs.h. We just need the first part of it to reach the
 * '_dl_load_lock'.
 *
 * Extracted from glibc 2.31
 *
 */
struct rtld_global__2_31
{
  struct
  {
    struct link_map *_ns_loaded;
    unsigned int _ns_nloaded;
    struct r_scope_elem *_ns_main_searchlist;
    unsigned int _ns_global_scope_alloc;
    unsigned int _ns_global_scope_pending_adds;
    struct
    {
      __rtld_lock_define_recursive(, lock) struct
      {
        uint32_t hashval;
        const char *name;
        const ElfW(Sym) * sym;
        const struct link_map *map;
      } * entries;
      size_t size;
      size_t n_elements;
      void (*free)(void *);
    } _ns_unique_sym_table;
    struct r_debug _ns_debug;
  } _dl_ns[DL_NNS];
  size_t _dl_nns;
  __rtld_lock_define_recursive(EXTERN, _dl_load_lock)
  __rtld_lock_define_recursive(EXTERN, _dl_load_write_lock)
  unsigned long long _dl_load_adds;
};

/**
 * Incomplete declaration of rtld_global, taken out from glibc's
 * sysdeps/generic/ldsodefs.h. We just need the first part of it to reach the
 * '_dl_load_lock'.
 *
 * Extracted from glibc 2.35.
 *
 */
struct rtld_global__2_35
{
  struct
  {
    struct link_map *_ns_loaded;
    unsigned int _ns_nloaded;
    struct r_scope_elem *_ns_main_searchlist;
    unsigned int _ns_global_scope_alloc;
    unsigned int _ns_global_scope_pending_adds;
    struct link_map *libc_map;
    struct
    {
      __rtld_lock_define_recursive (, lock)
      struct
      {
        uint32_t hashval;
        const char *name;
        const ElfW(Sym) *sym;
        const struct link_map *map;
      } *entries;
      size_t size;
      size_t n_elements;
      void (*free) (void *);
    } _ns_unique_sym_table;
    struct r_debug_extended _ns_debug;
  } _dl_ns[DL_NNS];
  size_t _dl_nns;
  __rtld_lock_define_recursive (EXTERN, _dl_load_lock)
  __rtld_lock_define_recursive (EXTERN, _dl_load_write_lock)
  __rtld_lock_define_recursive (EXTERN, _dl_load_tls_lock)
};

/* clang-format on */

#undef DL_NNS
#undef EXTERN

#endif
