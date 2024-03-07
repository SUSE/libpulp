/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2024 SUSE Software Solutions GmbH
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

#ifndef _HASH_H
#define _HASH_H

/** Hash table implementation using sorted arrays for fast search, but with slow
  * insertion tradeoff.
  */

#include <stddef.h>

/** Hash entry mapping a key to a value.  */
struct hash_entry
{
  void      *key;
  void      *value;
};

/** The hash table object.  */
struct hash_table
{
  /** Current size in bytes of the `hash` array.  */
  size_t              current_size;

  /** Number of elements currently in the `hash` array.  */
  size_t              num_elements;

  /** Array containing the objects.  */
  struct hash_entry   hash[];
};

/** Declare hash_t as a pointer to a hash_table.  Since we need to grow the
    array we have to pass the pointer as a reference rather than the object
    itself.  */
typedef struct hash_table *hash_t;

/** Create a hash table with N elements of space.  */
hash_t hash_table_create(size_t nelems);

/** Insert element into the hash.  If the hash is full, then it will grow
    automatically.  Returns 0 if success, anything else if failure.  */
int hash_insert_single(hash_t *hash, void *key, void *value);

/** Remove an element from the hash.  */
int hash_delete(hash_t *hash, void *key);

/** Get hash element with key.  Returns NULL if not found.  */
struct hash_entry *hash_get_entry(hash_t hash, void *key);

static inline void *hash_get_value(hash_t hash, void *key)
{
  struct hash_entry *h = hash_get_entry(hash, key);
  return h ? h->value : NULL;
}

#endif
