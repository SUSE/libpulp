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

#include "hash.h"

#include <errno.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

int hash_assert(hash_t hash)
{
  size_t n = hash->num_elements;
  struct hash_entry *v = hash->hash;

  for (size_t i = 0; i < n-1; i++) {
    if (v[i].key > v[i+1].key) {
      assert("Order is broken" && 0);
      return 1;
    }
  }

  return 0;
}

static int hash_table_grow(hash_t *hash)
{
  assert((*hash)->current_size != 0);

  size_t new_size = (*hash)->current_size * 2;
  hash_t new_ptr = (hash_t) realloc(*hash, sizeof(struct hash_table) +
                                    new_size * sizeof(struct hash_entry));

  if (new_ptr == NULL) {
    /* Flag that we had an error reallocating the array.  */
    return errno;
  }

  new_ptr->current_size = new_size;

  *hash = new_ptr;
  return 0;
}

hash_t hash_table_create(size_t size)
{
  hash_t ret = NULL;

  /* In case the number of elements requested is 0, then hardcode it to 32.  */
  if (size == 0) {
    size = 32;
  }

  ret = (hash_t) malloc(sizeof(struct hash_table) + size * sizeof(struct hash_entry));

  if (ret == NULL) {
    /* In case the array wasn't allocated then pass the error to the caller.  */
    return ret;
  }

  ret->current_size = size;
  ret->num_elements = 0;

  return ret;
}

static const struct hash_entry *last_a, *last_b;
static int comp(const void *a, const void *b)
{
  const struct hash_entry *ha, *hb;
  ha = (const struct hash_entry *) a;
  hb = (const struct hash_entry *) b;

  last_a = ha;
  last_b = hb;

  if ((uintptr_t) ha->key < (uintptr_t) hb->key) {
    return -1;
  }

  if ((uintptr_t) ha->key > (uintptr_t) hb->key) {
    return 1;
  }

  return 0;
}

size_t find_position(hash_t hash, void *key)
{
  struct hash_entry s = { .key = key };
  struct hash_entry *entry = bsearch(&s, hash->hash, hash->num_elements, sizeof(s), comp);
  size_t pos;

  if (entry) {
    pos = ((uintptr_t)entry - (uintptr_t)hash->hash) / sizeof(struct hash_entry);
  } else {
    pos = ((uintptr_t)last_b - (uintptr_t)hash->hash) / sizeof(struct hash_entry);
  }

  return pos;
}

struct hash_entry *hash_get_entry(hash_t hash, void *key)
{
  struct hash_entry s = { .key = key };
  struct hash_entry *entry = bsearch(&s, hash->hash, hash->num_elements, sizeof(s), comp);
  return entry;
}

int hash_insert_single(hash_t *hash, void *key, void *value)
{
  assert((*hash)->num_elements <= (*hash)->current_size);

  if ((*hash)->current_size == (*hash)->num_elements) {
    /* We have to grow the hash array.  */
    int ret = hash_table_grow(hash);
    if (ret != 0) {
      return ret;
    }
  }

  if (hash_get_entry(*hash, key) != NULL) {
    /* Element already exists.  */
    return 1;
  }

  size_t n = (*hash)->num_elements;
  struct hash_entry entry = {.key = key, .value = value};
  struct hash_entry *v = (*hash)->hash;

  /* There is a corner case when the array is empty: bsearch won't compare anything.*/
  if (n == 0) {
    (*hash)->hash[0] = entry;
    (*hash)->num_elements++;

    hash_assert(*hash);
    return 0;
  }

  /* Look for the last values in the comp function for a place to insert.  */
  size_t i = ((uintptr_t)last_b - (uintptr_t)v) / sizeof(struct hash_entry);

  /* Check if we should insert on the right side of the last occurence.  */
  if (v[i].key < key) {
    i = i + 1;
  }

  /* Move everything to the right.  */
  memmove(&v[i+1], &v[i], (n - i) * sizeof(struct hash_entry));

  /* Insert.   */
  (*hash)->hash[i] = entry;
  (*hash)->num_elements++;

  hash_assert(*hash);
  return 0;
}

static void hash_print(hash_t hash)
{
  printf("num_elements = %lu\n", hash->num_elements);
  printf("current_size = %lu\n", hash->current_size);
  for (size_t i = 0; i < hash->num_elements; i++) {
    printf("0x%lx => 0x%lx\n", (uintptr_t) hash->hash[i].key,
                               (uintptr_t) hash->hash[i].value);
  }
}

int hash_delete(hash_t *hash, void *key)
{
  size_t n = (*hash)->num_elements;
  struct hash_entry *entry = hash_get_value(*hash, key);
  struct hash_entry *v = (*hash)->hash;

  if (entry == NULL) {
    return 1;
  }

  size_t i = ((uintptr_t)entry - (uintptr_t)v) / sizeof(struct hash_entry);
  memmove(&v[i], &v[i+1], (n - i - 1) * sizeof(*entry));
  (*hash)->num_elements--;

  hash_print(*hash);

  return 0;
}

void hash_destroy(hash_t hash)
{
  if (hash) {
    free(hash);
  }
}

/* Used for testing.  */
#if 0
int main(void)
{
  hash_t hash = hash_table_create(2);

  const int n = 65536;

  int arr[n];
  for (int i = 0; i < n; i++) {
    arr[i] = n - i;
  }

  for (int i = 0; i < n; i++) {
    hash_insert_single(&hash, (void *) arr[i], (void *) i);
    arr[i] = i;
  }

/*
  hash_insert(&hash, (void *) 10, (void *) 1);
  hash_insert(&hash, (void *) 7 , (void *) 2);
  hash_insert(&hash, (void *) 11, (void *) 3);
  hash_insert(&hash, (void *) 3 , (void *) 4);
  hash_insert(&hash, (void *) 5 , (void *) 5);
  hash_insert(&hash, (void *) 2 , (void *) 6);
  hash_insert(&hash, (void *) 1 , (void *) 7);

  hash_insert(&hash, (void *) 20 , (void *) 7);
  hash_insert(&hash, (void *) 15 , (void *) 7);
  hash_insert(&hash, (void *) 17 , (void *) 7);
  hash_insert(&hash, (void *) 19 , (void *) 7);
*/

  hash_print(hash);
/*
  printf("-----------------------\n");

  hash_delete(&hash, (void *) 5);
  hash_delete(&hash, (void *) 10);
  hash_delete(&hash, (void *) 7);
  hash_delete(&hash, (void *) 11);
  hash_delete(&hash, (void *) 3);
  hash_delete(&hash, (void *) 2);
  hash_delete(&hash, (void *) 1);
*/
  hash_destroy(hash);

  return 0;
}
#endif
