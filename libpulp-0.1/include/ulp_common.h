/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017 SUSE Linux GmbH
 *
 *  This file is part of libpulp.
 *
 *  libpulp is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  libpulp is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with libpulp.  If not, see <http://www.gnu.org/licenses/>.
 *
 *  Author: Joao Moreira <jmoreira@suse.de>
 */

#include <stdint.h>

#ifndef _ULP_LIB_COMMON_
#define _ULP_LIB_COMMON_

#define OUT_PATCH_NAME "metadata.ulp"

#define WARN(format, ...) \
	fprintf(stderr, "ulp: " format "\n", ##__VA_ARGS__)

#define ULP_PATH_LEN 256
#define PRE_NOPS_LEN 33

extern __thread int __ulp_pending;

struct ulp_metadata {
  unsigned char patch_id[32];
  char *so_filename;
  void *so_handler;
  struct ulp_object *objs;
  uint32_t ndeps;
  struct ulp_dependency *deps;
  uint8_t type;
};

struct ulp_object {
  uint32_t build_id_len;
  uint32_t build_id_check;
  char *build_id;
  char *name;
  void *dl_handler;
  void *flag;
  uint32_t nunits;
  struct ulp_unit *units;
};

struct ulp_unit {
  char *old_fname;
  char *new_fname;
  void *old_faddr;
  struct ulp_unit *next;
};

struct ulp_dependency {
  unsigned char dep_id[32];
  char patch_id_check;
  struct ulp_dependency *next;
};

#endif
