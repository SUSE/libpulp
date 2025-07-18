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

#ifndef PATCHES_H
#define PATCHES_H

#include "pcqueue.h"

#include <dirent.h>
#include <stdbool.h>

struct arguments;
struct ulp_process;
struct argp_option;

struct ulp_process_iterator
{
  struct ulp_process *now;
  struct ulp_process *last;

  const char *wildcard;
  const char *user_wildcard;
  uid_t target_uid;

  DIR *slashproc;
  struct dirent *subdir;

  producer_consumer_t *pcqueue;
};

struct ulp_process *process_list_next(struct ulp_process_iterator *);
struct ulp_process *process_list_begin(struct ulp_process_iterator *,
                                       const char *, const char *);
int process_list_end(struct ulp_process_iterator *);

#define FOR_EACH_ULP_PROCESS_FROM_USER_WILDCARD(p, wildcard, user_wildcard) \
  struct ulp_process_iterator _it; \
  for (p = process_list_begin(&_it, wildcard, user_wildcard); \
       process_list_end(&_it); p = process_list_next(&_it))

#define FOR_EACH_ULP_PROCESS_MATCHING_WILDCARD(p, wildcard) \
  FOR_EACH_ULP_PROCESS_FROM_USER_WILDCARD(p, wildcard, NULL)

#define FOR_EACH_ULP_PROCESS(p) FOR_EACH_ULP_PROCESS_MATCHING_WILDCARD(p, NULL)

bool has_libpulp_loaded(int pid);

const char *buildid_to_string(const unsigned char[BUILDID_LEN]);

size_t extract_ulp_comment_to_mem(const char *livepatch, char **out);

int run_patches(struct arguments *);

struct argp_option *get_command_option_patches(void);

#endif
