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

#ifndef ARGUMENTS_H
#define ARGUMENTS_H

#include "config.h"

#define ARGS_MAX 1

typedef enum
{
  ULP_NONE,
  ULP_PATCHES,
  ULP_CHECK,
  ULP_DUMP,
  ULP_PACKER,
  ULP_TRIGGER,
  ULP_POST,
  ULP_MESSAGES,
  ULP_LIVEPATCHABLE,
  ULP_EXTRACT,
  ULP_SET_PATCHABLE,
} command_t;

struct arguments
{
  const char *args[ARGS_MAX];
  const char *livepatch;
  const char *library;
  const char *metadata;
  const char *process_wildcard;
  const char *user_wildcard;
  const char *prefix;
  const char *with_debuginfo;
  command_t command;
  int retries;
  int quiet;
  int verbose;
  int buildid;
  int revert;
  int disable_threads;
  int recursive;
  int no_summarization;
  int only_livepatched;
  int disable_seccomp;
#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
  int check_stack;
#endif
};

#endif
