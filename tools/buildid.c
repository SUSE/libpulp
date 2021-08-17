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

#include <argp.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/user.h>

#include "config.h"
#include "introspection.h"
#include "ulp_common.h"

struct ulp_process target;
extern struct ulp_metadata ulp;

const char *argp_program_version = PACKAGE_STRING;

struct arguments
{
  char *args[1];
  pid_t pid;
  int quiet;
  int verbose;
};

static char doc[] =
    "Gets the NT_GNU_BUILD_ID of the library at\n"
    "LIBPATH in the process with PID this is \n"
    "Mostly for interal use.";

static char args_doc[] = "-p PID LIBPATH";

static struct argp_option options[] = {
  { "pid", 'p', "PID", 0, "Check patch status in the process with PID", 0 },
  { 0, 0, 0, 0, "Options:", 0 },
  { "verbose", 'v', 0, 0, "Produce verbose output", 0 },
  { "quiet", 'q', 0, 0, "Don't produce any output", 0 },
  { 0 }
};

static error_t
parser(int key, char *arg, struct argp_state *state)
{
  int path_length;
  struct arguments *arguments;

  arguments = state->input;

  switch (key) {
    case 'v':
      arguments->verbose = 1;
      break;
    case 'q':
      arguments->quiet = 1;
      break;
    case 'p':
      arguments->pid = atoi(arg);
      if (arguments->pid < 1)
        argp_error(state,
                   "The argument to '-p' must be greater than zero; got %d.",
                   arguments->pid);
      break;
    case ARGP_KEY_ARG:
      if (state->arg_num >= 1) {
        argp_error(state, "Too many arguments.");
      }
      if (state->arg_num == 0) {
        /* Path to live patch metadata file. */
        path_length = strlen(arg);
        if (path_length > ULP_PATH_LEN)
          argp_error(state,
                     "LIBPATH path must be shorter than %d bytes; got %d.",
                     ULP_PATH_LEN, path_length);
      }
      arguments->args[state->arg_num] = arg;
      break;
    case ARGP_KEY_END:
      if (state->arg_num < 1)
        argp_error(state, "Too few arguments.");
      if (arguments->quiet && arguments->verbose)
        argp_error(state, "You must specify either '-v' or '-q' or none.");
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

int
main(int argc, char **argv)
{
  char *libpath;
  int ret;
  char *id;

  struct ulp_process target;

  struct argp argp = { options, parser, args_doc, doc, NULL, NULL, NULL };
  struct arguments arguments;

  arguments.pid = 0;
  arguments.verbose = 0;
  arguments.quiet = 0;
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  /* Set the verbosity level in the common introspection infrastructure. */
  ulp_verbose = arguments.verbose;
  ulp_quiet = arguments.quiet;

  libpath = arguments.args[0];

  memset(&target, 0, sizeof(target));
  target.pid = arguments.pid;
  ret = initialize_data_structures(&target);
  if (ret) {
    WARN("error gathering target process information.");
    return -1;
  }

  ret = hijack_threads(&target);
  if (ret == -1) {
    FATAL("fatal error during live patch application (hijacking).");
    return -1;
  }
  if (ret > 0) {
    WARN("unable to hijack process.");
    return -1;
  }

  ret = buildid(&target, libpath);

  if (ret != 0) {
    WARN("somne other error (hijacked execution).");
  }

  ret = restore_threads(&target);

  if (ret) {
    FATAL("fatal error during build id fetch (restoring).");
    return -1;
  }

  ret = read_string(&id,target.pid,
                  target.dynobj_libpulp->buildid_buffer);
  fprintf(stderr,"%s\n", id);

  return ret;
}
