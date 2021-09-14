/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020-2021 SUSE Software Solutions GmbH
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "arguments.h"
#include "check.h"
#include "config.h"
#include "dump.h"
#include "introspection.h"
#include "patches.h"

static error_t parser(int, char *, struct argp_state *);

/* These variables are used by ARGP.  */

const char *argp_program_version = PACKAGE_STRING;

static const char args_doc[] = "COMMAND [ARG1 ARG2 ...]";

/* clang-format off */
static const char doc[] =
"ulp: Userspace Live Patch tool.\n"
"\n"
" This tool executes a COMMAND passed in the argument list.\n"
" Possible COMMANDs are:\n"
"\n"
"   patches                   List active patches.\n"
"   check                     Check if patch in ARG1 is applied on process\n"
"                             with -p PID.\n"
"   dump                      Print the content of metadata file on ARG1 in\n"
"                             human readable form.\n";
/* clang-format on */

static struct argp_option options[] = {
  { 0, 0, 0, 0, "Options:", 0 },
  { "verbose", 'v', 0, 0, "Produce verbose output", 0 },
  { "quiet", 'q', 0, 0, "Don't produce any output", 0 },
  { 0, 0, 0, 0, "patches & check commands only:", 0 },
  { "pid", 'p', "PID", 0, "Target process with PID", 0 },
  { 0, 0, 0, 0, "dump command only:", 0 },
  { "buildid", 'b', 0, 0, "Only print the build id (dump only.)", 0 },
  { 0 }
};

static struct argp argp = { options, parser, args_doc, doc, NULL, NULL, NULL };

/* End of variables used by argp.  */

/* Get command string and return an command code for it.
 *
 * @param str - String representation of command.
 * @return code of command.
 */

static command_t
command_from_string(const char *str)
{
  struct entry
  {
    const char *string;
    command_t command;
  };

  static const struct entry entries[] = {
    { "patches", ULP_PATCHES },
    { "check", ULP_CHECK },
    { "dump", ULP_DUMP },
  };

  size_t i;

  for (i = 0; i < ARRAY_LENGTH(entries); i++) {
    if (!strcmp(entries[i].string, str))
      return entries[i].command;
  }

  return ULP_NONE;
}

/* This function is called when all arguments have been parsed.  */
static void
handle_end_of_arguments(const struct argp_state *state)
{
  const struct arguments *arguments = state->input;
  int path_length;

  if (state->arg_num < 1)
    argp_error(state, "Too few arguments.");

  if (arguments->quiet && arguments->verbose)
    argp_error(state, "You must specify either '-v' or '-q' or none.");

  switch (arguments->command) {
    case ULP_NONE:
      argp_error(state, "Invalid command.");
      break;

    case ULP_PATCHES:
      if (state->arg_num > 1)
        argp_error(state, "Too many arguments.");
      break;

    case ULP_CHECK:
      if (state->arg_num < 2)
        argp_error(state, "Too few arguments.");
      break;

    case ULP_DUMP:
      if (state->arg_num < 2)
        argp_error(state, "Too few arguments.");

      path_length = strlen(arguments->args[0]);
      if (path_length > ULP_PATH_LEN)
        argp_error(state,
                   "METADATA path must be shorter than %d bytes; got %d.",
                   ULP_PATH_LEN, path_length);
      break;
  }
}

/* Parse the arguments in command line.  */
static error_t
parser(int key, char *arg, struct argp_state *state)
{
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
      break;
    case 'b':
      arguments->buildid_only = 1;
      break;
    case ARGP_KEY_ARG:
      if (state->arg_num == 0) {
        arguments->command = command_from_string(arg);
        if (arguments->command == ULP_NONE)
          argp_error(state, "Invalid command: %s.", arg);
      }
      else if (state->arg_num <= ARGS_MAX)
        arguments->args[state->arg_num - 1] = arg;
      else
        argp_error(state, "Too many arguments.");
      break;

    case ARGP_KEY_END:
      handle_end_of_arguments(state);
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

int
main(int argc, char **argv)
{
  struct arguments arguments = { 0 };
  int ret = 0;

  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  switch (arguments.command) {
    case ULP_NONE:
      ret = 1;
      break;

    case ULP_PATCHES:
      ret = run_patches(&arguments);
      break;

    case ULP_CHECK:
      ret = run_check(&arguments);
      break;

    case ULP_DUMP:
      ret = run_dump(&arguments);
      break;
  }

  return ret;
}
