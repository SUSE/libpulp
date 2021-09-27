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
#include "messages.h"
#include "packer.h"
#include "patches.h"
#include "post.h"
#include "revert.h"
#include "trigger.h"

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
"                             human readable form.\n"
"   packer                    Creates a livepatch METADATA file based on a\n"
"                             live patch description on ARG1.\n"
"   trigger                   Applies the live patch in ARG1 to the process\n"
"                             with PID\n"
"   post                      Post process patch container (.so file) in ARG1.\n"
"   reverse                   Create reverse livepatch from metadata in ARG1.\n"
"   messages                  Print livepatch information contained in libpulp.\n";

/* clang-format on */

/* switches that don't have a shorthand.  */
#define ULP_OP_REVERT_ALL 256

static struct argp_option options[] = {
  { 0, 0, 0, 0, "Options:", 0 },
  { "verbose", 'v', 0, 0, "Produce verbose output", 0 },
  { "quiet", 'q', 0, 0, "Don't produce any output", 0 },
  { 0, 0, 0, 0, "patches, check & trigger commands only:", 0 },
  { "pid", 'p', "PID", 0, "Target process with PID", 0 },
  { 0, 0, 0, 0, "dump & patches command only:", 0 },
  { "buildid", 'b', 0, 0, "Print the build id", 0 },
  { 0, 0, 0, 0, "trigger command only:", 0 },
  { "retries", 'r', "N", 0, "Retry N times if process busy", 0 },
  { "revert-all", ULP_OP_REVERT_ALL, "LIB", 0, "Revert all patches from LIB",
    0 },
#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
  { "check-stack", 'c', 0, 0, "Check the call stack before live patching", 0 },
#endif
  { 0, 0, 0, 0, "packer & reverse commands only:", 0 },
  { "output", 'o', "FILE", 0, "Write output to FILE", 0 },
  { 0, 0, 0, 0, "packer command only:", 0 },
  { "livepatch", 'l', "LIVEPATCH", 0,
    "Use this livepatch file\nDefaults to the one described in ARG1", 0 },
  { "target", 't', "LIBRARY", 0,
    "Use this target library\nDefaults to the one described in ARG1", 0 },
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
    { "patches", ULP_PATCHES }, { "check", ULP_CHECK },
    { "dump", ULP_DUMP },       { "packer", ULP_PACKER },
    { "trigger", ULP_TRIGGER }, { "post", ULP_POST },
    { "reverse", ULP_REVERSE }, { "messages", ULP_MESSAGES },
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

    case ULP_PACKER:
    case ULP_CHECK:
      if (state->arg_num < 2)
        argp_error(state, "Too few arguments.");
      break;

    case ULP_TRIGGER:
      if (arguments->library) {
        /* revert-all was passed to trigger.  */
        if (state->arg_num < 1)
          argp_error(state, "Too few arguments.");

        path_length = strlen(arguments->library);
        if (path_length > ULP_PATH_LEN)
          argp_error(state, "LIB name must be shorter than %d bytes; got %d.",
                     ULP_PATH_LEN, path_length);
      }
      else {
        /* revert-all was not passed to trigger. Metadata file is required.  */
        if (state->arg_num < 2)
          argp_error(state, "Too few arguments.");
      }

      if (state->arg_num >= 2) {
        path_length = strlen(arguments->args[0]);
        if (path_length > ULP_PATH_LEN)
          argp_error(state,
                     "METADATA path must be shorter than %d bytes; got %d.",
                     ULP_PATH_LEN, path_length);
      }
      break;

    /* Currently, DUMP, POST & REVERT does the same checks.  */
    case ULP_REVERSE:
    case ULP_POST:
    case ULP_DUMP:
      if (state->arg_num < 2)
        argp_error(state, "Too few arguments.");

      path_length = strlen(arguments->args[0]);
      if (path_length > ULP_PATH_LEN)
        argp_error(state,
                   "METADATA path must be shorter than %d bytes; got %d.",
                   ULP_PATH_LEN, path_length);
      break;

    case ULP_MESSAGES:
      if (arguments->pid == 0)
        argp_error(state, "pid is mandatory in 'messages' comamnd.");
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
      arguments->buildid = 1;
      break;
    case 'o':
      arguments->metadata = arg;
      break;
    case 'l':
      arguments->livepatch = arg;
      break;
    case 't':
      arguments->library = arg;
      break;
    case 'r':
      arguments->retries = atoi(arg);
      if (arguments->retries < 1)
        argp_error(state,
                   "The argument to '-r' must be greater than zero; got %d.",
                   arguments->retries);
      break;
    case ULP_OP_REVERT_ALL:
      arguments->library = get_basename(arg);
      break;
#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
    case 'c':
      arguments->check_stack = 1;
      break;
#endif
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

  /* Initialize retries correctly.  */
  arguments.retries = 1;

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

    case ULP_PACKER:
      ret = run_packer(&arguments);
      break;

    case ULP_TRIGGER:
      ret = run_trigger(&arguments);
      break;

    case ULP_POST:
      ret = run_post(&arguments);
      break;

    case ULP_REVERSE:
      ret = run_reverse(&arguments);
      break;

    case ULP_MESSAGES:
      ret = run_messages(&arguments);
      break;
  }

  return ret;
}
