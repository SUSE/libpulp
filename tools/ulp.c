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
#include "extract.h"
#include "introspection.h"
#include "livepatchable.h"
#include "messages.h"
#include "packer.h"
#include "patches.h"
#include "post.h"
#include "set_patchable.h"
#include "trigger.h"

#include <unistd.h>

#ifdef ENABLE_AFL
#define AFL_INIT_SET0(_p) \
  do { \
    argv = afl_init_argv(&argc); \
    argv[0] = (_p); \
    if (!argc) \
      argc = 1; \
  } \
  while (0)

#define MAX_CMDLINE_LEN 100000
#define MAX_CMDLINE_PAR 1000

__attribute__((unused)) static char **
afl_init_argv(int *argc)
{

  static char in_buf[MAX_CMDLINE_LEN];
  static char *ret[MAX_CMDLINE_PAR];

  char *ptr = in_buf;
  int rc = 0;

  if (read(0, in_buf, MAX_CMDLINE_LEN - 2) < 0) {
  }

  while (*ptr) {

    ret[rc] = ptr;
    if (ret[rc][0] == 0x02 && !ret[rc][1])
      ret[rc]++;
    rc++;

    while (*ptr)
      ptr++;
    ptr++;
  }

  *argc = rc;

  return ret;
}

#undef MAX_CMDLINE_LEN
#undef MAX_CMDLINE_PAR
#endif /* ENABLE_AFL  */

static error_t parser(int, char *, struct argp_state *);
static bool check_color_available(void);

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
"   messages                  Print livepatch information contained in libpulp.\n"
"   livepatchable             Check if .so library in ARG1 is livepatchable.\n"
"   set_patchable             Enable/disable livepatching in process given by -p.\n";

/* clang-format on */

/* switches that don't have a shorthand.  */
#define ULP_OP_REVERT_ALL 256
#define ULP_OP_REVERT 257
#define ULP_OP_COLOR 258
#define ULP_OP_TIMEOUT 259
#define ULP_OP_DISABLE_THREADING 260
#define ULP_OP_RECURSIVE 261
#define ULP_OP_DISABLE_SUMMARIZATION 262

static struct argp_option options[] = {
  { 0, 0, 0, 0, "Options:", 0 },
  { "verbose", 'v', 0, 0, "Produce verbose output", 0 },
  { "quiet", 'q', 0, 0, "Don't produce any output", 0 },
  { 0, 0, 0, 0, "patches, check & trigger commands only:", 0 },
  { "process", 'p', "process", 0, "Target process name, wildcard, or PID", 0 },
  { "user", 'u', "user", 0, "User name, wildcard, or UID", 0 },
  { "disable-threading", ULP_OP_DISABLE_THREADING, 0, 0,
    "Do not launch additional threads", 0 },
  { 0, 0, 0, 0, "dump & patches command only:", 0 },
  { "buildid", 'b', 0, 0, "Print the build id", 0 },
  { 0, 0, 0, 0, "trigger command only:", 0 },
  { "revert-all", ULP_OP_REVERT_ALL, "LIB", 0,
    "Revert all patches from LIB. If LIB=target, then all patches from the "
    "target library within the passed livepatch will be reverted.",
    0 },
  { "timeout", ULP_OP_TIMEOUT, "t", 0,
    "Set trigger timeout to t seconds (default 200s)", 0 },
  { "disable-summarization", ULP_OP_DISABLE_SUMMARIZATION, 0, 0,
    "Disable trigger ouput summarization", 0 },
  { "recursive", ULP_OP_RECURSIVE, 0, 0, "Search for patches recursively", 0 },
  { "root", 'R', "PREFIX", 0,
    "Append prefix to livepatch path when passing it to target process", 0 },
#if defined ENABLE_STACK_CHECK && ENABLE_STACK_CHECK
  { "check-stack", 'c', 0, 0, "Check the call stack before live patching", 0 },
#endif
  { 0, 0, 0, 0, "trigger & set_patchable commands only:", 0 },
  { "retries", 'r', "N", 0, "Retry N times if process busy", 0 },
  { 0, 0, 0, 0, "trigger & dump commands only:", 0 },
  { "revert", ULP_OP_REVERT, 0, 0,
    "revert livepatch / dump reverse patch info.", 0 },
  { 0, 0, 0, 0, "packer commands only:", 0 },
  { "output", 'o', "FILE", 0, "Write output to FILE", 0 },
  { 0, 0, 0, 0, "packer command only:", 0 },
  { "livepatch", 'l', "LIVEPATCH", 0,
    "Use this livepatch file\nDefaults to the one described in ARG1", 0 },
  { "target", 't', "LIBRARY", 0,
    "Use this target library\nDefaults to the one described in ARG1", 0 },
  { "color", ULP_OP_COLOR, "yes/no/auto", 0, "Enable/disable colored messages",
    0 },
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
    { "patches", ULP_PATCHES },   { "check", ULP_CHECK },
    { "dump", ULP_DUMP },         { "packer", ULP_PACKER },
    { "trigger", ULP_TRIGGER },   { "post", ULP_POST },
    { "messages", ULP_MESSAGES }, { "livepatchable", ULP_LIVEPATCHABLE },
    { "extract", ULP_EXTRACT },   { "set_patchable", ULP_SET_PATCHABLE },
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

    case ULP_EXTRACT:
    case ULP_PACKER:
    case ULP_CHECK:
      if (state->arg_num < 2)
        argp_error(state, "Too few arguments.");
      break;

    case ULP_TRIGGER:
      if (arguments->library) {
        /* revert-all was passed to trigger.  */
        if (arguments->revert)
          argp_error(state,
                     "--revert and --revert-all can not be used together.");

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

    /* Currently, DUMP & POST does the same checks.  */
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
      if (arguments->process_wildcard == 0)
        argp_error(state, "process is mandatory in 'messages' command.");
      break;

    case ULP_SET_PATCHABLE:
      if (state->arg_num < 2)
        argp_error(state, "passing 'enable' or 'disable' in ARG1 is mandatory "
                          "in set_patches.");
      break;

    case ULP_LIVEPATCHABLE:
      if (state->arg_num < 2) {
        argp_error(state, "file is mandatory in 'livepatchable' command.");
      }
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
      arguments->process_wildcard = arg;
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
    case 'R':
      arguments->prefix = arg;
      break;
    case ULP_OP_REVERT_ALL:
      arguments->library = get_basename(arg);
      break;
    case ULP_OP_REVERT:
      arguments->revert = 1;
      break;
    case ULP_OP_DISABLE_THREADING:
      arguments->disable_threads = 1;
      break;

    case ULP_OP_RECURSIVE:
      arguments->recursive = 1;
      break;

    case ULP_OP_DISABLE_SUMMARIZATION:
      arguments->no_summarization = 1;
      break;

    case 'u':
      arguments->user_wildcard = arg;
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

    case ULP_OP_COLOR:
      if (strcmp(arg, "no") == 0 || strcmp(arg, "n") == 0) {
        no_color = true;
      }
      else if (strcmp(arg, "auto") == 0) {
        no_color = !check_color_available();
      }
      else {
        no_color = false;
      }
      break;

    case ULP_OP_TIMEOUT:
      if (isnumber(arg)) {
        long num = atol(arg);
        if (num < 0)
          argp_error(state, "--timeout value must be a non-negative integer");
        set_run_and_redirect_timeout(num);
      }
      else {
        argp_error(state, "--timeout value must be a non-negative integer");
      }
      break;

    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

static bool
check_color_available(void)
{
  /* Check if NO_COLOR env variable is set.  */
  if (getenv("NO_COLOR"))
    return false;

  /* Check if terminal supports ANSI escapes.  */
  if (isatty(STDOUT_FILENO)) {
    const char *term = getenv("TERM");
    if (term && strcmp(term, "dumb")) {
      return true;
    }
  }

  /* ANSI escapes not available.  */
  return false;
}

void
change_color(const char *ansi_escape)
{
  /* If no_color is set, doens't push colors.  */
  if (!no_color) {
    fputs(ansi_escape, stdout);
  }
}

int
main(int argc, char **argv, char *envp[] __attribute__((unused)))
{
#ifdef ENABLE_AFL
  while (*envp) {
    const char *key = strtok(*envp, "=");
    const char *val = strtok(NULL, "=");
    if (!strcmp(key, "ULP_IN_AFL_TEST") && val && *val == '1') {
      argv = afl_init_argv(&argc);
      break;
    }
    envp++;
  }
#endif /* ENABLE_AFL  */

  struct arguments arguments = { 0 };
  int ret = 0;

  /* Set no_color here, as user may not have passed --color.  */
  no_color = !check_color_available();

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

    case ULP_MESSAGES:
      ret = run_messages(&arguments);
      break;

    case ULP_LIVEPATCHABLE:
      ret = run_livepatchable(&arguments);
      break;

    case ULP_EXTRACT:
      ret = run_extract(&arguments);
      break;

    case ULP_SET_PATCHABLE:
      ret = run_set_patchable(&arguments);
      break;
  }

  return ret;
}
