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
static char doc[] =
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
"   set_patchable             Enable/disable livepatching in process.\n";

/* clang-format on */

static struct argp_option options[] = {};
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

static command_t
get_command_from_args(int argc, char **argv)
{
  command_t ret = ULP_NONE;
  int i;
  for (i = 0; i < argc; i++) {
    ret = command_from_string(argv[i]);
    if (ret != ULP_NONE) {
      return ret;
    }
  }

  return ret;
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
    case 'd':
      arguments->with_debuginfo = arg;
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

    case ULP_OP_ONLY_LIVEPATCHED:
      arguments->only_livepatched = 1;
      break;

    case ULP_OP_DISABLE_SECCOMP:
      arguments->disable_seccomp = 1;
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

static struct argp_option *
get_command_option(command_t cmd)
{
  static struct argp_option def = {};

  switch (cmd) {
    case ULP_NONE:
      return &def;
      break;

    case ULP_PATCHES:
      strcpy(doc, "Command: patches.\n");
      return get_command_option_patches();
      break;

    case ULP_CHECK:
      strcpy(doc, "Command: check.\n");
      return get_command_option_check();
      break;

    case ULP_DUMP:
      strcpy(doc, "Command: dump.\n");
      return get_command_option_dump();
      break;

    case ULP_PACKER:
      strcpy(doc, "Command: packer.\n");
      return get_command_option_packer();
      break;

    case ULP_TRIGGER:
      strcpy(doc, "Command: trigger.\n");
      return get_command_option_trigger();
      break;

    case ULP_POST:
      strcpy(doc, "Command: post.\n");
      return get_command_option_post();
      break;

    case ULP_MESSAGES:
      strcpy(doc, "Command: messages.\n");
      return get_command_option_messages();
      break;

    case ULP_LIVEPATCHABLE:
      strcpy(doc, "Command: livepatchable.\n");
      return get_command_option_livepatchable();
      break;

    case ULP_EXTRACT:
      strcpy(doc, "Command: extract.\n");
      return get_command_option_extract();
      break;

    case ULP_SET_PATCHABLE:
      strcpy(doc, "Command: set_patchable.\n");
      return get_command_option_set_patchable();
      break;
  }

  return &def;
}


static bool
requires_ptrace(command_t command)
{
  switch(command) {
    case ULP_NONE:
    case ULP_DUMP:
    case ULP_POST:
    case ULP_EXTRACT:
    case ULP_PACKER:
    case ULP_LIVEPATCHABLE:
      return false;

    case ULP_PATCHES:
    case ULP_TRIGGER:
    case ULP_CHECK:
    case ULP_MESSAGES:
    case ULP_SET_PATCHABLE:
      return true;
  }
  return false;
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

  /* Check for the command input.  */
  command_t cmd = get_command_from_args(argc, argv);

  /* Install an option parser according to command.  */
  argp.options = get_command_option(cmd);

  argp_parse(&argp, argc, argv, 0, 0, &arguments);


  /* Check if command requires ptrace.  */
  if (requires_ptrace(arguments.command) &&
        check_ptrace_scope() == false) {
    WARN("System has 'ptrace_scope' enabled. Please become root or disable it "
         "by setting:\n\n"
         "$ echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope\n\n"
         "and try again.");
    return EPERM;
  }

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
