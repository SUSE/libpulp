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
#include <stdio.h>

#include "introspection.h"

extern struct ulp_metadata ulp;

struct arguments
{
  char *args[1];
  int buildid_only;
};

static char doc[] = "Prints the content of the METADATA file\n"
                    "in human readable form.";

static char args_doc[] = "METADATA";

static struct argp_option options[] = { { 0, 0, 0, 0, "Options:", 0 },
                                        { "buildid", 'b', 0, 0,
                                          "Only print the build id", 0 },
                                        { 0 } };

static error_t
parser(int key, char *arg, struct argp_state *state)
{
  int path_length;
  struct arguments *arguments;

  arguments = state->input;

  switch (key) {
    case 'b':
      arguments->buildid_only = 1;
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
                     "METADATA path must be shorter than %d bytes; got %d.",
                     ULP_PATH_LEN, path_length);
      }
      arguments->args[state->arg_num] = arg;
      break;
    case ARGP_KEY_END:
      if (state->arg_num < 1)
        argp_error(state, "Too few arguments.");
      break;
    default:
      return ARGP_ERR_UNKNOWN;
  }

  return 0;
}

void
id2str(char *str, char *id, int idlen)
{
  int i;
  char item[4];

  for (i = 0; i < idlen; i++) {
    snprintf(item, 4, "%02x ", (unsigned int)(*(id + i) & 0x0FF));
    str = stpcpy(str, item);
  }
}

void
dump_metadata(struct ulp_metadata *ulp, int buildid_only)
{
  char buffer[128];
  struct ulp_object *obj;
  struct ulp_unit *unit;
  if (ulp) {
    if (!buildid_only) {
      id2str(buffer, (char *)ulp->patch_id, 32);
      fprintf(stdout, "patch id: %s\n", buffer);
      fprintf(stdout, "so filename: %s\n", ulp->so_filename);
    }
    obj = ulp->objs;
    if (obj) {
      id2str(buffer, obj->build_id, obj->build_id_len);
      if (!buildid_only) {
        fprintf(stdout, "\n* build id: %s\n", buffer);
      }
      else {
        fprintf(stdout, "%s\n", buffer);
      }
      if (obj->name && !buildid_only) {
        fprintf(stdout, "* name: %s\n", obj->name);
      }
      else if (!buildid_only) {
        fprintf(stdout, "* name: \n");
      }
      if (!buildid_only) {
        fprintf(stdout, "* units: %d\n", obj->nunits);
      }
      unit = obj->units;
      while (unit && !buildid_only) {
        fprintf(stdout, "\n** old_fname: %s\n", unit->old_fname);
        fprintf(stdout, "** new_fname: %s\n", unit->new_fname);
        fprintf(stdout, "** old_faddr: %p\n", unit->old_faddr);
        unit = unit->next;
      }
    }
  }
}

int
main(int argc, char **argv)
{
  struct argp argp = { options, parser, args_doc, doc, NULL, NULL, NULL };
  struct arguments arguments;

  arguments.buildid_only = 0;
  argp_parse(&argp, argc, argv, 0, 0, &arguments);

  load_patch_info(arguments.args[0]);
  dump_metadata(&ulp, arguments.buildid_only);
  return 0;
}
