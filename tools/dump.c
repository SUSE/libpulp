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

#include <stdio.h>
#include <sys/types.h>

#include "arguments.h"
#include "dump.h"
#include "introspection.h"
#include "patches.h"

extern struct ulp_metadata ulp;

static void
dump_metadata(struct ulp_metadata *ulp, int buildid_only)
{
  struct ulp_object *obj;
  struct ulp_unit *unit;
  const char *buildid_string = buildid_to_string(ulp->patch_id);

  if (ulp) {
    if (!buildid_only) {
      fprintf(stdout, "patch id: %s\n", buildid_string);
      fprintf(stdout, "so filename: %s\n", ulp->so_filename);
    }
    obj = ulp->objs;
    if (obj) {
      buildid_string = buildid_to_string((unsigned char *)obj->build_id);
      if (!buildid_only) {
        fprintf(stdout, "\n* build id: %s\n", buildid_string);
      }
      else {
        fprintf(stdout, "%s\n", buildid_string);
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
run_dump(struct arguments *arguments)
{
  if (load_patch_info(arguments->args[0])) {
    WARN("error parsing the metadata file (%s).", arguments->args[0]);
    return 1;
  }
  dump_metadata(&ulp, arguments->buildid);
  return 0;
}
