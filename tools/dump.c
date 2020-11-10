/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017-2020 SUSE Software Solutions GmbH
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

#include "introspection.h"

extern struct ulp_metadata ulp;

void id2str(char *str, char *id, int idlen)
{
    int i;
    char item[4];

    for (i = 0; i < idlen; i++) {
	snprintf(item, 4, "%02x ", (unsigned int) (*(id+i)&0x0FF));
	str = stpcpy(str, item);
    }
}

void dump_metadata(struct ulp_metadata *ulp)
{
    char buffer[128];
    struct ulp_object *obj;
    struct ulp_unit *unit;
    if (ulp) {
	id2str(buffer, (char *) ulp->patch_id, 32);
	fprintf(stderr, "patch id: %s\n", buffer);
	fprintf(stderr, "so filename: %s\n", ulp->so_filename);
	obj = ulp->objs;
	if (obj) {
	    id2str(buffer, obj->build_id, obj->build_id_len);
	    fprintf(stderr, "\n* build id: %s\n", buffer);
	    if (obj->name) {
		fprintf(stderr, "* name: %s\n", obj->name);
	    } else {
		fprintf(stderr, "* name: \n");
	    }
	    fprintf(stderr, "* units: %d\n", obj->nunits);
	    unit = obj->units;
	    while (unit) {
		fprintf(stderr, "\n** old_fname: %s\n", unit->old_fname);
		fprintf(stderr, "** new_fname: %s\n", unit->new_fname);
		fprintf(stderr, "** old_faddr: %p\n", unit->old_faddr);
		unit = unit->next;
	    }
	}
    }
}

int main(int argc, char **argv) {
    if (argc != 2)
      return 1;
    load_patch_info(argv[1]);
    dump_metadata(&ulp);
    return 0;
}

