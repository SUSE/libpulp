/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2017 SUSE Linux GmbH
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

#define _GNU_SOURCE
#include <stdio.h>
#include "../../include/ulp.h"

void dump_metadata(struct ulp_metadata *ulp)
{
    struct ulp_object *obj;
    struct ulp_unit *unit;
    if (ulp) {
	fprintf(stderr, "patch id: %s\n", ulp->patch_id);
	fprintf(stderr, "so filename: %s\n", ulp->so_filename);
	fprintf(stderr, "Objects: %d\n", ulp->nobjs);
	obj = ulp->objs;
	while (obj) {
	    fprintf(stderr, "\n* build id: %s\n", obj->build_id);
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
	    obj = obj->next;
	}
    }
}

int main() {
    struct ulp_metadata ulp;
    load_metadata(&ulp);
    dump_metadata(&ulp);
    return 0;
}

