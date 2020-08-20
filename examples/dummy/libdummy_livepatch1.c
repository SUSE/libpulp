/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2020 SUSE Linux GmbH
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
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>

int new_bar() {
    fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
    fprintf(stderr, "LIVEPATCHED!\n");
    return 1;
}

int new_sleeping_bar(int time) {
    fprintf(stderr, "[THREAD %lu] ", syscall(SYS_gettid));
    fprintf(stderr, "SLEEPIN' LIVEPATCHED %d\n", time);
    sleep(time);
    return 1;
}
