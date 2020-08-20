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
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

int fibo(int n);

int main(int argc, char *argv[])
{
    int r, i, j;
    clock_t t;
    double time;

    if (argc < 2) return -1;

    fprintf(stderr, "sleeping for: %d secs\n", atoi(argv[1]));
    sleep(atoi(argv[1]));

    for (i = 0; i < 46; i++) {
        for (j = 0; j < 10; j++) {
            t = clock();
            r = fibo(i);
            t = clock() - t;
            time = ((double) t) / CLOCKS_PER_SEC;
            fprintf(stderr, "fibo(%d), %d, %f\n", i, r, time);
         }
    }
    return 0;
}
