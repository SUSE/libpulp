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

#include <librecursion2.h>

long long int __attribute__((noinline))
new_func_1(long long int n)
{
  if (n < 0)
    return 0;

  return -n + func_2(n-1);
}

long long int __attribute__((noinline))
new_func_2(long long int n)
{
  if (n < 0)
    return 0;

  return -2*n + func_1(n-1);
}
