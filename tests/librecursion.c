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

#include <librecursion.h>

long long int fibonacci(long long int n)
{
  if (n < 2)
    return n;

  return fibonacci(n-1) + fibonacci(n-2);
}

long long int lucas(long long int n)
{
  if (n == 0)
    return 2;
  if (n == 1)
    return 1;

  return lucas(n-1) + lucas(n-2);
}

long long int recursion(long long int n)
{
  return fibonacci(n);
}
