/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2025 SUSE Software Solutions GmbH
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
#include <dlfcn.h>
#include <unistd.h>

int main()
{
  void *handle = dlopen(".libs/libhundreds.so", RTLD_NOW | RTLD_GLOBAL);
  if (!handle) {
    printf("Failed to load libhundreds.so: %s\n", dlerror());
    return 1;
  }
  int (*hundred)(void) = dlsym(handle, "hundred");
  do {
    printf("hundred: %d\n", hundred());
    sleep(1);
  } while (1);

  return 0;
}
