/*
 *  libpulp - User-space Livepatching Library
 *
 *  Copyright (C) 2024 SUSE Software Solutions GmbH
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

/* This function has hidden visibility.  We should not be able to do an weak
   externalization here.  */

static char string[] = "This is a hidden string";

__attribute__((visibility("hidden")))
void *get_hidden_address(void)
{
  return string;
}

void *get_address(void)
{
  return get_hidden_address();
}
