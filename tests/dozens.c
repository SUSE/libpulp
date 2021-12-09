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

static int
hidden_dozen(void)
{
  /* Clang removes the symbol completely if it sees that it can inline the
     function, even with -fno-inline or __attribute__((noinline)).  Even with
     the volatile, it generates a jump to symbol rather than a function, which
     means this function cannot be livepatched.  However, the hidden.py test
     only check if this symbol is present in .symtab, so this is fine.  */
  volatile int x = 12;
  return x;
}

int
dozen(void)
{
  return hidden_dozen();
}
