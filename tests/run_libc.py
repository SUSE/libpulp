#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020-2025 SUSE Software Solutions GmbH
#
#   This file is part of libpulp.
#
#   libpulp is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.
#
#   libpulp is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with libpulp.  If not, see <http://www.gnu.org/licenses/>.

import re
import testsuite
import subprocess

# Make sure we can call libc.so.6 and it doesn't crash.

# Distros can have libc in many many places, there seems to be no
# standard way.  So we try them all.
libc_potential_paths = (
  '/usr/lib64/libc.so.6',
  '/lib64/libc.so.6',
  '/usr/lib/libc.so.6',
  '/lib/libc.so.6',
)

env = {'LD_PRELOAD': testsuite.libpulp_path}

for libc in libc_potential_paths:
  try:
    output = subprocess.check_output(libc, timeout=2, stderr=subprocess.STDOUT, env=env)
    gnu = re.search('GNU C Library', output.decode())
    if gnu:
      exit(0)
  except FileNotFoundError:
    pass


# We tested them all and everything failed.
exit(1)
