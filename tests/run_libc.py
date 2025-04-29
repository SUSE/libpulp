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
import os
import signal

# Make sure we can call libc.so.6 and it doesn't crash.

# Distros can have libc in many many places, there seems to be no
# standard way.  So we try them all.
libc_potential_paths = (
  '/usr/lib64/',
  '/lib64/',
  '/usr/lib/',
  '/lib/',
)

# Global variables with the path of libdl and libc.
path_libc = None
path_libdl = None

# Old versions of glibc has 'libdl.so.2' not integrated into libc.so.6.
# Try to find where it is.
for path in libc_potential_paths:
  libdl = path + 'libdl.so.2'
  libc = path + 'libc.so.6'

  if path_libdl is None and os.path.isfile(libdl):
    # libdl found.
    path_libdl = libdl

  if path_libc is None and os.path.isfile(libc):
    # libc found.
    path_libc = libc

# Older versions of glibc has a bug where calling libc.so.6 with libdl.so.2
# preloaded causes it to crash.  Check if we are in such case.
if path_libdl is not None:
  env = {'LD_PRELOAD': path_libdl}
  proc = subprocess.Popen(path_libc, stderr=subprocess.STDOUT, env=env)
  proc.wait()

  if proc.returncode == -signal.SIGSEGV:
    # Our glibc has this bug. There is nothing we can do.
    exit(77)

# Proceed with the test.
env = {'LD_PRELOAD': testsuite.libpulp_path}

output = subprocess.check_output(path_libc, timeout=5, stderr=subprocess.STDOUT, env=env)
gnu = re.search('GNU C Library', output.decode())
if gnu:
  exit(0)


# We tested them all and everything failed.
exit(1)
