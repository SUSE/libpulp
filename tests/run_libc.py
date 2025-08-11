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

path_libc = subprocess.check_output(
  ["gcc", "-print-file-name=libc.so.6"]
).strip()

path_libc = subprocess.check_output(
  ["realpath", path_libc]
).strip()

if not os.path.exists(path_libc):
  raise FileNotFoundError(f"{libc_path} not found")

path_libdl = subprocess.check_output(
  ["gcc", "-print-file-name=libdl.so.2"]
).strip()

path_libdl = subprocess.check_output(
  ["realpath", path_libdl]
).strip()

if not os.path.exists(path_libdl):
  raise FileNotFoundError(f"{libdl_path} not found")

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
