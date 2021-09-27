#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020-2021 SUSE Software Solutions GmbH
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

import subprocess

import testsuite

# Since the deadlock demonstrated by this test case does not occur
# everytime it executes, run it in a loop. The amount of iterations
# hardcoded is arbitrary
errors = 0
for attempt in range(32):
  child = testsuite.spawn('deadlock', log=None)

  child.expect('Waiting for input.')

  child.sendline('')
  child.expect('hello')

  # Applying a live patch to a process entails stopping all of its
  # threads, then stealing one of them to jack into the process and call
  # libpulp.so's routines that load and apply the live patch. These
  # routines are called from the context of a signal-handler, and, as
  # such, should not make calls to Asynchronous Signal Unsafe functions.
  # However, libpulp calls dlopen, which is AS-Unsafe.
  try:
    child.livepatch('libblocked_livepatch1.ulp', retries=10000, timeout=20)
  except subprocess.TimeoutExpired:
    print('Deadlock detected.')
    errors = 1
  else:
    child.sendline('')
    child.expect('olleh', reject='hello')
  finally:
    # Always kill the child process
    child.close(force=True)

  # Stop the loop at the first time the deadlock occurs.
  if errors:
    break

exit(errors)
