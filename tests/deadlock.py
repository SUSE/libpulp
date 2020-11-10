#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020 SUSE Software Solutions GmbH
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

from tests import *

# Since the deadlock demonstrated by this test case does not occur
# everytime it executes, run it in a loop. The amount of iterations
# hardcoded is arbitrary
errors = 0
for attempt in range(32):
  # Start the test program
  child = pexpect.spawn('./' + testname, timeout=20, env=preload,
                        encoding='utf-8')

  # Wait for the test program to be ready
  child.expect('Waiting for input.\r\n')

  # Check default behavior
  print('Testing output before live patch... ', end='')
  child.sendline('')
  child.expect('hello\r\n')
  print('OK.')

  # Applying a live patch to a process entails stopping all of its
  # threads, then stealing one of them to jack into the process and call
  # libpulp.so's routines that load and apply the live patch. These
  # routines are called from the context of a signal-handler, and, as
  # such, should not make calls to Asynchronous Signal Unsafe functions.
  # However, libpulp calls dlopen, which is AS-Unsafe.
  try:
    ret = subprocess.run([trigger, str(child.pid),
                          'libblocked_livepatch1.ulp'], timeout=20)
    if ret.returncode:
      print('Failed to apply livepatch #1 for libblocked')
      errors = 1
  except subprocess.TimeoutExpired:
    print('Deadlock reached when appling livepatch')
    errors = 1
  else:
    # Check that the livepatch was applied correctly
    print('Testing output after live patch... ', end='')
    child.sendline('')
    child.expect('hello_world\r\n')
    print('OK.')
  finally:
    # Always kill the child process
    child.close(force=True)

  # Stop the loop at the first time the deadlock occurs.
  if errors:
    break

exit(errors)
