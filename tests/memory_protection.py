#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2021 SUSE Software Solutions GmbH
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

import testsuite

child = testsuite.spawn('memory_protection')

child.expect('Waiting for input.')

# Every time a newline is sent, the test program touchs code memory
child.sendline('')
child.expect('Non-NULL');

child.livepatch('libaddress_livepatch1.ulp')

# Try to touch code memory after live patching
child.sendline('')
try:
  child.expect('NULL');
except EOFError:
  # Diagnose the error
  print('Touching code after live patch failed.')
  if child.isalive() == False:
    print('The test program is dead')
  else:
    child.close(force=True)
  # Let the exception propagate, so that the stack trace gets printed
  raise

child.close(force=True)
exit(0)
