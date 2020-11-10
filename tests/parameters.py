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

# Start the test program and check default behavior
child = pexpect.spawn('./' + testname, timeout=1, env=preload,
                      encoding='utf-8')
child.logfile = sys.stdout

child.expect('Waiting for input.')
print('Greeting... ok.')

child.sendline('')
child.expect('1-2-3-4-5-6-7-8\r\n');
child.expect('1.0-2.0-3.0-4.0-5.0-6.0-7.0-8.0-9.0-10.0\r\n');
print('First call to libparameters... ok.')

# Apply live patch and check for new behavior
ret = subprocess.run([trigger, str(child.pid),
                      'libparameters_livepatch1.ulp'])
if ret.returncode:
  print('Failed to apply livepatch #1 for libparameters')
  exit(1)

child.sendline('')
child.expect('8-7-6-5-4-3-2-1\r\n');
child.expect('10.0-9.0-8.0-7.0-6.0-5.0-4.0-3.0-2.0-1.0\r\n');
print('Second call to libparameters... ok.')

# Kill the child process and exit
child.close(force=True)
exit(0)
