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
import sys
import os

if os.geteuid() == 0:
    child = testsuite.spawn('block_mprotect ./numserv')
else:
    print("Test not running as root.", file=sys.stdout)
    exit(77) # Skip test

child.expect('Waiting for input.')

child.sendline('dozen')
child.expect('12');

child.sendline('hundred')
child.expect('100');

# Now lets try to load a livepatch that would make seccomp complain.
child.livepatch('.libs/libsecdis_livepatch1.so', disable_seccomp=True)

# See if the process survived.
child.sendline('dozen')
child.expect('13', reject='12');

child.close(force=True)
exit(0)
