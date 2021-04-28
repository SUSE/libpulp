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

child = testsuite.spawn('contract')

child.expect('Waiting for input.')

errors = 0
child.sendline('')
child.sendline('')
child.expect('TYPE A data 128');
child.sendline('')
child.expect('TYPE B data 256.000000');

# Send the test program into the library.
child.sendline('')

# Apply live patch while inside library
child.livepatch('libcontract_livepatch1.ulp')

# Let the process resume and check fna behavior
child.sendline('')
child.expect('TYPE A data 128', reject='Invalid type.')

# Let the process resume and check fnb behavior
child.sendline('')
child.expect('TYPE B data 1024.000000', reject='Invalid type.')

child.close(force=True)
exit(errors)
