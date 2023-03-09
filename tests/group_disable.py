#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020-2023 SUSE Software Solutions GmbH
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
import os

env = { 'LD_PRELOAD': '../lib/.libs/libpulp.so',
        'LIBPULP_DISABLE_ON_GROUPS': str(os.getgid()) }

child = testsuite.spawn('numserv', env=env)

child.expect('Waiting for input.')

child.sendline('dozen')
child.expect('12');

child.sendline('hundred')
child.expect('100');

child.livepatch('.libs/libdozens_livepatch1.so', sanity=False)

child.sendline('dozen')
child.expect('12', reject='13');

child.close(force=True)
exit(0)
