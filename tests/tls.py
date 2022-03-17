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

child = testsuite.spawn(testsuite.testname)

child.expect('Original TLS banner')
child.expect('Banner changed from thread_func: 0')
child.expect('Banner changed from thread_func: 1')

child.livepatch('.libs/libtls_livepatch1.so')

child.sendline('')
child.expect('String from live patch',
        reject=['String from thread_func: 0',
                'String from thread_func: 1',
                'Live patch data references not initialized'])

child.close(force=True)
exit(0)
