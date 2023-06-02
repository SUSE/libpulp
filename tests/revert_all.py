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

import testsuite

child = testsuite.spawn('numserv')

child.expect('Waiting for input.')

# Reverting all patches from a library that currently have no patches installed
# should fail for a single process.
try:
  child.livepatch(revert_lib="libhundreds.so.0")
  exit(1)
except:
  pass

child.sendline('hundred')
child.expect('100')

child.livepatch('.libs/libhundreds_livepatch1.so')

child.sendline('hundred')
child.expect('200', reject='100')

child.livepatch('.libs/libhundreds_livepatch2.so')

child.sendline('hundred')
child.expect('300', reject=['100', '200'])

child.livepatch('.libs/libhundreds_livepatch3.so')

child.sendline('hundred')
child.expect('400', reject=['100', '200', '300'])

child.livepatch(revert_lib="libhundreds.so.0")

child.sendline('hundred')
child.expect('100', reject=['200', '300', '400']);

child.close(force=True)
exit(0)
