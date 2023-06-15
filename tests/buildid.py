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

# Check the comments of `libbuildid_livepatch1.ulp` Makefile rule in
# Makefile.am on this folder.
#
# This test should fail because of buildid mismatch.

import testsuite
import subprocess

errorcode = 1

child = testsuite.spawn('buildid')
child.expect('Waiting for input.')

child.sendline('')
child.expect('1338');

out = child.livepatch('.libs/libbuildid_livepatch1.so', capture_tool_output=True)
if out.find("buildid mismatch") == -1:
  errorcode = 1
else:
  errorcode = 0

child.close(force=True)
exit(errorcode)
