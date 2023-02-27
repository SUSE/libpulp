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

import os
import subprocess
import time

import testsuite
from testsuite import ulptool

errorcode = 1
child = testsuite.spawn('parameters', env=None)

child.expect('Waiting for input.')

child.sendline('')
child.expect('1-2-3-4-5-6-7-8');
child.expect('1.0-2.0-3.0-4.0-5.0-6.0-7.0-8.0-9.0-10.0');

try:
    child.livepatch('.libs/libparameters_livepatch1.so')
except subprocess.CalledProcessError:
    errorcode = 0

child.sendline('')
child.expect('1-2-3-4-5-6-7-8', reject='8-7-6-5-4-3-2-1');

child.close(force=True)
exit(errorcode)
