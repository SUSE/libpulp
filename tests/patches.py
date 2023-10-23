#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2023 SUSE Software Solutions GmbH
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

# Test `ulp patches` command.

import testsuite
import subprocess
import sys
import os

# Check if the ULP tool crashes if -p is passed to unexisting process.
command = [testsuite.ulptool, "patches", "-p", "99999"]
try:
    tool = subprocess.run(command, timeout=10, stderr=subprocess.STDOUT)
except:
    exit(1)

# It should actually return an error because we explicitly trieed to retrieve
# information of a non-running process.
if tool.returncode == 0:
    exit(1)

exit(0)
