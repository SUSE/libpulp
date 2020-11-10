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

# Common modules used in the test cases
import os
import pexpect
import re
import signal
import subprocess
import sys
import time

# Common variables used in the test cases

# ULP tools location
builddir = os.getcwd()
trigger = builddir + '/../tools/ulp_trigger'
check = builddir + '/../tools/ulp_check'
preload = {'LD_PRELOAD': builddir + '/../lib/.libs/libpulp.so'}

# Test case name
testname = os.path.splitext(sys.argv[0])
testname = os.path.basename(testname[0])
