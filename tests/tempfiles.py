#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2022 SUSE Software Solutions GmbH
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
import os

# This test checks if ulp tool left temporary files behind.
errno = 0
tmp_list = os.listdir("/tmp/")

for fname in tmp_list:
  if fname.startswith("ulp-") == True:
    # Flag error and remove any temp file we are left, so it does not
    # contaminate next test run.
    errno = 1
    os.remove("/tmp/" + fname)

exit(errno)
