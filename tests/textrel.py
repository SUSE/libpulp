#!/usr/bin/env python3

#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020-2025 SUSE Software Solutions GmbH
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
import subprocess

# Make sure libpulp is built without TEXTREL.

command = ['readelf', '-d', testsuite.libpulp_path]
try:
  output = subprocess.check_output(command, timeout=10, stderr=subprocess.STDOUT)
  textrel = re.search('TEXTREL', output.decode())
  if not textrel:
    exit(0)

except subprocess.TimeoutExpired:
  print('readelf timeout')
  exit(77)

exit(1)
