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

import subprocess
import testsuite

livepatch_metadata  = 'libparameters_livepatch2.ulp'
livepatch_container = 'libparameters_livepatch2.so'

child = testsuite.spawn('parameters')

child.expect('Waiting for input.')

errors = 1
try:
  child.livepatch(livepatch_metadata)
except subprocess.CalledProcessError:
  if not child.is_so_loaded(livepatch_container):
    errors = 0

child.close(force=True)
exit(errors)
