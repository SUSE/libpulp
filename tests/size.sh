#!/bin/sh
#
#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2021-2025 SUSE Software Solutions GmbH
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

# Check if the code / variable size from libpulp does not surpass 1Mb

SIZE=$(nm --print-size --size-sort --radix=d ../lib/.libs/libpulp.so.0 | awk '{ sum += $2 } END {print sum}')
echo "Size: $SIZE"

if [ "x$SIZE" == "x" ]; then
  exit 1
fi

if [ $SIZE -gt $(expr 1024 \* 1024) ]; then
  exit 1
fi

exit 0
