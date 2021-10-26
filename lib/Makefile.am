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

lib_LTLIBRARIES = libpulp.la

libpulp_la_SOURCES = \
  ulp.c \
  interpose.c \
  msg_queue.c \
  error.c \
  ulp_prologue.S \
  ulp_interface.S
libpulp_la_DEPENDENCIES= libpulp.versions
libpulp_la_LDFLAGS = \
  -ldl \
  -Wl,--version-script=$(srcdir)/libpulp.versions \
  -Wl,--hash-style=sysv \ # Ubuntu seems to default to gnu, so be clear we ...
  $(AM_LDFLAGS) # ... want old style hash sections, else DT_HASH is empty.

libpulp_la_LIBADD = $(top_builddir)/common/libcommon.la

AM_CFLAGS += -I$(top_srcdir)/include

EXTRA_DIST = libpulp.versions
