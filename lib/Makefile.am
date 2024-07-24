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
  error.c

libpulp_la_LDFLAGS = \
  -ldl \
  -Wl,--version-script=$(srcdir)/libpulp.versions \
  -Wl,--hash-style=sysv \ # Ubuntu seems to default to gnu, so be clear we ...
  $(AM_LDFLAGS) # ... want old style hash sections, else DT_HASH is empty.

# Workaround a bug in Autoconf 2.69
if CPU_X86_64
libpulp_la_SOURCES += \
  arch/x86_64/ulp_interface.S \
  arch/x86_64/patch.c

libpulp_la_LDFLAGS += \
  -l:ld-linux-x86-64.so.2
endif

if CPU_PPC64LE
libpulp_la_SOURCES += \
  arch/powerpc64le/ulp_interface.S \
  arch/powerpc64le/patch.c

libpulp_la_LDFLAGS += \
  -l:ld64.so.2
endif

libpulp_la_DEPENDENCIES= libpulp.versions

libpulp_la_LIBADD = $(top_builddir)/common/libcommon.la

AM_CFLAGS += -I$(top_srcdir)/include -I$(top_srcdir)/include/arch/$(target_cpu)

EXTRA_DIST = libpulp.versions
