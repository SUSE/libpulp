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

bin_PROGRAMS = ulp

noinst_HEADERS = \
  trigger.h \
  arguments.h \
  introspection.h \
  ptrace.h \
  packer.h \
  md4.h \
  check.h \
  patches.h \
  dump.h \
  post.h \
  revert.h

# Static library shared among the tools.

noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = introspection.c ptrace.c
libcommon_la_LIBADD = -lelf -ldl $(LIBUNWIND_LIBS)

ulp_SOURCES = \
  ulp.c \
  check.c \
  patches.c \
  dump.c \
  packer.c \
  md4.c \
  trigger.c \
  post.c \
  revert.c

ulp_LDADD = libcommon.la

# Ensure access to the include directory
AM_CFLAGS += -I$(abs_top_srcdir)/include
