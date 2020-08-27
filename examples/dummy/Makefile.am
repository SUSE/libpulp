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

# Include common definitions
include $(top_srcdir)/Makefile.common

# Convenience libraries
check_LTLIBRARIES = libdummy.la
noinst_HEADERS = libdummy.h

libdummy_la_SOURCES = libdummy.c $(TARGET_TRM_SOURCES)
libdummy_la_CFLAGS = $(TARGET_CFLAGS)
libdummy_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS = .libs/libdummy.post

# Live patches
check_LTLIBRARIES += libdummy_livepatch1.la libdummy_livepatch2.la

libdummy_livepatch1_la_SOURCES = libdummy_livepatch1.c
libdummy_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libdummy_livepatch2_la_SOURCES = libdummy_livepatch2.c
libdummy_livepatch2_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

METADATA = \
  libdummy_livepatch1.dsc \
  libdummy_livepatch1.ulp \
  libdummy_livepatch1.rev \
  libdummy_livepatch2.dsc \
  libdummy_livepatch2.ulp \
  libdummy_livepatch2.rev

EXTRA_DIST = \
  libdummy_livepatch1.in \
  libdummy_livepatch2.in

clean-local:
	rm -f $(METADATA)

# Test programs
check_PROGRAMS = ex1 ex2 ex3 ex4

ex1_SOURCES = ex1.c
ex1_LDADD = libdummy.la
ex1_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

ex2_SOURCES = ex2.c
ex2_LDADD = libdummy.la
ex2_LDFLAGS = -lpthread
ex2_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

ex3_SOURCES = ex3.c
ex3_LDADD = libdummy.la
ex3_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

ex4_SOURCES = ex4.c
ex4_LDADD = libdummy.la
ex4_LDFLAGS = -lpthread
ex4_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

TESTS = ex1 ex2 ex3 ex4
LOG_COMPILER = $(srcdir)/wrapper-script
AM_LOG_FLAGS = $(abs_top_builddir)
EXTRA_DIST += wrapper-script
