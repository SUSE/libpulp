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

# Target libraries to test live patching multiple libraries
#
# Each library is built twice: with and without -Bsymbolic passed to the
# linker, to test that libpulp's ref-by-name variable access works in
# both scenarios.
check_LTLIBRARIES = libdozens.la \
                    libhundreds.la \
                    libdozens_bsymbolic.la \
                    libhundreds_bsymbolic.la
noinst_HEADERS = dozens.h hundreds.h

libdozens_la_SOURCES = dozens.c $(TARGET_TRM_SOURCES)
libdozens_la_CFLAGS = $(TARGET_CFLAGS)
libdozens_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

libhundreds_la_SOURCES = hundreds.c $(TARGET_TRM_SOURCES)
libhundreds_la_CFLAGS = $(TARGET_CFLAGS)
libhundreds_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

libdozens_bsymbolic_la_SOURCES = dozens.c $(TARGET_TRM_SOURCES)
libdozens_bsymbolic_la_CFLAGS = $(TARGET_CFLAGS)
libdozens_bsymbolic_la_LDFLAGS = -Wl,-Bsymbolic \
  $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

libhundreds_bsymbolic_la_SOURCES = hundreds.c $(TARGET_TRM_SOURCES)
libhundreds_bsymbolic_la_CFLAGS = $(TARGET_CFLAGS)
libhundreds_bsymbolic_la_LDFLAGS = -Wl,-Bsymbolic \
  $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS = .libs/libdozens.post \
               .libs/libhundreds.post \
               .libs/libdozens_bsymbolic.post \
               .libs/libhundreds_bsymbolic.post

# Target libraries to test function parameters
check_LTLIBRARIES += libparameters.la
noinst_HEADERS += libparameters.h

libparameters_la_SOURCES = libparameters.c $(TARGET_TRM_SOURCES)
libparameters_la_CFLAGS = $(TARGET_CFLAGS)
libparameters_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libparameters.post

# Target libraries to test live patches blocked in threads
check_LTLIBRARIES += libblocked.la
noinst_HEADERS += libblocked.h

libblocked_la_SOURCES = libblocked.c $(TARGET_TRM_SOURCES)
libblocked_la_CFLAGS = $(TARGET_CFLAGS)
libblocked_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libblocked.post

# Live patches
check_LTLIBRARIES += libdozens_livepatch1.la \
                     libhundreds_livepatch1.la \
                     libdozens_bsymbolic_livepatch1.la \
                     libhundreds_bsymbolic_livepatch1.la \
                     libparameters_livepatch1.la \
                     libblocked_livepatch1.la

libdozens_livepatch1_la_SOURCES = libdozens_livepatch1.c
libdozens_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libhundreds_livepatch1_la_SOURCES = libhundreds_livepatch1.c
libhundreds_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libdozens_bsymbolic_livepatch1_la_SOURCES = libdozens_livepatch1.c
libdozens_bsymbolic_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libhundreds_bsymbolic_livepatch1_la_SOURCES = libhundreds_livepatch1.c
libhundreds_bsymbolic_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libparameters_livepatch1_la_SOURCES = libparameters_livepatch1.c
libparameters_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libblocked_livepatch1_la_SOURCES = libblocked_livepatch1.c
libblocked_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

METADATA = \
  libdozens_livepatch1.dsc \
  libdozens_livepatch1.ulp \
  libdozens_livepatch1.rev \
  libhundreds_livepatch1.dsc \
  libhundreds_livepatch1.ulp \
  libhundreds_livepatch1.rev \
  libdozens_bsymbolic_livepatch1.dsc \
  libdozens_bsymbolic_livepatch1.ulp \
  libdozens_bsymbolic_livepatch1.rev \
  libhundreds_bsymbolic_livepatch1.dsc \
  libhundreds_bsymbolic_livepatch1.ulp \
  libhundreds_bsymbolic_livepatch1.rev \
  libparameters_livepatch1.dsc \
  libparameters_livepatch1.ulp \
  libparameters_livepatch1.rev \
  libblocked_livepatch1.dsc \
  libblocked_livepatch1.ulp \
  libblocked_livepatch1.rev

EXTRA_DIST = \
  libdozens_livepatch1.in \
  libhundreds_livepatch1.in \
  libdozens_bsymbolic_livepatch1.in \
  libhundreds_bsymbolic_livepatch1.in \
  libparameters_livepatch1.in \
  libblocked_livepatch1.in

clean-local:
	rm -f $(METADATA)

# Test programs
check_PROGRAMS = \
  numserv \
  numserv_bsymbolic \
  parameters \
  blocked \
  deadlock \
  asunsafe_conversion

numserv_SOURCES = numserv.c
numserv_LDADD = libdozens.la libhundreds.la
numserv_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

numserv_bsymbolic_SOURCES = numserv.c
numserv_bsymbolic_LDADD = libdozens_bsymbolic.la libhundreds_bsymbolic.la
numserv_bsymbolic_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

parameters_SOURCES = parameters.c
parameters_LDADD = libparameters.la
parameters_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

blocked_SOURCES = blocked.c
blocked_CFLAGS = -pthread $(AM_CFLAGS)
blocked_LDADD = libblocked.la
blocked_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

deadlock_SOURCES = deadlock.c
deadlock_CFLAGS = -pthread $(AM_CFLAGS)
deadlock_LDFLAGS = -ldl $(AM_LDFLAGS)
deadlock_LDADD = libblocked.la
deadlock_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

asunsafe_conversion_SOURCES = asunsafe_conversion.c
asunsafe_conversion_CFLAGS = -pthread $(AM_CFLAGS)
asunsafe_conversion_LDFLAGS = -ldl $(AM_LDFLAGS)
asunsafe_conversion_LDADD = libblocked.la
asunsafe_conversion_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

TESTS = \
  numserv.py \
  numserv_bsymbolic.py \
  parameters.py \
  blocked.py \
  deadlock.py \
  asunsafe_conversion.py

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON)

EXTRA_DIST += $(TESTS)
