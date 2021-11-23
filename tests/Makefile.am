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

libdozens_la_SOURCES = dozens.c
libdozens_la_CFLAGS = $(TARGET_CFLAGS)
libdozens_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

libhundreds_la_SOURCES = hundreds.c
libhundreds_la_CFLAGS = $(TARGET_CFLAGS)
libhundreds_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

libdozens_bsymbolic_la_SOURCES = dozens.c
libdozens_bsymbolic_la_CFLAGS = $(TARGET_CFLAGS)
libdozens_bsymbolic_la_LDFLAGS = -Wl,-Bsymbolic \
  $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

libhundreds_bsymbolic_la_SOURCES = hundreds.c
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

libparameters_la_SOURCES = libparameters.c
libparameters_la_CFLAGS = $(TARGET_CFLAGS)
libparameters_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libparameters.post

# Target libraries to test recursion
check_LTLIBRARIES += librecursion.la
noinst_HEADERS += librecursion.h

librecursion_la_SOURCES = librecursion.c
librecursion_la_CFLAGS = $(TARGET_CFLAGS)
librecursion_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/librecursion.post

# Target libraries to test live patches blocked in threads
check_LTLIBRARIES += libblocked.la
noinst_HEADERS += libblocked.h

libblocked_la_SOURCES = libblocked.c
libblocked_la_CFLAGS = $(TARGET_CFLAGS)
libblocked_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libblocked.post

# Target libraries to test page boundary conditions
check_LTLIBRARIES += libpagecross.la

libpagecross_la_SOURCES = libpagecross_padding.S \
                          libpagecross.c

libpagecross_la_CFLAGS = $(TARGET_CFLAGS)
libpagecross_la_CCASFLAGS = -DPAGE_SIZE=$(PAGE_SIZE) $(AM_CCASFLAGS)
libpagecross_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libpagecross.post

# Target libraries to test memory access protections
check_LTLIBRARIES += libaddress.la
noinst_HEADERS += libaddress.h

libaddress_la_SOURCES = libaddress.c
libaddress_la_CFLAGS = $(TARGET_CFLAGS)
libaddress_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libaddress.post

# Target libraries to test constructors
check_LTLIBRARIES += libconstructor.la
noinst_HEADERS += libconstructor.h

libconstructor_la_SOURCES = libconstructor.c
libconstructor_la_CFLAGS = $(TARGET_CFLAGS)
libconstructor_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libconstructor.post

# Target libraries to test consistency
check_LTLIBRARIES += libcontract.la
noinst_HEADERS += libcontract.h

libcontract_la_SOURCES = libcontract.c
libcontract_la_CFLAGS = $(TARGET_CFLAGS)
libcontract_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libcontract.post

# Target libraries to test exception handling
check_LTLIBRARIES += libexception.la
noinst_HEADERS += libexception.h

libexception_la_SOURCES = libexception.cc
libexception_la_CXXFLAGS = $(TARGET_CFLAGS)
libexception_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libexception.post

# Target libraries to test static data access
check_LTLIBRARIES += libaccess.la
noinst_HEADERS += libaccess.h

libaccess_la_SOURCES = libaccess.c
libaccess_la_CFLAGS = $(TARGET_CFLAGS)
libaccess_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libaccess.post

# Target libraries to test static data access
check_LTLIBRARIES += libbuildid.la

libbuildid_la_SOURCES = libbuildid.c
libbuildid_la_CFLAGS = $(TARGET_CFLAGS)
libbuildid_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libbuildid.post

# Target libraries to test static data access
check_LTLIBRARIES += libmanyprocesses.la

libmanyprocesses_la_SOURCES = libmanyprocesses.c
libmanyprocesses_la_CFLAGS = $(TARGET_CFLAGS)
libmanyprocesses_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libmanyprocesses.post

# Live patches
check_LTLIBRARIES += libdozens_livepatch1.la \
                     libdozens_livepatch99.la \
                     libhundreds_livepatch1.la \
                     libhundreds_livepatch2.la \
                     libhundreds_livepatch3.la \
                     libdozens_bsymbolic_livepatch1.la \
                     libhundreds_bsymbolic_livepatch1.la \
                     libparameters_livepatch1.la \
                     libparameters_livepatch2.la \
                     libparameters_livepatch3.la \
                     librecursion_livepatch1.la \
                     libblocked_livepatch1.la \
                     libpagecross_livepatch1.la \
                     libaddress_livepatch1.la \
                     libcontract_livepatch1.la \
                     libaccess_livepatch1.la \
                     libbuildid_livepatch1.la \
                     libmanyprocesses_livepatch1.la

libdozens_livepatch1_la_SOURCES = libdozens_livepatch1.c
libdozens_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libdozens_livepatch99_la_SOURCES = libdozens_livepatch99.c
libdozens_livepatch99_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libhundreds_livepatch1_la_SOURCES = libhundreds_livepatch1.c
libhundreds_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libhundreds_livepatch2_la_SOURCES = libhundreds_livepatch2.c
libhundreds_livepatch2_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libhundreds_livepatch3_la_SOURCES = libhundreds_livepatch3.c
libhundreds_livepatch3_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libdozens_bsymbolic_livepatch1_la_SOURCES = libdozens_livepatch1.c
libdozens_bsymbolic_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libhundreds_bsymbolic_livepatch1_la_SOURCES = libhundreds_livepatch1.c
libhundreds_bsymbolic_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libparameters_livepatch1_la_SOURCES = libparameters_livepatch1.c
libparameters_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libparameters_livepatch2_la_SOURCES = libparameters_livepatch2.c
libparameters_livepatch2_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libparameters_livepatch3_la_SOURCES = libparameters_livepatch3.c
libparameters_livepatch3_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

librecursion_livepatch1_la_SOURCES = librecursion_livepatch1.c
librecursion_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libblocked_livepatch1_la_SOURCES = libblocked_livepatch1.c
libblocked_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libpagecross_livepatch1_la_SOURCES = libpagecross_livepatch1.c
libpagecross_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libaddress_livepatch1_la_SOURCES = libaddress_livepatch1.c
libaddress_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libcontract_livepatch1_la_SOURCES = libcontract_livepatch1.c
libcontract_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libaccess_livepatch1_la_SOURCES = libaccess_livepatch1.c
libaccess_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libbuildid_livepatch1_la_SOURCES = libbuildid_livepatch1.c
libbuildid_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libmanyprocesses_livepatch1_la_SOURCES = libmanyprocesses_livepatch1.c
libmanyprocesses_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

METADATA = \
  libdozens_livepatch1.dsc \
  libdozens_livepatch1.ulp \
  libdozens_livepatch1.rev \
  libdozens_livepatch99.dsc \
  libdozens_livepatch99.ulp \
  libdozens_livepatch99.rev \
  libhundreds_livepatch1.dsc \
  libhundreds_livepatch1.ulp \
  libhundreds_livepatch1.rev \
  libhundreds_livepatch2.dsc \
  libhundreds_livepatch2.ulp \
  libhundreds_livepatch2.rev \
  libhundreds_livepatch3.dsc \
  libhundreds_livepatch3.ulp \
  libhundreds_livepatch3.rev \
  libdozens_bsymbolic_livepatch1.dsc \
  libdozens_bsymbolic_livepatch1.ulp \
  libdozens_bsymbolic_livepatch1.rev \
  libhundreds_bsymbolic_livepatch1.dsc \
  libhundreds_bsymbolic_livepatch1.ulp \
  libhundreds_bsymbolic_livepatch1.rev \
  libparameters_livepatch1.dsc \
  libparameters_livepatch1.ulp \
  libparameters_livepatch1.rev \
  libparameters_livepatch2.dsc \
  libparameters_livepatch2.ulp \
  libparameters_livepatch2.rev \
  libparameters_livepatch3.dsc \
  libparameters_livepatch3.ulp \
  libparameters_livepatch3.rev \
  librecursion_livepatch1.dsc \
  librecursion_livepatch1.ulp \
  librecursion_livepatch1.rev \
  libblocked_livepatch1.dsc \
  libblocked_livepatch1.ulp \
  libblocked_livepatch1.rev \
  libpagecross_livepatch1.dsc \
  libpagecross_livepatch1.ulp \
  libpagecross_livepatch1.rev \
  libaddress_livepatch1.dsc \
  libaddress_livepatch1.ulp \
  libaddress_livepatch1.rev \
  libcontract_livepatch1.dsc \
  libcontract_livepatch1.ulp \
  libcontract_livepatch1.rev \
  libaccess_livepatch1.dsc \
  libaccess_livepatch1.ulp \
  libaccess_livepatch1.rev \
  libbuildid_livepatch1.dsc \
  libbuildid_livepatch1.ulp \
  libbuildid_livepatch1.rev \
  libmanyprocesses_livepatch1.dsc \
  libmanyprocesses_livepatch1.ulp \
  libmanyprocesses_livepatch1.rev

EXTRA_DIST = \
  libdozens_livepatch1.in \
  libdozens_livepatch99.in \
  libhundreds_livepatch1.in \
  libhundreds_livepatch2.in \
  libhundreds_livepatch3.in \
  libdozens_bsymbolic_livepatch1.in \
  libhundreds_bsymbolic_livepatch1.in \
  libparameters_livepatch1.in \
  libparameters_livepatch2.in \
  libparameters_livepatch3.in \
  librecursion_livepatch1.in \
  libblocked_livepatch1.in \
  libpagecross_livepatch1.in \
  libaddress_livepatch1.in \
  libcontract_livepatch1.in \
  libaccess_livepatch1.in \
  libbuildid_livepatch1.in \
  libmanyprocesses_livepatch1.in

clean-local:
	rm -f $(METADATA)

# There is a race condition within tests.  Some of them delete files used by
# other tests, other try to patch a process which is yet to be patched by a
# test. Enforcing that tests runs serially avoid such issues, so here we do
# so it. We may have to fix it in the future if this project grows (issue #82).
.NOTPARALLEL: check check-am dist-check

# Test programs
check_PROGRAMS = \
  numserv \
  numserv_bsymbolic \
  parameters \
  recursion \
  blocked \
  deadlock \
  asunsafe_conversion \
  redzone \
  pagecross \
  loop \
  terminal \
  syscall_restart \
  memory_protection \
  constructor \
  cancel \
  contract \
  exception_handling \
  access \
  buildid \
  manyprocesses

numserv_SOURCES = numserv.c
numserv_LDADD = libdozens.la libhundreds.la
numserv_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

numserv_bsymbolic_SOURCES = numserv.c
numserv_bsymbolic_LDADD = libdozens_bsymbolic.la libhundreds_bsymbolic.la
numserv_bsymbolic_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

parameters_SOURCES = parameters.c
parameters_LDADD = libparameters.la
parameters_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

syscall_restart_SOURCES = syscall_restart.c
syscall_restart_LDADD = libparameters.la
syscall_restart_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

recursion_SOURCES = recursion.c
recursion_LDADD = librecursion.la
recursion_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

blocked_SOURCES = blocked.c
blocked_CFLAGS = -pthread $(AM_CFLAGS)
blocked_LDADD = libblocked.la
blocked_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

cancel_SOURCES = cancel.c
cancel_CFLAGS = -pthread $(AM_CFLAGS)
cancel_LDADD = libblocked.la
cancel_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

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

redzone_SOURCES = redzone.c
redzone_LDADD = libblocked.la
redzone_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

pagecross_SOURCES = pagecross.c
pagecross_LDADD = libpagecross.la
pagecross_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

loop_SOURCES = loop.c
loop_LDADD = libblocked.la $(top_builddir)/lib/libpulp.la
loop_LDFLAGS = -Wl,--no-as-needed $(AM_LDFLAGS)
loop_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

terminal_SOURCES = terminal.c
terminal_CFLAGS = -pthread $(AM_CFLAGS)
terminal_DEPENDENCIES = $(POST_PROCESS) $(METADATA) loop

constructor_SOURCES = constructor.c
constructor_LDADD = libconstructor.la
constructor_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

EXTRA_DIST += constructor-template.c

memory_protection_SOURCES = memory_protection.c
memory_protection_LDADD = libaddress.la
memory_protection_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

contract_SOURCES = contract.c
contract_LDADD = libcontract.la
contract_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

exception_handling_SOURCES = exception_handling.cc
exception_handling_LDADD = libexception.la
exception_handling_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

access_SOURCES = access.c
access_LDADD = libaccess.la
access_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

buildid_SOURCES = buildid.c
buildid_LDADD = libbuildid.la
buildid_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

manyprocesses_SOURCES = manyprocesses.c
manyprocesses_LDADD = libmanyprocesses.la
manyprocesses_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

TESTS = \
  numserv.py \
  numserv_bsymbolic.py \
  parameters.py \
  recursion.py \
  blocked.py \
  deadlock.py \
  asunsafe_conversion.py \
  redzone.py \
  revert.py \
  pagecross.py \
  terminal.py \
  syscall_restart.py \
  hidden.py \
  memory_protection.py \
  constructor.py \
  cancel.py \
  contract.py \
  exception_handling.py \
  missing_function.py \
  access.py \
  buildid.py \
  libpulp_messages.py \
  relative_path.py \
  revert_all.py \
  revert_and_patch.py \
  manyprocesses.py

XFAIL_TESTS = \
  blocked.py \
  contract.py \
  hidden.py

TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON) -B

EXTRA_DIST += $(TESTS)

# Common definitions and imports for all test cases
EXTRA_DIST += \
  testsuite.py \
  offsets.py

if ENABLE_VALGRIND
check: export TESTS_THROUGH_VALGRIND=1
endif

# Custom rule for libbuild_livepatch1.ulp. This tests if the build id
# is correct before applying the patch. A trivial way of testing it
# would be editing the build id from the metadata file, however, that
# would rely on implementation details of the metadata file, which is
# yet to change.
#
# Therefore, instead of modifying the metadata build id, we recompile
# the target test library with a macro that would result in diferent
# code being output, and as consequence, a distinct build id.
libbuildid_livepatch1.ulp: libbuildid_livepatch1.dsc $(check_LTLIBRARIES)
	rm -f $(libbuildid_la_OBJECTS) # Clean up objects
	$(MAKE) libbuildid.la # Force compile libbuildid.la
	$(ULP_PACKER) $< -o $@
	rm -f $(libbuildid_la_OBJECTS) # Clean up object again
	$(MAKE) CFLAGS="$(CFLAGS) -DRETVAL=1338" libbuildid.la # Compile new libbuildid.
