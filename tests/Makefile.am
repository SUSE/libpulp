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

# Target libraries to test TLS data access
check_LTLIBRARIES += libtls.la

libtls_la_SOURCES = libtls.c
libtls_la_CFLAGS = $(TARGET_CFLAGS)
libtls_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libtls.post

# Target libraries to test static data access
check_LTLIBRARIES += libbuildid.la

libbuildid_la_SOURCES = libbuildid.c
libbuildid_la_CFLAGS = $(TARGET_CFLAGS)
libbuildid_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libbuildid.post

check_LTLIBRARIES += libendbr64.la

libendbr64_la_SOURCES = libendbr64.c
libendbr64_la_CFLAGS = $(TARGET_CFLAGS) $(FCF_PROTECTION)
libendbr64_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libendbr64.post

check_LTLIBRARIES += libprefix.la

libprefix_la_SOURCES = libprefix.c
libprefix_la_CFLAGS = $(TARGET_CFLAGS)
libprefix_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libprefix.post

# Target libraries to test static data access
check_LTLIBRARIES += libmanyprocesses.la

libmanyprocesses_la_SOURCES = libmanyprocesses.c
libmanyprocesses_la_CFLAGS = $(TARGET_CFLAGS)
libmanyprocesses_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libmanyprocesses.post

# Target libraries to test static data access
check_LTLIBRARIES += libstress.la

libstress_la_SOURCES = libstress.c
libstress_la_CFLAGS = $(TARGET_CFLAGS)
libstress_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libstress.post

libvisibility_la_SOURCES = libvisibility.c
libvisibility_la_CFLAGS  = $(TARGET_CFLAGS)
libvisibility_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS += .libs/libvisibility.post

check_LTLIBRARIES += libvisibility.la

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
                     libprocess_livepatch1.la \
                     librecursion_livepatch1.la \
                     libblocked_livepatch1.la \
                     libpagecross_livepatch1.la \
                     libaddress_livepatch1.la \
                     libcontract_livepatch1.la \
                     libaccess_livepatch1.la \
                     libaccess_livepatch2.la \
                     libtls_livepatch1.la \
                     libbuildid_livepatch1.la \
                     libprocess_access_livepatch1.la \
                     libendbr64_livepatch1.la \
                     libprefix_livepatch1.la \
                     libmanyprocesses_livepatch1.la \
                     libstress_livepatch1.la \
                     libcomments_livepatch1.la \
                     libvisibility_livepatch1.la \
                     libvisibility_livepatch2.la

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

libprocess_livepatch1_la_SOURCES = libprocess_livepatch1.c
libprocess_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

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

libaccess_livepatch2_la_SOURCES = libaccess_livepatch2.c
libaccess_livepatch2_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libtls_livepatch1_la_SOURCES = libtls_livepatch1.c
libtls_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libbuildid_livepatch1_la_SOURCES = libbuildid_livepatch1.c
libbuildid_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libendbr64_livepatch1_la_SOURCES = libhundreds_livepatch1.c
libendbr64_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libprefix_livepatch1_la_SOURCES = libhundreds_livepatch1.c
libprefix_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libprocess_access_livepatch1_la_SOURCES = process_access_livepatch1.c
libprocess_access_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libmanyprocesses_livepatch1_la_SOURCES = libmanyprocesses_livepatch1.c
libmanyprocesses_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libstress_livepatch1_la_SOURCES = libstress_livepatch1.c
libstress_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libcomments_livepatch1_la_SOURCES = libcomments_livepatch1.c
libcomments_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libvisibility_livepatch1_la_SOURCES = libvisibility_livepatch1.c
libvisibility_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libvisibility_livepatch2_la_SOURCES = libvisibility_livepatch2.c
libvisibility_livepatch2_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)


METADATA = \
  libdozens_livepatch1.dsc \
  libdozens_livepatch1.ulp \
  libdozens_livepatch99.dsc \
  libdozens_livepatch99.ulp \
  libhundreds_livepatch1.dsc \
  libhundreds_livepatch1.ulp \
  libhundreds_livepatch2.dsc \
  libhundreds_livepatch2.ulp \
  libhundreds_livepatch3.dsc \
  libhundreds_livepatch3.ulp \
  libdozens_bsymbolic_livepatch1.dsc \
  libdozens_bsymbolic_livepatch1.ulp \
  libhundreds_bsymbolic_livepatch1.dsc \
  libhundreds_bsymbolic_livepatch1.ulp \
  libparameters_livepatch1.dsc \
  libparameters_livepatch1.ulp \
  libparameters_livepatch2.dsc \
  libparameters_livepatch2.ulp \
  libparameters_livepatch3.dsc \
  libparameters_livepatch3.ulp \
  librecursion_livepatch1.dsc \
  librecursion_livepatch1.ulp \
  libblocked_livepatch1.dsc \
  libblocked_livepatch1.ulp \
  libpagecross_livepatch1.dsc \
  libpagecross_livepatch1.ulp \
  libaddress_livepatch1.dsc \
  libaddress_livepatch1.ulp \
  libcontract_livepatch1.dsc \
  libcontract_livepatch1.ulp \
  libaccess_livepatch1.dsc \
  libaccess_livepatch1.ulp \
  libaccess_livepatch2.dsc \
  libaccess_livepatch2.ulp \
  libtls_livepatch1.dsc \
  libtls_livepatch1.ulp \
  libbuildid_livepatch1.dsc \
  libbuildid_livepatch1.ulp \
  libmanyprocesses_livepatch1.dsc \
  libmanyprocesses_livepatch1.ulp \
  libendbr64_livepatch1.dsc \
  libendbr64_livepatch1.ulp \
  libprefix_livepatch1.dsc \
  libprefix_livepatch1.ulp \
  libprocess_livepatch1.dsc \
  libprocess_livepatch1.ulp \
  libprocess_access_livepatch1.dsc \
  libprocess_access_livepatch1.ulp \
  libcomments_livepatch1.dsc \
  libcomments_livepatch1.ulp \
  libstress_livepatch1.dsc \
  libstress_livepatch1.ulp \
  libvisibility_livepatch1.dsc \
  libvisibility_livepatch1.ulp \
  libvisibility_livepatch2.dsc \
  libvisibility_livepatch2.ulp

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
  libaccess_livepatch2.in \
  libtls_livepatch1.in \
  libbuildid_livepatch1.in \
  libendbr64_livepatch1.in \
  libprefix_livepatch1.in \
  libmanyprocesses_livepatch1.in \
  libprocess_livepatch1.in \
  libprocess_access_livepatch1.in \
  libcomments_livepatch1.in \
  libstress_livepatch1.in \
  libvisibility_livepatch1.in \
  libvisibility_livepatch2.in

clean-local:
	rm -f $(METADATA)

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
  process \
  tls \
  buildid \
  process_access \
  endbr64 \
  prefix \
  manyprocesses \
  dlsym \
  stress \
  pcqueue \
  comments \
  block_mprotect \
  chroot \
  visibility

numserv_SOURCES = numserv.c
numserv_LDADD = libdozens.la libhundreds.la
numserv_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

numserv_bsymbolic_SOURCES = numserv.c
numserv_bsymbolic_LDADD = libdozens_bsymbolic.la libhundreds_bsymbolic.la
numserv_bsymbolic_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

endbr64_SOURCES = endbr64.c
endbr64_LDADD = libdozens.la libendbr64.la
endbr64_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

prefix_SOURCES = prefix.c
prefix_LDADD = libdozens.la libprefix.la
prefix_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

parameters_SOURCES = parameters.c
parameters_LDADD = libparameters.la
parameters_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

process_SOURCES = process.c
process_CFLAGS = -fpatchable-function-entry=$(ULP_NOPS_LEN),$(PRE_NOPS_LEN) $(AM_CFLAGS)
process_DEPENDENCIES = $(POST_PROCESS)
process_LDFLAGS = $(AM_LDFLAGS)

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

tls_SOURCES = tls.c
tls_CFLAGS = -pthread $(AM_CFLAGS)
tls_LDADD = libtls.la
tls_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

buildid_SOURCES = buildid.c
buildid_LDADD = libbuildid.la
buildid_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

process_access_SOURCES = process_access.c
process_access_CFLAGS = -fpatchable-function-entry=$(ULP_NOPS_LEN),$(PRE_NOPS_LEN) $(AM_CFLAGS)
process_access_DEPENDENCIES = $(POST_PROCESS)

manyprocesses_SOURCES = manyprocesses.c
manyprocesses_LDADD = libmanyprocesses.la
manyprocesses_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

dlsym_SOURCES = dlsym.c
dlsym_LDADD = -lpthread -ldl -lrt
dlsym_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

# Workaround a bug in Autoconf 2.69
if CPU_X86_64
dlsym_LDADD += \
  -l:ld-linux-x86-64.so.2
endif
if CPU_PPC64LE
dlsym_LDADD += \
  -l:ld64.so.2
endif

stress_SOURCES = stress.c
stress_LDADD = libstress.la
stress_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

pcqueue_SOURCES = pcqueue.c
pcqueue_LDADD = -lpthread

comments_SOURCES = comments.c
comments_CFLAGS = -fpatchable-function-entry=$(ULP_NOPS_LEN),$(PRE_NOPS_LEN) $(AM_CFLAGS)
comments_LDADD =

# block_mprotect is a auxiliary program to block page flags change through
# mprotect.
block_mprotect_SOURCES = block_mprotect.c
block_mprotect_CFLAGS = $(AM_CFLAGS) -I/usr/include/libseccomp/
block_mprotect_LDADD = -lseccomp

chroot_SOURCES = chroot.c
chroot_CFLAGS = $(AM_CFLAGS)
chroot_LDADD = libparameters.la

visibility_SOURCES = visibility.c
visibility_CFLAGS = $(AM_CFLAGS)
visibility_LDADD = libvisibility.la

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
  access2.py \
  tls.py \
  buildid.py \
  libpulp_messages.py \
  relative_path.py \
  revert_all.py \
  revert_all_target1.py \
  revert_all_target2.py \
  revert_and_patch.py \
  process.py \
  process_revert.py \
  livepatchable.py \
  revert_with_invalid.py \
  process_access.py \
  manyprocesses.py \
  endbr64.py \
  prefix.py \
  dlsym_lock.py \
  stress.py \
  tempfiles.py \
  pcqueue.py \
  comments.py \
  nolibpulp.py \
  set_patchable.py \
  path_disable.py \
  user_disable.py \
  group_disable.py \
  mprotect_patch.py \
  patches.py \
  mprotect_patch.py \
  chroot.py \
  visibility.py

XFAIL_TESTS = \
  blocked.py \
  contract.py

# Some tests must run serially because they may interfere with other
# tests. We use *.log because automake rule that runs the tests are
# the rule that generates the *.log.
#
# manyprocesses must run serially because it touches all processes
# looking for libraries to patch, and for that it locks the ptrace
# lock.
#
# stress must run serially for the same reason as manyprocesses.
#
# tempfiles must run serially AFTER all tests because it checks if
# garbage were not left in filesystem after the testsuite was run.

SERIAL_TESTS = \
  manyprocesses.log \
  stress.log \
  tempfiles.log

# Remove the test itself from the dependency list.
MANYPROCESSES_DEPS = $(filter-out $(SERIAL_TESTS),$(TEST_LOGS))
STRESS_DEPS = $(MANYPROCESSES_DEPS) manyprocesses.log
TEMPFILES_DEPS = $(STRESS_DEPS)

manyprocesses.log: $(MANYPROCESSES_DEPS)

tempfiles.log: $(TEMPFILES_DEPS)

stress.log: $(STRESS_DEPS)

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

if ENABLE_AFL
check-afl: $(METADATA) $(check_LTLIBRARIES)
	ULP_IN_AFL_TEST=1 \
	$(AFL_FUZZ) -i $(srcdir)/fuz/ -o $(top_builddir)/afl_findings -- $(ULP)
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
	$(ULP_PACKER) $<
	rm -f $(libbuildid_la_OBJECTS) # Clean up object again
	$(MAKE) CFLAGS="$(CFLAGS) -DRETVAL=1338" libbuildid.la # Compile new libbuildid.
	echo Maintained for legacy reasons > $@

libprocess_livepatch1.ulp: process libprocess_livepatch1.dsc

libprocess_access_livepatch1.ulp: process_access libprocess_access_livepatch1.dsc

libcomments_livepatch1.ulp: comments libprocess_livepatch1.dsc
