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

bin_PROGRAMS = \
  ulp_packer \
  ulp_reverse \
  ulp_dump \
  ulp_trigger \
  ulp_check \
  ulp_post \
  ulp

noinst_HEADERS = introspection.h ptrace.h packer.h

# Static library shared among the tools.

noinst_LTLIBRARIES = libcommon.la

libcommon_la_SOURCES = introspection.c ptrace.c
libcommon_la_LIBADD = -lelf -ldl

# The post tool fills in the trampoline slots of each live-patchable
# function and updates the dynamic symbol table to use the trampolines.

ulp_post_SOURCES = post.c
ulp_post_LDADD = -lelf

# The packer and reverse tools create metadata files for live patches,
# whereas the dump tool dumps their content in human-readable format.

ulp_packer_SOURCES = packer.c
ulp_packer_LDADD = libcommon.la -lelf

ulp_reverse_SOURCES = revert.c

ulp_dump_SOURCES = dump.c
ulp_dump_LDADD = libcommon.la

# The trigger and check tools attach to live patchable processes to
# apply or check live patches, respectively. The ulp tool searches the
# whole system for live patchable processes and report their state.

ulp_trigger_SOURCES = trigger.c
ulp_trigger_LDADD = libcommon.la

ulp_check_SOURCES = check.c
ulp_check_LDADD = libcommon.la

ulp_SOURCES = ulp.c
ulp_LDADD = libcommon.la

# Ensure access to the include directory
AM_CFLAGS += -I$(abs_top_srcdir)/include
