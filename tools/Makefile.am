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
  messages.h \
  livepatchable.h \
  elf-extra.h \
  pcqueue.h \
  extract.h \
  set_patchable.h \
  insn_queue_tools.h

ulp_SOURCES = \
  ulp.c \
  check.c \
  patches.c \
  dump.c \
  packer.c \
  md4.c \
  trigger.c \
  post.c \
  messages.c \
  introspection.c \
  ptrace.c \
  livepatchable.c \
  elf-extra.c \
  pcqueue.c \
  extract.c \
  set_patchable.c \
  insn_queue.c

# Workaround a bug in Autoconf 2.69
if CPU_X86_64
ulp_SOURCES += \
  arch/x86_64/post-arch.c
endif

if CPU_PPC64LE
ulp_SOURCES += \
  arch/powerpc64le/post-arch.c
endif

ulp_LDADD = $(top_builddir)/common/libcommon.la -lelf -ljson-c -lpthread -ldl $(LIBUNWIND_LIBS)

# Ensure access to the include directory
AM_CFLAGS += -I$(abs_top_srcdir)/include -I$(top_srcdir)/include/arch/$(target_cpu)

# Add -fno-strict-alias to the insn_queue code.
insn_queue.$(OBJEXT) : CFLAGS += -fno-strict-aliasing

if ENABLE_ADDRSAN
# Add address sanitizer
AM_CFLAGS += -fsanitize=address,undefined
AM_LDFLAGS += -fsanitize=address,undefined
endif

if ENABLE_THREADSAN
# Add thread sanitizer
AM_CFLAGS += -fsanitize=thread
AM_LDFLAGS += -fsanitize=thread
endif
