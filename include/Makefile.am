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

noinst_HEADERS = \
	ulp.h \
	ulp_common.h \
	interpose.h \
	msg_queue.h \
	error.h \
	error_common.h \
	terminal_colors.h \
	ld_rtld.h \
	insn_queue.h

# Workaround a bug in Autoconf 2.69
if CPU_X86_64
noinst_HEADERS += \
  arch/x86_64/arch_common.h
endif

if CPU_PPC64LE
noinst_HEADERS += \
  arch/powerpc64le/arch_common.h
endif
