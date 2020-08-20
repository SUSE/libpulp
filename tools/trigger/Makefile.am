#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020 SUSE Linux GmbH
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

bin_PROGRAMS = ulp_trigger ulp_check ulp

noinst_HEADERS = introspection.h ptrace.h

noinst_LTLIBRARIES = libcommon.la
libcommon_la_SOURCES = introspection.c ptrace.c
libcommon_la_LIBADD = -lbfd -lz -liberty -ldl

ulp_trigger_SOURCES = trigger.c
ulp_trigger_LDADD = libcommon.la

ulp_check_SOURCES = check.c
ulp_check_LDADD = libcommon.la

ulp_SOURCES = ulp.c
ulp_LDADD = libcommon.la
