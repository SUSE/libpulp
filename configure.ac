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

AC_INIT([libpulp], [0.1], [noreply@suse.com])

# Keep most generated files under the config directory.
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIRS([config])

# Check for the availability of macros from autoconf-archive.
AC_MSG_CHECKING([autoconf-archive availability])
m4_ifndef([AX_CHECK_COMPILE_FLAG], [ax_available="no"])
m4_ifndef([AX_GCC_VAR_ATTRIBUTE], [ax_available="no"])
m4_ifndef([AX_PYTHON_MODULE], [ax_available="no"])
AS_IF([test "x$ax_available" == "xno"],
AC_MSG_RESULT([no]), AC_MSG_RESULT([yes]))
AS_IF([test "x$ax_available" == "xno"],
AC_MSG_ERROR(
[Libpulp needs the autoconf-archive package.
Make sure it is installed and re-run autoconf (or ./bootstrap)]))

# Use a config header instead of passing -D options to the compiler.
AC_CONFIG_HEADERS([include/config.h])

# Initialize automake with:
# -Wall: get automake warnings.
# -Wno-portability: ignore warnings about the use of % patterns.
# foreign: ignore GNU Standards.
# subdir-objects: when building sources in different directories, store
# object files in their respective source paths (useful to build trm.S
# only once, even though it is needed by all examples and tests).
AM_INIT_AUTOMAKE([-Wall -Wno-portability foreign subdir-objects])

# Initialize libtool with static libraries disabled, since libpulp is
# supposed to be dynamically linked into applications.
LT_INIT([shared disable-static])

AC_PROG_CC
AM_PROG_AS

# Check if the compiler provides the -fpatchable-function-entry option,
# needed to create the nop paddings in function entries.
AX_CHECK_COMPILE_FLAG([-fpatchable-function-entry=1],, AC_MSG_ERROR([\
Required compiler option missing: -fpatchable-function-entry]))

# Check if the assembler accepts the weak directive, needed in trm.S.
AX_GCC_VAR_ATTRIBUTE(weak)
AS_IF([test "$ax_cv_have_var_attribute_weak" != "yes"], AC_MSG_ERROR([\
The .weak assembler directive is required in trm.S]))

# The following headers are required to build libpulp's tools.
AC_CHECK_HEADER([gelf.h],,
AC_MSG_ERROR([Libelf development files are missing.]))

# Python and python's pexpect are required to run the tests.
AM_PATH_PYTHON([3])
AX_PYTHON_MODULE([pexpect], [fatal])
AX_PYTHON_MODULE([psutil], [fatal])

# Add the following flags to the compilation of all files
AC_SUBST([AM_CFLAGS], ["-Wall -Wextra -Werror"])
AC_SUBST([AM_CCASFLAGS], ["-Wa,--fatal-warnings"])

# The following test checks that a downstream/custom glibc provides
# __libpulp_tls_get_addr for optimized library entrance tracking.
# When available, trm.S avoids most of the register save/restore
# instructions.
AC_CHECK_FUNCS(__libpulp_tls_get_addr)

# The test suite covers patching of functions near page boundaries, so
# try to detect the size of a page in the system, using getconf. If
# getconf is not available, set the page size to a large power of two,
# in the hope that it will work on multiple architectures and system
# configurations.
AC_CHECK_PROGS([GETCONF], [getconf])
AS_IF([test -z "$GETCONF"],
AC_SUBST([PAGE_SIZE], [1048576]),
AC_SUBST([PAGE_SIZE], [$($GETCONF PAGE_SIZE)]))

# Libpulp uses -fpatchable-function-entry to add a total of ULP_NOPS_LEN
# padding nops to the prologue of all functions: PRE_NOPS_LEN nops
# before the entry point, and the remaining nops after it. These nops
# serve two different purposes: 1. at compilation time, the ulp_post
# tool replaces the initial TRM_NOPS_LEN nops with trampolines that
# redirect execution to the library entrance tracking routine; 2. at
# running time, and whenever a live patch is applied, libpulp replaces
# the remaining nops with instructions that redirect execution to the
# universe handling routines.
AC_SUBST([ULP_NOPS_LEN], [40])
AC_SUBST([PRE_NOPS_LEN], [38])
AC_SUBST([TRM_NOPS_LEN], [16])
AC_DEFINE_UNQUOTED([ULP_NOPS_LEN], [$ULP_NOPS_LEN],
[Total number of padding nops])
AC_DEFINE_UNQUOTED([PRE_NOPS_LEN], [$PRE_NOPS_LEN],
[Padding nops before the entry point of functions])
AC_DEFINE_UNQUOTED([TRM_NOPS_LEN], [$TRM_NOPS_LEN],
[Padding nops used by trampolines])

AC_CONFIG_FILES([Makefile
		 include/Makefile
		 lib/Makefile
		 tests/Makefile
		 tools/Makefile])

AC_OUTPUT
