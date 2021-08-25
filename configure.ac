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
# object files in their respective source paths.
AM_INIT_AUTOMAKE([-Wall -Wno-portability foreign subdir-objects])

# Initialize libtool with static libraries disabled, since libpulp is
# supposed to be dynamically linked into applications.
LT_INIT([shared disable-static])

AC_PROG_CC
AC_PROG_CXX
AM_PROG_AS

# On issue #41: configure AC_PROG_CXX set the C++ compiler to g++ even
# if wasn't found. Therefore, a safe way to check if there is a working
# C++ compiler is to compile a simple program.

AC_LANG_PUSH([C++])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
  [[#ifndef __cplusplus
    #error
    #endif]])],
  [cxx_works=yes],
  [cxx_works=no])
AC_LANG_POP([C++])

AS_IF([test "x$cxx_works" == "xno"],
AC_MSG_ERROR(
[Your C++ compiler seems to not be working.]))

# Check if the compiler provides the -fpatchable-function-entry option,
# needed to create the nop paddings in function entries.
AX_CHECK_COMPILE_FLAG([-fpatchable-function-entry=1],, AC_MSG_ERROR([\
Required compiler option missing: -fpatchable-function-entry]))

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

# Checking the call stack of all threads enables libpulp to only apply a live
# patch when no threads sit within the target library.
AC_ARG_ENABLE(stack-check,
AS_HELP_STRING([--enable-stack-check],
[build support for stack checking during live patch application [default=no]]),
[enable_stack_check=yes],
[enable_stach_check=no; break])
AS_IF([test "$enable_stack_check" = "yes"],
AC_CHECK_HEADER([libunwind.h],,
AC_MSG_ERROR([Libunwind required for stack checking.]))
AC_SUBST([LIBUNWIND_LIBS], ["-lunwind-generic -lunwind-ptrace -lunwind"])
AC_DEFINE(ENABLE_STACK_CHECK, 1, [Enable stack checking routines]),
AC_DEFINE(ENABLE_STACK_CHECK, 0, [Disable stack checking routines]))

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
# before the entry point, and the remaining nops after it. At running time,
# whenever a live patch is applied, libpulp replaces the remaining nops with
# instructions that redirect execution to the universe handling routines.
AC_SUBST([ULP_NOPS_LEN], [24])
AC_SUBST([PRE_NOPS_LEN], [22])
AC_DEFINE_UNQUOTED([ULP_NOPS_LEN], [$ULP_NOPS_LEN],
[Total number of padding nops])
AC_DEFINE_UNQUOTED([PRE_NOPS_LEN], [$PRE_NOPS_LEN],
[Padding nops before the entry point of functions])

AC_CONFIG_FILES([Makefile
		 include/Makefile
		 lib/Makefile
		 man/Makefile
		 tests/Makefile
		 tools/Makefile])

AC_OUTPUT
