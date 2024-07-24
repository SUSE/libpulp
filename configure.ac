#   libpulp - User-space Livepatching Library
#
#   Copyright (C) 2020-2024 SUSE Software Solutions GmbH
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

AC_INIT([libpulp],[0.3.6],[noreply@suse.com])

# Keep most generated files under the config directory.
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIRS([config])

# For multiarch builds.
AC_CANONICAL_TARGET

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

# Enable sanitizers on ulp tools
AC_ARG_ENABLE(sanitizers,
AS_HELP_STRING([--enable-sanitizers],
[compile ulp tools with address and undefined-behaviour sanitizer [default=no]]),
[enable_sanitizers=yes]
[AC_SUBST([UBSAN_OPTIONS], ["print_stack_trace=1 detect_stack_use_after_return=1"])],
[enable_sanitizers=no; break])

AM_CONDITIONAL([ENABLE_ADDRSAN], [test "x$enable_sanitizers" == "xyes"])

# Enable thread sanitizer. It can't run together with addrsan.
AC_ARG_ENABLE(thread-sanitizer,
AS_HELP_STRING([--enable-thread-sanitizer],
[compile ulp tools with thread sanitizer [default=no]]),
[enable_thread_sanitizer=yes]
[],
[enable_thread_sanitizer=no; break])

AM_CONDITIONAL([ENABLE_THREADSAN], [test "x$enable_thread_sanitizer" == "xyes"])

# We need to disable optimizations if libsanitizer is enabled, else we
# lose interesting informations about the leaks/errors.
AS_IF([test "x$enable_sanitizers" == "xyes" -o "x$enable_thread_sanitizer" == "xyes"],
      [CFLAGS="-O0 -g"], [])

# Enable valgrind on testing. Catches memory errors in libpulp.so.
AC_ARG_ENABLE(valgrind,
AS_HELP_STRING([--enable-valgrind],
[run tests through valgrind to catch memory errors in libpulp.so [default=no]]),
[enable_valgrind=yes],
[enable_valgrind=no; break])

AM_CONDITIONAL([ENABLE_VALGRIND], [test "x$enable_valgrind" == "xyes"])

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

# Check if the compiler provides the -fcf-protection=full option,
# needed to test functions with endbr64 prologue.
AX_CHECK_COMPILE_FLAG([-fcf-protection=full], [fcf_protection="yes"], [fcf_protection="no"])
AC_SUBST([FCF_PROTECTION], [""])
AS_IF([test "x$fcf_protection" == "xyes"],
  [AC_SUBST([FCF_PROTECTION], ["-fcf-protection=full"])],
  [AC_MSG_WARN([-fcf-protection=full not supported. Full testsuite coverage not possible])])

# The following headers are required to build libpulp's tools.
AC_CHECK_HEADER([gelf.h],,
AC_MSG_ERROR([Libelf development files are missing.]))

AC_CHECK_HEADER([json-c/json.h],,
AC_MSG_ERROR([json-c development files are missing.]))

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

# Check if libseccomp is present.  This is required for testing.
CFLAGS="$CFLAGS -I/usr/include/libseccomp/"
AC_CHECK_HEADER([seccomp.h],,
AC_MSG_ERROR([libseccomp required for testing.]))

# Check if Doxygen is present.
AC_CHECK_PROGS([DOXYGEN], [doxygen])
AC_CHECK_PROGS([DOT], [dot])
AC_CHECK_PROGS([PDFLATEX], [pdflatex])

# Use Doxygen to create documentation files. Use YES/NO because Doxygen
# expects the YES/NO to be in all caps.
AC_ARG_ENABLE(docs-generation,
AS_HELP_STRING([--enable-docs-generation],
[create documentation files using Doxygen [default=no]]),
[enable_docs_generation=yes],
[enable_docs_generation=no; break])
AS_IF([test "$enable_docs_generation" = "yes"],
[AS_IF([test "x$DOXYGEN" != "x"],
       [AS_IF([test "x$DOT" != "x"],
              [AS_IF([test "x$PDFLATEX" != "x"],
                     [AC_SUBST([HAVE_PDFLATEX_YESNO], ["YES"])],
                     [AC_SUBST([HAVE_PDFLATEX_YESNO], ["NO"])])]
              [AC_SUBST([HAVE_DOXYGEN], ["yes"])]
              [AC_CONFIG_FILES([docs/Doxyfile])],
              [AC_MSG_ERROR([dot is required for document generation])])],
      [AC_MSG_ERROR([doxygen is required for document generation])])], [])

# Automake require that those variables are always defined, so they can't be
# inside the above if.
AM_CONDITIONAL([HAVE_DOXYGEN], [test "$HAVE_DOXYGEN" == "yes"])
AM_CONDITIONAL([HAVE_PDFLATEX], [test "$HAVE_PDFLATEX_YESNO" == "YES"])


AC_CHECK_PROGS([AFL_GCC], [afl-gcc])
AC_CHECK_PROGS([AFL_FUZZ], [afl-fuzz])
AC_ARG_ENABLE(afl-testing,
AS_HELP_STRING([--enable-afl-testing],
[enable testing the ulp tool using the american fuzzer lop [default=no]]),
[enable_afl=yes],
[enable_afl=no; break])

AS_IF([test "$enable_afl" == "yes"],
      [AS_IF([test "x$AFL_GCC" != "x"],
             [CC="afl-gcc"],
             [AC_MSG_ERROR([afl not found in your system])])],
      [])
AM_CONDITIONAL([ENABLE_AFL], [test "x$enable_afl" == "xyes"])
if test "$enable_afl" == "yes"; then
  AC_DEFINE([ENABLE_AFL], [1], [afl support is enabled.])
fi

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
_NOPS_LEN=0
_PRE_NOPS_LEN=0

_LD_LINUX=""
AS_CASE([$target_cpu],
        [x86_64],
        [
          _NOPS_LEN=16
          _PRE_NOPS_LEN=14
          _LD_LINUX="ld-linux-x86-64.so.2"
          _PROC="x86_64"
        ],
        [powerpc64le],
        [
          _NOPS_LEN=17
          _PRE_NOPS_LEN=16
          _LD_LINUX="ld64.so.2"
          _PROC="powerpc64le"
        ]
)

AC_SUBST([ULP_NOPS_LEN], [$_NOPS_LEN])
AC_SUBST([PRE_NOPS_LEN], [$_PRE_NOPS_LEN])

AC_DEFINE_UNQUOTED([ULP_NOPS_LEN], [$ULP_NOPS_LEN],
[Total number of padding nops])
AC_DEFINE_UNQUOTED([PRE_NOPS_LEN], [$PRE_NOPS_LEN],
[Padding nops before the entry point of functions])

AC_DEFINE_UNQUOTED([LD_LINUX], ["$_LD_LINUX"],
[Path to the ld-linux loader] )

# Workaround a bug in autoconf 2.69
AM_CONDITIONAL([CPU_X86_64],  [test "$_PROC" == "x86_64"])
AM_CONDITIONAL([CPU_PPC64LE], [test "$_PROC" == "powerpc64le"])

# Use the glibc versions installed on path
AC_ARG_WITH([glibc],
AS_HELP_STRING([--with-glibc=GLIBC_PATH],[Use the glibc installed on GLIBC_PATH, where the .so file is present]),
[AC_SUBST([AM_LDFLAGS], ["-Wl,--dynamic-linker=$with_glibc/$_LD_LINUX -Wl,--rpath=$with_glibc/"])],
[])

# Check if -fpatchable-function-entry=$ULP_NOPS_LEN,$RE_NOPS_LEN works
# correctly.
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
  [[extern void g(void);
    __attribute__((patchable_function_entry($_NOPS_LEN, $_PRE_NOPS_LEN)))
    void f(void) { g(); }]])],
  [patchable_works=yes],
  [patchable_works=no])

AS_IF([test "x$patchable_works" == "xno"],
AC_MSG_ERROR(
[The -fpatchable-functions-entry flag of your C compiler does not work correctly]))

AC_CONFIG_FILES([Makefile
		 include/Makefile
		 lib/Makefile
		 man/Makefile
		 tests/Makefile
		 tools/Makefile
		 common/Makefile
		 docs/Makefile
		 scripts/Makefile])

AC_OUTPUT
