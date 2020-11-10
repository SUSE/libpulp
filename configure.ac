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

AC_INIT([libpulp], [0.1], [noreply@suse.com])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIRS([config])

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

# Check if the linker emits the .ulp section required to hold the live
# patching trampolines.
AC_MSG_CHECKING([whether the linker emits .ulp sections])
AC_LINK_IFELSE([AC_LANG_SOURCE([
asm (".pushsection .ulp.track");
asm (".popsection");
int main(void) {return 0;}
])],[
if readelf -S conftest$EXEEXT | grep -E "\.ulp " > /dev/null; then
AC_MSG_RESULT([yes])
else
AC_MSG_RESULT([no])
AC_MSG_ERROR([
Libpulp requires an assembler that emits the .ulp section when linking \
objects that contain a .ulp-track section])
fi
],[AC_MSG_ERROR([Unexpected configure error.])])

# The following headers are required to build libpulp's tools.
AC_CHECK_HEADERS([bfd.h gelf.h],
[build_ulp_tools=yes],
[build_ulp_tools=no; break])
AM_CONDITIONAL([BUILD_ULP_TOOLS], [test "$build_ulp_tools" = "yes"])
AS_IF([test "$build_ulp_tools" = "no"], AC_MSG_WARN([\
Not building the tools because of missing headers.]))

# Python and python's pexpect are required to run the tests.
AM_PATH_PYTHON([3])
AX_PYTHON_MODULE([pexpect], [fatal])

# Add the following flags to the compilation of all files
AC_SUBST([AM_CFLAGS], ["-Wall -Wextra -Werror"])

# Libpulp makes calls to AS-Unsafe functions, calloc and dlopen, from a
# signal handler, even though that might lead to a deadlock. To get rid
# of the deadlock while still sticking to calloc and dlopen, glibc could
# expose functions that let a signal handler check that all related
# locks are free, but that is not available upstream. This check tests
# that a downstream/custom glibc provides these lock-state checking
# functions:
AC_CHECK_FUNCS(__libpulp_malloc_checks)
AC_CHECK_FUNCS(__libpulp_dlopen_checks)

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

# Libpulp uses -fpatchable-function-entry to add 24 padding nops to the
# prologue of all functions (22 nops before the function address and 2
# right after it). These nops get replaced with other instructions when
# a live patch is applied.
AC_SUBST([ULP_NOP_LENGTH], [24,22])

AC_CONFIG_FILES([Makefile
		 include/Makefile
		 lib/Makefile
		 tests/Makefile
		 tools/Makefile])

AC_OUTPUT
