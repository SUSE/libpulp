AC_INIT([libpulp], [0.0.1], [noreply@suse.com])
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

# Initialize libtool with static libraries disabled, since libulp is
# supposed to be dynamically linked into applications.
LT_INIT([shared disable-static])

AC_PROG_CC
AM_PROG_AS

# Check if the compiler provides the -fpatchable-function-entry option,
# needed to create the nop paddings in function entries.
AX_CHECK_COMPILE_FLAG([-fpatchable-function-entry=1],, AC_MSG_ERROR([\
Required compiler option missing: -fpatchable-function-entry]))

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

AC_SUBST(AM_CFLAGS, ["-Wall -Wextra -Werror"])

AC_SUBST([ULP_NOP_LENGTH], [24,22])

AC_CONFIG_FILES([Makefile
		 include/Makefile
		 lib/Makefile
		 tests/Makefile
		 tools/Makefile
		 tools/dynsym_gate/Makefile
		 tools/packer/Makefile
		 tools/trigger/Makefile
		 examples/Makefile
		 examples/dummy/Makefile
		 examples/fibo/Makefile])

AC_OUTPUT
