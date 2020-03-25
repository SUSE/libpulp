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
AM_PATH_PYTHON([3])

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
