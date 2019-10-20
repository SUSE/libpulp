AC_INIT([libpulp], [0.0.1], [noreply@suse.com])
AC_CONFIG_AUX_DIR([config])
AC_CONFIG_MACRO_DIRS([config])
AM_INIT_AUTOMAKE
LT_INIT([shared disable-static])

AC_PROG_CC
AM_PROG_AS

AC_SUBST([ULP_NOP_LENGTH], [24,22])

AC_CONFIG_FILES([Makefile
		 include/Makefile
		 lib/Makefile
		 tools/Makefile
		 tools/dynsym_gate/Makefile
		 tools/packer/Makefile
		 tools/trigger/Makefile
		 libdummy-0.1/Makefile
		 libdummy_livepatch_1-0.1/Makefile
		 libdummy_livepatch_2-0.1/Makefile
		 libfibo-0.1/Makefile
		 libfibo-0.1/libfibo/Makefile
		 libfibo-0.1/ex_1/Makefile
		 libfibo_livepatch-0.1/Makefile])

AC_OUTPUT
