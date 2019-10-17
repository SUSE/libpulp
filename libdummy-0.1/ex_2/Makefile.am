check_PROGRAMS = ex2

ex2_SOURCES = ex2.c
ex2_LDFLAGS = -L$(abs_builddir)/../libdummy -rpath $(abs_builddir)/../libdummy \
	-pthread
ex2_LDADD = -ldummy
EXTRA_ex2_DEPENDENCIES = $(builddir)/../libdummy/libdummy.so
