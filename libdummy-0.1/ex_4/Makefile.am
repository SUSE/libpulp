check_PROGRAMS = ex4

ex4_SOURCES = ex4.c
ex4_LDFLAGS = -L$(abs_builddir)/../libdummy -rpath $(abs_builddir)/../libdummy \
	-pthread
ex4_LDADD = -ldummy
EXTRA_ex4_DEPENDENCIES = $(builddir)/../libdummy/libdummy.so
