check_PROGRAMS = ex1

ex1_SOURCES = ex1.c
ex1_LDFLAGS = -L$(abs_builddir)/../libdummy -rpath $(abs_builddir)/../libdummy
ex1_LDADD = -ldummy
EXTRA_ex1_DEPENDENCIES = $(builddir)/../libdummy/libdummy.so
