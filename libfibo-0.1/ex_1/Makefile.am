check_PROGRAMS = ex1

ex1_SOURCES = ex1.c
ex1_LDFLAGS = -L$(abs_builddir)/../libfibo -rpath $(abs_builddir)/../libfibo
ex1_LDADD = -lfibo
EXTRA_ex1_DEPENDENCIES = $(builddir)/../libfibo/libfibo.so
