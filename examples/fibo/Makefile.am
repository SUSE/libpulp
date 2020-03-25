# Include common definitions
include $(top_srcdir)/Makefile.common

# Convenience libraries
check_LTLIBRARIES = libfibo.la

libfibo_la_SOURCES = libfibo.c $(TARGET_TRM_SOURCES)
libfibo_la_CFLAGS = $(TARGET_CFLAGS)
libfibo_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS = .libs/libfibo.post

# Live patches
check_LTLIBRARIES += libfibo_livepatch1.la

libfibo_livepatch1_la_SOURCES = libfibo_livepatch1.c
libfibo_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

METADATA = \
  libfibo_livepatch1.dsc \
  libfibo_livepatch1.ulp \
  libfibo_livepatch1.rev

EXTRA_DIST = \
  libfibo_livepatch1.in

clean-local:
	rm -f $(METADATA)

# Test programs
check_PROGRAMS = ex1

ex1_SOURCES = ex1.c
ex1_LDADD = libfibo.la
ex1_DEPENDENCIES = $(POST_PROCESS) $(METADATA)
