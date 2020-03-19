# When building sources in different directories, store object files in
# their respective paths.  For example, trm.o, which is needed by the
# libraries under test, is left in the same path as trm.S, not here.
AUTOMAKE_OPTIONS = subdir-objects

# TODO: Move this to a higher level Makefile
#
# ULP tools location
ULP_DYNSYM_GATE = $(top_builddir)/tools/dynsym_gate/ulp_dynsym_gate
ULP_PACKER = $(top_builddir)/tools/packer/ulp_packer
ULP_REVERSE = $(top_builddir)/tools/packer/ulp_reverse

# TODO: Move this to a higher level Makefile
#
# Build and link requirements for live-patchable (target) libraries.
ULP_NOP_LENGTH = @ULP_NOP_LENGTH@
TARGET_CFLAGS = -fPIC -fpatchable-function-entry=$(ULP_NOP_LENGTH)
TARGET_LDFLAGS = --build-id
TARGET_TRM_SOURCES = $(top_srcdir)/lib/trm.S

# In libtool, convenience libraries are not installed, so they do not
# need -rpath, which causes them to be statically linked.  However,
# libpulp can only live patch dynamically linked libraries, so pass
# -rpath to libtool, which causes the linking to become dynamic.
CONVENIENCE_LDFLAGS = -rpath $(libdir)

# Convenience libraries.
check_LTLIBRARIES = libdozens.la libhundreds.la
noinst_HEADERS = dozens.h hundreds.h

libdozens_la_SOURCES = dozens.c $(TARGET_TRM_SOURCES)
libdozens_la_CFLAGS = $(TARGET_CFLAGS)
libdozens_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

libhundreds_la_SOURCES = hundreds.c $(TARGET_TRM_SOURCES)
libhundreds_la_CFLAGS = $(TARGET_CFLAGS)
libhundreds_la_LDFLAGS = $(TARGET_LDFLAGS) $(CONVENIENCE_LDFLAGS)

POST_PROCESS = .libs/libdozens.post .libs/libhundreds.post

# Live patches
check_LTLIBRARIES += libdozens_livepatch1.la libhundreds_livepatch1.la

libdozens_livepatch1_la_SOURCES = libdozens_livepatch1.c
libdozens_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

libhundreds_livepatch1_la_SOURCES = libhundreds_livepatch1.c
libhundreds_livepatch1_la_LDFLAGS = $(CONVENIENCE_LDFLAGS)

METADATA = \
  libdozens_livepatch1.dsc \
  libdozens_livepatch1.ulp \
  libdozens_livepatch1.rev \
  libhundreds_livepatch1.dsc \
  libhundreds_livepatch1.ulp \
  libhundreds_livepatch1.rev

EXTRA_DIST = \
  libdozens_livepatch1.in \
  libhundreds_livepatch1.in

clean-local:
	rm -f $(METADATA)

# The following custom rules are triggered by <testname>_DEPENDENCIES:

# This rule causes the target library to be post-processed with
# ulp_dynsym_gate, so that its .ulp section gets filled.  Files with
# .post extension track whether the respective libraries have already
# been post-processed.
.libs/lib%.post: lib%.la
	$(ULP_DYNSYM_GATE) .libs/lib$*.so
	touch $@

# These rules cause the livepatch metadata to be built.  The .ulp target
# depends on check_LTLIBRARIES, because .la targets indirectly produce
# the .so files they need (it is impossible to have .ulp targets depend
# directly on .so files, because libtool does not create .so targets).
%.dsc: %.in
	sed -e "s|__ABS_BUILDDIR__|$(abs_builddir)|" $^ > $@

%.ulp: %.dsc $(check_LTLIBRARIES)
	$(ULP_PACKER) $< $@

%.rev: %.ulp
	$(ULP_REVERSE) $< $@

# Test programs
check_PROGRAMS = numserv

numserv_SOURCES = numserv.c
numserv_LDADD = libdozens.la libhundreds.la
numserv_DEPENDENCIES = $(POST_PROCESS) $(METADATA)

TESTS = numserv.py
TEST_EXTENSIONS = .py
PY_LOG_COMPILER = $(PYTHON)

EXTRA_DIST += $(TESTS)
