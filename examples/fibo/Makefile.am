SUBDIRS = . livepatch1

check_PROGRAMS = ex1

EXTRA_DIST = libfibo.c

clean-local:
	-rm -f *.so
	-rm -f .deps/libfibo.Po


ulp_tools_builddir = $(top_builddir)/tools
ULP_DYNSYM_GATE = $(ulp_tools_builddir)/dynsym_gate/ulp_dynsym_gate
ULP_NOP_LENGTH = @ULP_NOP_LENGTH@

libfibo.o: AM_CFLAGS += -fPIC -fpatchable-function-entry=$(ULP_NOP_LENGTH)

libfibo.so: libfibo.o $(top_builddir)/lib/trm.o
	$(CCLD) -shared -Wl,--build-id $(AM_CFLAGS) $(CFLAGS) \
		$(AM_LDFLAGS) $(LDFLAGS) -o $@ $^
	$(ULP_DYNSYM_GATE) $@


ex1_SOURCES = ex1.c
ex1_LDFLAGS = -L$(builddir) -rpath $(abs_builddir)
ex1_LDADD = -lfibo
EXTRA_ex1_DEPENDENCIES = libfibo.so
