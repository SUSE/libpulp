check_PROGRAMS = ex1 ex2 ex3 ex4

noinst_HEADERS = libdummy.h
EXTRA_DIST = libdummy.c weak.c

check-local: libdummy.so

clean-local:
	-rm -f *.so


ulp_tools_builddir = $(top_builddir)/tools
ULP_DYNSYM_GATE = $(ulp_tools_builddir)/dynsym_gate/ulp_dynsym_gate
ULP_NOP_LENGTH = @ULP_NOP_LENGTH@

libdummy.o: AM_CFLAGS += -fPIC -fpatchable-function-entry=$(ULP_NOP_LENGTH)
weak.o: AM_CFLAGS += -fPIC -fpatchable-function-entry=$(ULP_NOP_LENGTH)

libdummy.so: libdummy.h libdummy.o weak.o $(top_builddir)/lib/trm.o
	$(CCLD) -shared -Wl,--build-id $(AM_CFLAGS) $(CFLAGS) \
		$(AM_LDFLAGS) $(LDFLAGS) -o $@ $^
	$(ULP_DYNSYM_GATE) $@


ex1_SOURCES = ex1.c
ex1_LDFLAGS = -L$(builddir) -rpath $(abs_builddir)
ex1_LDADD = -ldummy
EXTRA_ex1_DEPENDENCIES = libdummy.so


ex2_SOURCES = ex2.c
ex2_LDFLAGS = -L$(builddir) -rpath $(abs_builddir) -pthread
ex2_LDADD = -ldummy
EXTRA_ex2_DEPENDENCIES = libdummy.so


ex3_SOURCES = ex3.c
ex3_LDFLAGS = -L$(builddir) -rpath $(abs_builddir)
ex3_LDADD = -ldummy
EXTRA_ex3_DEPENDENCIES = libdummy.so


ex4_SOURCES = ex4.c
ex4_LDFLAGS = -L$(builddir) -rpath $(abs_builddir) -pthread
ex4_LDADD = -ldummy
EXTRA_ex4_DEPENDENCIES = libdummy.so
