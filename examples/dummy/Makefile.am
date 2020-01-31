check_PROGRAMS = ex1 ex2 ex3 ex4

noinst_HEADERS = libdummy.h
EXTRA_DIST = libdummy.c

clean-local:
	-rm -f *.o
	-rm -f *.so
	-rm -f *.ulp
	-rm -f *.txt
	-rm -f .deps/libdummy.Po


ulp_tools_builddir = $(top_builddir)/tools
ULP_DYNSYM_GATE = $(ulp_tools_builddir)/dynsym_gate/ulp_dynsym_gate
ULP_PACKER = $(ulp_tools_builddir)/packer/ulp_packer
ULP_REVERSE = $(ulp_tools_builddir)/packer/ulp_reverse
ULP_NOP_LENGTH = @ULP_NOP_LENGTH@

libdummy.o: AM_CFLAGS += -fPIC -fpatchable-function-entry=$(ULP_NOP_LENGTH)

libdummy.so: libdummy.h libdummy.o $(top_builddir)/lib/trm.o
	$(CCLD) -shared -Wl,--build-id $(AM_CFLAGS) $(CFLAGS) \
		$(AM_LDFLAGS) $(LDFLAGS) -o $@ $^
	$(ULP_DYNSYM_GATE) $@

LIVEPATCH_METADATA= metadata1.ulp reverse1.ulp metadata2.ulp reverse2.ulp

ex1_SOURCES = ex1.c
ex1_LDFLAGS = -L$(builddir) -rpath $(abs_builddir)
ex1_LDADD = -ldummy
EXTRA_ex1_DEPENDENCIES = libdummy.so $(LIVEPATCH_METADATA)


ex2_SOURCES = ex2.c
ex2_LDFLAGS = -L$(builddir) -rpath $(abs_builddir) -pthread
ex2_LDADD = -ldummy
EXTRA_ex2_DEPENDENCIES = libdummy.so $(LIVEPATCH_METADATA)


ex3_SOURCES = ex3.c
ex3_LDFLAGS = -L$(builddir) -rpath $(abs_builddir)
ex3_LDADD = -ldummy
EXTRA_ex3_DEPENDENCIES = libdummy.so $(LIVEPATCH_METADATA)


ex4_SOURCES = ex4.c
ex4_LDFLAGS = -L$(builddir) -rpath $(abs_builddir) -pthread
ex4_LDADD = -ldummy
EXTRA_ex4_DEPENDENCIES = libdummy.so $(LIVEPATCH_METADATA)

COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)

LINK = $(CC) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@

.c.o:
	$(COMPILE) -fPIC -c -o $@ $<

EXTRA_DIST += patch1.c patch2.c descr1.in descr2.in

.PRECIOUS: patch1.so patch2.so
patch%.so: patch%.o
	$(LINK) -shared -Wl,--build-id $^

.PRECIOUS: descr1.txt descr2.txt
descr%.txt: descr%.in
	sed -e "s|__ABS_BUILDDIR__|$(abs_builddir)|" $^ > $@

metadata%.ulp: patch%.so descr%.txt libdummy.so
	$(ULP_PACKER) descr$*.txt libdummy.so $@

reverse%.ulp: metadata%.ulp
	$(ULP_REVERSE) $< $@

TESTS = ex1 ex2 ex3 ex4
LOG_COMPILER = $(srcdir)/wrapper-script
AM_LOG_FLAGS = $(abs_top_builddir)
EXTRA_DIST += wrapper-script
