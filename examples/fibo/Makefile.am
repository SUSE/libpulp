check_PROGRAMS = ex1

EXTRA_DIST = libfibo.c

clean-local:
	-rm -f *.o
	-rm -f *.so
	-rm -f *.ulp
	-rm -f *.txt
	-rm -f .deps/libfibo.Po


ulp_tools_builddir = $(top_builddir)/tools
ULP_DYNSYM_GATE = $(ulp_tools_builddir)/dynsym_gate/ulp_dynsym_gate
ULP_PACKER = $(ulp_tools_builddir)/packer/ulp_packer
ULP_REVERSE=$(ulp_tools_builddir)/packer/ulp_reverse
ULP_NOP_LENGTH = @ULP_NOP_LENGTH@

libfibo.o: AM_CFLAGS += -fPIC -fpatchable-function-entry=$(ULP_NOP_LENGTH)

libfibo.so: libfibo.o $(top_builddir)/lib/trm.o
	$(CCLD) -shared -Wl,--build-id $(AM_CFLAGS) $(CFLAGS) \
		$(AM_LDFLAGS) $(LDFLAGS) -o $@ $^
	$(ULP_DYNSYM_GATE) $@


ex1_SOURCES = ex1.c
ex1_LDFLAGS = -L$(builddir) -rpath $(abs_builddir)
ex1_LDADD = -lfibo
EXTRA_ex1_DEPENDENCIES = libfibo.so metadata1.ulp reverse1.ulp


COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)

LINK = $(CC) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@

.c.o:
	$(COMPILE) -fPIC -c -o $@ $<

EXTRA_DIST += patch1.c descr1.in

.PRECIOUS: patch1.so
patch1.so: patch1.o
	$(LINK) -shared -Wl,--build-id $^

.PRECIOUS: descr1.txt
descr1.txt: descr1.in
	sed -e "s|__ABS_BUILDDIR__|$(abs_builddir)|" $^ > $@

metadata1.ulp: patch1.so descr1.txt libfibo.so
	$(ULP_PACKER) descr1.txt libfibo.so $@

reverse1.ulp: metadata1.ulp
	$(ULP_REVERSE) $< $@
