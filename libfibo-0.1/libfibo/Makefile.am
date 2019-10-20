ulp_tools_builddir = $(top_builddir)/tools
ULP_DYNSYM_GATE = $(ulp_tools_builddir)/dynsym_gate/ulp_dynsym_gate

COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)

LINK = $(CC) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@

ULP_NOP_LENGTH = @ULP_NOP_LENGTH@

.c.o:
	$(COMPILE) -fPIC -fpatchable-function-entry=$(ULP_NOP_LENGTH) \
	-c -o $@ $<


EXTRA_DIST = libfibo.c

check-local: libfibo.so

clean-local:
	-rm -f *.o
	-rm -f *.so

libfibo.so: libfibo.o $(top_builddir)/lib/trm.o
	$(LINK) -shared -Wl,--build-id $^
	$(ULP_DYNSYM_GATE) $@
