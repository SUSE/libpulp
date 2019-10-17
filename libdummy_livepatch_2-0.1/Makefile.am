ulp_tools_builddir = $(top_builddir)/libpulp-0.1/tools
ULP_PACKER = $(ulp_tools_builddir)/packer/ulp_packer
ULP_REVERSE=$(ulp_tools_builddir)/packer/ulp_reverse

COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)

LINK = $(CC) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@

.c.o:
	$(COMPILE) -fPIC -c -o $@ $<


EXTRA_DIST = src/patch/patch.c src/patch/descr.txt

check-local: metadata2.ulp reverse2.ulp

clean-local:
	-rm -f *.o
	-rm -f *.so
	-rm -f *.ulp

patch2.so: patch.o
	$(LINK) -shared -Wl,--build-id $^

metadata2.ulp: patch2.so						\
		$(srcdir)/src/patch/descr.txt				\
		$(top_builddir)/libdummy-0.1/libdummy/libdummy.so
	$(ULP_PACKER) $(srcdir)/src/patch/descr.txt \
		$(top_builddir)/libdummy-0.1/libdummy/libdummy.so
	mv metadata.ulp $@

reverse2.ulp: metadata2.ulp
	$(ULP_REVERSE) $<
	mv reverse.ulp $@

patch.o: src/patch/patch.c
	$(COMPILE) -fPIC -c -o $@ $<
