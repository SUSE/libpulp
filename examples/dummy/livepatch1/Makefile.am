ulp_tools_builddir = $(top_builddir)/tools
ULP_PACKER = $(ulp_tools_builddir)/packer/ulp_packer
ULP_REVERSE=$(ulp_tools_builddir)/packer/ulp_reverse

COMPILE = $(CC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(AM_CPPFLAGS) \
	$(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS)

LINK = $(CC) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@

.c.o:
	$(COMPILE) -fPIC -c -o $@ $<


EXTRA_DIST = patch1.c descr1.in

check-local: metadata1.ulp reverse1.ulp

clean-local:
	-rm -f *.o
	-rm -f *.so
	-rm -f *.ulp
	-rm -f *.txt

.PRECIOUS: patch1.so
patch%.so: patch%.o
	$(LINK) -shared -Wl,--build-id $^

.PRECIOUS: descr1.txt
descr%.txt: descr%.in
	sed -e "s|__ABS_BUILDDIR__|$(abs_builddir)|" \
	    -e "s|__ABS_TOP_BUILDDIR__|$(abs_top_builddir)|" \
	    $^ > $@

metadata%.ulp: patch%.so descr%.txt ../libdummy.so
	$(ULP_PACKER) descr$*.txt ../libdummy.so
	mv metadata.ulp $@

reverse%.ulp: metadata%.ulp
	$(ULP_REVERSE) $<
	mv reverse.ulp $@
