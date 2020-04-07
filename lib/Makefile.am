lib_LTLIBRARIES = libulp.la

libulp_la_SOURCES = ulp.c ulp_prologue.S ulp_interface.S
libulp_la_LDFLAGS = -ldl

EXTRA_DIST = trm.S

all-local: trm.o

trm.o: $(srcdir)/trm.S
	$(CPPASCOMPILE) -fPIC -c -o $@ $^

install-exec-local: trm.o
	install -d $(DESTDIR)/$(libdir)
	install -t $(DESTDIR)/$(libdir) $^

uninstall-local:
	rm -f $(DESTDIR)/$(libdir)/trm.o
