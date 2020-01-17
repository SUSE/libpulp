lib_LTLIBRARIES = libulp.la

libulp_la_SOURCES = ulp.c ulp_prologue.S ulp_interface.S
libulp_la_LDFLAGS = -ldl

EXTRA_DIST = trm.S

all-local: trm.o

trm.o: $(srcdir)/trm.S
	$(CPPASCOMPILE) -fPIC -c -o $@ $^
