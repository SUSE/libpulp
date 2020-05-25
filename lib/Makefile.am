lib_LTLIBRARIES = libulp.la

libulp_la_SOURCES = ulp.c alloc.c ulp_prologue.S ulp_interface.S
libulp_la_CFLAGS = -I$(top_srcdir)/include
libulp_la_LDFLAGS = -ldl -pthread

EXTRA_DIST = trm.S

all-local: trm.o

trm.o: $(srcdir)/trm.S
	$(CPPASCOMPILE) -fPIC -c -o $@ $^

install-exec-local: trm.o
	install -d $(DESTDIR)/$(libdir)
	install -t $(DESTDIR)/$(libdir) $^

uninstall-local:
	rm -f $(DESTDIR)/$(libdir)/trm.o

check_PROGRAMS = test-alloc test-alloc-semaphore

test_alloc_SOURCES = test-alloc.c
test_alloc_CFLAGS = -I$(top_srcdir)/include
test_alloc_LDADD = libulp.la

test_alloc_semaphore_SOURCES = test-alloc-semaphore.c
test_alloc_semaphore_CFLAGS = -I$(top_srcdir)/include
test_alloc_semaphore_LDADD = libulp.la

TESTS = $(check_PROGRAMS)
