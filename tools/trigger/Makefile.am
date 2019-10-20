bin_PROGRAMS = ulp_trigger ulp_check

noinst_HEADERS = introspection.h ptrace.h

noinst_LTLIBRARIES = libcommon.la
libcommon_la_SOURCES = introspection.c ptrace.c
libcommon_la_LIBADD = -lbfd -lz -liberty -ldl

ulp_trigger_SOURCES = trigger.c
ulp_trigger_LDADD = libcommon.la

ulp_check_SOURCES = check.c
ulp_check_LDADD = libcommon.la
