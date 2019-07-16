AM_CPPFLAGS += -I$(top_srcdir)/plugins -I/home/dn/cheetah/include/dn_logger
AM_LDFLAGS = -lrt -ldn_traces -ldn_logger -llttng-ust -lm -ldl

noinst_LTLIBRARIES = libbabeltrace-plugin-text-dnfiles-cc.la

# ctf-text plugin
libbabeltrace_plugin_text_dnfiles_cc_la_SOURCES = \
	dnfiles.h \
	msg_handler.c \
	dnfiles.c
