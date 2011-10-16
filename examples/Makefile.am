include $(top_srcdir)/Make_global.am

check_PROGRAMS = nfacct-get nfacct-add

nfacct_add_SOURCES = nfacct-add.c
nfacct_add_LDADD = ../src/libnetfilter_acct.la ${LIBMNL_LIBS}

nfacct_get_SOURCES = nfacct-get.c
nfacct_get_LDADD = ../src/libnetfilter_acct.la ${LIBMNL_LIBS}
