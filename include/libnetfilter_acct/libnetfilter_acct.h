#ifndef _LIBNETFILTER_ACCT_H_
#define _LIBNETFILTER_ACCT_H_

#include <sys/types.h>
#include <linux/netfilter/nfnetlink_acct.h>

struct nfacct {
	char		name[NFACCT_NAME_MAX];
	uint64_t	pkts;
	uint64_t	bytes;
};

struct nlmsghdr *nfacct_add(char *buf, struct nfacct *nfacct);
struct nlmsghdr *nfacct_list(char *buf);
int nfacct_list_cb(const struct nlmsghdr *nlh, void *data);
struct nlmsghdr *nfacct_flush(char *buf);
struct nlmsghdr *nfacct_delete(char *buf, const char *filter_name);

#endif
