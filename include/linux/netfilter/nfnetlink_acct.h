#ifndef _NFNL_ACCT_H_
#define _NFNL_ACCT_H_
#include <linux/netfilter/nfnetlink.h>

/* FIXME: tweak to get it working with external headers. */
#define NFNL_SUBSYS_ACCT NFNL_SUBSYS_OSF

#define NFACCT_NAME_MAX		64

enum nfnl_acct_msg_types {
	NFNL_MSG_ACCT_NEW,
	NFNL_MSG_ACCT_GET,
	NFNL_MSG_ACCT_DEL,
	NFNL_MSG_ACCT_MAX
};

enum nfnl_acct_type {
	NFACCT_UNSPEC,
	NFACCT_NAME,
	NFACCT_PKTS,
	NFACCT_BYTES,
	__NFACCT_MAX
};
#define NFACCT_MAX (__NFACCT_MAX - 1)

#ifdef __KERNEL__

struct nf_acct;

extern struct nf_acct *nfnl_acct_find_get(char *filter_name);
extern void nfnl_acct_put(struct nf_acct *acct);

#endif /* __KERNEL__ */

#endif /* _NFNL_ACCT_H */
