/*
 * (C) 2011 by Pablo Neira Ayuso <pablo@netfilter.org>
 * (C) 2011 by Intra2net AG <http://www.intra2net.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Lesser GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include "internal.h"

#include <time.h>
#include <endian.h>
#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_acct.h>

#include <libnetfilter_acct/libnetfilter_acct.h>

struct nlmsghdr *nfacct_add(char *buf, struct nfacct *nfacct)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_ACCT << 8) | NFNL_MSG_ACCT_NEW;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
	nlh->nlmsg_seq = time(NULL);

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_UNSPEC;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	mnl_attr_put_strz(nlh, NFACCT_NAME, nfacct->name);
	mnl_attr_put_u64(nlh, NFACCT_PKTS, htobe64(nfacct->pkts));
	mnl_attr_put_u64(nlh, NFACCT_PKTS, htobe64(nfacct->bytes));

	return nlh;
}
EXPORT_SYMBOL(nfacct_add);

struct nlmsghdr *nfacct_list(char *buf)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_ACCT << 8) | NFNL_MSG_ACCT_GET;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
	nlh->nlmsg_seq = time(NULL);

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_UNSPEC;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	return nlh;
}
EXPORT_SYMBOL(nfacct_list);

static int nfacct_list_attr_cb(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFACCT_MAX) < 0)
		return MNL_CB_OK;

	switch(type) {
	case NFACCT_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFACCT_PKTS:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	case NFACCT_BYTES:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
			perror("mnl_attr_validate");
			return MNL_CB_ERROR;
		}
		break;
	}
	tb[type] = attr;
	return MNL_CB_OK;
}

int nfacct_list_cb(const struct nlmsghdr *nlh, void *data)
{
	struct nlattr *tb[NFACCT_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);
	bool *full = data;

	mnl_attr_parse(nlh, sizeof(*nfg), nfacct_list_attr_cb, tb);
	if (!tb[NFACCT_NAME] && !tb[NFACCT_PKTS] && !tb[NFACCT_BYTES])
		return MNL_CB_OK;

	if (full) {
		printf("%s = { pkts = %.12llu,\tbytes = %.12llu }; \n",
			mnl_attr_get_str(tb[NFACCT_NAME]),
			(unsigned long long)
				be64toh(mnl_attr_get_u64(tb[NFACCT_PKTS])),
			(unsigned long long)
				be64toh(mnl_attr_get_u64(tb[NFACCT_BYTES])));
	} else {
		printf("%s\n", mnl_attr_get_str(tb[NFACCT_NAME]));
	}

	return MNL_CB_OK;
}
EXPORT_SYMBOL(nfacct_list_cb);

struct nlmsghdr *nfacct_flush(char *buf)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_ACCT << 8) | NFNL_MSG_ACCT_DEL;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
	nlh->nlmsg_seq = time(NULL);

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_UNSPEC;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	return nlh;
}
EXPORT_SYMBOL(nfacct_flush);

struct nlmsghdr *nfacct_delete(char *buf, const char *filter_name)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_ACCT << 8) | NFNL_MSG_ACCT_DEL;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = time(NULL);

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_UNSPEC;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	mnl_attr_put_strz(nlh, NFACCT_NAME, filter_name);

	return nlh;
}
EXPORT_SYMBOL(nfacct_delete);
