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
#include <stdlib.h>
#include <string.h>

#include <libmnl/libmnl.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_acct.h>

#include <libnetfilter_acct/libnetfilter_acct.h>

struct nfacct {
	char		name[NFACCT_NAME_MAX];
	uint64_t	pkts;
	uint64_t	bytes;
	uint32_t	bitset;
};

struct nfacct *nfacct_alloc(void)
{
	return calloc(1, sizeof(struct nfacct));
}
EXPORT_SYMBOL(nfacct_alloc);

void nfacct_free(struct nfacct *nfacct)
{
	free(nfacct);
}
EXPORT_SYMBOL(nfacct_free);

void
nfacct_attr_set(struct nfacct *nfacct, enum nfacct_attr_type type,
		const void *data)
{
	switch(type) {
	case NFACCT_ATTR_NAME:
		strncpy(nfacct->name, data, NFACCT_NAME_MAX);
		nfacct->name[NFACCT_NAME_MAX-1] = '\0';
		nfacct->bitset |= (1 << NFACCT_ATTR_NAME);
		break;
	case NFACCT_ATTR_PKTS:
		nfacct->bytes = *((uint64_t *) data);
		nfacct->bitset |= (1 << NFACCT_ATTR_PKTS);
		break;
	case NFACCT_ATTR_BYTES:
		nfacct->pkts = *((uint64_t *) data);
		nfacct->bitset |= (1 << NFACCT_ATTR_BYTES);
		break;
	}
}
EXPORT_SYMBOL(nfacct_attr_set);

void
nfacct_attr_set_str(struct nfacct *nfacct, enum nfacct_attr_type type,
		    const char *name)
{
	nfacct_attr_set(nfacct, type, name);
}
EXPORT_SYMBOL(nfacct_attr_set_str);

void
nfacct_attr_set_u64(struct nfacct *nfacct, enum nfacct_attr_type type,
		    uint64_t value)
{
	nfacct_attr_set(nfacct, type, &value);
}
EXPORT_SYMBOL(nfacct_attr_set_u64);

void
nfacct_attr_unset(struct nfacct *nfacct, enum nfacct_attr_type type)
{
	switch(type) {
	case NFACCT_ATTR_NAME:
		nfacct->bitset &= ~(1 << NFACCT_ATTR_NAME);
		break;
	case NFACCT_ATTR_PKTS:
		nfacct->bitset &= ~(1 << NFACCT_ATTR_PKTS);
		break;
	case NFACCT_ATTR_BYTES:
		nfacct->bitset &= ~(1 << NFACCT_ATTR_BYTES);
		break;
	}
}
EXPORT_SYMBOL(nfacct_attr_unset);

const void *nfacct_attr_get(struct nfacct *nfacct, enum nfacct_attr_type type)
{
	const void *ret = NULL;

	switch(type) {
	case NFACCT_ATTR_NAME:
		ret = nfacct->name;
		break;
	case NFACCT_ATTR_PKTS:
		ret = &nfacct->pkts;
		break;
	case NFACCT_ATTR_BYTES:
		ret = &nfacct->bytes;
		break;
	}
	return ret;
}
EXPORT_SYMBOL(nfacct_attr_get);

const char *
nfacct_attr_get_str(struct nfacct *nfacct, enum nfacct_attr_type type)
{
	return (char *)nfacct_attr_get(nfacct, type);
}
EXPORT_SYMBOL(nfacct_attr_get_str);

uint64_t nfacct_attr_get_u64(struct nfacct *nfacct, enum nfacct_attr_type type)
{
	return *((uint64_t *)nfacct_attr_get(nfacct, type));
}
EXPORT_SYMBOL(nfacct_attr_get_u64);

/**
 * nfacct_nlmsg_build_hdr - build netlink message header for nfacct subsystem
 * @buf: buffer where this function outputs the netlink message.
 * @cmd: nfacct nfnetlink command.
 * @flags: netlink flags.
 * @seq: sequence number for this message.
 *
 * Possible commands:
 * - NFNL_MSG_ACCT_NEW: new accounting object.
 * - NFNL_MSG_ACCT_GET: get accounting object.
 * - NFNL_MSG_ACCT_GET_CTRZERO: get accounting object and atomically reset.
 *
 * Examples:
 * - Command NFNL_MSG_ACCT_NEW + flags NLM_F_CREATE | NLM_F_ACK, to create
 *   one new accounting object (if it does not already exists). You receive
 *   one acknoledgment in any case with the result of the operation.
 *
 * - Command NFNL_MSG_ACCT_GET + flags NLM_F_DUMP, to obtain all the
 *   existing accounting objects.
 *
 * - Command NFNL_MSG_ACCT_GET_CTRZERO + flags NLM_F_DUMP, to atomically
 *   obtain all the existing accounting objects and reset them.
 *
 * - Command NFNL_MSG_ACCT_DEL, to delete all existing unused objects.
 *
 * - Command NFNL_MSG_ACCT_DEL, to delete one specific nfacct object (if
 *   unused, otherwise you hit EBUSY).
 */
struct nlmsghdr *
nfacct_nlmsg_build_hdr(char *buf, uint8_t cmd, uint16_t flags, uint32_t seq)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfh;

	nlh = mnl_nlmsg_put_header(buf);
	nlh->nlmsg_type = (NFNL_SUBSYS_ACCT << 8) | cmd;
	nlh->nlmsg_flags = NLM_F_REQUEST | flags;
	nlh->nlmsg_seq = seq;

	nfh = mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
	nfh->nfgen_family = AF_UNSPEC;
	nfh->version = NFNETLINK_V0;
	nfh->res_id = 0;

	return nlh;
}
EXPORT_SYMBOL(nfacct_nlmsg_build_hdr);

void nfacct_nlmsg_build_payload(struct nlmsghdr *nlh, struct nfacct *nfacct)
{
	if (nfacct->name)
		mnl_attr_put_strz(nlh, NFACCT_NAME, nfacct->name);

	if (nfacct->pkts)
		mnl_attr_put_u64(nlh, NFACCT_PKTS, htobe64(nfacct->pkts));

	if (nfacct->bytes)
		mnl_attr_put_u64(nlh, NFACCT_PKTS, htobe64(nfacct->bytes));
}
EXPORT_SYMBOL(nfacct_nlmsg_build_payload);

static int nfacct_nlmsg_parse_attr_cb(const struct nlattr *attr, void *data)
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

int
nfacct_nlmsg_parse_payload(const struct nlmsghdr *nlh, struct nfacct *nfacct)
{
	struct nlattr *tb[NFACCT_MAX+1] = {};
	struct nfgenmsg *nfg = mnl_nlmsg_get_payload(nlh);

	mnl_attr_parse(nlh, sizeof(*nfg), nfacct_nlmsg_parse_attr_cb, tb);
	if (!tb[NFACCT_NAME] && !tb[NFACCT_PKTS] && !tb[NFACCT_BYTES])
		return -1;

	nfacct_attr_set_str(nfacct, NFACCT_ATTR_NAME,
			    mnl_attr_get_str(tb[NFACCT_NAME]));
	nfacct_attr_set_u64(nfacct, NFACCT_ATTR_PKTS,
			    be64toh(mnl_attr_get_u64(tb[NFACCT_PKTS])));
	nfacct_attr_set_u64(nfacct, NFACCT_ATTR_BYTES,
			    be64toh(mnl_attr_get_u64(tb[NFACCT_BYTES])));

	return 0;
}
EXPORT_SYMBOL(nfacct_nlmsg_parse_payload);

int nfacct_snprintf(char *buf, size_t size, struct nfacct *nfacct,
		    unsigned int flags)
{
	int ret;

	if (flags & NFACCT_SNPRINTF_F_FULL) {
		ret = snprintf(buf, size,
			"%s = { pkts = %.12llu,\tbytes = %.12llu };",
			nfacct_attr_get_str(nfacct, NFACCT_ATTR_NAME),
			(unsigned long long)
			nfacct_attr_get_u64(nfacct, NFACCT_ATTR_BYTES),
			(unsigned long long)
			nfacct_attr_get_u64(nfacct, NFACCT_ATTR_PKTS));
	} else {
		ret = snprintf(buf, size, "%s\n",
			nfacct_attr_get_str(nfacct, NFACCT_ATTR_NAME));
	}
	return ret;
}
EXPORT_SYMBOL(nfacct_snprintf);
