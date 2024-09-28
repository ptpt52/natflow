/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 27 Jun 2018 22:13:17 +0800
 */
#ifndef _NATFLOW_USER_H_
#define _NATFLOW_USER_H_
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/atomic.h>
#include <linux/if_ether.h>
#include <net/netfilter/nf_conntrack.h>
#include <linux/netfilter/ipset/ip_set.h>
#include "natflow.h"

struct token_ctrl {
	spinlock_t lock;
	int tokens;
	int tokens_per_jiffy;
	uint32_t jiffies;
};

typedef struct fakeuser_data_t {
	uint32_t timestamp;
	uint8_t macaddr[ETH_ALEN];
	uint8_t auth_type;
	uint8_t auth_status;
	uint16_t auth_rule_id;
	uint16_t auth_rule_magic;
	atomic_t rx_speed_jiffies;
	atomic_t tx_speed_jiffies;
	atomic_t rx_speed_bytes[4];
	atomic_t rx_speed_packets[4];
	atomic_t tx_speed_bytes[4];
	atomic_t tx_speed_packets[4];
	struct {
		struct token_ctrl rx;
		struct token_ctrl tx;
	} tc;
} fakeuser_data_t;

typedef struct nf_conn natflow_fakeuser_t;

extern int rx_token_ctrl(struct sk_buff *skb, struct fakeuser_data_t *fud, natflow_t *nf);
extern int tx_token_ctrl(struct sk_buff *skb, struct fakeuser_data_t *fud, natflow_t *nf);

extern natflow_fakeuser_t *natflow_user_get(struct nf_conn *ct);

extern void natflow_user_timeout_touch(natflow_fakeuser_t *nfu);

extern int natflow_user_init(void);
extern void natflow_user_exit(void);

extern void natflow_user_disabled_set(int v);
extern int natflow_user_disabled_get(void);

static inline struct fakeuser_data_t *natflow_fakeuser_data(natflow_fakeuser_t *nfu)
{
	return (void *)nfu->ext + nfu->ext->len;
}
#define FAKEUSER_IPADDR(u) ((natflow_fakeuser_t *)(u)->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)

static inline unsigned int timestamp_offset(unsigned int a, unsigned int b)
{
	if (b > a)
		return b - a;
	return a - b;
}

struct auth_rule_t {
#define INVALID_AUTH_RULE_ID 255
	unsigned int id;
	unsigned int src_zone_id;
#define AUTH_TYPE_UNKNOWN 0
#define AUTH_TYPE_AUTO 1
#define AUTH_TYPE_WEB 2
	unsigned int auth_type;
	char src_ipgrp_name[IPSET_MAXNAMELEN];
	char src_whitelist_name[IPSET_MAXNAMELEN];
	char mac_whitelist_name[IPSET_MAXNAMELEN];
};

struct auth_conf {
	unsigned int num;
	char dst_bypasslist_name[IPSET_MAXNAMELEN];
	char src_bypasslist_name[IPSET_MAXNAMELEN];
#define MAX_AUTH 16
	struct auth_rule_t auth[MAX_AUTH];
};

typedef enum {
	AUTH_NONE = 0,
	AUTH_OK = 1,
	AUTH_BYPASS = 2,
	AUTH_REQ = 3,
	AUTH_NOAUTH = 4,
	AUTH_VIP = 5,
	AUTH_BLOCK = 6,
	AUTH_UNKNOWN = 15,
} auth_status_t;

extern natflow_fakeuser_t *natflow_user_in(struct nf_conn *ct, int dir);

#endif /* _NATFLOW_USER_H_ */
