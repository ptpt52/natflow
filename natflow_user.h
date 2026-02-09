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
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/ip6_checksum.h>
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
#if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t vline_lan:1,
	        auth_type:7;
#elif defined (__BIG_ENDIAN_BITFIELD)
	uint8_t auth_type:7,
	        vline_lan:1;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
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

extern void natflow_user_release_put(natflow_fakeuser_t *user);
extern natflow_fakeuser_t *natflow_user_in(struct nf_conn *ct, int dir);
extern natflow_fakeuser_t *natflow_user_find_get(__be32 ip);
extern natflow_fakeuser_t *natflow_user_find_get6(const union nf_inet_addr *u3);
extern natflow_fakeuser_t *natflow_user_in_get(__be32 ip, const uint8_t *macaddr);
extern natflow_fakeuser_t *natflow_user_in_get6(const union nf_inet_addr *u3, const uint8_t *macaddr);

static inline void natflow_auth_convert_tcprst(struct sk_buff *skb)
{
	int offset = 0;
	int len;
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP)
		return;
	if (skb->len < ntohs(iph->tot_len))
		return;
	tcph = (struct tcphdr *)((void *)iph + iph->ihl * 4);
	offset = iph->ihl * 4 + sizeof(struct tcphdr) - skb->len;
	if (offset > 0)
		return;
	if (pskb_trim(skb, skb->len + offset))
		return;

	tcph->res1 = 0;
	tcph->doff = 5;
	tcph->syn = 0;
	tcph->rst = 1;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->fin = 0;
	tcph->urg = 0;
	tcph->ece = 0;
	tcph->cwr = 0;
	tcph->window = __constant_htons(0);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	iph->tot_len = htons(skb->len);
	iph->id = __constant_htons(0xDEAD);
	iph->frag_off = 0;

	len = ntohs(iph->tot_len);
	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
		tcph->check = 0;
		tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_TCP, 0);
		skb->csum_start = (unsigned char *)tcph - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);
		skb->csum = 0;
		tcph->check = 0;
		skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
		tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);
	}
}

static inline void natflow_auth_convert_tcprst6(struct sk_buff *skb)
{
	struct ipv6hdr *ip6h = ipv6_hdr(skb);
	struct tcphdr *tcph;
	int tcphoff = sizeof(struct ipv6hdr);

	if (ip6h->nexthdr != IPPROTO_TCP)
		return;
	if (skb->len < tcphoff + sizeof(struct tcphdr))
		return;
	tcph = (struct tcphdr *)((void *)ip6h + tcphoff);

	if (pskb_trim(skb, tcphoff + sizeof(struct tcphdr)))
		return;

	tcph->doff = 5;
	tcph->syn = 0;
	tcph->rst = 1;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->fin = 0;
	tcph->urg = 0;
	tcph->ece = 0;
	tcph->cwr = 0;
	tcph->window = __constant_htons(0);
	tcph->check = 0;
	tcph->urg_ptr = 0;

	ip6h->payload_len = htons(sizeof(struct tcphdr));

	if (skb->ip_summed == CHECKSUM_PARTIAL) {
		tcph->check = 0;
		tcph->check = ~csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
		                               sizeof(struct tcphdr), IPPROTO_TCP, 0);
		skb->csum_start = (unsigned char *)tcph - skb->head;
		skb->csum_offset = offsetof(struct tcphdr, check);
	} else {
		skb->csum = 0;
		tcph->check = 0;
		skb->csum = skb_checksum(skb, tcphoff, sizeof(struct tcphdr), 0);
		tcph->check = csum_ipv6_magic(&ip6h->saddr, &ip6h->daddr,
		                              sizeof(struct tcphdr), IPPROTO_TCP, skb->csum);
	}
}

#endif /* _NATFLOW_USER_H_ */
