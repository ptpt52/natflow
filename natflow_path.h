/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Mon, 14 May 2018 14:49:40 +0800
 */
#ifndef _NATFLOW_PATH_H_
#define _NATFLOW_PATH_H_
#include <linux/version.h>
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_core.h>
#include "natflow.h"
#include "natflow_common.h"


extern void natflow_update_magic(void);

static inline int natflow_nat_ip_tcp(struct sk_buff *skb, unsigned int thoff,
			      __be32 addr, __be32 new_addr)
{
	struct tcphdr *tcph;

	if (!pskb_may_pull(skb, thoff + sizeof(*tcph)) ||
	    skb_try_make_writable(skb, thoff + sizeof(*tcph)))
		return -1;

	tcph = (void *)(skb_network_header(skb) + thoff);
	inet_proto_csum_replace4(&tcph->check, skb, addr, new_addr, true);

	return 0;
}

static inline int natflow_nat_ip_udp(struct sk_buff *skb, unsigned int thoff,
			      __be32 addr, __be32 new_addr)
{
	struct udphdr *udph;

	if (!pskb_may_pull(skb, thoff + sizeof(*udph)) ||
	    skb_try_make_writable(skb, thoff + sizeof(*udph)))
		return -1;

	udph = (void *)(skb_network_header(skb) + thoff);
	if (udph->check || skb->ip_summed == CHECKSUM_PARTIAL) {
		inet_proto_csum_replace4(&udph->check, skb, addr,
					 new_addr, true);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
	}

	return 0;
}


static inline int natflow_nat_ip_l4proto(struct sk_buff *skb, struct iphdr *iph,
				  unsigned int thoff, __be32 addr,
				  __be32 new_addr)
{
	switch (iph->protocol) {
	case IPPROTO_TCP:
		return natflow_nat_ip_tcp(skb, thoff, addr, new_addr);
	case IPPROTO_UDP:
		return natflow_nat_ip_udp(skb, thoff, addr, new_addr);
	default:
		break;
	}

	return -1;
}

static inline int natflow_nat_port_tcp(struct sk_buff *skb, unsigned int thoff,
				__be16 port, __be16 new_port)
{
	struct tcphdr *tcph;

	tcph = (void *)(skb_network_header(skb) + thoff);
	inet_proto_csum_replace2(&tcph->check, skb, port, new_port, true);

	return 0;
}

static inline int natflow_nat_port_udp(struct sk_buff *skb, unsigned int thoff,
				__be16 port, __be16 new_port)
{
	struct udphdr *udph;

	if (!pskb_may_pull(skb, thoff + sizeof(*udph)) ||
	    skb_try_make_writable(skb, thoff + sizeof(*udph)))
		return -1;

	udph = (void *)(skb_network_header(skb) + thoff);
	if (udph->check || skb->ip_summed == CHECKSUM_PARTIAL) {
		inet_proto_csum_replace2(&udph->check, skb, port,
					 new_port, true);
		if (!udph->check)
			udph->check = CSUM_MANGLED_0;
	}

	return 0;
}

static inline int natflow_nat_port(struct sk_buff *skb, unsigned int thoff,
			    u8 protocol, __be16 port, __be16 new_port)
{
	switch (protocol) {
	case IPPROTO_TCP:
		return natflow_nat_port_tcp(skb, thoff, port, new_port);
	case IPPROTO_UDP:
		return natflow_nat_port_udp(skb, thoff, port, new_port);
	default:
		break;
	}

	return -1;
}

static inline int natflow_do_snat(struct sk_buff *skb, struct nf_conn *ct, int dir) {
	struct iphdr *iph;
	void *l4;
	__be32 addr;
	__be16 port = 0;

	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	switch(iph->protocol) {
		case IPPROTO_TCP:
			if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)) ||
					skb_try_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
				return -1;
			port = TCPH(l4)->source;
			TCPH(l4)->source = ct->tuplehash[!dir].tuple.dst.u.all;
			if (natflow_nat_port(skb, iph->ihl * 4, iph->protocol, port, TCPH(l4)->source) != 0) {
				return -1;
			}
			break;
		case IPPROTO_UDP:
			port = UDPH(l4)->source;
			UDPH(l4)->source = ct->tuplehash[!dir].tuple.dst.u.all;
			if (natflow_nat_port(skb, iph->ihl * 4, iph->protocol, port, UDPH(l4)->source) != 0) {
				return -1;
			}
			break;
		default:
			return -1;
	}
	iph = ip_hdr(skb);

	addr = iph->saddr;
	iph->saddr = ct->tuplehash[!dir].tuple.dst.u3.ip;
	csum_replace4(&iph->check, addr, iph->saddr);
	if (natflow_nat_ip_l4proto(skb, iph, iph->ihl * 4, addr, iph->saddr) != 0) {
		return -1;
	}

	return 0;
}

static inline int natflow_do_dnat(struct sk_buff *skb, struct nf_conn *ct, int dir) {
	struct iphdr *iph;
	void *l4;
	__be32 addr;
	__be16 port = 0;

	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	switch(iph->protocol) {
		case IPPROTO_TCP:
			if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)) ||
					skb_try_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr)))
				return -1;
			port = TCPH(l4)->dest;
			TCPH(l4)->dest = ct->tuplehash[!dir].tuple.src.u.all;
			if (natflow_nat_port(skb, iph->ihl * 4, iph->protocol, port, TCPH(l4)->dest) != 0) {
				return -1;
			}
			break;
		case IPPROTO_UDP:
			port = UDPH(l4)->dest;
			UDPH(l4)->dest = ct->tuplehash[!dir].tuple.src.u.all;
			if (natflow_nat_port(skb, iph->ihl * 4, iph->protocol, port, UDPH(l4)->dest) != 0) {
				return -1;
			}
			break;
		default:
			return -1;
	}
	iph = ip_hdr(skb);

	addr = iph->daddr;
	iph->daddr = ct->tuplehash[!dir].tuple.src.u3.ip;
	csum_replace4(&iph->check, addr, iph->daddr);
	if (natflow_nat_ip_l4proto(skb, iph, iph->ihl * 4, addr, iph->daddr) != 0) {
		return -1;
	}

	return 0;
}


extern int natflow_path_init(void);
extern void natflow_path_exit(void);

#endif /* _NATFLOW_PATH_H_ */
