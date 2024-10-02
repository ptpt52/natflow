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
#include <linux/if_macvlan.h>
#include "natflow.h"
#include "natflow_common.h"

extern unsigned short hwnat;
extern unsigned short hwnat_wed_disabled;
extern unsigned int delay_pkts;
extern unsigned int go_slowpath_if_no_qos;

extern void natflow_disabled_set(int v);
extern int natflow_disabled_get(void);

extern void natflow_update_magic(int init);

static inline int natflow_nat_ip_tcp(struct sk_buff *skb, unsigned int thoff,
                                     __be32 addr, __be32 new_addr)
{
	struct tcphdr *tcph;

	tcph = (void *)(skb_network_header(skb) + thoff);
	inet_proto_csum_replace4(&tcph->check, skb, addr, new_addr, true);

	return 0;
}

static inline int natflow_nat_ip_udp(struct sk_buff *skb, unsigned int thoff,
                                     __be32 addr, __be32 new_addr)
{
	struct udphdr *udph;

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

static inline int natflow_nat_ipv6_l4proto(struct sk_buff *skb, struct ipv6hdr *ipv6h,
        unsigned int thoff, struct in6_addr *addr, struct in6_addr *new_addr)
{
	int i;
	switch (ipv6h->nexthdr) {
	case IPPROTO_TCP:
		for (i = 0; i < 4; i++)
			natflow_nat_ip_tcp(skb, thoff, addr->s6_addr32[i], new_addr->s6_addr32[i]);
		break;
	case IPPROTO_UDP:
		for (i = 0; i < 4; i++)
			natflow_nat_ip_udp(skb, thoff, addr->s6_addr32[i], new_addr->s6_addr32[i]);
		break;
	default:
		break;
	}

	return 0;
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
		port = TCPH(l4)->source;
		TCPH(l4)->source = ct->tuplehash[!dir].tuple.dst.u.all;
		if (natflow_nat_port(skb, iph->ihl * 4, IPPROTO_TCP, port, TCPH(l4)->source) != 0) {
			return -1;
		}
		break;
	case IPPROTO_UDP:
		port = UDPH(l4)->source;
		UDPH(l4)->source = ct->tuplehash[!dir].tuple.dst.u.all;
		if (natflow_nat_port(skb, iph->ihl * 4, IPPROTO_UDP, port, UDPH(l4)->source) != 0) {
			return -1;
		}
		break;
	default:
		return -1;
	}

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
		port = TCPH(l4)->dest;
		TCPH(l4)->dest = ct->tuplehash[!dir].tuple.src.u.all;
		if (natflow_nat_port(skb, iph->ihl * 4, IPPROTO_TCP, port, TCPH(l4)->dest) != 0) {
			return -1;
		}
		break;
	case IPPROTO_UDP:
		port = UDPH(l4)->dest;
		UDPH(l4)->dest = ct->tuplehash[!dir].tuple.src.u.all;
		if (natflow_nat_port(skb, iph->ihl * 4, IPPROTO_UDP, port, UDPH(l4)->dest) != 0) {
			return -1;
		}
		break;
	default:
		return -1;
	}

	addr = iph->daddr;
	iph->daddr = ct->tuplehash[!dir].tuple.src.u3.ip;
	csum_replace4(&iph->check, addr, iph->daddr);
	if (natflow_nat_ip_l4proto(skb, iph, iph->ihl * 4, addr, iph->daddr) != 0) {
		return -1;
	}

	return 0;
}

static inline int natflow_do_snat6(struct sk_buff *skb, struct nf_conn *ct, int dir) {
	struct ipv6hdr *ipv6h;
	void *l4;
	__be16 port = 0;

	ipv6h = ipv6_hdr(skb);
	l4 = (void *)ipv6h + sizeof(struct ipv6hdr);

	switch(ipv6h->nexthdr) {
	case IPPROTO_TCP:
		port = TCPH(l4)->source;
		TCPH(l4)->source = ct->tuplehash[!dir].tuple.dst.u.all;
		if (natflow_nat_port(skb, sizeof(struct ipv6hdr), IPPROTO_TCP, port, TCPH(l4)->source) != 0) {
			return -1;
		}
		break;
	case IPPROTO_UDP:
		port = UDPH(l4)->source;
		UDPH(l4)->source = ct->tuplehash[!dir].tuple.dst.u.all;
		if (natflow_nat_port(skb, sizeof(struct ipv6hdr), IPPROTO_UDP, port, UDPH(l4)->source) != 0) {
			return -1;
		}
		break;
	default:
		return -1;
	}

	if (natflow_nat_ipv6_l4proto(skb, ipv6h, sizeof(struct ipv6hdr), &ipv6h->saddr, &ct->tuplehash[!dir].tuple.dst.u3.in6) != 0) {
		return -1;
	}
	ipv6h->saddr = ct->tuplehash[!dir].tuple.dst.u3.in6;

	return 0;
}

static inline int natflow_do_dnat6(struct sk_buff *skb, struct nf_conn *ct, int dir) {
	struct ipv6hdr *ipv6h;
	void *l4;
	__be16 port = 0;

	ipv6h = ipv6_hdr(skb);
	l4 = (void *)ipv6h + sizeof(struct ipv6hdr);

	switch(ipv6h->nexthdr) {
	case IPPROTO_TCP:
		port = TCPH(l4)->dest;
		TCPH(l4)->dest = ct->tuplehash[!dir].tuple.src.u.all;
		if (natflow_nat_port(skb, sizeof(struct ipv6hdr), IPPROTO_TCP, port, TCPH(l4)->dest) != 0) {
			return -1;
		}
		break;
	case IPPROTO_UDP:
		port = UDPH(l4)->dest;
		UDPH(l4)->dest = ct->tuplehash[!dir].tuple.src.u.all;
		if (natflow_nat_port(skb, sizeof(struct ipv6hdr), IPPROTO_UDP, port, UDPH(l4)->dest) != 0) {
			return -1;
		}
		break;
	default:
		return -1;
	}

	if (natflow_nat_ipv6_l4proto(skb, ipv6h, sizeof(struct ipv6hdr), &ipv6h->daddr, &ct->tuplehash[!dir].tuple.src.u3.in6) != 0) {
		return -1;
	}
	ipv6h->daddr = ct->tuplehash[!dir].tuple.src.u3.in6;

	return 0;
}

static inline struct net_device *vlan_lookup_dev(struct net_device *dev, unsigned short vlan_id)
{
	struct net_device *vlan_dev;

	vlan_dev = first_net_device(dev_net(dev));
	while (vlan_dev) {
		if (is_vlan_dev(vlan_dev)) {
			struct vlan_dev_priv *vlan = vlan_dev_priv(vlan_dev);
			if (vlan->vlan_id == vlan_id && vlan->real_dev == dev) {
				return vlan_dev;
			}
		}
		vlan_dev = next_net_device(vlan_dev);
	}
	return NULL;
}

static inline struct net_device *get_vlan_real_dev(struct net_device *dev)
{
	if (is_vlan_dev(dev)) {
		struct vlan_dev_priv *vlan = vlan_dev_priv(dev);
		return vlan->real_dev;
	}
	return dev;
}

static inline __be16 get_vlan_vid(struct net_device *dev)
{
	if (is_vlan_dev(dev)) {
		struct vlan_dev_priv *vlan = vlan_dev_priv(dev);
		return vlan->vlan_id;
	}
	return 0;
}

static inline __be16 get_vlan_proto(struct net_device *dev)
{
	if (is_vlan_dev(dev)) {
		struct vlan_dev_priv *vlan = vlan_dev_priv(dev);
		return vlan->vlan_proto;
	}
	return 0;
}

static inline struct net_device *get_macvlan_real_dev(struct net_device *dev)
{
#if IS_ENABLED(CONFIG_MACVLAN)
	if (netif_is_macvlan(dev)) {
		return macvlan_dev_real_dev(dev);
	}
#endif
	return dev;
}

void natflow_session_learn(struct sk_buff *skb, struct nf_conn *ct, natflow_t *nf, int dir);

/* define IFF_PPPOE indicate pppoe dev (ref: include/uapi/linux/if.h) */
#define IFF_PPPOE (1<<25)
#define IFF_IFNAME_GROUP (1<<26)
#define IFF_VLINE_L2_PORT (1<<27)
#define IFF_VLINE_FAMILY_IPV4 (1<<28)
#define IFF_VLINE_FAMILY_IPV6 (1<<29)
#define IFF_IS_LAN (1<<30)

extern int ifname_group_type;
extern void ifname_group_clear(void);
extern int ifname_group_add(const unsigned char *ifname);
extern struct net_device *ifname_group_get(int idx);

#define VLINE_L3_PORT 0
#define VLINE_L2_PORT 1
extern unsigned char (*vline_fwd_map_config_get(unsigned int idx, unsigned char *family))[2][IFNAMSIZ];
extern int vline_fwd_map_config_add(const unsigned char *dst_ifname, const unsigned char *src_ifname, unsigned char family);
extern void vline_fwd_map_config_clear(void);
extern int vline_fwd_map_config_apply(void);

#define VLINE_FAMILY_ALL 0
#define VLINE_FAMILY_IPV4 1
#define VLINE_FAMILY_IPV6 2

extern int natflow_path_init(void);
extern void natflow_path_exit(void);

#endif /* _NATFLOW_PATH_H_ */
