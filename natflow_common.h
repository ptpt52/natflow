/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Fri, 11 May 2018 14:20:56 +0800
 */
#ifndef _NATFLOW_COMMON_H_
#define _NATFLOW_COMMON_H_
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
#include "natflow.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 1, 0)
#include <net/netfilter/nf_nat_core.h>
#endif

#define MODULE_NAME "natflow"
#define NATFLOW_VERSION "1.0.0"

#if !(defined(CONFIG_NF_NAT) || defined(CONFIG_NF_NAT_MODULE))
#error "CONFIG_NF_NAT and CONFIG_NF_NAT_MODULE not defined"
#endif

extern unsigned int debug;

#define IS_NATFLOW_FIXME() (debug & 0x10)
#define IS_NATFLOW_DEBUG() (debug & 0x8)
#define IS_NATFLOW_INFO() (debug & 0x4)
#define IS_NATFLOW_WARN() (debug & 0x2)
#define IS_NATFLOW_ERROR() (debug & 0x1)

#define NATFLOW_println(fmt, ...) \
	do { \
		printk(KERN_DEFAULT "{" MODULE_NAME "}:%s(): " pr_fmt(fmt) "\n", __FUNCTION__, ##__VA_ARGS__); \
	} while (0)

#define NATFLOW_FIXME(fmt, ...) \
	do { \
		if (IS_NATFLOW_FIXME()) { \
			printk(KERN_ALERT "fixme: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATFLOW_DEBUG(fmt, ...) \
	do { \
		if (IS_NATFLOW_DEBUG()) { \
			printk(KERN_DEBUG "debug: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATFLOW_INFO(fmt, ...) \
	do { \
		if (IS_NATFLOW_INFO()) { \
			printk(KERN_DEFAULT "info: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATFLOW_WARN(fmt, ...) \
	do { \
		if (IS_NATFLOW_WARN()) { \
			printk(KERN_WARNING "warning: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)

#define NATFLOW_ERROR(fmt, ...) \
	do { \
		if (IS_NATFLOW_ERROR()) { \
			printk(KERN_ERR "error: " pr_fmt(fmt), ##__VA_ARGS__); \
		} \
	} while (0)


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 13, 0)
static inline int nf_register_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	return nf_register_net_hooks(&init_net, reg, n);
}

static inline void nf_unregister_hooks(struct nf_hook_ops *reg, unsigned int n)
{
	nf_unregister_net_hooks(&init_net, reg, n);
}
#endif

#define __ALIGN_64BITS 8

extern int natflow_session_init(struct nf_conn *ct, gfp_t gfp);
extern struct natflow_t *natflow_session_get(struct nf_conn *ct);
static inline struct natflow_t *natflow_session_in(struct nf_conn *ct)
{
	struct natflow_t *nf = natflow_session_get(ct);

	if (nf) {
		return nf;
	}

	if (natflow_session_init(ct, GFP_ATOMIC) != 0) {
		return NULL;
	}

	return natflow_session_get(ct);
}

static inline struct natflow_t *natflow_session_get_safe(struct nf_conn *ct)
{
	if (!nf_ct_is_confirmed(ct)) {
		return NULL;
	}
	return natflow_session_get(ct);
}

extern const char *const hooknames[];

#define MAC_HEADER_FMT "%02X:%02X:%02X:%02X:%02X:%02X->%02X:%02X:%02X:%02X:%02X:%02X h_proto=%04X"
#define MAC_HEADER_ARG(eth) \
	((struct ethhdr *)(eth))->h_source[0],((struct ethhdr *)(eth))->h_source[1],((struct ethhdr *)(eth))->h_source[2], \
	((struct ethhdr *)(eth))->h_source[3],((struct ethhdr *)(eth))->h_source[4],((struct ethhdr *)(eth))->h_source[5], \
	((struct ethhdr *)(eth))->h_dest[0],((struct ethhdr *)(eth))->h_dest[1],((struct ethhdr *)(eth))->h_dest[2],\
	((struct ethhdr *)(eth))->h_dest[3],((struct ethhdr *)(eth))->h_dest[4],((struct ethhdr *)(eth))->h_dest[5],\
	((struct ethhdr *)(eth))->h_proto

#define IP_TCPUDP_FMT	"%pI4:%u->%pI4:%u"
#define IP_TCPUDP_ARG(i,t)	&(i)->saddr, ntohs(((struct tcphdr *)(t))->source), &(i)->daddr, ntohs(((struct tcphdr *)(t))->dest)
#define TCP_ST_FMT	"%c%c%c%c%c%c%c%c"
#define TCP_ST_ARG(t) \
	((struct tcphdr *)(t))->cwr ? 'C' : '.', \
	((struct tcphdr *)(t))->ece ? 'E' : '.', \
	((struct tcphdr *)(t))->urg ? 'U' : '.', \
	((struct tcphdr *)(t))->ack ? 'A' : '.', \
	((struct tcphdr *)(t))->psh ? 'P' : '.', \
	((struct tcphdr *)(t))->rst ? 'R' : '.', \
	((struct tcphdr *)(t))->syn ? 'S' : '.', \
	((struct tcphdr *)(t))->fin ? 'F' : '.'
#define UDP_ST_FMT "UL:%u,UC:%04X"
#define UDP_ST_ARG(u) ntohs(((struct udphdr *)(u))->len), ntohs(((struct udphdr *)(u))->check)

#define DEBUG_FMT_PREFIX "(%s:%u)"
#define DEBUG_ARG_PREFIX __FUNCTION__, __LINE__

#define DEBUG_FMT_TCP "[" IP_TCPUDP_FMT "|ID:%04X,IL:%u|" TCP_ST_FMT "]"
#define DEBUG_ARG_TCP(i, t) IP_TCPUDP_ARG(i,t), ntohs(((struct iphdr *)(i))->id), ntohs(((struct iphdr *)(i))->tot_len), TCP_ST_ARG(t)

#define DEBUG_FMT_UDP "[" IP_TCPUDP_FMT "|ID:%04X,IL:%u|" UDP_ST_FMT "]"
#define DEBUG_ARG_UDP(i, u) IP_TCPUDP_ARG(i,u), ntohs((i)->id), ntohs((i)->tot_len), UDP_ST_ARG(u)

#define DEBUG_TCP_FMT "[%s]" DEBUG_FMT_PREFIX DEBUG_FMT_TCP
#define DEBUG_TCP_ARG(i, t) hooknames[hooknum], DEBUG_ARG_PREFIX, DEBUG_ARG_TCP(i, t)

#define DEBUG_UDP_FMT "[%s]" DEBUG_FMT_PREFIX DEBUG_FMT_UDP
#define DEBUG_UDP_ARG(i, u) hooknames[hooknum], DEBUG_ARG_PREFIX, DEBUG_ARG_UDP(i, u)

#define TUPLE_FMT "%pI4:%u-%c"
#define TUPLE_ARG(t) &((struct tuple *)(t))->ip, ntohs(((struct tuple *)(t))->port), ((struct tuple *)(t))->encryption ? 'e' : 'o'

#define ETH(e) ((struct ethhdr *)(e))
#define TCPH(t) ((struct tcphdr *)(t))
#define UDPH(u) ((struct udphdr *)(u))
#define ICMPH(i) ((struct icmphdr *)(i))
#define PPPOEH(p) ((struct pppoe_hdr *)(p))

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)) || (LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 15) && LINUX_VERSION_CODE <KERNEL_VERSION(4, 5, 0))
#else
static inline int skb_try_make_writable(struct sk_buff *skb,
                                        unsigned int write_len)
{
	return skb_cloned(skb) && !skb_clone_writable(skb, write_len) &&
	       pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
}
#endif

#if !defined(SKB_NFCT_PTRMASK) && !defined(NFCT_PTRMASK)
static inline struct nf_conntrack *skb_nfct(const struct sk_buff *skb)
{
	return (void *)skb->nfct;
}
#endif

static inline void skb_nfct_reset(struct sk_buff *skb)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
	nf_reset_ct(skb);
#else
	nf_reset(skb);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
#define nf_reset nf_reset_ct
#else
#define skb_frag_off(f) (f)->page_offset
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
extern int ip_set_test_src_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_src_ip(state, in, out, skb, name) ip_set_test_src_ip(state, skb, name)
extern int ip_set_test_dst_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_dst_ip(state, in, out, skb, name) ip_set_test_dst_ip(state, skb, name)
extern int ip_set_add_src_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_add_src_ip(state, in, out, skb, name) ip_set_add_src_ip(state, skb, name)
extern int ip_set_add_dst_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_add_dst_ip(state, in, out, skb, name) ip_set_add_dst_ip(state, skb, name)
extern int ip_set_del_src_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_del_src_ip(state, in, out, skb, name) ip_set_del_src_ip(state, skb, name)
extern int ip_set_del_dst_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_del_dst_ip(state, in, out, skb, name) ip_set_del_dst_ip(state, skb, name)
extern int ip_set_test_src_mac(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_src_mac(state, in, out, skb, name) ip_set_test_src_mac(state, skb, name)
#else
extern int ip_set_test_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_src_ip(state, in, out, skb, name) ip_set_test_src_ip(in, out, skb, name)
extern int ip_set_test_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_dst_ip(state, in, out, skb, name) ip_set_test_dst_ip(in, out, skb, name)
extern int ip_set_add_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_add_src_ip(state, in, out, skb, name) ip_set_add_src_ip(in, out, skb, name)
extern int ip_set_add_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_add_dst_ip(state, in, out, skb, name) ip_set_add_dst_ip(in, out, skb, name)
extern int ip_set_del_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_del_src_ip(state, in, out, skb, name) ip_set_del_src_ip(in, out, skb, name)
extern int ip_set_del_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_del_dst_ip(state, in, out, skb, name) ip_set_del_dst_ip(in, out, skb, name)
extern int ip_set_test_src_mac(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_src_mac(state, in, out, skb, name) ip_set_test_src_mac(in, out, skb, name)
#endif

unsigned int natflow_dnat_setup(struct nf_conn *ct, __be32 addr, __be16 man_proto);

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 20, 0)
static inline unsigned int nf_conntrack_in_compat(struct net *net, u_int8_t pf, unsigned int hooknum, struct sk_buff *skb)
{
	return nf_conntrack_in(net, pf, hooknum, skb);
}
#else
static inline unsigned int nf_conntrack_in_compat(struct net *net, u_int8_t pf, unsigned int hooknum, struct sk_buff *skb)
{
	struct nf_hook_state state = {
		.hook = hooknum,
		.pf = pf,
		.net = net,
	};

	return nf_conntrack_in(skb, &state);
}

#define need_conntrack() do {} while (0)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define skb_make_writable !skb_ensure_writable
#endif

#ifndef for_ifa
#define for_ifa(in_dev) { struct in_ifaddr *ifa; \
	in_dev_for_each_ifa_rcu(ifa, in_dev)

#define endfor_ifa(in_dev) }
#endif

static inline unsigned char get_byte1(const unsigned char *p)
{
	return p[0];
}

static inline unsigned short get_byte2(const unsigned char *p)
{
	unsigned short v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static inline unsigned int get_byte4(const unsigned char *p)
{
	unsigned int v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static inline void set_byte1(unsigned char *p, unsigned char v)
{
	p[0] = v;
}

static inline void set_byte2(unsigned char *p, unsigned short v)
{
	memcpy(p, &v, sizeof(v));
}

static inline void set_byte4(unsigned char *p, unsigned int v)
{
	memcpy(p, &v, sizeof(v));
}

static inline void set_byte6(unsigned char *p, const unsigned char *pv)
{
	memcpy(p, pv, 6);
}

static inline void get_byte6(const unsigned char *p, unsigned char *pv)
{
	memcpy(pv, p, 6);
}

#endif /* _NATFLOW_COMMON_H_ */
