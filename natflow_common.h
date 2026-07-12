/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Fri, 11 May 2018 14:20:56 +0800
 */
#ifndef _NATFLOW_COMMON_H_
#define _NATFLOW_COMMON_H_
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/jiffies.h>
#include <linux/rcupdate.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <linux/printk.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <net/icmp.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_nat.h>
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#include "natflow.h"

#if NATFLOW_KERNEL_BEFORE(5, 1, 0)
#include <net/netfilter/nf_nat_core.h>
#endif

#define MODULE_NAME "natflow"
#ifndef NATFLOW_VERSION
#define NATFLOW_VERSION "1.0.1"
#endif

#if !(defined(CONFIG_NF_NAT) || defined(CONFIG_NF_NAT_MODULE))
#error "CONFIG_NF_NAT and CONFIG_NF_NAT_MODULE not defined"
#endif

/* NAT66 is upstream since 3.7; older vendor trees may backport it. */
#if NATFLOW_NAT66_AVAILABLE
#define NATFLOW_HAVE_NAT66 1
#endif

extern unsigned int debug;

#define NATFLOW_LOG_ERROR 0x01u
#define NATFLOW_LOG_WARN  0x02u
#define NATFLOW_LOG_INFO  0x04u
#define NATFLOW_LOG_DEBUG 0x08u
#define NATFLOW_LOG_FIXME 0x10u
#define NATFLOW_LOG_DEBUG_LIMITED 0x20u

#define IS_NATFLOW_FIXME() (debug & NATFLOW_LOG_FIXME)
#define IS_NATFLOW_DEBUG() (debug & NATFLOW_LOG_DEBUG)
#define IS_NATFLOW_DEBUG_LIMITED() (debug & NATFLOW_LOG_DEBUG_LIMITED)
#define IS_NATFLOW_DEBUG_ANY() (debug & (NATFLOW_LOG_DEBUG | NATFLOW_LOG_DEBUG_LIMITED))
#define IS_NATFLOW_INFO() (debug & NATFLOW_LOG_INFO)
#define IS_NATFLOW_WARN() (debug & NATFLOW_LOG_WARN)
#define IS_NATFLOW_ERROR() (debug & NATFLOW_LOG_ERROR)

#define NATFLOW_LOG_PREFIX "{" MODULE_NAME "}:%s():%d: "

#define NATFLOW_LOG_EMIT(level, fmt, ...) \
	printk(level NATFLOW_LOG_PREFIX pr_fmt(fmt), __func__, __LINE__, ##__VA_ARGS__)

#define NATFLOW_LOG_IF(enabled, level, tag, fmt, ...) \
	do { \
		if (enabled) { \
			printk(level tag NATFLOW_LOG_PREFIX pr_fmt(fmt), __func__, __LINE__, ##__VA_ARGS__); \
		} \
	} while (0)

#define NATFLOW_LOG_RATELIMITED_IF(enabled, level, tag, fmt, ...) \
	do { \
		if (enabled) { \
			printk_ratelimited(level tag NATFLOW_LOG_PREFIX pr_fmt(fmt), __func__, __LINE__, ##__VA_ARGS__); \
		} \
	} while (0)

#define NATFLOW_println(fmt, ...) \
	do { \
		NATFLOW_LOG_EMIT(KERN_DEFAULT, fmt "\n", ##__VA_ARGS__); \
	} while (0)

#define NATFLOW_FIXME(fmt, ...) \
	NATFLOW_LOG_IF(IS_NATFLOW_FIXME(), KERN_ALERT, "fixme:", fmt, ##__VA_ARGS__)

#define NATFLOW_DEBUG(fmt, ...) \
	do { \
		if (IS_NATFLOW_DEBUG()) { \
			NATFLOW_LOG_IF(1, KERN_DEBUG, "debug:", fmt, ##__VA_ARGS__); \
		} else { \
			NATFLOW_LOG_RATELIMITED_IF(IS_NATFLOW_DEBUG_LIMITED(), KERN_DEBUG, "debug:", fmt, ##__VA_ARGS__); \
		} \
	} while (0)

#define NATFLOW_INFO(fmt, ...) \
	NATFLOW_LOG_IF(IS_NATFLOW_INFO(), KERN_DEFAULT, "info:", fmt, ##__VA_ARGS__)

#define NATFLOW_WARN(fmt, ...) \
	NATFLOW_LOG_IF(IS_NATFLOW_WARN(), KERN_WARNING, "warning:", fmt, ##__VA_ARGS__)

#define NATFLOW_ERROR(fmt, ...) \
	NATFLOW_LOG_IF(IS_NATFLOW_ERROR(), KERN_ERR, "error:", fmt, ##__VA_ARGS__)

#ifdef NO_DEBUG
#undef NATFLOW_FIXME
#undef NATFLOW_DEBUG
#undef NATFLOW_INFO
#undef NATFLOW_WARN
#undef NATFLOW_ERROR
#define NATFLOW_FIXME(fmt, ...) do { } while (0)
#define NATFLOW_DEBUG(fmt, ...) do { } while (0)
#define NATFLOW_INFO(fmt, ...) do { } while (0)
#define NATFLOW_WARN(fmt, ...) do { } while (0)
#define NATFLOW_ERROR(fmt, ...) do { } while (0)
#endif

#if NATFLOW_HAVE_NF_REGISTER_NET_HOOKS
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

struct natflow_ct_ext_layout {
	unsigned int nat_key_off;
	unsigned int natflow_off;
	unsigned int natflow_len;
	unsigned int total_len;
};

extern void natflow_ct_ext_layout_get(struct natflow_ct_ext_layout *layout);
extern int natflow_ct_ext_layout_validate(void);
extern int natflow_probe_ct_ext(void);

extern int natflow_session_init(struct nf_conn *ct, gfp_t gfp);
extern struct natflow_t *natflow_session_get(struct nf_conn *ct);
typedef void (*natflow_queue_cache_set_fn)(unsigned int cache_limit);
struct natflow_queue_cache_write_state {
	char data[MAX_IOCTL_LEN];
	int data_left;
};
extern ssize_t natflow_queue_cache_write(struct natflow_queue_cache_write_state *state,
        const char __user *buf, size_t buf_len, loff_t *offset,
        natflow_queue_cache_set_fn set_cache);
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

#define DEBUG_FMT_TCP "[" IP_TCPUDP_FMT "|ID:%04X,IL:%u|" TCP_ST_FMT "]"
#define DEBUG_ARG_TCP(i, t) IP_TCPUDP_ARG(i,t), ntohs(((struct iphdr *)(i))->id), ntohs(((struct iphdr *)(i))->tot_len), TCP_ST_ARG(t)

#define DEBUG_FMT_UDP "[" IP_TCPUDP_FMT "|ID:%04X,IL:%u|" UDP_ST_FMT "]"
#define DEBUG_ARG_UDP(i, u) IP_TCPUDP_ARG(i,u), ntohs((i)->id), ntohs((i)->tot_len), UDP_ST_ARG(u)

#define DEBUG_TCP_FMT "[%s]" DEBUG_FMT_TCP
#define DEBUG_TCP_ARG(i, t) hooknames[hooknum], DEBUG_ARG_TCP(i, t)

#define DEBUG_UDP_FMT "[%s]" DEBUG_FMT_UDP
#define DEBUG_UDP_ARG(i, u) hooknames[hooknum], DEBUG_ARG_UDP(i, u)

#define TUPLE_FMT "%pI4:%u-%c"
#define TUPLE_ARG(t) &((struct tuple *)(t))->ip, ntohs(((struct tuple *)(t))->port), ((struct tuple *)(t))->encryption ? 'e' : 'o'

#define IPV6_TCPUDP_FMT	"[%pI6c]:%u->[%pI6c]:%u"
#define IPV6_TCPUDP_ARG(i,t)	&((struct ipv6hdr *)i)->saddr, ntohs(((struct tcphdr *)(t))->source), &((struct ipv6hdr *)i)->daddr, ntohs(((struct tcphdr *)(t))->dest)

#define DEBUG_FMT6_TCP "[" IPV6_TCPUDP_FMT "|FL:%08X,HL:%u,PL:%u|" TCP_ST_FMT "]"
#define DEBUG_ARG6_TCP(i, t) IPV6_TCPUDP_ARG(i,t), \
	ntohl((__force __be32)(((((struct ipv6hdr *)i)->flow_lbl[0] & 0xF) << 16) | (((struct ipv6hdr *)i)->flow_lbl[1] << 8) | ((struct ipv6hdr *)i)->flow_lbl[2])), \
	((struct ipv6hdr *)i)->hop_limit, \
	ntohs(((struct ipv6hdr *)i)->payload_len), \
	TCP_ST_ARG(t)

#define DEBUG_FMT6_UDP "[" IPV6_TCPUDP_FMT "|FL:%08X,HL:%u,PL:%u|" UDP_ST_FMT "]"
#define DEBUG_ARG6_UDP(i, u) IPV6_TCPUDP_ARG(i,u), \
	ntohl((__force __be32)(((((struct ipv6hdr *)i)->flow_lbl[0] & 0xF) << 16) | (((struct ipv6hdr *)i)->flow_lbl[1] << 8) | ((struct ipv6hdr *)i)->flow_lbl[2])), \
	((struct ipv6hdr *)i)->hop_limit, \
	ntohs(((struct ipv6hdr *)i)->payload_len), \
	UDP_ST_ARG(u)

#define DEBUG_TCP_FMT6 "[%s]" DEBUG_FMT6_TCP
#define DEBUG_TCP_ARG6(i, t) hooknames[hooknum], DEBUG_ARG6_TCP(i, t)

#define DEBUG_UDP_FMT6 "[%s]" DEBUG_FMT6_UDP
#define DEBUG_UDP_ARG6(i, u) hooknames[hooknum], DEBUG_ARG6_UDP(i, u)

#define ETH(e) ((struct ethhdr *)(e))
#define TCPH(t) ((struct tcphdr *)(t))
#define UDPH(u) ((struct udphdr *)(u))
#define ICMPH(i) ((struct icmphdr *)(i))
#define PPPOEH(p) ((struct pppoe_hdr *)(p))
#define ICMP6H(i) ((struct icmp6hdr *)(i))

#if !NATFLOW_HAVE_SKB_TRY_MAKE_WRITABLE
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
#if NATFLOW_HAVE_NF_RESET_CT
	nf_reset_ct(skb);
#else
	nf_reset(skb);
#endif
}

#if NATFLOW_HAVE_IP_SET_STATE_API
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
extern int ip_set_test_dst_netport(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_dst_netport(state, in, out, skb, name) ip_set_test_dst_netport(state, skb, name)
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
extern int ip_set_test_dst_netport(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name);
#define IP_SET_test_dst_netport(state, in, out, skb, name) ip_set_test_dst_netport(in, out, skb, name)
#endif

#define IP_SET_test_src_port IP_SET_test_src_ip
#define IP_SET_test_dst_port IP_SET_test_dst_ip

unsigned int natflow_dnat_setup(struct nf_conn *ct, __be32 addr, __be16 man_proto);
#ifdef NATFLOW_HAVE_NAT66
unsigned int natflow_dnat_setup6(struct nf_conn *ct, const struct in6_addr *addr, __be16 man_proto);
#endif

#if !NATFLOW_NF_CONNTRACK_IN_TAKES_STATE
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

#if NATFLOW_SKB_MAKE_WRITABLE_IS_ENSURE_WRITABLE
#define skb_make_writable !skb_ensure_writable
#endif

#ifndef for_ifa
#define for_ifa(in_dev) { struct in_ifaddr *ifa; \
	in_dev_for_each_ifa_rcu(ifa, in_dev)

#define endfor_ifa(in_dev) }
#endif

static inline __be16 pppoe_proto(const struct sk_buff *skb)
{
	return *((__be16 *)(skb_mac_header(skb) + ETH_HLEN +
	                    sizeof(struct pppoe_hdr)));
}

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


#if !NATFLOW_HAVE_NF_CT_EXPIRES
static inline unsigned long nf_ct_expires(const struct nf_conn *ct)
{
	long timeout = (long)ct->timeout.expires - (long)jiffies;

	return timeout > 0 ? timeout : 0;
}
#endif

#if NATFLOW_REFCOUNT_USES_REFCOUNT_T
#define REFCOUNT_inc_not_zero refcount_inc_not_zero
#define REFCOUNT_read refcount_read
#else
#define REFCOUNT_inc_not_zero atomic_inc_not_zero
#define REFCOUNT_read atomic_read
#endif

#if NATFLOW_U64_STATS_HAS_ADD
#define compat_u64_stats_add u64_stats_add
#else
static inline void compat_u64_stats_add(u64 *r, unsigned long v)
{
	*r += v;
}
#endif

#if !NATFLOW_HAVE_GET_RANDOM_U32
#define get_random_u32 prandom_u32
#endif

#if NATFLOW_NF_BRIDGE_PHYSINDEV_TAKES_NET
static inline struct net_device *nf_bridge_get_physindev_compat(const struct sk_buff *skb)
{
	return nf_bridge_get_physindev(skb, &init_net);
}
#else
#define nf_bridge_get_physindev_compat nf_bridge_get_physindev
#endif

static inline void *natflow_ct_ext_krealloc(struct nf_ct_ext *ext, size_t size, gfp_t gfp)
{
#if NATFLOW_NF_CONNTRACK_EXT_REPLACE_NEEDS_RCU
	return __krealloc(ext, size, gfp);
#else
	return krealloc(ext, size, gfp);
#endif
}

static inline void natflow_ct_ext_replace(struct nf_conn *ct, struct nf_ct_ext *old,
        struct nf_ct_ext *new)
{
#if NATFLOW_NF_CONNTRACK_EXT_REPLACE_NEEDS_RCU
	kfree_rcu(old, rcu);
#if NATFLOW_NF_CONNTRACK_EXT_ASSIGN_NEEDS_RCU
	rcu_assign_pointer(ct->ext, new);
#else
	ct->ext = new;
#endif
#else
	ct->ext = new;
#endif
}

static inline struct nf_conntrack_tuple_hash *
natflow_nf_conntrack_find_get(struct net *net, const struct nf_conntrack_tuple *tuple)
{
#if NATFLOW_NF_CONNTRACK_FIND_GET_USES_ZONE_PTR
	return nf_conntrack_find_get(net, &nf_ct_zone_dflt, tuple);
#else
	return nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, tuple);
#endif
}

static inline void natflow_ct_timeout_extend(struct nf_conn *ct,
        unsigned long extra_jiffies)
{
#if NATFLOW_NF_CONNTRACK_TIMEOUT_IS_TIMER
	extra_jiffies += ct->timeout.expires;
	if (extra_jiffies - ct->timeout.expires >= HZ) {
		mod_timer_pending(&ct->timeout, extra_jiffies);
	}
#else
	extra_jiffies += ct->timeout;
	ct->timeout = extra_jiffies;
#endif
}

static inline void natflow_ct_timeout_set(struct nf_conn *ct,
        unsigned long expires)
{
#if NATFLOW_NF_CONNTRACK_TIMEOUT_IS_TIMER
	if (expires - ct->timeout.expires > HZ) {
		mod_timer_pending(&ct->timeout, expires);
	}
#else
	ct->timeout = expires;
#endif
}

#if NATFLOW_HAVE_NEW_CLASS_CREATE
#define natflow_class_create(name) class_create(name)
#else
#define natflow_class_create(name) class_create(THIS_MODULE, name)
#endif

#if NATFLOW_HAVE_REGISTER_SYSCTL_PATH
#define natflow_register_sysctl(path, root_table, table) register_sysctl(path, table)
#else
#define natflow_register_sysctl(path, root_table, table) register_sysctl_table(root_table)
#endif

#define IPV6H ((struct ipv6hdr *)iph)

#endif /* _NATFLOW_COMMON_H_ */
