/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Mon, 14 May 2018 14:49:40 +0800
 */
#include <linux/ctype.h>
#include <linux/device.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/netfilter.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/netfilter.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_acct.h>
#ifdef CONFIG_NETFILTER_INGRESS
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#endif
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
#include <net/netfilter/nf_flow_table.h>
#endif
#include "natflow_common.h"
#include "natflow_path.h"
#include "natflow_user.h"

#ifdef CONFIG_NETFILTER_INGRESS
static inline __be16 pppoe_proto(const struct sk_buff *skb)
{
	return *((__be16 *)(skb_mac_header(skb) + ETH_HLEN +
	                    sizeof(struct pppoe_hdr)));
}
#endif

unsigned int hwnat = 1;

static int disabled = 1;
void natflow_disabled_set(int v)
{
	disabled = v;
}
int natflow_disabled_get(void)
{
	return disabled;
}

static unsigned short natflow_path_magic = 0;
void natflow_update_magic(int init)
{
	if (init) {
		natflow_path_magic = jiffies + prandom_u32();
	} else {
		natflow_path_magic++;
	}
}

#ifdef CONFIG_NETFILTER_INGRESS
static natflow_fastnat_node_t *natflow_fast_nat_table = NULL;

static inline void natflow_update_ct_timeout(struct nf_conn *ct, unsigned long extra_jiffies)
{
	if (!nf_ct_is_confirmed(ct)) {
		/* nothing to do */
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		extra_jiffies += ct->timeout.expires;
		if (extra_jiffies - ct->timeout.expires >= HZ) {
			mod_timer_pending(&ct->timeout, extra_jiffies);
		}
#else
		extra_jiffies += ct->timeout;
		ct->timeout = extra_jiffies;
#endif
	}
}

static void natflow_offload_keepalive(unsigned int hash, unsigned long bytes, unsigned long packets, unsigned int *speed_bytes, unsigned int *speed_packets)
{
	struct nf_conn_acct *acct;
	natflow_fastnat_node_t *nfn;
	unsigned long diff_jiffies = 0;
	unsigned long current_jiffies = jiffies;

	hash = hash % (NATFLOW_FASTNAT_TABLE_SIZE * 2);
	nfn = &natflow_fast_nat_table[hash];
	diff_jiffies = ulongmindiff(current_jiffies, nfn->jiffies);

	if ((u32)diff_jiffies < NATFLOW_FF_TIMEOUT_HIGH) {
		struct nf_conntrack_tuple tuple;
		struct nf_conntrack_tuple_hash *h;

		nfn->jiffies = current_jiffies;

		memset(&tuple, 0, sizeof(tuple));
		tuple.src.u3.ip = nfn->saddr;
		tuple.src.u.tcp.port = nfn->source;
		tuple.dst.u3.ip = nfn->daddr;
		tuple.dst.u.tcp.port = nfn->dest;
		tuple.src.l3num = PF_INET;
		tuple.dst.protonum = nfn->protonum;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
		h = nf_conntrack_find_get(&init_net, NF_CT_DEFAULT_ZONE, &tuple);
#else
		h = nf_conntrack_find_get(&init_net, &nf_ct_zone_dflt, &tuple);
#endif
		if (h) {
			struct nf_conn *ct = nf_ct_tuplehash_to_ctrack(h);
			int d = !NF_CT_DIRECTION(h);
			__be32 saddr = ct->tuplehash[d].tuple.src.u3.ip;
			__be32 daddr = ct->tuplehash[d].tuple.dst.u3.ip;
			__be16 source = ct->tuplehash[d].tuple.src.u.all;
			__be16 dest = ct->tuplehash[d].tuple.dst.u.all;
			__be16 protonum = ct->tuplehash[d].tuple.dst.protonum;

			NATFLOW_INFO("keepalive[%u] nfn[%pI4:%u->%pI4:%u] ct%d diff_jiffies=%u HZ=%u\n",
			             hash, &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest), !d, (unsigned int)diff_jiffies, HZ);

			natflow_update_ct_timeout(ct, diff_jiffies);

			hash = natflow_hash_v4(saddr, daddr, source, dest, protonum);
			nfn = &natflow_fast_nat_table[hash];
			if (nfn->saddr != saddr || nfn->daddr != daddr || nfn->source != source || nfn->dest != dest || nfn->protonum != protonum) {
				hash += 1;
				nfn = &natflow_fast_nat_table[hash];
			}

			diff_jiffies = ulongmindiff(current_jiffies, nfn->jiffies);

			if ((u32)diff_jiffies < NATFLOW_FF_TIMEOUT_HIGH &&
			        nfn->saddr == saddr && nfn->daddr == daddr && nfn->source == source && nfn->dest == dest && nfn->protonum == protonum) {
				if (!(nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
					nfn->jiffies = current_jiffies;
					NATFLOW_INFO("keepalive[%u] nfn[%pI4:%u->%pI4:%u] diff_jiffies=%u\n",
					             hash, &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest), (unsigned int)diff_jiffies);
				}
			}

			acct = nf_conn_acct_find(ct);
			if (acct) {
				struct nf_conn_counter *counter = acct->counter;
				atomic64_add(packets, &counter[!d].packets);
				atomic64_add(bytes, &counter[!d].bytes);
			}
			do {
				natflow_fakeuser_t *user;
				struct fakeuser_data_t *fud;
				user = natflow_user_get(ct);
				if (NULL == user) {
					break;
				}
				if (user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip != ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
					d = !d;
				}
				acct = nf_conn_acct_find(user);
				if (acct) {
					struct nf_conn_counter *counter = acct->counter;
					atomic64_add(packets, &counter[d].packets);
					atomic64_add(bytes, &counter[d].bytes);
				}
				if (!speed_bytes) {
					break;
				}
				fud = natflow_fakeuser_data(user);
				if (d == 0) {
					int i = (jiffies/HZ) % 4;
					int j = (fud->rx_speed_jiffies/HZ) % 4;
					int diff = 0;
					diff_jiffies = ulongmindiff(jiffies, fud->rx_speed_jiffies);
					fud->rx_speed_jiffies = jiffies;
					if (diff_jiffies >= HZ * 4) {
						for(j = 0; j < 4; j++) {
							fud->rx_speed_bytes[j] = 0;
							fud->rx_speed_packets[j] = 0;
						}
						j = i;
					}
					for (; j != i; ) {
						diff++;
						j = (j + 1) % 4;
						fud->rx_speed_bytes[j] = speed_bytes[j];
						fud->rx_speed_packets[j] = speed_packets[j];
						speed_bytes[j] = speed_packets[j] = 0;
					}
					for (; diff < 4; diff++) {
						j = (j + 1) % 4;
						fud->rx_speed_bytes[j] += speed_bytes[j];
						fud->rx_speed_packets[j] += speed_packets[j];
						speed_bytes[j] = speed_packets[j] = 0;
					}
				} else {
					int i = (jiffies/HZ) % 4;
					int j = (fud->tx_speed_jiffies/HZ) % 4;
					int diff = 0;
					diff_jiffies = ulongmindiff(jiffies, fud->tx_speed_jiffies);
					fud->tx_speed_jiffies = jiffies;
					if (diff_jiffies >= HZ * 4) {
						for(j = 0; j < 4; j++) {
							fud->tx_speed_bytes[j] = 0;
							fud->tx_speed_packets[j] = 0;
						}
						j = i;
					}
					for (; j != i; ) {
						diff++;
						j = (j + 1) % 4;
						fud->tx_speed_bytes[j] = speed_bytes[j];
						fud->tx_speed_packets[j] = speed_packets[j];
						speed_bytes[j] = speed_packets[j] = 0;
					}
					for (; diff < 4; diff++) {
						j = (j + 1) % 4;
						fud->tx_speed_bytes[j] += speed_bytes[j];
						fud->tx_speed_packets[j] += speed_packets[j];
						speed_bytes[j] = speed_packets[j] = 0;
					}
				}
			} while (0);
			nf_ct_put(ct);
			return;
		}
		NATFLOW_INFO("keepalive[%u] nfn[%pI4:%u->%pI4:%u] diff_jiffies=%u ct not found\n",
		             hash, &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest), (unsigned int)diff_jiffies);
		nfn->jiffies = jiffies - NATFLOW_FF_TIMEOUT_HIGH;
		return;
	}
	NATFLOW_WARN("keepalive[%u] nfn[%pI4:%u->%pI4:%u] diff_jiffies=%u timeout\n",
	             hash, &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest), (unsigned int)diff_jiffies);
}

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
#if defined(NATFLOW_OFFLOAD_HWNAT_FAKE)
#else
typedef struct flow_offload flow_offload_t;
typedef struct flow_offload_tuple flow_offload_tuple_t;
typedef struct flow_offload_hw_path flow_offload_hw_path_t;
typedef enum flow_offload_type flow_offload_type_t;
#endif
struct natflow_offload {
	flow_offload_t flow;
};

static struct natflow_offload *natflow_offload_alloc(struct nf_conn *ct, natflow_t *nf)
{
	static struct natflow_offload natflow_offload[NR_CPUS];

	int dir;
	flow_offload_tuple_t *ft;
	struct nf_conntrack_tuple *ctt;
	struct natflow_offload *natflow = &natflow_offload[smp_processor_id()];
	flow_offload_t *flow = &natflow->flow;
	int orig_hash, reply_hash;
	natflow_fastnat_node_t *nfn;

	dir = 0;
	ft = &flow->tuplehash[dir].tuple;
	ctt = &ct->tuplehash[dir].tuple;
	ft->src_v4 = ctt->src.u3.in;
	ft->dst_v4 = ctt->dst.u3.in;
	ft->l3proto = ctt->src.l3num;
	ft->l4proto = ctt->dst.protonum;
	ft->src_port = ctt->src.u.tcp.port;
	ft->dst_port = ctt->dst.u.tcp.port;

	orig_hash = natflow_hash_v4(ft->src_v4.s_addr, ft->dst_v4.s_addr, ft->src_port, ft->dst_port, ft->l4proto);
	nfn = &natflow_fast_nat_table[orig_hash];
	if (nfn->saddr != ft->src_v4.s_addr || nfn->daddr != ft->dst_v4.s_addr || nfn->source != ft->src_port || nfn->dest != ft->dst_port || nfn->protonum != ft->l4proto)
	{
		orig_hash += 1;
	}

	dir = 1;
	ft = &flow->tuplehash[dir].tuple;
	ctt = &ct->tuplehash[dir].tuple;
	ft->src_v4 = ctt->src.u3.in;
	ft->dst_v4 = ctt->dst.u3.in;
	ft->l3proto = ctt->src.l3num;
	ft->l4proto = ctt->dst.protonum;
	ft->src_port = ctt->src.u.tcp.port;
	ft->dst_port = ctt->dst.u.tcp.port;

	reply_hash = natflow_hash_v4(ft->src_v4.s_addr, ft->dst_v4.s_addr, ft->src_port, ft->dst_port, ft->l4proto);
	nfn = &natflow_fast_nat_table[reply_hash];
	if (nfn->saddr != ft->src_v4.s_addr || nfn->daddr != ft->dst_v4.s_addr || nfn->source != ft->src_port || nfn->dest != ft->dst_port || nfn->protonum != ft->l4proto)
	{
		reply_hash += 1;
	}

	/*XXX: in fact ppe don't care flags  */
	flow->flags = 0;
	if ((void *)flow->priv != (void *)natflow_offload_keepalive) {
		flow->priv = (void *)natflow_offload_keepalive;
	}

	flow->timeout = (orig_hash << 16) | reply_hash;

	return natflow;
}
#endif
#endif

void natflow_session_learn(struct sk_buff *skb, struct nf_conn *ct, natflow_t *nf, int dir)
{
	int magic = natflow_path_magic;
	struct iphdr *iph = ip_hdr(skb);
	struct net_device *dev;

	if (nf->magic != magic) {
		simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
		simple_clear_bit(NF_FF_REPLY_OK_BIT, &nf->status);
		simple_clear_bit(NF_FF_REPLY_BIT, &nf->status);

		simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
		simple_clear_bit(NF_FF_ORIGINAL_OK_BIT, &nf->status);
		simple_clear_bit(NF_FF_ORIGINAL_BIT, &nf->status);
		nf->magic = magic;
	}
	if (!skb->dev) {
		return;
	}
	dev = get_macvlan_real_dev(skb->dev);

	if (dir == IP_CT_DIR_ORIGINAL) {
		if (!(nf->status & NF_FF_REPLY) && !simple_test_and_set_bit(NF_FF_REPLY_BIT, &nf->status)) {
			void *l2 = (void *)skb_mac_header(skb);
			int l2_len = (void *)iph - l2;
			if (dev->type == ARPHRD_PPP || dev->type == ARPHRD_NONE) {
				l2_len = 0;
			}
			if (l2_len >= 0 && l2_len <= NF_L2_MAX_LEN) {
				nf->rroute[NF_FF_DIR_REPLY].l2_head_len = l2_len;
				if (l2_len >= ETH_HLEN) {
					memcpy(ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH(l2)->h_dest, ETH_ALEN);
					memcpy(ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH(l2)->h_source, ETH_ALEN);
					ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_proto = ETH(l2)->h_proto;
					memcpy(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN, l2 + ETH_HLEN, l2_len - ETH_HLEN);
				}
				nf->rroute[NF_FF_DIR_REPLY].outdev = dev;
				if (skb_vlan_tag_present(skb)) {
					nf->rroute[NF_FF_DIR_REPLY].vlan_present = 1;
					nf->rroute[NF_FF_DIR_REPLY].vlan_tci = skb_vlan_tag_get_id(skb);
					if (skb->vlan_proto == htons(ETH_P_8021Q))
						nf->rroute[NF_FF_DIR_REPLY].vlan_proto = FF_ETH_P_8021Q;
					else if (skb->vlan_proto == htons(ETH_P_8021AD))
						nf->rroute[NF_FF_DIR_REPLY].vlan_proto = FF_ETH_P_8021AD;
				}
				simple_set_bit(NF_FF_REPLY_OK_BIT, &nf->status);
			}
		}
	} else {
		if (!(nf->status & NF_FF_ORIGINAL) && !simple_test_and_set_bit(NF_FF_ORIGINAL_BIT, &nf->status)) {
			void *l2 = (void *)skb_mac_header(skb);
			int l2_len = (void *)iph - l2;
			if (dev->type == ARPHRD_PPP || dev->type == ARPHRD_NONE) {
				l2_len = 0;
			}
			if (l2_len >= 0 && l2_len <= NF_L2_MAX_LEN) {
				nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len = l2_len;
				if (l2_len >= ETH_HLEN) {
					memcpy(ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH(l2)->h_dest, ETH_ALEN);
					memcpy(ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH(l2)->h_source, ETH_ALEN);
					ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_proto = ETH(l2)->h_proto;
					memcpy(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN, l2 + ETH_HLEN, l2_len - ETH_HLEN);
				}
				nf->rroute[NF_FF_DIR_ORIGINAL].outdev = dev;
				if (skb_vlan_tag_present(skb)) {
					nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present = 1;
					nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci = skb_vlan_tag_get_id(skb);
					if (skb->vlan_proto == htons(ETH_P_8021Q))
						nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto = FF_ETH_P_8021Q;
					else if (skb->vlan_proto == htons(ETH_P_8021AD))
						nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto = FF_ETH_P_8021AD;
				}
				simple_set_bit(NF_FF_ORIGINAL_OK_BIT, &nf->status);
			}
		}
	}
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natflow_path_pre_ct_in_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#ifdef CONFIG_NETFILTER_INGRESS
	u_int8_t pf = PF_INET;
#endif
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_path_pre_ct_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#ifdef CONFIG_NETFILTER_INGRESS
	u_int8_t pf = ops->pf;
#endif
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_path_pre_ct_in_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
#ifdef CONFIG_NETFILTER_INGRESS
	u_int8_t pf = state->pf;
#endif
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natflow_path_pre_ct_in_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
#ifdef CONFIG_NETFILTER_INGRESS
	u_int8_t pf = state->pf;
#endif
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	//const struct net_device *out = state->out;
#endif
#endif
	int dir = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn_acct *acct;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	natflow_t *nf;
	int ret = NF_ACCEPT;
#ifdef CONFIG_NETFILTER_INGRESS
	int d;
	unsigned int re_learn = 0;
	unsigned int ingress_pad_len = 0;
#endif
	unsigned int ingress_trim_off = 0;

	if (disabled)
		return NF_ACCEPT;

#ifdef CONFIG_NETFILTER_INGRESS
	if (pf == NFPROTO_NETDEV) {
		u32 _I;
		u32 hash;
		natflow_fastnat_node_t *nfn;

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
		/* XXX: check MTK_CPU_REASON_HIT_BIND_FORCE_CPU
		 * nated-skb come to cpu from ppe, we just forward to ext dev(Wi-Fi)
		 * skb->hash stored the hash key
		 */
		if (hwnat && skb->dev->netdev_ops->ndo_flow_offload &&
		        (skb->vlan_tci & HWNAT_QUEUE_MAPPING_MAGIC_MASK) == HWNAT_QUEUE_MAPPING_MAGIC &&
		        (skb->hash & HWNAT_QUEUE_MAPPING_MAGIC_MASK) == HWNAT_QUEUE_MAPPING_MAGIC) {
			_I = (skb->hash & HWNAT_QUEUE_MAPPING_HASH_MASK) % (NATFLOW_FASTNAT_TABLE_SIZE * 2);
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
			if (_I == 0) _I = (skb->vlan_tci & HWNAT_QUEUE_MAPPING_HASH_MASK) % (NATFLOW_FASTNAT_TABLE_SIZE * 2);
#endif
			nfn = &natflow_fast_nat_table[_I];
			_I = (u32)ulongmindiff(jiffies, nfn->jiffies);

			if (nfn->outdev && _I <= NATFLOW_FF_TIMEOUT_LOW && nfn->magic == natflow_path_magic) {
				//nfn->jiffies = jiffies; /* we update jiffies in keepalive */
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
				__vlan_hwaccel_clear_tag(skb);
				skb->dev = nfn->outdev;
#else
				skb->dev = get_vlan_real_dev(nfn->outdev);
#endif
				skb_push(skb, (void *)ip_hdr(skb) - (void *)eth_hdr(skb));
				dev_queue_xmit(skb);
				return NF_STOLEN;
			}
			/* Strict conditions can determine that it is a specially marked skb
			 * so it is safe to drop
			 * TODO: del foe
			 */
			return NF_DROP;
		}
#endif

		if (skb->mac_len != ETH_HLEN) {
			return NF_ACCEPT;
		}
		if (skb->protocol == __constant_htons(ETH_P_PPP_SES) &&
		        pppoe_proto(skb) == __constant_htons(PPP_IP) /* Internet Protocol */) {
			ingress_pad_len = PPPOE_SES_HLEN;
		} else if (skb->protocol == __constant_htons(ETH_P_IP)) {
			ingress_pad_len = 0;
		} else {
			return NF_ACCEPT;
		}

		if (ingress_pad_len > 0) {
			skb_pull_rcsum(skb, ingress_pad_len);
			skb->network_header += ingress_pad_len;
		}

		if (!pskb_may_pull(skb, sizeof(struct iphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);

		if (iph->ihl < 5 || iph->version != 4 || ip_is_fragment(iph)) {
			goto out;
		}

		_I = ntohs(iph->tot_len);
		if (skb->len < _I || _I < (iph->ihl * 4)) {
			goto out;
		}
		if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
			goto out;
		}

		if (!pskb_may_pull(skb, iph->ihl * 4)) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl))) {
			return NF_DROP;
		}

		ingress_trim_off = skb->len - _I;
		if (pskb_trim_rcsum(skb, _I)) {
			return NF_DROP;
		}

		skb->protocol = __constant_htons(ETH_P_IP);
		skb->transport_header = skb->network_header + ip_hdr(skb)->ihl * 4;

#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
		/* XXX:
		 * MT7622 hwnat cannot handle vlan for ext dev
		 * Route forwarding: all good
		 * Bridge forwarding: cannot handle vlan tag packets, pppoe tag is good
		 */
		if (skb_vlan_tag_present(skb)) {
			goto out;
		}
#endif

		if (iph->protocol == IPPROTO_TCP) {
			if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)) || skb_try_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
			_I = natflow_hash_v4(iph->saddr, iph->daddr, TCPH(l4)->source, TCPH(l4)->dest, IPPROTO_TCP);
			nfn = &natflow_fast_nat_table[_I];
			if (nfn->saddr != iph->saddr || nfn->daddr != iph->daddr ||
			        nfn->source != TCPH(l4)->source || nfn->dest != TCPH(l4)->dest ||
			        nfn->protonum != IPPROTO_TCP) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
			hash = _I;
			_I = (u32)ulongmindiff(jiffies, nfn->jiffies);
			if (nfn->magic == natflow_path_magic &&
			        nfn->saddr == iph->saddr && nfn->daddr == iph->daddr &&
			        nfn->source == TCPH(l4)->source && nfn->dest == TCPH(l4)->dest &&
			        nfn->protonum == IPPROTO_TCP) {
				if (_I > NATFLOW_FF_TIMEOUT_LOW) {
					re_learn = 2;
					goto slow_fastpath;
				}
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
				/* check hnat hw timeout */
				if (_I > 14 * HZ && (nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
					nfn->flags &= ~FASTNAT_EXT_HWNAT_FLAG;
				}
#endif
				nfn->jiffies = jiffies;
				if ((re_learn = (nfn->flags & FASTNAT_RE_LEARN)) || (u16)skb->dev->ifindex != nfn->ifindex || _I > HZ) {
					if (re_learn) {
						nfn->flags &= ~FASTNAT_RE_LEARN;
						goto slow_fastpath;
					}
					goto out;
				}
				if (TCPH(l4)->fin || TCPH(l4)->rst || TCPH(l4)->syn) {
					goto out;
				}

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
				if ((nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
					__vlan_hwaccel_clear_tag(skb);
#else
					if (nfn->vlan_present) {
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					} else
						__vlan_hwaccel_clear_tag(skb);
#endif
					skb_push(skb, (void *)ip_hdr(skb) - (void *)eth_hdr(skb));
					skb->dev = nfn->outdev;
					skb->mark = HWNAT_QUEUE_MAPPING_MAGIC;
					skb->hash = HWNAT_QUEUE_MAPPING_MAGIC;
					dev_queue_xmit(skb);
					/*FIXME what if gso? */
					return NF_STOLEN;
				}
#endif
				/* sample up to slow path every 5s */
				if ((u32)ucharmindiff(((nfn->jiffies / HZ) & 0xff), nfn->count) >= NATFLOW_FF_SAMPLE_TIME && !test_and_set_bit(0, &nfn->status)) {
					unsigned long bytes = nfn->flow_bytes;
					unsigned long packets = nfn->flow_packets;
					natflow_offload_keepalive(hash, bytes, packets, nfn->speed_bytes, nfn->speed_packets);
					nfn->flow_bytes -= bytes;
					nfn->flow_packets -= packets;
					nfn->count = (nfn->jiffies / HZ) & 0xff;
					wmb();
					clear_bit(0, &nfn->status);
					goto out;
				}
				do {
					_I = (jiffies / HZ) % 4;
					nfn->speed_bytes[_I] += skb->len;
					nfn->speed_packets[_I] += 1;
					nfn->flow_bytes += skb->len;
					nfn->flow_packets += 1;
					_I = (_I + 1) % 4;
					if (nfn->speed_bytes[_I] != 0) {
						nfn->speed_bytes[_I] = 0;
						nfn->speed_packets[_I] = 0;
					}
					nfn->speed_jiffies = jiffies;
				} while (0);

				if (!(nfn->flags & FASTNAT_BRIDGE_FWD)) {
					if (iph->ttl <= 1) {
						return NF_DROP;
					}
					ip_decrease_ttl(iph);
				}
				if (TCPH(l4)->source != nfn->nat_source) {
					natflow_nat_port_tcp(skb, iph->ihl * 4, TCPH(l4)->source, nfn->nat_source);
					TCPH(l4)->source = nfn->nat_source;
				}
				if (TCPH(l4)->dest != nfn->nat_dest) {
					natflow_nat_port_tcp(skb, iph->ihl * 4, TCPH(l4)->dest, nfn->nat_dest);
					TCPH(l4)->dest = nfn->nat_dest;
				}
				if (iph->saddr != nfn->nat_saddr) {
					csum_replace4(&iph->check, iph->saddr, nfn->nat_saddr);
					natflow_nat_ip_tcp(skb, iph->ihl * 4, iph->saddr, nfn->nat_saddr);
					iph->saddr = nfn->nat_saddr;
				}
				if (iph->daddr != nfn->nat_daddr) {
					csum_replace4(&iph->check, iph->daddr, nfn->nat_daddr);
					natflow_nat_ip_tcp(skb, iph->ihl * 4, iph->daddr, nfn->nat_daddr);
					iph->daddr = nfn->nat_daddr;
				}

fast_output:
				_I = ETH_HLEN;
				if ((nfn->flags & FASTNAT_PPPOE_FLAG)) {
					_I += PPPOE_SES_HLEN;
				} else if ((nfn->flags & FASTNAT_NO_ARP)) {
					_I = 0;
				}

				ingress_trim_off = (nfn->outdev->features & NETIF_F_TSO) && \
				                   iph->protocol == IPPROTO_TCP && \
				                   !netif_is_bridge_master(nfn->outdev) && \
				                   _I == ETH_HLEN;

				if (skb_is_gso(skb) && !ingress_trim_off) {
					struct sk_buff *segs;
					skb->ip_summed = CHECKSUM_UNNECESSARY;
					segs = skb_gso_segment(skb, 0);
					if (IS_ERR(segs)) {
						return NF_DROP;
					}
					consume_skb(skb);
					skb = segs;
				}

				do {
					struct sk_buff *next = skb->next;
					if (_I > skb_headroom(skb) && pskb_expand_head(skb, _I, skb_tailroom(skb), GFP_ATOMIC)) {
						kfree_skb_list(skb);
						return NF_STOLEN;
					}
					skb_push(skb, _I);
					skb_reset_mac_header(skb);
					if (_I >= ETH_HLEN) {
						memcpy(eth_hdr(skb)->h_source, nfn->h_source, ETH_ALEN);
						memcpy(eth_hdr(skb)->h_dest, nfn->h_dest, ETH_ALEN);
					}
					if (_I == ETH_HLEN + PPPOE_SES_HLEN) {
						struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth_hdr(skb) + ETH_HLEN);
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_PPP_SES);
						skb->protocol = __constant_htons(ETH_P_PPP_SES);
						ph->ver = 1;
						ph->type = 1;
						ph->code = 0;
						ph->sid = nfn->pppoe_sid;
						ph->length = htons(ntohs(ip_hdr(skb)->tot_len) + 2);
						*(__be16 *)((void *)ph + sizeof(struct pppoe_hdr)) = __constant_htons(PPP_IP);
					} else if (_I == ETH_HLEN) {
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_IP);
					}
					skb->dev = nfn->outdev;
					if (nfn->vlan_present) {
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					} else
						__vlan_hwaccel_clear_tag(skb);
					skb->next = NULL;
					dev_queue_xmit(skb);
					skb = next;
				} while (skb);

				return NF_STOLEN;
			}
			/* for TCP */
			goto slow_fastpath;
		} else {
			if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)) || skb_try_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
			_I = natflow_hash_v4(iph->saddr, iph->daddr, UDPH(l4)->source, UDPH(l4)->dest, IPPROTO_UDP);
			nfn = &natflow_fast_nat_table[_I];
			if (nfn->saddr != iph->saddr || nfn->daddr != iph->daddr ||
			        nfn->source != UDPH(l4)->source || nfn->dest != UDPH(l4)->dest ||
			        nfn->protonum != IPPROTO_UDP) {
				_I += 1;
				nfn = &natflow_fast_nat_table[_I];
			}
			hash = _I;
			_I = (u32)ulongmindiff(jiffies, nfn->jiffies);
			if (nfn->magic == natflow_path_magic &&
			        nfn->saddr == iph->saddr && nfn->daddr == iph->daddr &&
			        nfn->source == UDPH(l4)->source && nfn->dest == UDPH(l4)->dest &&
			        nfn->protonum == IPPROTO_UDP) {
				if (_I > NATFLOW_FF_TIMEOUT_LOW) {
					re_learn = 2;
					goto slow_fastpath;
				}
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
				/* check hnat hw timeout */
				if (_I > 14 * HZ && (nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
					nfn->flags &= ~FASTNAT_EXT_HWNAT_FLAG;
				}
#endif
				nfn->jiffies = jiffies;
				if ((re_learn = (nfn->flags & FASTNAT_RE_LEARN)) || (u16)skb->dev->ifindex != nfn->ifindex || _I > HZ) {
					if (re_learn) {
						nfn->flags &= ~FASTNAT_RE_LEARN;
						goto slow_fastpath;
					}
					goto out;
				}

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
				if ((nfn->flags & FASTNAT_EXT_HWNAT_FLAG)) {
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
					__vlan_hwaccel_clear_tag(skb);
#else
					if (nfn->vlan_present) {
						if (nfn->vlan_proto == FF_ETH_P_8021Q)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nfn->vlan_tci);
						else if (nfn->vlan_proto == FF_ETH_P_8021AD)
							__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nfn->vlan_tci);
					} else
						__vlan_hwaccel_clear_tag(skb);
#endif
					skb_push(skb, (void *)ip_hdr(skb) - (void *)eth_hdr(skb));
					skb->dev = nfn->outdev;
					skb->mark = HWNAT_QUEUE_MAPPING_MAGIC;
					skb->hash = HWNAT_QUEUE_MAPPING_MAGIC;
					dev_queue_xmit(skb);
					/*FIXME what if gso? */
					return NF_STOLEN;
				}
#endif
				/* sample up to slow path every 5s */
				if ((u32)ucharmindiff(((nfn->jiffies / HZ) & 0xff), nfn->count) >= NATFLOW_FF_SAMPLE_TIME && !test_and_set_bit(0, &nfn->status)) {
					unsigned long bytes = nfn->flow_bytes;
					unsigned long packets = nfn->flow_packets;
					natflow_offload_keepalive(hash, bytes, packets, nfn->speed_bytes, nfn->speed_packets);
					nfn->flow_bytes -= bytes;
					nfn->flow_packets -= packets;
					nfn->count = (nfn->jiffies / HZ) & 0xff;
					wmb();
					clear_bit(0, &nfn->status);
					goto out;
				}
				do {
					_I = (jiffies / HZ) % 4;
					nfn->speed_bytes[_I] += skb->len;
					nfn->speed_packets[_I] += 1;
					nfn->flow_bytes += skb->len;
					nfn->flow_packets += 1;
					_I = (_I + 1) % 4;
					if (nfn->speed_bytes[_I] != 0) {
						nfn->speed_bytes[_I] = 0;
						nfn->speed_packets[_I] = 0;
					}
					nfn->speed_jiffies = jiffies;
				} while (0);

				if (!(nfn->flags & FASTNAT_BRIDGE_FWD)) {
					if (iph->ttl <= 1) {
						return NF_DROP;
					}
					ip_decrease_ttl(iph);
				}
				if (UDPH(l4)->source != nfn->nat_source) {
					natflow_nat_port_udp(skb, iph->ihl * 4, UDPH(l4)->source, nfn->nat_source);
					UDPH(l4)->source = nfn->nat_source;
				}
				if (UDPH(l4)->dest != nfn->nat_dest) {
					natflow_nat_port_udp(skb, iph->ihl * 4, UDPH(l4)->dest, nfn->nat_dest);
					UDPH(l4)->dest = nfn->nat_dest;
				}
				if (iph->saddr != nfn->nat_saddr) {
					csum_replace4(&iph->check, iph->saddr, nfn->nat_saddr);
					natflow_nat_ip_udp(skb, iph->ihl * 4, iph->saddr, nfn->nat_saddr);
					iph->saddr = nfn->nat_saddr;
				}
				if (iph->daddr != nfn->nat_daddr) {
					csum_replace4(&iph->check, iph->daddr, nfn->nat_daddr);
					natflow_nat_ip_udp(skb, iph->ihl * 4, iph->daddr, nfn->nat_daddr);
					iph->daddr = nfn->nat_daddr;
				}

				goto fast_output;
			}
			/* for UDP */
			goto slow_fastpath;
		}
		goto out;

slow_fastpath:
		ret = nf_conntrack_in_compat(dev_net(skb->dev), PF_INET, NF_INET_PRE_ROUTING, skb);
		if (ret != NF_ACCEPT) {
			goto out;
		}
	}
#endif

	if (skb->protocol != __constant_htons(ETH_P_IP))
		goto out;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		goto out;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		goto out;
	}
	if (iph->protocol == IPPROTO_TCP && (TCPH(l4)->fin || TCPH(l4)->rst)) {
		goto out;
	}
	/*
	 * XXX: FIXME:
	 * we assume ct->ext->len > 24(=NATFLOW_MAX_OFF / NATFLOW_FACTOR) is always true
	 * after the nf_conntrack_in() call
	 * ct->ext->len <= 24 means natflow_session is ready
	 */
	nf = natflow_session_in(ct);
	if (NULL == nf) {
		goto out;
	}

	dir = CTINFO2DIR(ctinfo);
#ifdef CONFIG_NETFILTER_INGRESS
	if (re_learn != 0) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
			simple_clear_bit(NF_FF_REPLY_OK_BIT, &nf->status);
			simple_clear_bit(NF_FF_REPLY_BIT, &nf->status);
			if (re_learn == 2) simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
		} else {
			simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
			simple_clear_bit(NF_FF_ORIGINAL_OK_BIT, &nf->status);
			simple_clear_bit(NF_FF_ORIGINAL_BIT, &nf->status);
			if (re_learn == 2) simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
		}
	}
#endif
	natflow_session_learn(skb, ct, nf, dir);

	if (!nf_ct_is_confirmed(ct)) {
		goto out;
	}
	if ((ct->status & IPS_NATFLOW_FF_STOP)) {
		goto out;
	}

	//if (!(nf->status & NF_FF_OFFLOAD)) {
	if (!(nf->status & NF_FF_REPLY_OK) || !(nf->status & NF_FF_ORIGINAL_OK)) {
		switch (iph->protocol) {
		case IPPROTO_TCP:
			NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT ": dir=%d reply:%d original:%d, dev=%s\n", DEBUG_TCP_ARG(iph,l4), dir,
			              !!(nf->status & NF_FF_REPLY_OK), !!(nf->status & NF_FF_ORIGINAL_OK), skb->dev->name);
			break;
		case IPPROTO_UDP:
			NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT ": dir=%d reply:%d original:%d, dev=%s\n", DEBUG_UDP_ARG(iph,l4), dir,
			              !!(nf->status & NF_FF_REPLY_OK), !!(nf->status & NF_FF_ORIGINAL_OK), skb->dev->name);
			break;
		}
		goto out;
	}

	acct = nf_conn_acct_find(ct);
	if (acct) {
		struct nf_conn_counter *counter = acct->counter;
		int packets = atomic64_read(&counter[0].packets) + atomic64_read(&counter[1].packets);
		/* do FF check every 1024 packets */
		if (packets % 1024 == 1) {
			simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
			simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
		}
		/* skip 1/64 packets to slow path */
		if (packets % 64 == 63) {
			goto out;
		}
	}

	do {
		int d = !dir;
		natflow_fakeuser_t *user;
		struct fakeuser_data_t *fud;
		user = natflow_user_get(ct);
		if (NULL == user) {
			break;
		}
		if (user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip != ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip) {
			d = !d;
		}
		acct = nf_conn_acct_find(user);
		if (acct) {
			struct nf_conn_counter *counter = acct->counter;
			atomic64_inc(&counter[d].packets);
			atomic64_add(skb->len, &counter[d].bytes);
		}

		fud = natflow_fakeuser_data(user);
		if (d == 0) {
			int i = (jiffies/HZ) % 4;
			int j = (fud->rx_speed_jiffies/HZ) % 4;
			unsigned long diff_jiffies = ulongmindiff(jiffies, fud->rx_speed_jiffies);
			fud->rx_speed_jiffies = jiffies;
			if (diff_jiffies >= HZ * 4) {
				for(j = 0; j < 4; j++) {
					fud->rx_speed_bytes[j] = 0;
					fud->rx_speed_packets[j] = 0;
				}
				j = i;
			}
			for (; j != i; ) {
				j = (j + 1) % 4;
				fud->rx_speed_bytes[j] = 0;
				fud->rx_speed_packets[j] = 0;
			}
			fud->rx_speed_packets[j] += 1;
			fud->rx_speed_bytes[j] += skb->len;
		} else {
			int i = (jiffies/HZ) % 4;
			int j = (fud->tx_speed_jiffies/HZ) % 4;
			unsigned long diff_jiffies = ulongmindiff(jiffies, fud->tx_speed_jiffies);
			fud->tx_speed_jiffies = jiffies;
			if (diff_jiffies >= HZ * 4) {
				for(j = 0; j < 4; j++) {
					fud->tx_speed_bytes[j] = 0;
					fud->tx_speed_packets[j] = 0;
				}
				j = i;
			}
			for (; j != i; ) {
				j = (j + 1) % 4;
				fud->tx_speed_bytes[j] = 0;
				fud->tx_speed_packets[j] = 0;
			}
			fud->tx_speed_packets[j] += 1;
			fud->tx_speed_bytes[j] += skb->len;
		}
	} while (0);


	if (!simple_test_bit(NF_FF_BRIDGE_BIT, &nf->status)) {
		if (skb->len > nf->rroute[dir].mtu || (IPCB(skb)->flags & IPSKB_FRAG_PMTU)) {
			switch (iph->protocol) {
			case IPPROTO_TCP:
				NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT ": pmtu=%u FRAG=%p\n",
				              DEBUG_TCP_ARG(iph,l4), nf->rroute[dir].mtu, (void *)(IPCB(skb)->flags & IPSKB_FRAG_PMTU));
				break;
			case IPPROTO_UDP:
				NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT ": pmtu=%u FRAG=%p\n",
				              DEBUG_UDP_ARG(iph,l4), nf->rroute[dir].mtu, (void *)(IPCB(skb)->flags & IPSKB_FRAG_PMTU));
				break;
			}
			goto out;
		}

		if (iph->ttl <= 1) {
			return NF_DROP;
		}
		ip_decrease_ttl(iph);
	}
	if ((ct->status & IPS_DST_NAT)) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			//do DNAT
			if (natflow_do_dnat(skb, ct, dir) != 0) {
				return NF_DROP;
			}
		} else {
			//do SNAT
			if (natflow_do_snat(skb, ct, dir) != 0) {
				return NF_DROP;
			}
		}
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	if ((ct->status & IPS_SRC_NAT)) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			//do SNAT
			if (natflow_do_snat(skb, ct, dir) != 0) {
				return NF_DROP;
			}
		} else {
			//do DNAT
			if (natflow_do_dnat(skb, ct, dir) != 0) {
				return NF_DROP;
			}
		}
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		goto out;
	}

#ifdef CONFIG_NETFILTER_INGRESS
	if (!(nf->status & NF_FF_FAIL)) {
		for (d = 0; d < NF_FF_DIR_MAX; d++) {
			if (d == NF_FF_DIR_ORIGINAL) {
				if (!(nf->status & NF_FF_ORIGINAL_CHECK) && !simple_test_and_set_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status)) {
fastnat_check:
					do {
						__be32 saddr = ct->tuplehash[d].tuple.src.u3.ip;
						__be32 daddr = ct->tuplehash[d].tuple.dst.u3.ip;
						__be16 source = ct->tuplehash[d].tuple.src.u.all;
						__be16 dest = ct->tuplehash[d].tuple.dst.u.all;
						__be16 protonum = ct->tuplehash[d].tuple.dst.protonum;
						u32 hash = natflow_hash_v4(saddr, daddr, source, dest, protonum);
						natflow_fastnat_node_t *nfn = &natflow_fast_nat_table[hash];
						struct ethhdr *eth = (struct ethhdr *)nf->rroute[d].l2_head;

						if (natflow_hash_skip(hash) ||
						        (ulongmindiff(jiffies, nfn->jiffies) < NATFLOW_FF_TIMEOUT_HIGH &&
						         (nfn->saddr != saddr || nfn->daddr != daddr || nfn->source != source || nfn->dest != dest || nfn->protonum != protonum))) {
							hash += 1;
							nfn = &natflow_fast_nat_table[hash];
						}
						if (!natflow_hash_skip(hash) &&
						        (ulongmindiff(jiffies, nfn->jiffies) > NATFLOW_FF_TIMEOUT_HIGH ||
						         (nfn->saddr == saddr && nfn->daddr == daddr && nfn->source == source && nfn->dest == dest && nfn->protonum == protonum))) {

							if (ulongmindiff(jiffies, nfn->jiffies) > NATFLOW_FF_TIMEOUT_HIGH) {
								nfn->status = 0;
								nfn->flow_bytes = 0;
								nfn->flow_packets = 0;
								memset(nfn->speed_bytes, 0, sizeof(*nfn->speed_bytes) * 4);
								memset(nfn->speed_packets, 0, sizeof(*nfn->speed_packets) * 4);
								nfn->speed_jiffies = 0;
							}

							nfn->saddr = saddr;
							nfn->daddr = daddr;
							nfn->source = source;
							nfn->dest = dest;
							nfn->protonum = protonum;

							nfn->nat_saddr = ct->tuplehash[!d].tuple.dst.u3.ip;
							nfn->nat_daddr = ct->tuplehash[!d].tuple.src.u3.ip;
							nfn->nat_source = ct->tuplehash[!d].tuple.dst.u.all;
							nfn->nat_dest = ct->tuplehash[!d].tuple.src.u.all;

							nfn->flags = 0;
							nfn->outdev = nf->rroute[d].outdev;
							nfn->ifindex = nf->rroute[!d].outdev->ifindex;
							if (nf->rroute[d].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
								struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth + ETH_HLEN);
								nfn->pppoe_sid = ph->sid;
								nfn->flags |= FASTNAT_PPPOE_FLAG;
								nfn->flags &= ~FASTNAT_NO_ARP;
								memcpy(nfn->h_source, eth->h_source, ETH_ALEN);
								memcpy(nfn->h_dest, eth->h_dest, ETH_ALEN);
							} else if (nf->rroute[d].l2_head_len == ETH_HLEN) {
								nfn->pppoe_sid = 0;
								memcpy(nfn->h_source, eth->h_source, ETH_ALEN);
								memcpy(nfn->h_dest, eth->h_dest, ETH_ALEN);
								nfn->flags &= ~FASTNAT_NO_ARP;
							} else {
								nfn->flags |= FASTNAT_NO_ARP;
							}
							if (simple_test_bit(NF_FF_BRIDGE_BIT, &nf->status))
								nfn->flags |= FASTNAT_BRIDGE_FWD;

							nfn->vlan_present = nf->rroute[d].vlan_present;
							nfn->vlan_proto = nf->rroute[d].vlan_proto;
							nfn->vlan_tci = nf->rroute[d].vlan_tci;
							nfn->magic = natflow_path_magic;
							nfn->jiffies = jiffies;

							switch (iph->protocol) {
							case IPPROTO_TCP:
								NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT ": dir=%d use hash=%d outdev=%s(vlan:%d pppoe=%d)\n",
								             DEBUG_TCP_ARG(iph,l4), d, hash, nfn->outdev->name,
								             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
								             (nfn->flags & FASTNAT_PPPOE_FLAG) ? (int)nfn->pppoe_sid : -1);
								break;
							case IPPROTO_UDP:
								NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT ": dir=%d use hash=%d outdev=%s(vlan:%d pppoe=%d)\n",
								             DEBUG_UDP_ARG(iph,l4), d, hash, nfn->outdev->name,
								             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
								             (nfn->flags & FASTNAT_PPPOE_FLAG) ? (int)nfn->pppoe_sid : -1);
								break;
							}
						} else {
							/* mark FF_FAIL so never try FF */
							simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
							switch (iph->protocol) {
							case IPPROTO_TCP:
								NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT ": dir=%d skip hash=%d\n", DEBUG_TCP_ARG(iph,l4), d, hash);
								break;
							case IPPROTO_UDP:
								NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT ": dir=%d skip hash=%d\n", DEBUG_UDP_ARG(iph,l4), d, hash);
								break;
							}
						}

						if ((nf->status & NF_FF_ORIGINAL_CHECK) && (nf->status & NF_FF_REPLY_CHECK)) {
							if (nfn->magic == natflow_path_magic && ulongmindiff(jiffies, nfn->jiffies) < NATFLOW_FF_TIMEOUT_LOW &&
							        (nfn->saddr == saddr && nfn->daddr == daddr &&
							         nfn->source == source && nfn->dest == dest && nfn->protonum == protonum)) {
								natflow_fastnat_node_t *nfn_i;
								saddr = ct->tuplehash[!d].tuple.src.u3.ip;
								daddr = ct->tuplehash[!d].tuple.dst.u3.ip;
								source = ct->tuplehash[!d].tuple.src.u.all;
								dest = ct->tuplehash[!d].tuple.dst.u.all;
								protonum = ct->tuplehash[!d].tuple.dst.protonum;
								hash = natflow_hash_v4(saddr, daddr, source, dest, protonum);
								nfn_i = &natflow_fast_nat_table[hash];

								if (nfn_i->saddr != saddr || nfn_i->daddr != daddr ||
								        nfn_i->source != source || nfn_i->dest != dest || nfn_i->protonum != protonum) {
									hash += 1;
									nfn_i = &natflow_fast_nat_table[hash];
								}
								if (nfn_i->magic == natflow_path_magic && ulongmindiff(jiffies, nfn_i->jiffies) < NATFLOW_FF_TIMEOUT_LOW &&
								        (nfn_i->saddr == saddr && nfn_i->daddr == daddr &&
								         nfn_i->source == source && nfn_i->dest == dest && nfn_i->protonum == protonum)) {
									if ((nfn_i->flags & FASTNAT_NO_ARP) ||
									        netif_is_bridge_master(nfn_i->outdev)) {
										if (!(nfn->flags & FASTNAT_STOP_LEARN)) {
											nfn->flags |= FASTNAT_RE_LEARN;
											nfn->flags |= FASTNAT_STOP_LEARN;
										}
									}
									if ((nfn->flags & FASTNAT_NO_ARP) ||
									        netif_is_bridge_master(nfn->outdev)) {
										if (!(nfn_i->flags & FASTNAT_STOP_LEARN)) {
											nfn_i->flags |= FASTNAT_RE_LEARN;
											nfn_i->flags |= FASTNAT_STOP_LEARN;
										}
									}
									nfn->ifindex = (u16)nfn_i->outdev->ifindex;
									nfn_i->ifindex = (u16)nfn->outdev->ifindex;
									nfn_i->jiffies = jiffies;
									if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.protonum == IPPROTO_TCP) {
										ct->proto.tcp.seen[0].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
										ct->proto.tcp.seen[1].flags |= IP_CT_TCP_FLAG_BE_LIBERAL;
									}
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
									if (hwnat) {
										/* hwnat enabled */
										if (!(nfn->flags & FASTNAT_NO_ARP) && !(nfn_i->flags & FASTNAT_NO_ARP) &&
										        !netif_is_bridge_master(nfn->outdev) && !netif_is_bridge_master(nfn_i->outdev)) {
											struct net_device *orig_dev = get_vlan_real_dev(nf->rroute[NF_FF_DIR_ORIGINAL].outdev);
											struct net_device *reply_dev = get_vlan_real_dev(nf->rroute[NF_FF_DIR_REPLY].outdev);
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
											__be16 orig_vid = get_vlan_vid(nf->rroute[NF_FF_DIR_ORIGINAL].outdev);
											__be16 reply_vid = get_vlan_vid(nf->rroute[NF_FF_DIR_REPLY].outdev);
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0) /* no dsa support before kernel 5.4 in openwrt */
											/* hwnat ready to go */
											u16 orig_dsa_port = 0xffff;
											u16 reply_dsa_port = 0xffff;
											if (!orig_dev->netdev_ops->ndo_flow_offload && orig_dev->netdev_ops->ndo_flow_offload_check) {
												flow_offload_hw_path_t orig = {
													.dev = orig_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET,
												};
												orig_dev->netdev_ops->ndo_flow_offload_check(&orig);
												if (orig.dev != orig_dev) {
													orig_dev = orig.dev;
													orig_dsa_port = orig.dsa_port;
												}
											}
											if (!reply_dev->netdev_ops->ndo_flow_offload && reply_dev->netdev_ops->ndo_flow_offload_check) {
												flow_offload_hw_path_t reply = {
													.dev = reply_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET,
												};
												reply_dev->netdev_ops->ndo_flow_offload_check(&reply);
												if (reply.dev != reply_dev) {
													reply_dev = reply.dev;
													reply_dsa_port = reply.dsa_port;
												}
											}
#endif
											if (orig_dev->netdev_ops->ndo_flow_offload) {
												/* xxx: orig_dev has offload api */
												if (orig_dev == reply_dev || reply_dev->netdev_ops->ndo_flow_offload) {
													/* xxx: both orig_dev and reply_dev has offload api */
													struct natflow_offload *natflow = natflow_offload_alloc(ct, nf);
													flow_offload_hw_path_t orig = {
														.dev = orig_dev,
														.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
														.dsa_port = orig_dsa_port,
#endif
													};
													flow_offload_hw_path_t reply = {
														.dev = reply_dev,
														.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
														.dsa_port = reply_dsa_port,
#endif
													};
													memcpy(orig.eth_src, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
													memcpy(orig.eth_dest, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
													memcpy(reply.eth_src, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
													memcpy(reply.eth_dest, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
													if (orig_vid > 0) {
														orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
														orig.vlan_proto = get_vlan_proto(nf->rroute[NF_FF_DIR_ORIGINAL].outdev);
														orig.vlan_id = orig_vid;
													}
													if (reply_vid > 0) {
														reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
														reply.vlan_proto = get_vlan_proto(nf->rroute[NF_FF_DIR_REPLY].outdev);
														reply.vlan_id = reply_vid;
													}
#else
													if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
														orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
														orig.vlan_proto = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
														                  htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
														orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
													}
													if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
														reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
														reply.vlan_proto = nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
														                   htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
														reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
													}
#endif
													if (nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
														orig.flags |= FLOW_OFFLOAD_PATH_PPPOE;
														orig.pppoe_sid =
														    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN)->sid);
													}
													if (nf->rroute[NF_FF_DIR_REPLY].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
														reply.flags |= FLOW_OFFLOAD_PATH_PPPOE;
														reply.pppoe_sid =
														    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN)->sid);
													}
													if (orig_dev->netdev_ops->ndo_flow_offload(
													            FLOW_OFFLOAD_ADD, &natflow->flow, &reply, &orig) == 0) {
														NATFLOW_INFO("(PCO) set hwnat offload 1 dev=%s(vlan:%d pppoe:%d)"
														             " s=%pI4:%u d=%pI4:%u dev=%s(vlan:%d pppoe:%d)"
														             " s=%pI4:%u d=%pI4:%u\n",
														             nfn->outdev->name,
														             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
														             (nfn->flags & FASTNAT_PPPOE_FLAG) ? (int)nfn->pppoe_sid : -1,
														             &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest),
														             nfn_i->outdev->name,
														             nfn_i->vlan_present ? (int)nfn_i->vlan_tci : -1,
														             (nfn->flags & FASTNAT_PPPOE_FLAG) ? (int)nfn->pppoe_sid : -1,
														             &nfn_i->saddr, ntohs(nfn_i->source),
														             &nfn_i->daddr, ntohs(nfn_i->dest));
													} else {
														/* mark FF_FAIL so never try FF */
														simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
														switch (iph->protocol) {
														case IPPROTO_TCP:
															NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT
															             ": dir=%d set hwnat offload fail1\n",
															             DEBUG_TCP_ARG(iph,l4), d);
															break;
														case IPPROTO_UDP:
															NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT
															             ": dir=%d set hwnat offload fail1\n",
															             DEBUG_UDP_ARG(iph,l4), d);
															break;
														}
													}
													/* end: both orig_dev and reply_dev has offload api */
												}
#if !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
												else
												{
													/* xxx: olny orig_dev has offload api */
													struct natflow_offload *natflow = natflow_offload_alloc(ct, nf);
													flow_offload_hw_path_t orig = {
														.dev = orig_dev,
														.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
														.dsa_port = orig_dsa_port,
#endif
													};
													flow_offload_hw_path_t reply = {
														.dev = reply_dev,
														.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
														.dsa_port = reply_dsa_port,
#endif
													};
													/* no vlan for ext dev */
													reply_dev = nf->rroute[NF_FF_DIR_REPLY].outdev;
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
													reply_vid = (natflow->flow.timeout) & 0xffff;
#endif
													memcpy(orig.eth_src, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
													memcpy(orig.eth_dest, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
													memcpy(reply.eth_src, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
													memcpy(reply.eth_dest, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
													if (orig_vid > 0) {
														orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
														orig.vlan_proto = get_vlan_proto(nf->rroute[NF_FF_DIR_ORIGINAL].outdev);
														orig.vlan_id = orig_vid;
													}
													/* must set reply_vid */
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto = htons(ETH_P_8021Q);
													reply.vlan_id = reply_vid;
#else
													if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
														orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
														orig.vlan_proto = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
														                  htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
														orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
													}
													if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
														reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
														reply.vlan_proto = nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
														                   htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
														reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
													}
#endif
													if (nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
														orig.flags |= FLOW_OFFLOAD_PATH_PPPOE;
														orig.pppoe_sid =
														    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN)->sid);
													}
													if (nf->rroute[NF_FF_DIR_REPLY].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
														reply.flags |= FLOW_OFFLOAD_PATH_PPPOE;
														reply.pppoe_sid =
														    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN)->sid);
													}
													if (orig_dev->netdev_ops->ndo_flow_offload(
													            FLOW_OFFLOAD_ADD, &natflow->flow, &reply, &orig) == 0) {
														NATFLOW_INFO("(PCO) set hwnat offload 2 dev=%s(vlan:%d pppoe:%d)"
														             " s=%pI4:%u d=%pI4:%u dev=%s(vlan:%d pppoe:%d)"
														             " s=%pI4:%u d=%pI4:%u\n",
														             nfn->outdev->name,
														             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
														             (nfn->flags & FASTNAT_PPPOE_FLAG) ? (int)nfn->pppoe_sid : -1,
														             &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest),
														             nfn_i->outdev->name,
														             nfn_i->vlan_present ? (int)nfn_i->vlan_tci : -1,
														             (nfn->flags & FASTNAT_PPPOE_FLAG) ? (int)nfn->pppoe_sid : -1,
														             &nfn_i->saddr, ntohs(nfn_i->source),
														             &nfn_i->daddr, ntohs(nfn_i->dest));

														if (nf->rroute[NF_FF_DIR_REPLY].outdev == nfn->outdev) {
															nfn_i->flags |= FASTNAT_EXT_HWNAT_FLAG;
														} else {
															nfn->flags |= FASTNAT_EXT_HWNAT_FLAG;
														}
													} else {
														/* mark FF_FAIL so never try FF */
														simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
														switch (iph->protocol) {
														case IPPROTO_TCP:
															NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT
															             ": dir=%d set hwnat offload fail2\n",
															             DEBUG_TCP_ARG(iph,l4), d);
															break;
														case IPPROTO_UDP:
															NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT
															             ": dir=%d set hwnat offload fail2\n",
															             DEBUG_UDP_ARG(iph,l4), d);
															break;
														}
													}
													/* end: olny orig_dev has offload api */
												}
												/* end: orig_dev has offload api */
											} else if (reply_dev->netdev_ops->ndo_flow_offload) {
												/* xxx: only reply_dev has offload api */
												struct natflow_offload *natflow = natflow_offload_alloc(ct, nf);
												flow_offload_hw_path_t orig = {
													.dev = orig_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = orig_dsa_port,
#endif
												};
												flow_offload_hw_path_t reply = {
													.dev = reply_dev,
													.flags = FLOW_OFFLOAD_PATH_ETHERNET,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 4, 0)
													.dsa_port = reply_dsa_port,
#endif
												};
												/* no vlan for ext dev */
												orig_dev = nf->rroute[NF_FF_DIR_ORIGINAL].outdev;
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
												orig_vid = (natflow->flow.timeout >> 16) & 0xffff;
#endif
												memcpy(orig.eth_src, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
												memcpy(orig.eth_dest, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
												memcpy(reply.eth_src, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
												memcpy(reply.eth_dest, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);
#if defined(CONFIG_HWNAT_EXTDEV_USE_VLAN_HASH) && !defined(CONFIG_HWNAT_EXTDEV_DISABLED)
												if (reply_vid > 0) {
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto = get_vlan_proto(nf->rroute[NF_FF_DIR_REPLY].outdev);
													reply.vlan_id = reply_vid;
												}
												/* must set orig_vid */
												orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
												orig.vlan_proto = htons(ETH_P_8021Q);
												orig.vlan_id = orig_vid;
#else
												if (nf->rroute[NF_FF_DIR_ORIGINAL].vlan_present) {
													orig.flags |= FLOW_OFFLOAD_PATH_VLAN;
													orig.vlan_proto = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_proto == FF_ETH_P_8021Q ?
													                  htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													orig.vlan_id = nf->rroute[NF_FF_DIR_ORIGINAL].vlan_tci;
												}
												if (nf->rroute[NF_FF_DIR_REPLY].vlan_present) {
													reply.flags |= FLOW_OFFLOAD_PATH_VLAN;
													reply.vlan_proto = nf->rroute[NF_FF_DIR_REPLY].vlan_proto == FF_ETH_P_8021Q ?
													                   htons(ETH_P_8021Q) : htons(ETH_P_8021AD);
													reply.vlan_id = nf->rroute[NF_FF_DIR_REPLY].vlan_tci;
												}
#endif
												if (nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													orig.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													orig.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN)->sid);
												}
												if (nf->rroute[NF_FF_DIR_REPLY].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
													reply.flags |= FLOW_OFFLOAD_PATH_PPPOE;
													reply.pppoe_sid =
													    ntohs(PPPOEH(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN)->sid);
												}
												if (reply_dev->netdev_ops->ndo_flow_offload(
												            FLOW_OFFLOAD_ADD, &natflow->flow, &reply, &orig) == 0) {
													NATFLOW_INFO("(PCO) set hwnat offload 1 dev=%s(vlan:%d pppoe:%d)"
													             " s=%pI4:%u d=%pI4:%u dev=%s(vlan:%d pppoe:%d)"
													             " s=%pI4:%u d=%pI4:%u\n",
													             nfn->outdev->name,
													             nfn->vlan_present ? (int)nfn->vlan_tci : -1,
													             (nfn->flags & FASTNAT_PPPOE_FLAG) ? (int)nfn->pppoe_sid : -1,
													             &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest),
													             nfn_i->outdev->name,
													             nfn_i->vlan_present ? (int)nfn_i->vlan_tci : -1,
													             (nfn->flags & FASTNAT_PPPOE_FLAG) ? (int)nfn->pppoe_sid : -1,
													             &nfn_i->saddr, ntohs(nfn_i->source),
													             &nfn_i->daddr, ntohs(nfn_i->dest));
													if (nf->rroute[NF_FF_DIR_ORIGINAL].outdev == nfn->outdev) {
														nfn_i->flags |= FASTNAT_EXT_HWNAT_FLAG;
													} else {
														nfn->flags |= FASTNAT_EXT_HWNAT_FLAG;
													}
												} else {
													/* mark FF_FAIL so never try FF */
													simple_set_bit(NF_FF_FAIL_BIT, &nf->status);
													switch (iph->protocol) {
													case IPPROTO_TCP:
														NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT
														             ": dir=%d set hwnat offload fail3\n",
														             DEBUG_TCP_ARG(iph,l4), d);
														break;
													case IPPROTO_UDP:
														NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT
														             ": dir=%d set hwnat offload fail3\n",
														             DEBUG_UDP_ARG(iph,l4), d);
														break;
													}
												}
												/* end: only reply_dev has offload api */
#endif /* !defined(CONFIG_HWNAT_EXTDEV_DISABLED) */
											} else {
												/* neither orig_dev nor reply_dev has offload api */
											}
										} else {
											/* hwnat is not ready to go */
										}
									} else {
										/* hwnat is not enabled */
									}
#endif
								} else {
									/* nfn is ready, but nfn_i is not */
								}
							} else {
								/* nfn is not ready */
							}
						} else {
							/* either NF_FF_ORIGINAL_CHECK or NF_FF_REPLY_CHECK is not ready */
						}
					} while (0);
				}
			} else {
				if (!(nf->status & NF_FF_REPLY_CHECK) && !simple_test_and_set_bit(NF_FF_REPLY_CHECK_BIT, &nf->status)) {
					goto fastnat_check;
				}
			}
		} /* for (d = 0; d < NF_FF_DIR_MAX; d++) */
	} /* end NF_FF_FAIL */
#endif

	ingress_trim_off = (nf->rroute[dir].outdev->features & NETIF_F_TSO) && \
	                   iph->protocol == IPPROTO_TCP && \
	                   !netif_is_bridge_master(nf->rroute[dir].outdev) && \
	                   nf->rroute[dir].l2_head_len == ETH_HLEN;

	if (skb_is_gso(skb) && !ingress_trim_off) {
		struct sk_buff *segs;
		skb->ip_summed = CHECKSUM_UNNECESSARY;
		segs = skb_gso_segment(skb, 0);
		if (IS_ERR(segs)) {
			return NF_DROP;
		}
		consume_skb(skb);
		skb = segs;
	}

	do {
		struct sk_buff *next = skb->next;
		if (nf->rroute[dir].l2_head_len > skb_headroom(skb) && pskb_expand_head(skb, nf->rroute[dir].l2_head_len, skb_tailroom(skb), GFP_ATOMIC)) {
			kfree_skb_list(skb);
			return NF_STOLEN;
		}
		skb_push(skb, nf->rroute[dir].l2_head_len);
		skb_reset_mac_header(skb);
		memcpy(skb_mac_header(skb), nf->rroute[dir].l2_head, nf->rroute[dir].l2_head_len);
		skb->dev = nf->rroute[dir].outdev;
#ifdef CONFIG_NETFILTER_INGRESS
		if (nf->rroute[dir].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
			struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth_hdr(skb) + ETH_HLEN);
			ph->length = htons(ntohs(ip_hdr(skb)->tot_len) + 2);
			skb->protocol = __constant_htons(ETH_P_PPP_SES);
		}
		if (nf->rroute[dir].vlan_present) {
			if (nf->rroute[dir].vlan_proto == FF_ETH_P_8021Q)
				__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021Q), nf->rroute[dir].vlan_tci);
			else if (nf->rroute[dir].vlan_proto == FF_ETH_P_8021AD)
				__vlan_hwaccel_put_tag(skb, htons(ETH_P_8021AD), nf->rroute[dir].vlan_tci);
		} else
			__vlan_hwaccel_clear_tag(skb);
#endif
		skb->next = NULL;
		dev_queue_xmit(skb);
		skb = next;
	} while (skb);

	return NF_STOLEN;

out:
#ifdef CONFIG_NETFILTER_INGRESS
	if (pf == NFPROTO_NETDEV) {
		if (ingress_pad_len == PPPOE_SES_HLEN) {
			skb->protocol = cpu_to_be16(ETH_P_PPP_SES);
			skb_push_rcsum(skb, PPPOE_SES_HLEN);
			skb->network_header -= PPPOE_SES_HLEN;
		}
		if (ingress_trim_off) {
			skb->len += ingress_trim_off;
		}
	}
#endif
	return ret;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natflow_path_post_ct_out_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = PF_INET;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_path_post_ct_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	u_int8_t pf = ops->pf;
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_path_post_ct_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natflow_path_post_ct_out_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	u_int8_t pf = state->pf;
	unsigned int hooknum = state->hook;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#endif
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	natflow_t *nf;
	unsigned int mtu;
	int dir = 0;
	int ret;

	if (disabled)
		return NF_ACCEPT;

	if (skb->protocol != __constant_htons(ETH_P_IP))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	if (ipv4_is_lbcast(iph->daddr) ||
	        ipv4_is_loopback(iph->daddr) ||
	        ipv4_is_multicast(iph->daddr) ||
	        ipv4_is_zeronet(iph->daddr)) {
		return NF_ACCEPT;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if ((ct->status & IPS_NATFLOW_URLLOGGER_HANDLED) && (ct->status & IPS_NATFLOW_FF_STOP) && !(IPS_NATCAP & ct->status)) {
		struct nf_conn_help *help = nfct_help(ct);
		if (!help || !help->helper) {
			clear_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
		}
	}
	if ((ct->status & IPS_NATFLOW_FF_STOP)) {
		return NF_ACCEPT;
	}

	nf = natflow_session_get(ct);
	if (NULL == nf) {
		return NF_ACCEPT;
	}

	//skip nf session for ct with helper
	if (!nf_ct_is_confirmed(ct)) {
		struct nf_conn_help *help = nfct_help(ct);
		if (help && help->helper) {
			switch (iph->protocol) {
			case IPPROTO_TCP:
				NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT ": this conn need helper\n", DEBUG_TCP_ARG(iph,l4));
				break;
			case IPPROTO_UDP:
				NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT ": this conn need helper\n", DEBUG_UDP_ARG(iph,l4));
				break;
			}
			set_bit(IPS_NATFLOW_FF_STOP_BIT, &ct->status);
			return NF_ACCEPT;
		}

		if (pf == NFPROTO_BRIDGE) {
			/* this is bridge forward flow */
			simple_set_bit(NF_FF_BRIDGE_BIT, &nf->status);
		}
	}

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		return ret;
	}

	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) {
		dir = NF_FF_DIR_ORIGINAL;
	} else {
		dir = NF_FF_DIR_REPLY;
	}

	if (!skb_dst(skb))
		return NF_ACCEPT;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
	mtu = ip_skb_dst_mtu(skb);
#else
	mtu = ip_skb_dst_mtu(NULL, skb);
#endif
	if (nf->rroute[dir].mtu != mtu) {
		switch (iph->protocol) {
		case IPPROTO_TCP:
			NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT ": update pmtu from %u to %u\n", DEBUG_TCP_ARG(iph,l4), nf->rroute[dir].mtu, mtu);
			break;
		case IPPROTO_UDP:
			NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT ": update pmtu from %u to %u\n", DEBUG_UDP_ARG(iph,l4), nf->rroute[dir].mtu, mtu);
			break;
		}
		nf->rroute[dir].mtu = mtu;
	}

	return NF_ACCEPT;
}

#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
void natflow_hwnat_stop(struct net_device *dev)
{

	flow_offload_hw_path_t stop = {
		.dev = dev,
		.flags = FLOW_OFFLOAD_PATH_ETHERNET | FLOW_OFFLOAD_PATH_STOP,
	};

	if (dev->netdev_ops && dev->netdev_ops->ndo_flow_offload && dev->netdev_ops->ndo_flow_offload_check) {
		dev->netdev_ops->ndo_flow_offload_check(&stop);
	}
}
#endif

static struct nf_hook_ops path_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_path_post_ct_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 10 - 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_path_post_ct_out_hook,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 10 - 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_path_pre_ct_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	},
};

#ifdef CONFIG_NETFILTER_INGRESS
struct natflow_hook_t {
	struct hlist_node list;
	struct nf_hook_ops ops;
};

static HLIST_HEAD(natflow_hooks);
static DEFINE_SPINLOCK(natflow_hooks_lock);

static struct natflow_hook_t *natflow_lookup_hook(struct net_device *dev)
{
	struct natflow_hook_t *hook;

	hlist_for_each_entry(hook, &natflow_hooks, list) {
		if (hook->ops.dev == dev)
			return hook;
	}

	return NULL;
}

static int natflow_create_hook(struct net_device *dev)
{
	struct natflow_hook_t *hook;
	struct nf_hook_ops *ops;

	hook = kzalloc(sizeof(*hook), GFP_ATOMIC);
	if (!hook)
		return -ENOMEM;

	ops = &hook->ops;
	ops->pf = NFPROTO_NETDEV;
	ops->hooknum = NF_NETDEV_INGRESS;
	ops->priority = 9;
	ops->hook = natflow_path_pre_ct_in_hook;
	ops->dev = dev;

	if (nf_register_net_hook(dev_net(dev), ops) != 0) {
		kfree(hook);
		return -EINVAL;
	}

	hlist_add_head(&hook->list, &natflow_hooks);

	return 0;
}

static void natflow_check_device(struct net_device *dev)
{
	struct natflow_hook_t *hook;

	spin_lock_bh(&natflow_hooks_lock);
	hook = natflow_lookup_hook(dev);
	if (!hook)
		natflow_create_hook(dev);
	spin_unlock_bh(&natflow_hooks_lock);
}

static void natflow_unhook_device(struct net_device *dev)
{
	struct natflow_hook_t *hook;
	spin_lock_bh(&natflow_hooks_lock);
	hook = natflow_lookup_hook(dev);
	if (hook) {
		hlist_del(&hook->list);
		nf_unregister_net_hook(dev_net(dev), &hook->ops);
		kfree(hook);
	}
	spin_unlock_bh(&natflow_hooks_lock);
}
#endif

static int natflow_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

#ifdef CONFIG_NETFILTER_INGRESS
	if (event == NETDEV_UP) {
		if (!((dev->flags & (IFF_LOOPBACK | IFF_POINTOPOINT)) || (dev->type == ARPHRD_PPP || dev->type == ARPHRD_NONE))) {
			natflow_check_device(dev);
			NATFLOW_println("catch NETDEV_UP event for dev=%s, add ingress hook", dev->name);
		}
		return NOTIFY_DONE;
	}
#endif

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

#ifdef CONFIG_NETFILTER_INGRESS
	natflow_unhook_device(dev);
#endif

	natflow_update_magic(0);
#if (defined(CONFIG_NET_RALINK_OFFLOAD) || defined(NATFLOW_OFFLOAD_HWNAT_FAKE) && defined(CONFIG_NET_MEDIATEK_SOC))
	natflow_hwnat_stop(dev);
#endif

	NATFLOW_println("catch NETDEV_UNREGISTER event for dev=%s", dev->name);

	return NOTIFY_DONE;
}

static struct notifier_block natflow_netdev_notifier = {
	.notifier_call  = natflow_netdev_event,
};

int natflow_path_init(void)
{
	int ret = 0;

#ifdef CONFIG_NETFILTER_INGRESS
	natflow_fast_nat_table = kmalloc(sizeof(natflow_fastnat_node_t) * NATFLOW_FASTNAT_TABLE_SIZE * 2, GFP_KERNEL);
	if (natflow_fast_nat_table == NULL) {
		return -ENOMEM;
	}
#endif

	need_conntrack();
	natflow_update_magic(1);

	register_netdevice_notifier(&natflow_netdev_notifier);

	ret = nf_register_hooks(path_hooks, ARRAY_SIZE(path_hooks));
	if (ret != 0)
		goto nf_register_hooks_failed;

	return 0;
nf_register_hooks_failed:
	unregister_netdevice_notifier(&natflow_netdev_notifier);
#ifdef CONFIG_NETFILTER_INGRESS
	kfree(natflow_fast_nat_table);
#endif
	return ret;
}

void natflow_path_exit(void)
{
	disabled = 1;
	nf_unregister_hooks(path_hooks, ARRAY_SIZE(path_hooks));
	synchronize_rcu();
	unregister_netdevice_notifier(&natflow_netdev_notifier);
#ifdef CONFIG_NETFILTER_INGRESS
	synchronize_rcu();
	kfree(natflow_fast_nat_table);
#endif
}
