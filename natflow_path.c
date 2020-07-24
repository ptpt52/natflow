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
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_acct.h>
#ifdef CONFIG_NETFILTER_INGRESS
#include <linux/if_pppox.h>
#include <linux/ppp_defs.h>
#endif
#ifdef CONFIG_NET_RALINK_OFFLOAD
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

static int disabled = 1;
void natflow_disabled_set(int v)
{
	disabled = v;
}
int natflow_disabled_get(void)
{
	return disabled;
}

static unsigned int natflow_path_magic = 0;
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
#endif

#ifdef CONFIG_NET_RALINK_OFFLOAD
struct natflow_offload {
	struct flow_offload flow;
};

static struct natflow_offload *natflow_offload_alloc(struct nf_conn *ct, natflow_t *nf)
{
	static struct natflow_offload natflow_offload[NR_CPUS];

	int dir;
	struct flow_offload_tuple *ft;
	struct nf_conntrack_tuple *ctt;
	struct natflow_offload *natflow = &natflow_offload[smp_processor_id()];
	struct flow_offload *flow = &natflow->flow;

	dir = 0;
	ft = &flow->tuplehash[dir].tuple;
	ctt = &ct->tuplehash[dir].tuple;
	ft->src_v4 = ctt->src.u3.in;
	ft->dst_v4 = ctt->dst.u3.in;
	ft->l3proto = ctt->src.l3num;
	ft->l4proto = ctt->dst.protonum;
	ft->src_port = ctt->src.u.tcp.port;
	ft->dst_port = ctt->dst.u.tcp.port;

	dir = 1;
	ft = &flow->tuplehash[dir].tuple;
	ctt = &ct->tuplehash[dir].tuple;
	ft->src_v4 = ctt->src.u3.in;
	ft->dst_v4 = ctt->dst.u3.in;
	ft->l3proto = ctt->src.l3num;
	ft->l4proto = ctt->dst.protonum;
	ft->src_port = ctt->src.u.tcp.port;
	ft->dst_port = ctt->dst.u.tcp.port;

	/*XXX: in fact ppe don't care flags  */
	flow->flags = 0;
	if (ct->status & IPS_SRC_NAT)
		flow->flags |= FLOW_OFFLOAD_SNAT;
	if (ct->status & IPS_DST_NAT)
		flow->flags |= FLOW_OFFLOAD_DNAT;

	return natflow;
}
#endif

void natflow_session_learn(struct sk_buff *skb, struct nf_conn *ct, natflow_t *nf, int dir)
{
	int magic = natflow_path_magic;
	struct iphdr *iph = ip_hdr(skb);

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

	if (dir == IP_CT_DIR_ORIGINAL) {
		if (!(nf->status & NF_FF_REPLY) && !simple_test_and_set_bit(NF_FF_REPLY_BIT, &nf->status)) {
			void *l2 = (void *)skb_mac_header(skb);
			int l2_len = (void *)iph - l2;
			if (skb->dev->flags & IFF_NOARP) {
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
				nf->rroute[NF_FF_DIR_REPLY].outdev = skb->dev;
				simple_set_bit(NF_FF_REPLY_OK_BIT, &nf->status);
			}
		}
	} else {
		if (!(nf->status & NF_FF_ORIGINAL) && !simple_test_and_set_bit(NF_FF_ORIGINAL_BIT, &nf->status)) {
			void *l2 = (void *)skb_mac_header(skb);
			int l2_len = (void *)iph - l2;
			if (skb->dev->flags & IFF_NOARP) {
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
				nf->rroute[NF_FF_DIR_ORIGINAL].outdev = skb->dev;
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
	unsigned int ingress_pad_len = 0;
#endif
	unsigned int ingress_trim_off = 0;
	unsigned int re_learn = 0;
	int d;

	if (disabled)
		return NF_ACCEPT;

#ifdef CONFIG_NETFILTER_INGRESS
	if (pf == NFPROTO_NETDEV) {
		u32 _I;
		natflow_fastnat_node_t *nfn;

		if (skb_vlan_tag_present(skb) || skb->mac_len != ETH_HLEN) {
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

		if (iph->protocol == IPPROTO_TCP) {
			if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)) || skb_try_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
			_I = natflow_hash_v4(iph->saddr, iph->daddr, TCPH(l4)->source, TCPH(l4)->dest, IPPROTO_TCP);
			nfn = &natflow_fast_nat_table[_I];
			_I = (u32)ulongmindiff(jiffies, nfn->jiffies);
			if (nfn->magic == natflow_path_magic &&
			        _I < NATFLOW_FF_TIMEOUT_LOW &&
			        nfn->saddr == iph->saddr && nfn->daddr == iph->daddr &&
			        nfn->source == TCPH(l4)->source && nfn->dest == TCPH(l4)->dest &&
			        nfn->protonum == IPPROTO_TCP) {
				nfn->jiffies = jiffies;
				if ((re_learn = ((nfn->flags & FASTNAT_RE_LEARN) || (u16)skb->dev->ifindex != nfn->ifindex)) || _I > HZ) {
					if (re_learn) {
						nfn->flags &= ~FASTNAT_RE_LEARN;
						goto slow_fastpath;
					}
					goto out;
				}

				if (iph->ttl <= 1) {
					return NF_DROP;
				}
				ip_decrease_ttl(iph);
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
					skb->next = NULL;
					dev_queue_xmit(skb);
					skb = next;
				} while (skb);

				return NF_STOLEN;
			}
		} else {
			if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct udphdr)) || skb_try_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr))) {
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
			_I = natflow_hash_v4(iph->saddr, iph->daddr, UDPH(l4)->source, UDPH(l4)->dest, IPPROTO_UDP);
			nfn = &natflow_fast_nat_table[_I];
			_I = (u32)ulongmindiff(jiffies, nfn->jiffies);
			if (nfn->magic == natflow_path_magic &&
			        _I < NATFLOW_FF_TIMEOUT_LOW &&
			        nfn->saddr == iph->saddr && nfn->daddr == iph->daddr &&
			        nfn->source == UDPH(l4)->source && nfn->dest == UDPH(l4)->dest &&
			        nfn->protonum == IPPROTO_UDP) {
				nfn->jiffies = jiffies;
				if ((re_learn = ((nfn->flags & FASTNAT_RE_LEARN) || (u16)skb->dev->ifindex != nfn->ifindex)) || _I > HZ) {
					if (re_learn) {
						nfn->flags &= ~FASTNAT_RE_LEARN;
						goto slow_fastpath;
					}
					goto out;
				}

				if (iph->ttl <= 1) {
					return NF_DROP;
				}
				ip_decrease_ttl(iph);
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
	if (re_learn != 0) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
			simple_clear_bit(NF_FF_REPLY_OK_BIT, &nf->status);
			simple_clear_bit(NF_FF_REPLY_BIT, &nf->status);
		} else {
			simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
			simple_clear_bit(NF_FF_ORIGINAL_OK_BIT, &nf->status);
			simple_clear_bit(NF_FF_ORIGINAL_BIT, &nf->status);
		}
	}
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
		if (packets % 1024 == 0) {
			simple_clear_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status);
			simple_clear_bit(NF_FF_REPLY_CHECK_BIT, &nf->status);
		}
		/* skip 1/64 packets to slow path */
		if (packets % 64 == 0) {
			goto out;
		}
	}

	if (skb->len > nf->rroute[dir].mtu || (IPCB(skb)->flags & IPSKB_FRAG_PMTU)) {
		switch (iph->protocol) {
		case IPPROTO_TCP:
			NATFLOW_DEBUG("(PCO)" DEBUG_TCP_FMT ": pmtu=%u FRAG=%p\n", DEBUG_TCP_ARG(iph,l4), nf->rroute[dir].mtu, (void *)(IPCB(skb)->flags & IPSKB_FRAG_PMTU));
			break;
		case IPPROTO_UDP:
			NATFLOW_DEBUG("(PCO)" DEBUG_UDP_FMT ": pmtu=%u FRAG=%p\n", DEBUG_UDP_ARG(iph,l4), nf->rroute[dir].mtu, (void *)(IPCB(skb)->flags & IPSKB_FRAG_PMTU));
			break;
		}
		goto out;
	}

	if (iph->ttl <= 1) {
		return NF_DROP;
	}
	ip_decrease_ttl(iph);
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

					if (ulongmindiff(jiffies, nfn->jiffies) > NATFLOW_FF_TIMEOUT_HIGH ||
					        (nfn->saddr == saddr && nfn->daddr == daddr && nfn->source == source && nfn->dest == dest && nfn->protonum == protonum)) {
						switch (iph->protocol) {
						case IPPROTO_TCP:
							NATFLOW_INFO("(PCO)" DEBUG_TCP_FMT ": dir=%d use hash=%d\n", DEBUG_TCP_ARG(iph,l4), d, hash);
							break;
						case IPPROTO_UDP:
							NATFLOW_INFO("(PCO)" DEBUG_UDP_FMT ": dir=%d use hash=%d\n", DEBUG_UDP_ARG(iph,l4), d, hash);
							break;
						}

						if ((nfn->saddr == saddr && nfn->daddr == daddr && nfn->source == source && nfn->dest == dest && nfn->protonum == protonum) &&
						        (nfn->flags & FASTNAT_HALF_LEARN)) {
							nfn->ifindex = (u16)skb->dev->ifindex;
						} else {
							nfn->ifindex = (u16)-1;
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

						nfn->magic = natflow_path_magic;
						nfn->jiffies = jiffies;
					} else {
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
						        (nfn->saddr == saddr && nfn->daddr == daddr && nfn->source == source && nfn->dest == dest && nfn->protonum == protonum)) {
							natflow_fastnat_node_t *nfn_i;
							saddr = ct->tuplehash[!d].tuple.src.u3.ip;
							daddr = ct->tuplehash[!d].tuple.dst.u3.ip;
							source = ct->tuplehash[!d].tuple.src.u.all;
							dest = ct->tuplehash[!d].tuple.dst.u.all;
							protonum = ct->tuplehash[!d].tuple.dst.protonum;
							hash = natflow_hash_v4(saddr, daddr, source, dest, protonum);
							nfn_i = &natflow_fast_nat_table[hash];

							if (nfn_i->magic == natflow_path_magic && ulongmindiff(jiffies, nfn_i->jiffies) < NATFLOW_FF_TIMEOUT_LOW &&
							        (nfn_i->saddr == saddr && nfn_i->daddr == daddr && nfn_i->source == source && nfn_i->dest == dest && nfn_i->protonum == protonum)) {
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
#ifdef CONFIG_NET_RALINK_OFFLOAD
								if (get_vlan_real_dev(nf->rroute[NF_FF_DIR_ORIGINAL].outdev) == get_vlan_real_dev(nf->rroute[NF_FF_DIR_REPLY].outdev)) {
									struct net_device *real_dev = get_vlan_real_dev(nf->rroute[NF_FF_DIR_ORIGINAL].outdev);
									__be16 orig_vid = get_vlan_vid(nf->rroute[NF_FF_DIR_ORIGINAL].outdev);
									__be16 reply_vid = get_vlan_vid(nf->rroute[NF_FF_DIR_REPLY].outdev);
									if (real_dev->netdev_ops->ndo_flow_offload) {
										struct natflow_offload *natflow = natflow_offload_alloc(ct, nf);
										struct flow_offload_hw_path orig = {
											.dev = real_dev,
											.flags = FLOW_OFFLOAD_PATH_ETHERNET,
										};
										struct flow_offload_hw_path reply = {
											.dev = real_dev,
											.flags = FLOW_OFFLOAD_PATH_ETHERNET,
										};
										memcpy(orig.eth_src, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
										memcpy(orig.eth_dest, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
										memcpy(reply.eth_src, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
										memcpy(reply.eth_dest, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);

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

										if (nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
											orig.flags |= FLOW_OFFLOAD_PATH_PPPOE;
											orig.pppoe_sid = ntohs(PPPOEH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head + ETH_HLEN)->sid);
										}
										if (nf->rroute[NF_FF_DIR_REPLY].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
											reply.flags |= FLOW_OFFLOAD_PATH_PPPOE;
											reply.pppoe_sid = ntohs(PPPOEH(nf->rroute[NF_FF_DIR_REPLY].l2_head + ETH_HLEN)->sid);
										}

										real_dev->netdev_ops->ndo_flow_offload(FLOW_OFFLOAD_ADD, &natflow->flow, &reply, &orig);

										NATFLOW_INFO("(PCO) set hwnat offload dev=%s s=%pI4:%u d=%pI4:%u dev=%s s=%pI4:%u d=%pI4:%u\n",
										             nfn->outdev->name, &nfn->saddr, ntohs(nfn->source), &nfn->daddr, ntohs(nfn->dest),
										             nfn_i->outdev->name, &nfn_i->saddr, ntohs(nfn_i->source), &nfn_i->daddr, ntohs(nfn_i->dest));
									}
								}
#endif
							} else {
								if (!(nfn->flags & FASTNAT_HALF_LEARN)) {
									nfn->flags |= FASTNAT_HALF_LEARN;
								}
								nfn->ifindex = (u16)skb->dev->ifindex;
							}
						} else {
							natflow_fastnat_node_t *nfn_i;
							saddr = ct->tuplehash[!d].tuple.src.u3.ip;
							daddr = ct->tuplehash[!d].tuple.dst.u3.ip;
							source = ct->tuplehash[!d].tuple.src.u.all;
							dest = ct->tuplehash[!d].tuple.dst.u.all;
							protonum = ct->tuplehash[!d].tuple.dst.protonum;
							hash = natflow_hash_v4(saddr, daddr, source, dest, protonum);
							nfn_i = &natflow_fast_nat_table[hash];

							if (nfn_i->magic == natflow_path_magic && ulongmindiff(jiffies, nfn_i->jiffies) < NATFLOW_FF_TIMEOUT_LOW &&
							        (nfn_i->saddr == saddr && nfn_i->daddr == daddr && nfn_i->source == source && nfn_i->dest == dest && nfn_i->protonum == protonum)) {
								if (!(nfn_i->flags & FASTNAT_HALF_LEARN)) {
									nfn_i->flags |= FASTNAT_HALF_LEARN;
								}
							}
						}
					}
				} while (0);
			}
		} else {
			if (!(nf->status & NF_FF_REPLY_CHECK) && !simple_test_and_set_bit(NF_FF_REPLY_CHECK_BIT, &nf->status)) {
				goto fastnat_check;
			}
		}
	}
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
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_path_post_ct_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_path_post_ct_out_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natflow_path_post_ct_out_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
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
		if (!(dev->flags & (IFF_NOARP | IFF_LOOPBACK | IFF_POINTOPOINT))) {
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
	synchronize_rcu();

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
	natflow_fast_nat_table = kmalloc(sizeof(natflow_fastnat_node_t) * NATFLOW_FASTNAT_TABLE_SIZE, GFP_KERNEL);
	if (natflow_fast_nat_table == NULL) {
		return -ENOMEM;
	}
#endif

	need_conntrack();
	natflow_update_magic(1);

	ret = natflow_user_init();
	if (ret != 0)
		goto natflow_user_init_failed;

	register_netdevice_notifier(&natflow_netdev_notifier);

	ret = nf_register_hooks(path_hooks, ARRAY_SIZE(path_hooks));
	if (ret != 0)
		goto nf_register_hooks_failed;

	return 0;
nf_register_hooks_failed:
	unregister_netdevice_notifier(&natflow_netdev_notifier);
	natflow_user_exit();
natflow_user_init_failed:
#ifdef CONFIG_NETFILTER_INGRESS
	kfree(natflow_fast_nat_table);
#endif
	return ret;
}

void natflow_path_exit(void)
{
	nf_unregister_hooks(path_hooks, ARRAY_SIZE(path_hooks));
	unregister_netdevice_notifier(&natflow_netdev_notifier);
	natflow_user_exit();
#ifdef CONFIG_NETFILTER_INGRESS
	synchronize_rcu();
	kfree(natflow_fast_nat_table);
#endif
}
