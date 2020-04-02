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
static natflow_fastnat_node_t natflow_fast_nat_table[NATFLOW_FASTNAT_TABLE_SIZE];
#endif

void natflow_session_learn(struct sk_buff *skb, struct nf_conn *ct, natflow_t *nf, int dir)
{
	int magic = natflow_path_magic;
	struct iphdr *iph = ip_hdr(skb);

	if (nf->magic != magic) {
		simple_clear_bit(NF_FF_REPLY_OK_BIT, &nf->status);
		simple_clear_bit(NF_FF_ORIGINAL_OK_BIT, &nf->status);
		simple_clear_bit(NF_FF_REPLY_BIT, &nf->status);
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
				memcpy(nf->rroute[NF_FF_DIR_REPLY].l2_head, l2, l2_len);
				nf->rroute[NF_FF_DIR_REPLY].outdev = skb->dev;
				if (l2_len >= ETH_HLEN) {
					unsigned char mac[ETH_ALEN];
					memcpy(mac, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
					memcpy(ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);
					memcpy(ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, mac, ETH_ALEN);
				}
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
				memcpy(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head, l2, l2_len);
				nf->rroute[NF_FF_DIR_ORIGINAL].outdev = skb->dev;
				if (l2_len >= ETH_HLEN) {
					unsigned char mac[ETH_ALEN];
					memcpy(mac, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
					memcpy(ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
					memcpy(ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, mac, ETH_ALEN);
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
	int ingress_pad_len = 0;
#endif

	if (disabled)
		return NF_ACCEPT;

#ifdef CONFIG_NETFILTER_INGRESS
	if (pf == NFPROTO_NETDEV) {
		struct iphdr _iph;
		int _netoff;
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

		skb->network_header += ingress_pad_len;
		_netoff = skb_network_offset(skb);
		if (skb_copy_bits(skb, _netoff, &_iph, sizeof(_iph)) < 0) {
			skb->network_header -= ingress_pad_len;
			return NF_ACCEPT;
		}
		skb->network_header -= ingress_pad_len;

		if (_iph.ihl < 5 || _iph.version != 4 || ip_is_fragment(&_iph)) {
			return NF_ACCEPT;
		}

		_I = ntohs(_iph.tot_len);
		if (skb->len < _netoff + _I || _I < (_iph.ihl * 4)) {
			return NF_ACCEPT;
		}
		if (_iph.protocol != IPPROTO_TCP && _iph.protocol != IPPROTO_UDP) {
			return NF_ACCEPT;
		}

		if (ingress_pad_len > 0) {
			skb_pull(skb, ingress_pad_len);
			skb->network_header += ingress_pad_len;
		}

		if (!pskb_may_pull(skb, sizeof(struct iphdr))) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		if (!pskb_may_pull(skb, iph->ihl * 4)) {
			return NF_DROP;
		}
		iph = ip_hdr(skb);
		if (unlikely(ip_fast_csum((u8 *)iph, iph->ihl))) {
			return NF_DROP;
		}

		if (pskb_trim_rcsum(skb, _I)) {
			return NF_DROP;
		}

		skb->protocol = htons(ETH_P_IP);
		skb->transport_header = skb->network_header + ip_hdr(skb)->ihl * 4;

		if (_iph.protocol == IPPROTO_TCP) {
			if (!pskb_may_pull(skb, iph->ihl * 4 + sizeof(struct tcphdr)) || skb_try_make_writable(skb, iph->ihl * 4 + sizeof(struct tcphdr))) {
				return NF_DROP;
			}
			iph = ip_hdr(skb);
			l4 = (void *)iph + iph->ihl * 4;
			_I = natflow_hash_v4(iph->saddr, iph->daddr, TCPH(l4)->source, TCPH(l4)->dest, IPPROTO_TCP);
			nfn = &natflow_fast_nat_table[_I];
			if (nfn->magic == natflow_path_magic &&
			        ulongmindiff(jiffies, nfn->jiffies) < NATFLOW_FF_TIMEOUT &&
			        nfn->saddr == iph->saddr && nfn->daddr == iph->daddr &&
			        nfn->source == TCPH(l4)->source && nfn->dest == TCPH(l4)->dest &&
			        nfn->protonum == IPPROTO_TCP) {
				nfn->jiffies = jiffies;
				nfn->count++;
				if (nfn->count % 64 == 0)
					goto slow_fastpath;

				if (TCPH(l4)->source != nfn->nat_source) {
					natflow_nat_port_tcp(skb, iph->ihl * 4, TCPH(l4)->source, nfn->source);
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
				ip_decrease_ttl(iph);

fast_output:
				_I = ETH_HLEN;
				if ((nfn->flags & FASTNAT_PPPOE_FLAG)) {
					_I += PPPOE_SES_HLEN;
				}
				if (_I == ETH_HLEN + PPPOE_SES_HLEN) {
					if (skb_is_gso(skb)) {
						struct sk_buff *segs = skb_gso_segment(skb, 0);
						if (IS_ERR(segs)) {
							return NF_DROP;
						}
						consume_skb(skb);
						skb = segs;
					}
				}

				do {
					struct sk_buff *next = skb->next;
					if (_I > skb_headroom(skb) && pskb_expand_head(skb, _I, skb_tailroom(skb), GFP_ATOMIC)) {
						kfree_skb_list(skb);
						return NF_STOLEN;
					}
					skb_push(skb, _I);
					skb_reset_mac_header(skb);
					memcpy(eth_hdr(skb)->h_source, nfn->h_source, ETH_ALEN);
					memcpy(eth_hdr(skb)->h_dest, nfn->h_dest, ETH_ALEN);
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
					} else {
						eth_hdr(skb)->h_proto = __constant_htons(ETH_P_IP);
						skb->protocol = __constant_htons(ETH_P_IP);
					}
					skb->dev = nfn->outdev;
					if (_I != ETH_HLEN + PPPOE_SES_HLEN) { /* do GSO for PPPOE packets only */
						dev_queue_xmit(skb);
						break;
					} else {
						skb->next = NULL;
						dev_queue_xmit(skb);
					}
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
			if (nfn->magic == natflow_path_magic &&
			        ulongmindiff(jiffies, nfn->jiffies) < NATFLOW_FF_TIMEOUT &&
			        nfn->saddr == iph->saddr && nfn->daddr == iph->daddr &&
			        nfn->source == UDPH(l4)->source && nfn->dest == UDPH(l4)->dest &&
			        nfn->protonum == IPPROTO_UDP) {
				nfn->jiffies = jiffies;
				nfn->count++;
				if (nfn->count % 64 == 0)
					goto slow_fastpath;

				if (UDPH(l4)->source != nfn->nat_source) {
					natflow_nat_port_udp(skb, iph->ihl * 4, UDPH(l4)->source, nfn->source);
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
				ip_decrease_ttl(iph);

				goto fast_output;
			}
		}

slow_fastpath:
		ret = nf_conntrack_in_compat(dev_net(skb->dev), PF_INET, NF_INET_PRE_ROUTING, skb);
		if (ret != NF_ACCEPT) {
			goto out;
		}
	}
#endif

	if (skb->protocol != htons(ETH_P_IP))
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
	if (!nf_ct_is_confirmed(ct)) {
		goto out;
	}
	/*
	 * XXX: FIXME:
	 * we assume ct->ext->len > 24(=NATFLOW_MAX_OFF / NATFLOW_FACTOR) is always true
	 * after the nf_conntrack_in() call
	 * ct->ext->len <= 24 means natflow_session is ready
	 */
	nf = natflow_session_get(ct);
	if (NULL == nf) {
		goto out;
	}

	dir = CTINFO2DIR(ctinfo);
	natflow_session_learn(skb, ct, nf, dir);

	if ((ct->status & IPS_NATFLOW_FF_STOP)) {
		goto out;
	}

	//if (!(nf->status & NF_FF_OFFLOAD)) {
	if (!(nf->status & NF_FF_REPLY_OK) || !(nf->status & NF_FF_ORIGINAL_OK)) {
		goto out;
	}

	//skip 1/32 packets to slow path
	acct = nf_conn_acct_find(ct);
	if (acct) {
		struct nf_conn_counter *counter = acct->counter;
		if ((atomic64_read(&counter[0].packets) + atomic64_read(&counter[1].packets)) % 32 == 0) {
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

	ip_decrease_ttl(iph);

	/* XXX I just confirm it first  */
	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		goto out;
	}

#ifdef CONFIG_NETFILTER_INGRESS
	if (nf->rroute[dir].l2_head_len >= ETH_HLEN) {
		if (dir == NF_FF_DIR_ORIGINAL) {
			if (!(nf->status & NF_FF_ORIGINAL_CHECK) && !simple_test_and_set_bit(NF_FF_ORIGINAL_CHECK_BIT, &nf->status)) {
fastnat_check:
				do {
					struct ethhdr *eth = (struct ethhdr *)nf->rroute[dir].l2_head;
					__be32 saddr = ct->tuplehash[dir].tuple.src.u3.ip;
					__be32 daddr = ct->tuplehash[dir].tuple.dst.u3.ip;
					__be16 source = ct->tuplehash[dir].tuple.src.u.all;
					__be16 dest = ct->tuplehash[dir].tuple.dst.u.all;
					__be16 protonum = ct->tuplehash[dir].tuple.dst.protonum;
					u32 hash = natflow_hash_v4(saddr, daddr, source, dest, protonum);
					natflow_fastnat_node_t *nfn = &natflow_fast_nat_table[hash];

					if (ulongmindiff(jiffies, nfn->jiffies) > NATFLOW_FF_TIMEOUT) {
						nfn->saddr = saddr;
						nfn->daddr = daddr;
						nfn->source = source;
						nfn->dest = dest;
						nfn->protonum = protonum;

						nfn->nat_saddr = ct->tuplehash[!dir].tuple.dst.u3.ip;
						nfn->nat_daddr = ct->tuplehash[!dir].tuple.src.u3.ip;
						nfn->nat_source = ct->tuplehash[!dir].tuple.dst.u.all;
						nfn->nat_dest = ct->tuplehash[!dir].tuple.src.u.all;

						memcpy(nfn->h_source, eth->h_source, ETH_ALEN);
						memcpy(nfn->h_dest, eth->h_dest, ETH_ALEN);

						nfn->flags = 0;
						nfn->vlan_tci = 0;
						nfn->pppoe_sid = 0;
						if (nf->rroute[dir].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
							struct pppoe_hdr *ph = (struct pppoe_hdr *)((void *)eth + ETH_HLEN);
							nfn->pppoe_sid = ph->sid;
							nfn->flags |= FASTNAT_PPPOE_FLAG;
						}

						nfn->outdev = nf->rroute[dir].outdev;
						nfn->magic = natflow_path_magic;
						nfn->jiffies = jiffies;
					}
				} while (0);
			}
		} else {
			if (!(nf->status & NF_FF_REPLY_CHECK) && !simple_test_and_set_bit(NF_FF_REPLY_CHECK_BIT, &nf->status)) {
				goto fastnat_check;
			}
		}
	}

	if (nf->rroute[dir].l2_head_len == ETH_HLEN + PPPOE_SES_HLEN) {
		if (skb_is_gso(skb)) {
			struct sk_buff *segs = skb_gso_segment(skb, 0);
			if (IS_ERR(segs)) {
				return NF_DROP;
			}
			consume_skb(skb);
			skb = segs;
		}
	}
#endif

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
		if (nf->rroute[dir].l2_head_len != ETH_HLEN + PPPOE_SES_HLEN) { /* do GSO for PPPOE packets only */
			dev_queue_xmit(skb);
			break;
		} else {
			skb->next = NULL;
			dev_queue_xmit(skb);
		}
		skb = next;
	} while (skb);

	return NF_STOLEN;

out:
#ifdef CONFIG_NETFILTER_INGRESS
	if (pf == NFPROTO_NETDEV) {
		if (ingress_pad_len == PPPOE_SES_HLEN) {
			skb->protocol = cpu_to_be16(ETH_P_PPP_SES);
			skb->network_header -= PPPOE_SES_HLEN;
			skb_push(skb, PPPOE_SES_HLEN);
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

	if (skb->protocol != htons(ETH_P_IP))
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	nf = natflow_session_get(ct);
#else
	nf = natflow_session_in(ct);
#endif
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned int natflow_path_post_snat_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_path_post_snat_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
	//unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_path_post_snat_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natflow_path_post_snat_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#endif
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct iphdr *iph;
	natflow_t *nf;

	if (disabled)
		return NF_ACCEPT;

	if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}

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
	if ((ct->status & IPS_SRC_NAT_DONE)) {
		return NF_ACCEPT;
	}

	nf = natflow_session_in(ct);
	if (NULL == nf) {
		return NF_ACCEPT;
	}

	return NF_ACCEPT;
}
#endif

static struct nf_hook_ops path_hooks[] = {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_path_post_snat_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_NAT_SRC - 1,
	},
#endif
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
	return ret;
}

void natflow_path_exit(void)
{
	nf_unregister_hooks(path_hooks, ARRAY_SIZE(path_hooks));
	unregister_netdevice_notifier(&natflow_netdev_notifier);
	natflow_user_exit();
}
