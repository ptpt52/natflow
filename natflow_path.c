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
#include "natflow_common.h"
#include "natflow_path.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natflow_path_pre_ct_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_path_pre_ct_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_path_pre_ct_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natflow_path_pre_ct_in_hook(void *priv,
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
	int ret;
	int dir = 0;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP &&
			iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	nf = natflow_session_in(ct);
	if (NULL == nf) {
		return NF_ACCEPT;
	}

	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) {
		if (!(nf->status & NF_FF_REPLY) && !test_and_set_bit(NF_FF_REPLY_BIT, &nf->status)) {
			void *l2 = (void *)skb_mac_header(skb);
			int l2_len = (void *)iph - l2;
			if (l2_len >= 0 && l2_len <= NF_L2_MAX_LEN) {
				nf->rroute[NF_FF_DIR_REPLY].l2_head_len = l2_len;
				memcpy(nf->rroute[NF_FF_DIR_REPLY].l2_head, l2, l2_len);
				nf->rroute[NF_FF_DIR_REPLY].outindex = skb->dev->ifindex;
				nf->rroute[NF_FF_DIR_REPLY].outdev = skb->dev;
				if (l2_len >= ETH_HLEN) {
					unsigned char mac[ETH_ALEN];
					memcpy(mac, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH_ALEN);
					memcpy(ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_source, ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, ETH_ALEN);
					memcpy(ETH(nf->rroute[NF_FF_DIR_REPLY].l2_head)->h_dest, mac, ETH_ALEN);
				}
				set_bit(NF_FF_REPLY_OK_BIT, &nf->status);

				if (iph->protocol == IPPROTO_TCP) {
					NATFLOW_DEBUG("(PCI)" DEBUG_TCP_FMT ": NF_FF_REPLY_OK\n" MAC_HEADER_FMT " l2_len=%d dev=%s\n",
							DEBUG_TCP_ARG(iph,l4),
							MAC_HEADER_ARG(nf->rroute[NF_FF_DIR_REPLY].l2_head),
							nf->rroute[NF_FF_DIR_REPLY].l2_head_len,
							nf->rroute[NF_FF_DIR_REPLY].outdev->name);
				} else {
					NATFLOW_DEBUG("(PCI)" DEBUG_UDP_FMT ": NF_FF_REPLY_OK\n" MAC_HEADER_FMT " l2_len=%d dev=%s\n",
							DEBUG_UDP_ARG(iph,l4),
							MAC_HEADER_ARG(nf->rroute[NF_FF_DIR_REPLY].l2_head),
							nf->rroute[NF_FF_DIR_REPLY].l2_head_len,
							nf->rroute[NF_FF_DIR_REPLY].outdev->name);
				}
			}
		}
		dir = NF_FF_DIR_ORIGINAL;
	} else {
		if (!(nf->status & NF_FF_ORIGINAL) && !test_and_set_bit(NF_FF_ORIGINAL_BIT, &nf->status)) {
			void *l2 = (void *)skb_mac_header(skb);
			int l2_len = (void *)iph - l2;
			if (l2_len >= 0 && l2_len <= NF_L2_MAX_LEN) {
				nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len = l2_len;
				memcpy(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head, l2, l2_len);
				nf->rroute[NF_FF_DIR_ORIGINAL].outindex = skb->dev->ifindex;
				nf->rroute[NF_FF_DIR_ORIGINAL].outdev = skb->dev;
				if (l2_len >= ETH_HLEN) {
					unsigned char mac[ETH_ALEN];
					memcpy(mac, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH_ALEN);
					memcpy(ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_source, ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, ETH_ALEN);
					memcpy(ETH(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head)->h_dest, mac, ETH_ALEN);
				}
				set_bit(NF_FF_ORIGINAL_OK_BIT, &nf->status);

				if (iph->protocol == IPPROTO_TCP) {
					NATFLOW_DEBUG("(PCI)" DEBUG_TCP_FMT ": NF_FF_ORIGINAL_OK\n" MAC_HEADER_FMT " l2_len=%d dev=%s\n",
							DEBUG_TCP_ARG(iph,l4),
							MAC_HEADER_ARG(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head),
							nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len,
							nf->rroute[NF_FF_DIR_REPLY].outdev->name);
				} else {
					NATFLOW_DEBUG("(PCI)" DEBUG_UDP_FMT ": NF_FF_ORIGINAL_OK\n" MAC_HEADER_FMT " l2_len=%d dev=%s\n",
							DEBUG_UDP_ARG(iph,l4),
							MAC_HEADER_ARG(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head),
							nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len,
							nf->rroute[NF_FF_DIR_REPLY].outdev->name);
				}
			}
		}
		dir = NF_FF_DIR_REPLY;
	}

	//if (!(nf->status & NF_FF_OFFLOAD)) {
	if (!(nf->status & NF_FF_REPLY_OK) || !(nf->status & NF_FF_ORIGINAL_OK)) {
		return NF_ACCEPT;
	}

	if (nf->rroute[dir].l2_head_len > skb_headroom(skb) && pskb_expand_head(skb, nf->rroute[dir].l2_head_len, skb_tailroom(skb), GFP_ATOMIC)) {
		return NF_ACCEPT;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

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
		return ret;
	}

	skb_push(skb, nf->rroute[dir].l2_head_len);
	skb_reset_mac_header(skb);
	memcpy(skb_mac_header(skb), nf->rroute[dir].l2_head, nf->rroute[dir].l2_head_len);
	skb->dev = nf->rroute[dir].outdev;

	dev_queue_xmit(skb);

	return NF_STOLEN;
}

static struct nf_hook_ops path_hooks[] = {
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

int natflow_path_init(void)
{
	int ret = 0;

	need_conntrack();

	ret = nf_register_hooks(path_hooks, ARRAY_SIZE(path_hooks));
	return ret;
}

void natflow_path_exit(void)
{
	nf_unregister_hooks(path_hooks, ARRAY_SIZE(path_hooks));
}
