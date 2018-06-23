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
#include "natflow_common.h"
#include "natflow_path.h"

static unsigned int natflow_path_magic = 0;

void natflow_update_magic(void)
{
	natflow_path_magic++;
}

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
	int dir = 0;
	enum ip_conntrack_info ctinfo;
	struct nf_conn_acct *acct;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	natflow_t *nf;
	int ret;
	int magic = natflow_path_magic;

	if (disabled)
		return NF_ACCEPT;

	if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	if (skb_is_gso(skb))
		return NF_ACCEPT;

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}
	l4 = (void *)iph + iph->ihl * 4;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	nf = natflow_session_get(ct);
	if (NULL == nf) {
		return NF_ACCEPT;
	}
	if (nf->magic != magic) {
		if ((ct->status & IPS_NOS_TRACK_INIT) && (ct->status & IPS_NATFLOW_FF)) {
			clear_bit(IPS_NATFLOW_FF_BIT, &ct->status);
		}
		simple_clear_bit(NF_FF_REPLY_OK_BIT, &nf->status);
		simple_clear_bit(NF_FF_ORIGINAL_OK_BIT, &nf->status);
		simple_clear_bit(NF_FF_REPLY_BIT, &nf->status);
		simple_clear_bit(NF_FF_ORIGINAL_BIT, &nf->status);
		nf->magic = magic;
	}

	if (CTINFO2DIR(ctinfo) == IP_CT_DIR_ORIGINAL) {
		if (!(nf->status & NF_FF_REPLY) && !simple_test_and_set_bit(NF_FF_REPLY_BIT, &nf->status)) {
			void *l2 = (void *)skb_mac_header(skb);
			int l2_len = (void *)iph - l2;
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
		if (!(nf->status & NF_FF_ORIGINAL) && !simple_test_and_set_bit(NF_FF_ORIGINAL_BIT, &nf->status)) {
			void *l2 = (void *)skb_mac_header(skb);
			int l2_len = (void *)iph - l2;
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

				switch (iph->protocol) {
					case IPPROTO_TCP:
						NATFLOW_DEBUG("(PCI)" DEBUG_TCP_FMT ": NF_FF_ORIGINAL_OK\n" MAC_HEADER_FMT " l2_len=%d dev=%s\n",
								DEBUG_TCP_ARG(iph,l4),
								MAC_HEADER_ARG(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head),
								nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len,
								nf->rroute[NF_FF_DIR_REPLY].outdev->name);
						break;
					case IPPROTO_UDP:
						NATFLOW_DEBUG("(PCI)" DEBUG_UDP_FMT ": NF_FF_ORIGINAL_OK\n" MAC_HEADER_FMT " l2_len=%d dev=%s\n",
								DEBUG_UDP_ARG(iph,l4),
								MAC_HEADER_ARG(nf->rroute[NF_FF_DIR_ORIGINAL].l2_head),
								nf->rroute[NF_FF_DIR_ORIGINAL].l2_head_len,
								nf->rroute[NF_FF_DIR_REPLY].outdev->name);
						break;
				}
			}
		}
		dir = NF_FF_DIR_REPLY;
	}

	if ((ct->status & IPS_NATFLOW_STOP)) {
		return NF_ACCEPT;
	}

	//if (!(nf->status & NF_FF_OFFLOAD)) {
	if (!(nf->status & NF_FF_REPLY_OK) || !(nf->status & NF_FF_ORIGINAL_OK)) {
		return NF_ACCEPT;
	}

	if ((ct->status & IPS_NOS_TRACK_INIT) && !(ct->status & IPS_NATFLOW_FF)) {
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
			return NF_ACCEPT;
		}
	}

	//skip 1/32 packets to slow path
	acct = nf_conn_acct_find(ct);
	if (acct) {
		struct nf_conn_counter *counter = acct->counter;
		if ((atomic64_read(&counter[0].packets) + atomic64_read(&counter[1].packets)) % 32 == 0) {
			return NF_ACCEPT;
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

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natflow_path_post_ct_out_hook(unsigned int hooknum,
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

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	nf = natflow_session_in(ct);
	if (NULL == nf) {
		return NF_ACCEPT;
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
		.hook = natflow_path_pre_ct_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_CONNTRACK + 1,
	},
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_path_post_ct_out_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_POST_ROUTING,
		.priority = NF_IP_PRI_LAST - 10 - 1,
	},
};

static int natflow_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;

	natflow_update_magic();
	synchronize_rcu();

	NATFLOW_WARN("catch unregister event for dev=%s\n", dev ? dev->name : "(null)");

	return NOTIFY_DONE;
}

static struct notifier_block natflow_netdev_notifier = {
	.notifier_call  = natflow_netdev_event,
};

int natflow_path_init(void)
{
	int ret = 0;

	need_conntrack();

	register_netdevice_notifier(&natflow_netdev_notifier);

	ret = nf_register_hooks(path_hooks, ARRAY_SIZE(path_hooks));
	if (ret != 0)
		goto nf_register_hooks_failed;

	return 0;
nf_register_hooks_failed:
	unregister_netdevice_notifier(&natflow_netdev_notifier);
	return ret;
}

void natflow_path_exit(void)
{
	nf_unregister_hooks(path_hooks, ARRAY_SIZE(path_hooks));
	unregister_netdevice_notifier(&natflow_netdev_notifier);
}
