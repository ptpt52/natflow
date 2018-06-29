/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 27 Jun 2018 22:13:17 +0800
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
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/netdevice.h>
#include <linux/bitops.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include "natflow.h"
#include "natflow_common.h"
#include "natflow_user.h"

static int disabled = 0;
void natflow_user_disabled_set(int v)
{
	disabled = v;
}
int natflow_user_disabled_get(void)
{
	return disabled;
}

/* user timeout 1800s */
static unsigned int natflow_user_timeout = 1800;

static struct sk_buff *natflow_user_uskbs[NR_CPUS];
#define NATFLOW_USKB_SIZE (sizeof(struct iphdr) + sizeof(struct udphdr))
#define NATFLOW_FAKEUSER_DADDR 0xffffffff;

static inline struct sk_buff *uskb_of_this_cpu(int id)
{
	BUG_ON(id >= NR_CPUS);
	if (!natflow_user_uskbs[id]) {
		natflow_user_uskbs[id] = __alloc_skb(NATFLOW_USKB_SIZE, GFP_ATOMIC, 0, numa_node_id());
	}
	return natflow_user_uskbs[id];
}

void natflow_user_timeout_touch(natflow_fakeuser_t *nfu)
{
	nfu->timeout = jiffies + natflow_user_timeout * HZ;
}

natflow_fakeuser_t *natflow_user_in(struct nf_conn *ct)
{
	natflow_fakeuser_t *user = NULL;

	if (disabled)
		return NULL;

	if (ct->master) {
		if ((IPS_NATFLOW_USER & ct->master->status)) {
			user = ct->master;
		} else if (ct->master->master && (IPS_NATFLOW_USER & ct->master->master->status)) {
			user = ct->master->master;
		}
	}

	if (!user) {
		struct nf_ct_ext *new = NULL;
		unsigned int newoff = 0;
		int ret;
		struct sk_buff *uskb;
		struct iphdr *iph;
		struct udphdr *udph;
		enum ip_conntrack_info ctinfo;

		uskb = uskb_of_this_cpu(smp_processor_id());
		if (uskb == NULL) {
			return NULL;
		}
		skb_reset_transport_header(uskb);
		skb_reset_network_header(uskb);
		skb_reset_mac_len(uskb);

		uskb->protocol = __constant_htons(ETH_P_IP);
		uskb->tail = uskb->len = NATFLOW_USKB_SIZE;
		uskb->pkt_type = PACKET_HOST;
		uskb->transport_header = uskb->network_header + sizeof(struct iphdr);

		iph = ip_hdr(uskb);
		iph->version = 4;
		iph->ihl = 5;
		iph->saddr = ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip;
		iph->daddr = NATFLOW_FAKEUSER_DADDR;
		iph->tos = 0;
		iph->tot_len = htons(NATFLOW_USKB_SIZE);
		iph->ttl=255;
		iph->protocol = IPPROTO_UDP;
		iph->id = __constant_htons(0xDEAD);
		iph->frag_off = 0;
		iph->check = 0;
		iph->check = ip_fast_csum(iph, iph->ihl);

		udph = (struct udphdr *)((char *)iph + sizeof(struct iphdr));
		udph->source = __constant_htons(0);
		udph->dest = __constant_htons(65535);
		udph->len = __constant_htons(sizeof(struct udphdr));
		udph->check = 0;

		ret = nf_conntrack_in(&init_net, PF_INET, NF_INET_PRE_ROUTING, uskb);
		if (ret != NF_ACCEPT) {
			return NULL;
		}
		user = nf_ct_get(uskb, &ctinfo);

		if (!user) {
			NATFLOW_ERROR("fakeuser create for ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] failed, ctinfo=%x\n",
					&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
					&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
					&ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
					&ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all), (unsigned int)ctinfo);
			return NULL;
		}

		if (!user->ext) {
			NATFLOW_ERROR("fakeuser create for ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] failed, user->ext is NULL\n",
					&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
					&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
					&ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
					&ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all));
			skb_nfct_reset(uskb);
			return NULL;
		}
		newoff = ALIGN(user->ext->len, __ALIGN_64BITS);
		new = __krealloc(user->ext, newoff + sizeof(struct fakeuser_data_t), GFP_ATOMIC);
		if (!new) {
			NATFLOW_ERROR("fakeuser create for ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] failed, realloc user->ext failed\n",
					&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
					&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
					&ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
					&ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all));
			skb_nfct_reset(uskb);
			return NULL;
		}
		if (user->ext != new) {
			kfree_rcu(user->ext, rcu);
			rcu_assign_pointer(user->ext, new);
		}
		new->len = newoff;
		nf_conntrack_get(&user->ct_general);
		set_bit(IPS_NATFLOW_USER_BIT, &user->status);
		ct->master = user;
		ret = nf_conntrack_confirm(uskb);
		skb_nfct_reset(uskb);

		natflow_user_timeout_touch(user);

		NATFLOW_INFO("fakeuser create for ct[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u] user[%pI4:%u->%pI4:%u %pI4:%u<-%pI4:%u]\n",
				&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
				&ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
				&ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
				&ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(ct->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all),
				&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip, ntohs(user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u.all),
				&user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u3.ip, ntohs(user->tuplehash[IP_CT_DIR_ORIGINAL].tuple.dst.u.all),
				&user->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u3.ip, ntohs(user->tuplehash[IP_CT_DIR_REPLY].tuple.dst.u.all),
				&user->tuplehash[IP_CT_DIR_REPLY].tuple.src.u3.ip, ntohs(user->tuplehash[IP_CT_DIR_REPLY].tuple.src.u.all)
				);
	}

	return user;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natflow_user_pre_ct_in_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_user_pre_ct_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	//unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_user_pre_ct_in_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#else
static unsigned int natflow_user_pre_ct_in_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	//const struct net_device *in = state->in;
	//const struct net_device *out = state->out;
#endif
#endif
	struct fakeuser_data_t *fud;
	natflow_fakeuser_t *user;
	struct nf_conn *ct;
	enum ip_conntrack_info ctinfo;

	if (disabled)
		return NF_ACCEPT;

	if (skb->protocol != htons(ETH_P_IP))
		return NF_ACCEPT;

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}

	user = natflow_user_in(ct);
	if (NULL == user) {
		return NF_ACCEPT;
	}

	fud = natflow_fakeuser_data(user);

	if (timestamp_offset(fud->timestamp, jiffies) >= 32 * HZ) {
		if (memcmp(eth_hdr(skb)->h_source, fud->macaddr, ETH_ALEN) != 0) {
			memcpy(fud->macaddr, eth_hdr(skb)->h_source, ETH_ALEN);
		}
		fud->timestamp = jiffies;
	}

	return NF_ACCEPT;
}

static struct nf_hook_ops user_hooks[] = {
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_user_pre_ct_in_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST + 1,
	},
};



int natflow_user_init(void)
{
	int ret;
	int i;

	for (i = 0; i < NR_CPUS; i++) {
		natflow_user_uskbs[i] = NULL;
	}

	ret = nf_register_hooks(user_hooks, ARRAY_SIZE(user_hooks));
	if (ret != 0)
		goto nf_register_hooks_failed;

	natflow_user_disabled_set(0);

	return 0;

nf_register_hooks_failed:
	return ret;
}

void natflow_user_exit(void)
{
	int i;

	natflow_user_disabled_set(1);
	synchronize_rcu();

	nf_unregister_hooks(user_hooks, ARRAY_SIZE(user_hooks));

	for (i = 0; i < NR_CPUS; i++) {
		if (natflow_user_uskbs[i]) {
			kfree(natflow_user_uskbs[i]);
			natflow_user_uskbs[i] = NULL;
		}
	}
}
