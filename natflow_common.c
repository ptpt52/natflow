/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Fri, 11 May 2018 14:20:56 +0800
 */
#include <linux/module.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_nat.h>
#include <net/netfilter/nf_nat_helper.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_set.h>
#include "natflow_common.h"

unsigned int debug = 0;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "Debug level (0=none,1=error,2=warn,4=info,8=debug,16=fixme,...,31=all) default=0");

#if defined(nf_ct_ext_add)
void *compat_nf_ct_ext_add(struct nf_conn *ct, int id, gfp_t gfp)
{
	return __nf_ct_ext_add_length(ct, id, 0, gfp);
}
#else
#define compat_nf_ct_ext_add nf_ct_ext_add
#endif

#define NATCAP_MAX_OFF 512u
#define __ALIGN_64BYTES (__ALIGN_64BITS * 8)
#define NATCAP_FACTOR (__ALIGN_64BITS * 2)

int natflow_session_init(struct nf_conn *ct, gfp_t gfp)
{
	int i;
	struct nat_key_t *nk = NULL;
	struct nf_ct_ext *old, *new = NULL;
	unsigned int nkoff, newoff, newlen = 0;
	size_t alloc_size;
	size_t var_alloc_len = ALIGN(sizeof(struct natflow_t), __ALIGN_64BITS);

	if (nf_ct_is_confirmed(ct)) {
		return -1;
	}

	for (i = 0; i < ARRAY_SIZE((((struct nf_ct_ext *)0)->offset)); i++) {
		if (!nf_ct_ext_exist(ct, i)) compat_nf_ct_ext_add(ct, i, gfp);
	}

	if (!ct->ext) {
		return -1;
	}

	old = ct->ext;
	nkoff = ALIGN(old->len, __ALIGN_64BYTES);
	newoff = ALIGN(nkoff + ALIGN(sizeof(struct nat_key_t), __ALIGN_64BITS), __ALIGN_64BITS);

	if (old->len * NATCAP_FACTOR <= NATCAP_MAX_OFF) {
		nk = (struct nat_key_t *)((void *)old + old->len * NATCAP_FACTOR);
		if (nk->magic == NATCAP_MAGIC && nk->ext_magic == (((unsigned long)ct) & 0xffffffff)) {
			if (nk->natflow_off) {
				//natflow exist
				return 0;
			}
			nkoff = old->len * NATCAP_FACTOR;
			newoff = ALIGN(nk->len, __ALIGN_64BITS);
		} else {
			nk = NULL;
		}
	}

	if (nkoff > NATCAP_MAX_OFF) {
		NATFLOW_ERROR(DEBUG_FMT_PREFIX "realloc ct->ext->len > %u not supported!\n", DEBUG_ARG_PREFIX, NATCAP_MAX_OFF);
		return -1;
	}

	newlen = ALIGN(newoff + var_alloc_len, __ALIGN_64BITS);
	alloc_size = ALIGN(newlen, __ALIGN_64BITS);

	new = __krealloc(old, alloc_size, gfp);
	if (!new) {
		return -1;
	}
	memset((void *)new + newoff, 0, newlen - newoff);
	if (nk == NULL) {
		nk = (struct nat_key_t *)((void *)new + nkoff);
		memset((void *)nk, 0, newoff - nkoff);
	}

	if (new != old) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
		kfree_rcu(old, rcu);
		ct->ext = new;
#else
		kfree_rcu(old, rcu);
		rcu_assign_pointer(ct->ext, new);
#endif
	}

	new->len = nkoff / NATCAP_FACTOR;
	nk = (struct nat_key_t *)((void *)new + nkoff);
	nk->magic = NATCAP_MAGIC;
	nk->ext_magic = (unsigned long)ct & 0xffffffff;
	nk->len = newlen;
	nk->natflow_off = newoff;

	return 0;
}

struct natflow_t *natflow_session_get(struct nf_conn *ct)
{
	struct nat_key_t *nk;
	struct natflow_t *nf = NULL;

	if (!ct->ext) {
		return NULL;
	}

	if (ct->ext->len * NATCAP_FACTOR > NATCAP_MAX_OFF) {
		return NULL;
	}

	nk = (struct nat_key_t *)((void *)ct->ext + ct->ext->len * NATCAP_FACTOR);
	if (nk->magic != NATCAP_MAGIC || nk->ext_magic != (((unsigned long)ct) & 0xffffffff)) {
		return NULL;
	}

	if (nk->natflow_off == 0) {
		return NULL;
	}

	nf = (struct natflow_t *)((void *)ct->ext + nk->natflow_off);

	return nf;
}

const char *const hooknames[] = {
	[NF_INET_PRE_ROUTING] = "PRE",
	[NF_INET_LOCAL_IN] = "IN",
	[NF_INET_FORWARD] = "FD",
	[NF_INET_LOCAL_OUT] = "OUT",
	[NF_INET_POST_ROUTING] = "POST",
};

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_test_src_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_test_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_test(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_test_dst_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_test_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_test(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_add_src_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_add_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_add(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_add_dst_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_add_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_add(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_del_src_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_del_src_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_del(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_del_dst_ip(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_del_dst_ip(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_IPV4;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_del(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
int ip_set_test_src_mac(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_test_src_mac(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	struct net *net = state->net;
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = NFPROTO_UNSPEC;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 10, 0)
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 4, 0)
	par.net = net;
#endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	id = ip_set_get_byname(net, ip_set_name, &set);
#else
	id = ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_test(id, skb, &par, &opt);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

unsigned int natflow_dnat_setup(struct nf_conn *ct, __be32 addr, __be16 man_proto)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
	struct nf_nat_range range;
	if (nf_nat_initialized(ct, IP_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
	memset(&range.min_ip, 0, sizeof(range.min_ip));
	memset(&range.max_ip, 0, sizeof(range.max_ip));
	range.flags = IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED;
	range.min_ip = addr;
	range.max_ip = addr;
	range.min.all = man_proto;
	range.max.all = man_proto;
	return nf_nat_setup_info(ct, &range, IP_NAT_MANIP_DST);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
	struct nf_nat_ipv4_range range;
	if (nf_nat_initialized(ct, NF_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
	memset(&range.min_ip, 0, sizeof(range.min_ip));
	memset(&range.max_ip, 0, sizeof(range.max_ip));
	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_ip = addr;
	range.max_ip = addr;
	range.min.all = man_proto;
	range.max.all = man_proto;
	return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
	struct nf_nat_range range;
	if (nf_nat_initialized(ct, NF_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
	memset(&range.min_addr, 0, sizeof(range.min_addr));
	memset(&range.max_addr, 0, sizeof(range.max_addr));
	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_addr.ip = addr;
	range.max_addr.ip = addr;
	range.min_proto.all = man_proto;
	range.max_proto.all = man_proto;
	return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
#else
	struct nf_nat_range2 range;
	if (nf_nat_initialized(ct, NF_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
	memset(&range.min_addr, 0, sizeof(range.min_addr));
	memset(&range.max_addr, 0, sizeof(range.max_addr));
	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_addr.ip = addr;
	range.max_addr.ip = addr;
	range.min_proto.all = man_proto;
	range.max_proto.all = man_proto;
	memset(&range.base_proto, 0, sizeof(range.base_proto));
	return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
#endif
}
