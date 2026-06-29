/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Fri, 11 May 2018 14:20:56 +0800
 */
#include <linux/module.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
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
#define NATCAP_FIXED_EXT_OFF (256 / NATCAP_FACTOR)

static int static_fixed_ext_off = NATCAP_FIXED_EXT_OFF;

void natflow_probe_ct_ext(void)
{
	int i = 0;
	struct nf_conn ct = { };

	for (i = 0; i < ARRAY_SIZE((((struct nf_ct_ext *)0)->offset)); i++) {
		if (!nf_ct_ext_exist(&ct, i)) compat_nf_ct_ext_add(&ct, i, GFP_KERNEL);
	}
	if (ct.ext) {
		i = ALIGN(ct.ext->len, __ALIGN_64BYTES);
		kfree(ct.ext);
		static_fixed_ext_off = i / NATCAP_FACTOR;
		NATFLOW_println("probe static_fixed_ext_off = %u", static_fixed_ext_off);
	} else {
		NATFLOW_println("default static_fixed_ext_off = %u", static_fixed_ext_off);
	}
}

/*
 * XXX: NOTE ABOUT krealloc() SHRINK BEHAVIOR for natflow_session_init()
 *
 * This implementation intentionally relies on assumptions that are
 * NOT guaranteed by the kernel API.
 *
 * On the current production system:
 *   - KASAN / SLUB debug / redzone / poisoning are disabled
 *   - SLUB usually does not move objects when shrinking
 *   - the underlying slab object typically remains intact
 *
 * Therefore, after krealloc(ptr, new_size, ...),
 * although the region [new_size, old_size) is no longer owned by
 * the caller according to the API contract, accessing it tends to
 * work in practice in this environment.
 *
 * IMPORTANT:
 * This is a pragmatic workaround based on allocator behavior,
 * not a formal guarantee.
 *
 * If in the future:
 *   - debugging or hardening options are enabled, or
 *   - the allocator implementation changes, or
 *   - the object gets reallocated during shrink,
 *
 * then accessing the tail beyond new_size may trigger out-of-bounds
 * reports, panics, or memory corruption.
 *
 * When a safer design becomes available, this dependency should be
 * removed by explicitly tracking sizes or restructuring the data.
 */
int natflow_session_init(struct nf_conn *ct, gfp_t gfp)
{
	struct nat_key_t *nk = NULL;
	struct nf_ct_ext *old, *new = NULL;
	unsigned int nkoff, newoff, newlen = 0;
	size_t alloc_size;
	size_t var_alloc_len = ALIGN(sizeof(struct natflow_t), __ALIGN_64BITS);

	if (nf_ct_is_confirmed(ct)) {
		return -1;
	}

	if (test_and_set_bit(IPS_NATFLOW_SESSION_BIT, &ct->status)) {
		/* someone else is already running in this progress */
		NATFLOW_INFO("another process is already running!\n");
		return -1;
	}

	nf_ct_nat_ext_add(ct);

	if (!ct->ext) {
		clear_bit(IPS_NATFLOW_SESSION_BIT, &ct->status);
		return -1;
	}

	old = ct->ext;
	nkoff = ALIGN(static_fixed_ext_off * NATCAP_FACTOR, __ALIGN_64BYTES);
	newoff = ALIGN(nkoff + ALIGN(sizeof(struct nat_key_t), __ALIGN_64BITS), __ALIGN_64BITS);

	newlen = ALIGN(newoff + var_alloc_len, __ALIGN_64BITS);
	alloc_size = ALIGN(newlen, __ALIGN_64BITS);

	new = natflow_ct_ext_krealloc(old, alloc_size, gfp);
	if (!new) {
		clear_bit(IPS_NATFLOW_SESSION_BIT, &ct->status);
		NATFLOW_ERROR("failed to krealloc size=%u\n", (unsigned int)alloc_size);
		return -1;
	}

	if (new != old) {
		natflow_ct_ext_replace(ct, old, new);
		old = new;
	}

	if (static_fixed_ext_off * NATCAP_FACTOR <= NATCAP_MAX_OFF) {
		nk = (struct nat_key_t *)((void *)old + static_fixed_ext_off * NATCAP_FACTOR);
		if (nk->magic == NATCAP_MAGIC && nk->ext_magic == (((unsigned long)ct) & 0xffffffff)) {
			if (nk->natcap_off && (ct->status & IPS_NATCAP_SESSION)) {
				NATFLOW_DEBUG("append natflow key after natcap: len=%u natcap_off=%u natflow_off=%u\n",
				              nk->len, nk->natcap_off, nk->natflow_off);
				newoff = ALIGN(nk->len, __ALIGN_64BITS);
			} else {
				/*
				 * natflow just claimed IPS_NATFLOW_SESSION_BIT above. Any
				 * existing natflow_off before this point is stale unless
				 * natcap has an active session owning the shared layout.
				 */
				nk = NULL;
			}
		} else {
			nk = NULL;
		}
	}

	if (nkoff > NATCAP_MAX_OFF) {
		clear_bit(IPS_NATFLOW_SESSION_BIT, &ct->status);
		NATFLOW_ERROR("realloc: ct->ext->len > %u is not supported!\n", NATCAP_MAX_OFF);
		return -1;
	}

	newlen = ALIGN(newoff + var_alloc_len, __ALIGN_64BITS);
	alloc_size = ALIGN(newlen, __ALIGN_64BITS);

	new = natflow_ct_ext_krealloc(old, alloc_size, gfp);
	if (!new) {
		clear_bit(IPS_NATFLOW_SESSION_BIT, &ct->status);
		NATFLOW_ERROR("failed to krealloc size=%u\n", (unsigned int)alloc_size);
		return -1;
	}
	memset((void *)new + newoff, 0, newlen - newoff);
	if (nk == NULL) {
		nk = (struct nat_key_t *)((void *)new + nkoff);
		memset((void *)nk, 0, newoff - nkoff);
	}

	if (new != old) {
		natflow_ct_ext_replace(ct, old, new);
	}

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

	if (!(ct->status & IPS_NATFLOW_SESSION)) {
		return NULL;
	}

	if (!ct->ext) {
		return NULL;
	}

	if (static_fixed_ext_off * NATCAP_FACTOR > NATCAP_MAX_OFF) {
		return NULL;
	}

	nk = (struct nat_key_t *)((void *)ct->ext + static_fixed_ext_off * NATCAP_FACTOR);
	if (nk->magic != NATCAP_MAGIC || nk->ext_magic != (((unsigned long)ct) & 0xffffffff)) {
		return NULL;
	}

	if (nk->natflow_off == 0) {
		return NULL;
	}

	nf = (struct natflow_t *)((void *)ct->ext + nk->natflow_off);

	return nf;
}

#if NATFLOW_IP_SET_GET_BYNAME_TAKES_NLATTR
static ip_set_id_t natflow_ip_set_get_byname(struct net *net, const char *ip_set_name, struct ip_set **set)
{
	struct {
		struct nlattr nla;
		char name[IPSET_MAXNAMELEN];
	} name_attr;
	size_t name_len;

	memset(&name_attr, 0, sizeof(name_attr));
	name_len = strnlen(ip_set_name, IPSET_MAXNAMELEN - 1);
	memcpy(name_attr.name, ip_set_name, name_len);
	name_attr.nla.nla_type = 0;
	name_attr.nla.nla_len = nla_attr_size(name_len + 1);

	return ip_set_get_byname(net, &name_attr.nla, set);
}
#elif NATFLOW_HAVE_IP_SET_NET_API
static inline ip_set_id_t natflow_ip_set_get_byname(struct net *net, const char *ip_set_name, struct ip_set **set)
{
	return ip_set_get_byname(net, ip_set_name, set);
}
#else
static inline ip_set_id_t natflow_ip_set_get_byname(const char *ip_set_name, struct ip_set **set)
{
	return ip_set_get_byname(ip_set_name, set);
}
#endif

const char *const hooknames[] = {
	[NF_INET_PRE_ROUTING] = "PRE",
	[NF_INET_LOCAL_IN] = "IN",
	[NF_INET_FORWARD] = "FD",
	[NF_INET_LOCAL_OUT] = "OUT",
	[NF_INET_POST_ROUTING] = "POST",
};

#if NATFLOW_HAVE_IP_SET_STATE_API
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
#if NATFLOW_HAVE_IP_SET_STATE_API
	struct net *net = state->net;
#elif NATFLOW_HAVE_IP_SET_NET_API
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = skb->protocol == __constant_htons(ETH_P_IP) ? NFPROTO_IPV4 : NFPROTO_IPV6;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if NATFLOW_HAVE_IP_SET_STATE_API
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if NATFLOW_HAVE_XT_ACTION_PARAM_NET
	par.net = net;
#endif
#endif

#if NATFLOW_HAVE_IP_SET_NET_API
	id = natflow_ip_set_get_byname(net, ip_set_name, &set);
#else
	id = natflow_ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		return -EINVAL;
	}

	ret = ip_set_test(id, skb, &par, &opt);

#if NATFLOW_HAVE_IP_SET_NET_API
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if NATFLOW_HAVE_IP_SET_STATE_API
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
#if NATFLOW_HAVE_IP_SET_STATE_API
	struct net *net = state->net;
#elif NATFLOW_HAVE_IP_SET_NET_API
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = skb->protocol == __constant_htons(ETH_P_IP) ? NFPROTO_IPV4 : NFPROTO_IPV6;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if NATFLOW_HAVE_IP_SET_STATE_API
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if NATFLOW_HAVE_XT_ACTION_PARAM_NET
	par.net = net;
#endif
#endif

#if NATFLOW_HAVE_IP_SET_NET_API
	id = natflow_ip_set_get_byname(net, ip_set_name, &set);
#else
	id = natflow_ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_test(id, skb, &par, &opt);

#if NATFLOW_HAVE_IP_SET_NET_API
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if NATFLOW_HAVE_IP_SET_STATE_API
int ip_set_test_dst_netport(const struct nf_hook_state *state, struct sk_buff *skb, const char *ip_set_name)
#else
int ip_set_test_dst_netport(const struct net_device *in, const struct net_device *out, struct sk_buff *skb, const char *ip_set_name)
#endif
{
	int ret = 0;
	ip_set_id_t id;
	struct ip_set *set;
	struct ip_set_adt_opt opt;
	struct xt_action_param par;
#if NATFLOW_HAVE_IP_SET_STATE_API
	struct net *net = state->net;
#elif NATFLOW_HAVE_IP_SET_NET_API
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = skb->protocol == __constant_htons(ETH_P_IP) ? NFPROTO_IPV4 : NFPROTO_IPV6;
	opt.dim = IPSET_DIM_TWO;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if NATFLOW_HAVE_IP_SET_STATE_API
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if NATFLOW_HAVE_XT_ACTION_PARAM_NET
	par.net = net;
#endif
#endif

#if NATFLOW_HAVE_IP_SET_NET_API
	id = natflow_ip_set_get_byname(net, ip_set_name, &set);
#else
	id = natflow_ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_test(id, skb, &par, &opt);

#if NATFLOW_HAVE_IP_SET_NET_API
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if NATFLOW_HAVE_IP_SET_STATE_API
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
#if NATFLOW_HAVE_IP_SET_STATE_API
	struct net *net = state->net;
#elif NATFLOW_HAVE_IP_SET_NET_API
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = skb->protocol == __constant_htons(ETH_P_IP) ? NFPROTO_IPV4 : NFPROTO_IPV6;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if NATFLOW_HAVE_IP_SET_STATE_API
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if NATFLOW_HAVE_XT_ACTION_PARAM_NET
	par.net = net;
#endif
#endif

#if NATFLOW_HAVE_IP_SET_NET_API
	id = natflow_ip_set_get_byname(net, ip_set_name, &set);
#else
	id = natflow_ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_add(id, skb, &par, &opt);

#if NATFLOW_HAVE_IP_SET_NET_API
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if NATFLOW_HAVE_IP_SET_STATE_API
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
#if NATFLOW_HAVE_IP_SET_STATE_API
	struct net *net = state->net;
#elif NATFLOW_HAVE_IP_SET_NET_API
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = skb->protocol == __constant_htons(ETH_P_IP) ? NFPROTO_IPV4 : NFPROTO_IPV6;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if NATFLOW_HAVE_IP_SET_STATE_API
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if NATFLOW_HAVE_XT_ACTION_PARAM_NET
	par.net = net;
#endif
#endif

#if NATFLOW_HAVE_IP_SET_NET_API
	id = natflow_ip_set_get_byname(net, ip_set_name, &set);
#else
	id = natflow_ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_add(id, skb, &par, &opt);

#if NATFLOW_HAVE_IP_SET_NET_API
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if NATFLOW_HAVE_IP_SET_STATE_API
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
#if NATFLOW_HAVE_IP_SET_STATE_API
	struct net *net = state->net;
#elif NATFLOW_HAVE_IP_SET_NET_API
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = skb->protocol == __constant_htons(ETH_P_IP) ? NFPROTO_IPV4 : NFPROTO_IPV6;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = IPSET_DIM_ONE_SRC;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if NATFLOW_HAVE_IP_SET_STATE_API
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if NATFLOW_HAVE_XT_ACTION_PARAM_NET
	par.net = net;
#endif
#endif

#if NATFLOW_HAVE_IP_SET_NET_API
	id = natflow_ip_set_get_byname(net, ip_set_name, &set);
#else
	id = natflow_ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_del(id, skb, &par, &opt);

#if NATFLOW_HAVE_IP_SET_NET_API
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if NATFLOW_HAVE_IP_SET_STATE_API
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
#if NATFLOW_HAVE_IP_SET_STATE_API
	struct net *net = state->net;
#elif NATFLOW_HAVE_IP_SET_NET_API
	struct net *net = &init_net;
	if (in)
		net = dev_net(in);
	else if (out)
		net = dev_net(out);
#endif

	memset(&opt, 0, sizeof(opt));
	opt.family = skb->protocol == __constant_htons(ETH_P_IP) ? NFPROTO_IPV4 : NFPROTO_IPV6;
	opt.dim = IPSET_DIM_ONE;
	opt.flags = 0;
	opt.cmdflags = 0;
	opt.ext.timeout = UINT_MAX;

	memset(&par, 0, sizeof(par));
#if NATFLOW_HAVE_IP_SET_STATE_API
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if NATFLOW_HAVE_XT_ACTION_PARAM_NET
	par.net = net;
#endif
#endif

#if NATFLOW_HAVE_IP_SET_NET_API
	id = natflow_ip_set_get_byname(net, ip_set_name, &set);
#else
	id = natflow_ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		NATFLOW_DEBUG("ip_set '%s' not found\n", ip_set_name);
		return 0;
	}

	ret = ip_set_del(id, skb, &par, &opt);

#if NATFLOW_HAVE_IP_SET_NET_API
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

#if NATFLOW_HAVE_IP_SET_STATE_API
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
#if NATFLOW_HAVE_IP_SET_STATE_API
	struct net *net = state->net;
#elif NATFLOW_HAVE_IP_SET_NET_API
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
#if NATFLOW_HAVE_IP_SET_STATE_API
	par.state = state;
#else
	par.in = in;
	par.out = out;
#if NATFLOW_HAVE_XT_ACTION_PARAM_NET
	par.net = net;
#endif
#endif

#if NATFLOW_HAVE_IP_SET_NET_API
	id = natflow_ip_set_get_byname(net, ip_set_name, &set);
#else
	id = natflow_ip_set_get_byname(ip_set_name, &set);
#endif
	if (id == IPSET_INVALID_ID) {
		return -EINVAL;
	}

	ret = ip_set_test(id, skb, &par, &opt);

#if NATFLOW_HAVE_IP_SET_NET_API
	ip_set_put_byindex(net, id);
#else
	ip_set_put_byindex(id);
#endif

	return ret;
}

unsigned int natflow_dnat_setup(struct nf_conn *ct, __be32 addr, __be16 man_proto)
{
#if NATFLOW_NAT_RANGE_USES_IP_NAT_MANIP
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
#elif NATFLOW_NAT_RANGE_USES_IPV4_RANGE
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
#elif !NATFLOW_NAT_RANGE_USES_RANGE2
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

#ifdef NATFLOW_HAVE_NAT66
unsigned int natflow_dnat_setup6(struct nf_conn *ct, const struct in6_addr *addr, __be16 man_proto)
{
#if !NATFLOW_NAT_RANGE_USES_RANGE2
	struct nf_nat_range range;
	if (nf_nat_initialized(ct, NF_NAT_MANIP_DST)) {
		return NF_ACCEPT;
	}
	memset(&range.min_addr, 0, sizeof(range.min_addr));
	memset(&range.max_addr, 0, sizeof(range.max_addr));
	range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
	range.min_addr.in6 = *addr;
	range.max_addr.in6 = *addr;
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
	range.min_addr.in6 = *addr;
	range.max_addr.in6 = *addr;
	range.min_proto.all = man_proto;
	range.max_proto.all = man_proto;
	memset(&range.base_proto, 0, sizeof(range.base_proto));
	return nf_nat_setup_info(ct, &range, NF_NAT_MANIP_DST);
#endif
}
#endif
