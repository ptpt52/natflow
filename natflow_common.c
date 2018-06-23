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
#include <net/netfilter/nf_nat_core.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_set.h>
#include "natflow_common.h"

unsigned int debug = 0;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, "Debug level (0=none,1=error,2=warn,4=info,8=debug,16=fixme,...,31=all) default=0");

unsigned int disabled = 1;

#define __ALIGN_64BITS 8

int natflow_session_init(struct nf_conn *ct, gfp_t gfp)
{
	struct nat_key_t *nk = NULL;
	struct natflow_t *nf;
	struct nf_ct_ext *old, *new;
	unsigned int newoff, newlen = 0;
	size_t alloc_size;
	size_t var_alloc_len = ALIGN(sizeof(struct natflow_t), __ALIGN_64BITS);

	if (natflow_session_get(ct) != NULL) {
		return 0;
	}

	if (nf_ct_is_confirmed(ct)) {
		return -1;
	}

	old = ct->ext;
	if (!old) {
		newoff = ALIGN(sizeof(struct nf_ct_ext), __ALIGN_64BITS);
		newlen = ALIGN(newoff + var_alloc_len, __ALIGN_64BITS) + ALIGN(sizeof(struct nat_key_t), __ALIGN_64BITS);
		alloc_size = ALIGN(newlen, __ALIGN_64BITS);

		new = kzalloc(alloc_size, gfp);
		if (!new) {
			return -1;
		}
		new->len = newoff;
		ct->ext = new;
	} else {
		newoff = ALIGN(old->len, __ALIGN_64BITS);
		newlen = ALIGN(newoff + var_alloc_len, __ALIGN_64BITS) + ALIGN(sizeof(struct nat_key_t), __ALIGN_64BITS);
		alloc_size = ALIGN(newlen, __ALIGN_64BITS);

		new = __krealloc(old, alloc_size, gfp);
		if (!new) {
			return -1;
		}
		new->len = newoff;
		memset((void *)new + newoff, 0, newlen - newoff);

		if (new != old) {
			kfree_rcu(old, rcu);
			rcu_assign_pointer(ct->ext, new);
		}
	}

	nk = (struct nat_key_t *)((void *)ct->ext + ct->ext->len);
	nk->magic = NATFLOW_MAGIC;
	nf = (struct natflow_t *)((void *)nk + ALIGN(sizeof(struct nat_key_t), __ALIGN_64BITS));

	return 0;
}

struct natflow_t *natflow_session_get(struct nf_conn *ct)
{
	struct nat_key_t *nk;
	struct natflow_t *nf;

	if (!ct->ext) {
		return NULL;
	}

	nk = (struct nat_key_t *)((void *)ct->ext + ct->ext->len);
	if (nk->magic != NATFLOW_MAGIC) {
		return NULL;
	}

	nf = (struct natflow_t *)((void *)nk + ALIGN(sizeof(struct nat_key_t), __ALIGN_64BITS));

	return nf;
}

const char *const hooknames[] = {
	[NF_INET_PRE_ROUTING] = "PRE",
	[NF_INET_LOCAL_IN] = "IN",
	[NF_INET_FORWARD] = "FD",
	[NF_INET_LOCAL_OUT] = "OUT",
	[NF_INET_POST_ROUTING] = "POST",
};
