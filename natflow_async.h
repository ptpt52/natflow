/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Asynchronous offload client, included after the path keepalive code. */
#ifndef _NATFLOW_ASYNC_H_
#define _NATFLOW_ASYNC_H_

#if NATFLOW_HAVE_ASYNC_HW_OFFLOAD
struct natflow_async_ticket {
	struct nf_conn *ct;
	u32 magic;
	u32 hash[2];
	u64 generation[2];
	bool invalid;
	bool ready;
};

struct natflow_async_slot {
	struct natflow_async_ticket *owner;
	u64 generation;
	unsigned long retry;
};

static struct natflow_async_slot *natflow_async_slots;
static DEFINE_SPINLOCK(natflow_async_lock);

/* The publication lock is only taken while learning/replacing a software
 * slot, never by packet forwarding. Old async requests retain their own ct
 * reference until RELEASE, but can no longer act on this slot after begin.
 */
static void natflow_async_write_begin(u32 hash)
{
	struct natflow_async_ticket *old;
	int d;

	spin_lock_bh(&natflow_async_lock);
	natflow_async_slots[hash].generation++;
	natflow_async_slots[hash].retry = 0;
	old = natflow_async_slots[hash].owner;
	if (!old)
		return;
	old->invalid = true;
	for (d = 0; d < 2; d++)
		if (natflow_async_slots[old->hash[d]].owner == old)
			natflow_async_slots[old->hash[d]].owner = NULL;
}

static void natflow_async_write_end(void)
{
	spin_unlock_bh(&natflow_async_lock);
}

static bool natflow_async_match(const natflow_fastnat_node_t *nfn,
                                const struct nf_conntrack_tuple *tuple)
{
	return NFN_L3NUM_DEC(nfn->flags) != AF_INET6 &&
	       nfn->saddr == tuple->src.u3.ip && nfn->daddr == tuple->dst.u3.ip &&
	       nfn->source == tuple->src.u.all && nfn->dest == tuple->dst.u.all &&
	       NFN_PROTO_DEC(nfn->flags) == tuple->dst.protonum;
}

static int natflow_async_find(const struct nf_conntrack_tuple *tuple)
{
	u32 base = natflow_hash_v4(tuple->src.u3.ip, tuple->dst.u3.ip,
	                           tuple->src.u.all, tuple->dst.u.all);
	int way;

	for (way = 0; way < NATFLOW_FASTNAT_TABLE_WAYS; way++)
		if (natflow_async_match(&natflow_fast_nat_table[base + way], tuple))
			return base + way;
	return -ENOENT;
}

#if NATFLOW_HAVE_ZTE_NPPT || (NATFLOW_HAVE_QCA_PPE && QCA_PPE_NATFLOW_API_VERSION >= 2)
/* The learner supplies one metadata VLAN plus an optional on-wire PPPoE header. */
static bool natflow_async_decode_l2(const natflow_route_t *route,
                                    struct ethhdr *eth, u16 *vid, u16 *sid)
{
	u16 len = READ_ONCE(route->l2_head_len);

	if (len != ETH_HLEN && len != ETH_HLEN + PPPOE_SES_HLEN)
		return false;
	memcpy(eth, route->l2_head, ETH_HLEN);
	*vid = 0;
	*sid = 0;
	if (route->vlan_present) {
		if (route->vlan_proto != FF_ETH_P_8021Q ||
		        !route->vlan_tci || route->vlan_tci >= VLAN_VID_MASK)
			return false;
		*vid = route->vlan_tci;
	}
	if (len == ETH_HLEN + PPPOE_SES_HLEN) {
		struct pppoe_hdr ph;
		__be16 proto;

		memcpy(&ph, route->l2_head + ETH_HLEN, sizeof(ph));
		memcpy(&proto, route->l2_head + ETH_HLEN + sizeof(ph), sizeof(proto));
		if (eth->h_proto != htons(ETH_P_PPP_SES) ||
		        ph.ver != 1 || ph.type != 1 || ph.code ||
		        !ph.sid || ph.sid == htons(0xffff) || proto != htons(PPP_IP))
			return false;
		*sid = ntohs(ph.sid);
		eth->h_proto = htons(ETH_P_IP);
	}
	return eth->h_proto == htons(ETH_P_IP);
}
#endif

/* The selected adapter prepares requests and owns its extra references.
 * The shared client owns both software slots and the conntrack reference.
 */
#if NATFLOW_HAVE_ZTE_NPPT
#include "natflow_zte.h"
#else
#include "natflow_qca.h"
#endif

static bool natflow_async_allowed(struct nf_conn *ct, natflow_t *nf)
{
	u32 magic = atomic_read_acquire(&natflow_path_magic);

	if (READ_ONCE(disabled) || !READ_ONCE(hwnat) || !nf ||
	        test_bit(IPS_DYING_BIT, &ct->status) ||
	        (ct->status & IPS_NATFLOW_FF_STOP) ||
	        (nf->status & (NF_FF_BUSY_USE | NF_FF_TOKEN_CTRL | NF_FF_BRIDGE)) ||
	        READ_ONCE(nf->magic) != (magic & NATFLOW_PATH_MAGIC_MASK))
		return false;
	if (ct->tuplehash[0].tuple.dst.protonum == IPPROTO_TCP &&
	        ct->proto.tcp.state != TCP_CONNTRACK_ESTABLISHED)
		return false;
	return natflow_async_backend_allowed(ct);
}

static bool natflow_async_valid(struct natflow_async_backend_ticket *backend)
{
	struct natflow_async_ticket *ticket = &backend->common;
	natflow_t *nf = natflow_session_get(ticket->ct);
	int d;

	if (ticket->invalid ||
	        ticket->magic != (u32)atomic_read_acquire(&natflow_path_magic) ||
	        !natflow_async_allowed(ticket->ct, nf) ||
	        !natflow_async_backend_session_valid(backend))
		return false;

	for (d = 0; d < 2; d++) {
		u32 hash = ticket->hash[d];
		natflow_fastnat_node_t *nfn = &natflow_fast_nat_table[hash];

		if (natflow_async_slots[hash].owner != ticket ||
		        natflow_async_slots[hash].generation != ticket->generation[d] ||
		        !natflow_async_match(nfn, &ticket->ct->tuplehash[d].tuple) ||
		        nfn->magic != (ticket->magic & NATFLOW_PATH_MAGIC_MASK) ||
		        ulongmindiff(jiffies, nfn->jiffies) >= NATFLOW_FF_TIMEOUT_LOW ||
		        !natflow_async_backend_path_valid(backend, nf, d))
			return false;
	}
	return true;
}

static int natflow_async_notify(void *context, enum natflow_async_event event,
                                const struct natflow_async_stats *stats)
{
	struct natflow_async_backend_ticket *backend = context;
	struct natflow_async_ticket *ticket = &backend->common;
	int d, ret = 0;

	spin_lock_bh(&natflow_async_lock);
	/* A final hardware delta can arrive after the software slots have moved. */
	natflow_async_backend_account(backend, event, stats);
	if (event == NATFLOW_ASYNC_RELEASE) {
		for (d = 0; d < 2; d++) {
			struct natflow_async_slot *slot = &natflow_async_slots[ticket->hash[d]];

			if (slot->owner == ticket) {
				slot->owner = NULL;
				slot->retry = jiffies + 8 * HZ;
			}
		}
		spin_unlock_bh(&natflow_async_lock);
		natflow_async_backend_put(backend);
		nf_ct_put(ticket->ct);
		kfree(backend);
		return 0;
	}
	if (!natflow_async_valid(backend))
		ret = -ESTALE;
	else if (event == NATFLOW_ASYNC_READY)
		ticket->ready = true;
	else if (event == NATFLOW_ASYNC_STATS)
		ret = natflow_async_backend_keepalive(backend, stats);

	if (ret)
		ticket->invalid = true;
	spin_unlock_bh(&natflow_async_lock);
	return ret;
}

static void natflow_async_try(struct nf_conn *ct, natflow_t *nf)
{
	struct natflow_async_request req = {};
	const struct natflow_async_stats failed = {};
	struct natflow_async_backend_ticket *backend;
	struct natflow_async_ticket *ticket;
	int hash[2], d;

	if (!natflow_async_allowed(ct, nf) ||
	        ct->tuplehash[0].tuple.src.l3num != AF_INET ||
	        (ct->tuplehash[0].tuple.dst.protonum != IPPROTO_TCP &&
	         ct->tuplehash[0].tuple.dst.protonum != IPPROTO_UDP) ||
	        nf_ct_zone_id(nf_ct_zone(ct), IP_CT_DIR_ORIGINAL) ||
	        nf_ct_zone_id(nf_ct_zone(ct), IP_CT_DIR_REPLY))
		return;
	spin_lock_bh(&natflow_async_lock);
	for (d = 0; d < 2; d++) {
		if (!natflow_async_backend_load_path(&req, nf, d))
			goto unlock;
		hash[d] = natflow_async_find(&ct->tuplehash[d].tuple);
		if (hash[d] < 0 || natflow_async_slots[hash[d]].owner ||
		        time_before(jiffies, natflow_async_slots[hash[d]].retry))
			goto unlock;
	}
	if (hash[0] == hash[1])
		goto unlock;
	backend = kzalloc(sizeof(*backend), GFP_ATOMIC);
	if (!backend)
		goto unlock;
	ticket = &backend->common;
	ticket->ct = ct;
	if (!natflow_async_backend_save(backend, &req, nf)) {
		kfree(backend);
		goto unlock;
	}
	nf_conntrack_get(&ct->ct_general);
	ticket->magic = atomic_read_acquire(&natflow_path_magic);
	for (d = 0; d < 2; d++) {
		const struct nf_conntrack_tuple *tuple = &ct->tuplehash[d].tuple;

		ticket->hash[d] = hash[d];
		ticket->generation[d] = natflow_async_slots[hash[d]].generation;
		natflow_async_slots[hash[d]].owner = ticket;
		req.native.tuple[d] = (struct natflow_async_tuple) {
			.src = tuple->src.u3.ip, .dst = tuple->dst.u3.ip,
			.sport = tuple->src.u.all, .dport = tuple->dst.u.all,
			.proto = tuple->dst.protonum,
		};
		req.native.dev[d] = nf->rroute[!d].outdev;
	}
	req.native.context = backend;
	req.native.notify = natflow_async_notify;
	spin_unlock_bh(&natflow_async_lock);
	if (natflow_async_backend_submit(&req))
		natflow_async_notify(backend, NATFLOW_ASYNC_RELEASE, &failed);
	return;
unlock:
	spin_unlock_bh(&natflow_async_lock);
}

static int natflow_async_init(void)
{
	natflow_async_slots = kcalloc(NATFLOW_FASTNAT_TABLE_SIZE, sizeof(*natflow_async_slots), GFP_KERNEL);
	if (!natflow_async_slots)
		return -ENOMEM;
	natflow_async_backend_bind();
	return 0;
}

static void natflow_async_free(void)
{
	natflow_async_backend_unbind();
	kfree(natflow_async_slots);
	natflow_async_slots = NULL;
}
#else
static inline void natflow_async_write_begin(u32 hash) { }
static inline void natflow_async_write_end(void) { }
static inline void natflow_async_try(struct nf_conn *ct, natflow_t *nf) { }
#endif
#endif
