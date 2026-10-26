/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Included by natflow_path.c after its keepalive implementation. */
#ifndef _NATFLOW_QCA_H_
#define _NATFLOW_QCA_H_

#if NATFLOW_HAVE_QCA_PPE
struct natflow_qca_ticket {
	struct nf_conn *ct;
	u32 magic;
	u32 hash[2];
	u64 generation[2];
	bool invalid;
	bool ready;
};

struct natflow_qca_slot {
	struct natflow_qca_ticket *owner;
	u64 generation;
	unsigned long retry;
};

static struct natflow_qca_slot *natflow_qca_slots;
static DEFINE_SPINLOCK(natflow_qca_lock);

/* The publication lock is only taken while learning/replacing a software
 * slot, never by packet forwarding. Old async requests retain their own ct
 * reference until RELEASE, but can no longer act on this slot after begin.
 */
static void natflow_qca_write_begin(u32 hash)
{
	struct natflow_qca_ticket *old;
	int d;

	spin_lock_bh(&natflow_qca_lock);
	natflow_qca_slots[hash].generation++;
	natflow_qca_slots[hash].retry = 0;
	old = natflow_qca_slots[hash].owner;
	if (!old)
		return;
	old->invalid = true;
	for (d = 0; d < 2; d++)
		if (natflow_qca_slots[old->hash[d]].owner == old)
			natflow_qca_slots[old->hash[d]].owner = NULL;
}

static void natflow_qca_write_end(void)
{
	spin_unlock_bh(&natflow_qca_lock);
}

static bool natflow_qca_match(const natflow_fastnat_node_t *nfn,
                              const struct nf_conntrack_tuple *tuple)
{
	return NFN_L3NUM_DEC(nfn->flags) != AF_INET6 &&
	       nfn->saddr == tuple->src.u3.ip && nfn->daddr == tuple->dst.u3.ip &&
	       nfn->source == tuple->src.u.all && nfn->dest == tuple->dst.u.all &&
	       NFN_PROTO_DEC(nfn->flags) == tuple->dst.protonum;
}

static int natflow_qca_find(const struct nf_conntrack_tuple *tuple)
{
	u32 base = natflow_hash_v4(tuple->src.u3.ip, tuple->dst.u3.ip,
	                           tuple->src.u.all, tuple->dst.u.all);
	int way;

	for (way = 0; way < NATFLOW_FASTNAT_TABLE_WAYS; way++)
		if (natflow_qca_match(&natflow_fast_nat_table[base + way], tuple))
			return base + way;
	return -ENOENT;
}

static bool natflow_qca_allowed(struct nf_conn *ct, natflow_t *nf)
{
	natflow_fakeuser_t *user;
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
	user = natflow_user_get(ct);
	return !user || natflow_fakeuser_data(user)->auth_status != AUTH_BLOCK;
}

static bool natflow_qca_valid(struct natflow_qca_ticket *ticket)
{
	natflow_t *nf = natflow_session_get(ticket->ct);
	int d;

	if (ticket->invalid ||
	        ticket->magic != (u32)atomic_read_acquire(&natflow_path_magic) ||
	        !natflow_qca_allowed(ticket->ct, nf))
		return false;
	for (d = 0; d < 2; d++) {
		u32 hash = ticket->hash[d];
		natflow_fastnat_node_t *nfn = &natflow_fast_nat_table[hash];

		if (natflow_qca_slots[hash].owner != ticket ||
		        natflow_qca_slots[hash].generation != ticket->generation[d] ||
		        !natflow_qca_match(nfn, &ticket->ct->tuplehash[d].tuple) ||
		        nfn->magic != (ticket->magic & NATFLOW_PATH_MAGIC_MASK) ||
		        ulongmindiff(jiffies, nfn->jiffies) >= NATFLOW_FF_TIMEOUT_LOW)
			return false;
	}
	return true;
}

static int natflow_qca_notify(void *context, enum qca_ppe_natflow_event event,
                              const struct qca_ppe_natflow_stats *stats)
{
	struct natflow_qca_ticket *ticket = context;
	int d, ret = 0;

	spin_lock_bh(&natflow_qca_lock);
	if (event == QCA_PPE_NATFLOW_RELEASE) {
		for (d = 0; d < 2; d++) {
			struct natflow_qca_slot *slot = &natflow_qca_slots[ticket->hash[d]];

			if (slot->owner == ticket) {
				slot->owner = NULL;
				slot->retry = jiffies + 8 * HZ;
			}
		}
		spin_unlock_bh(&natflow_qca_lock);
		nf_ct_put(ticket->ct);
		kfree(ticket);
		return 0;
	}
	if (!natflow_qca_valid(ticket)) {
		ret = -ESTALE;
		goto out;
	}
	if (event == QCA_PPE_NATFLOW_READY)
		ticket->ready = true;
	if (event == QCA_PPE_NATFLOW_STATS) {
		for (d = 0; d < 2; d++) {
			if (!(stats->active & BIT(d)))
				continue;
			/* PPE credits bridge/VLAN statistics, natflow credits ct
			 * and fakeuser. Each direction uses its own SOFTWARE hash.
			 */
			ret = natflow_offload_keepalive_ex(ticket->hash[d],
			                                   stats->bytes[d], stats->packets[d], NULL, NULL, 2,
			                                   jiffies, 0, ticket->ct);
			if (ret)
				break;
		}
	}
out:
	if (ret)
		ticket->invalid = true;
	spin_unlock_bh(&natflow_qca_lock);
	return ret;
}

static void natflow_qca_try(struct nf_conn *ct, natflow_t *nf)
{
	struct qca_ppe_natflow_request req = {};
	struct qca_ppe_natflow_stats failed = {};
	struct natflow_qca_ticket *ticket;
	int hash[2], d, ret;

	if (!natflow_qca_allowed(ct, nf) ||
	        ct->tuplehash[0].tuple.src.l3num != AF_INET ||
	        (ct->tuplehash[0].tuple.dst.protonum != IPPROTO_TCP &&
	         ct->tuplehash[0].tuple.dst.protonum != IPPROTO_UDP) ||
	        nf_ct_zone_id(nf_ct_zone(ct), IP_CT_DIR_ORIGINAL) ||
	        nf_ct_zone_id(nf_ct_zone(ct), IP_CT_DIR_REPLY))
		return;
	/* First version: untagged, routed Ethernet in both directions. */
	for (d = 0; d < 2; d++) {
		if (nf->rroute[d].vlan_present ||
		        nf->rroute[d].l2_head_len != ETH_HLEN ||
		        !nf->rroute[d].outdev ||
		        nf->rroute[d].outdev->type != ARPHRD_ETHER)
			return;
	}
	spin_lock_bh(&natflow_qca_lock);
	for (d = 0; d < 2; d++) {
		hash[d] = natflow_qca_find(&ct->tuplehash[d].tuple);
		if (hash[d] < 0 || natflow_qca_slots[hash[d]].owner ||
		        time_before(jiffies, natflow_qca_slots[hash[d]].retry))
			goto unlock;
	}
	if (hash[0] == hash[1])
		goto unlock;
	ticket = kzalloc(sizeof(*ticket), GFP_ATOMIC);
	if (!ticket)
		goto unlock;
	ticket->ct = ct;
	nf_conntrack_get(&ct->ct_general);
	ticket->magic = atomic_read_acquire(&natflow_path_magic);
	for (d = 0; d < 2; d++) {
		const struct nf_conntrack_tuple *tuple = &ct->tuplehash[d].tuple;

		ticket->hash[d] = hash[d];
		ticket->generation[d] = natflow_qca_slots[hash[d]].generation;
		natflow_qca_slots[hash[d]].owner = ticket;
		req.tuple[d] = (struct qca_ppe_natflow_tuple) {
			.src = tuple->src.u3.ip, .dst = tuple->dst.u3.ip,
			.sport = tuple->src.u.all, .dport = tuple->dst.u.all,
			.proto = tuple->dst.protonum,
		};
		req.dev[d] = nf->rroute[!d].outdev;
		memcpy(&req.eth[d], nf->rroute[d].l2_head, ETH_HLEN);
	}
	req.owner = &natflow_qca_slots;
	req.context = ticket;
	req.notify = natflow_qca_notify;
	spin_unlock_bh(&natflow_qca_lock);
	ret = qca_ppe_natflow_submit(&req);
	if (ret) {
		failed.error = ret;
		natflow_qca_notify(ticket, QCA_PPE_NATFLOW_RELEASE, &failed);
	}
	return;
unlock:
	spin_unlock_bh(&natflow_qca_lock);
}

static void natflow_qca_stop(void)
{
	if (natflow_qca_slots)
		qca_ppe_natflow_flush(&natflow_qca_slots);
}
#else
static inline void natflow_qca_write_begin(u32 hash) { }
static inline void natflow_qca_write_end(void) { }
static inline void natflow_qca_try(struct nf_conn *ct, natflow_t *nf) { }
#endif
#endif
