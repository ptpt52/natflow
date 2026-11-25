/* SPDX-License-Identifier: GPL-2.0-or-later */
/* ZTE NPPT adapter, included by natflow_async.h. */
#ifndef _NATFLOW_ZTE_H_
#define _NATFLOW_ZTE_H_

#define natflow_async_tuple zte_nppt_natflow_tuple
#define natflow_async_stats zte_nppt_natflow_stats
#define natflow_async_event zte_nppt_natflow_event
#define NATFLOW_ASYNC_READY ZTE_NPPT_NATFLOW_READY
#define NATFLOW_ASYNC_STATS ZTE_NPPT_NATFLOW_STATS
#define NATFLOW_ASYNC_RELEASE ZTE_NPPT_NATFLOW_RELEASE

struct natflow_async_request {
	struct zte_nppt_natflow_request native;
	int ppp_ifindex[2];
};

struct natflow_async_backend_ticket {
	struct natflow_async_ticket common;
	natflow_fakeuser_t *user;
	unsigned long accounted_at;
	struct zte_nppt_natflow_path path[2];
	int ppp_ifindex[2];
	struct ethhdr eth[2];
	struct net_device *dev[2];
};

static const struct zte_nppt_natflow_api *natflow_zte_api;
static atomic_t natflow_zte_policy_writers = ATOMIC_INIT(0);

/* Hold the provider while it can still deliver callbacks into natflow. */
static void natflow_async_backend_bind(void)
{
	const struct zte_nppt_natflow_api *api = symbol_get(zte_nppt_natflow_api);

	if (!api)
		return;
	if (api->version != ZTE_NPPT_NATFLOW_API_VERSION || !api->submit || !api->flush) {
		symbol_put(zte_nppt_natflow_api);
		return;
	}
	natflow_zte_api = api;
}

static void natflow_async_backend_unbind(void)
{
	if (!natflow_zte_api)
		return;

	natflow_zte_api = NULL;
	symbol_put(zte_nppt_natflow_api);
}

static int natflow_async_drain(bool disconnect)
{
	if (natflow_async_slots && natflow_zte_api)
		return natflow_zte_api->flush(disconnect);
	return 0;
}

int natflow_zte_policy_begin(void)
{
	int ret;

	atomic_inc_return(&natflow_zte_policy_writers);
	/* A submitter that already passed CHECK must finish before the drain. */
	synchronize_net();
	ret = natflow_async_drain(false);
	if (ret)
		atomic_dec_return(&natflow_zte_policy_writers);
	return ret;
}

void natflow_zte_policy_end(void)
{
	natflow_update_magic(0);
	atomic_dec_return(&natflow_zte_policy_writers);
}

static bool natflow_async_backend_allowed(struct nf_conn *ct)
{
	natflow_fakeuser_t *user = natflow_user_get(ct);

	return natflow_zte_api && !atomic_read_acquire(&natflow_zte_policy_writers) &&
	       net_eq(nf_ct_net(ct), &init_net) && !nf_ct_is_expired(ct) &&
	       (ct->status & IPS_NAT_MASK) && (ct->status & IPS_ASSURED) &&
	       (ct->status & NATFLOW_USER_BYPASS) &&
	       !(ct->status & (IPS_NATFLOW_CT_DROP | IPS_HELPER | IPS_SEQ_ADJUST |
	                       IPS_OFFLOAD | IPS_FIXED_TIMEOUT)) &&
	       nf_conn_acct_find(ct) && natflow_user_zte_allowed(user);
}

static bool natflow_async_backend_session_valid(const struct natflow_async_backend_ticket *ticket)
{
	return natflow_user_get(ticket->common.ct) == ticket->user;
}

/* Validate the current PPP channel so redial invalidates the saved header.
 * Called under the packet or driver's RCU read lock.
 */
static bool natflow_zte_pppoe(const struct net_device *lower, const struct ethhdr *eth,
                              const struct zte_nppt_natflow_path *path, int ifindex)
{
	struct net_device *ppp = dev_get_by_index_rcu(&init_net, ifindex);
	struct net_device_path_ctx ctx = { .dev = ppp };
	struct net_device_path node = {};

	if (!ppp || ppp->type != ARPHRD_PPP || !netif_running(ppp) ||
	        !netif_carrier_ok(ppp) || READ_ONCE(ppp->mtu) < path->mtu ||
	        !ppp->netdev_ops->ndo_fill_forward_path ||
	        ppp->netdev_ops->ndo_fill_forward_path(&ctx, &node))
		return false;

	/* Ingress learns the wire device and MAC before macvlan RX demux. */
	if (ctx.dev != lower &&
	        (!ctx.dev || !netif_is_macvlan(ctx.dev) || !netif_running(ctx.dev) ||
	         get_macvlan_real_dev(ctx.dev) != lower ||
	         !ether_addr_equal(ctx.dev->dev_addr, eth->h_source)))
		return false;

	return node.type == DEV_PATH_PPPOE &&
	       node.encap.proto == htons(ETH_P_PPP_SES) &&
	       node.encap.id == path->pppoe_sid &&
	       ether_addr_equal(node.encap.h_dest, eth->h_dest);
}

static bool natflow_zte_path(const natflow_t *nf, int d, struct ethhdr *eth,
                             struct zte_nppt_natflow_path *path, int *ppp_ifindex)
{
	const natflow_route_t *route = &nf->rroute[d];
	const struct net_device *dev = READ_ONCE(route->outdev);

	path->mtu = READ_ONCE(route->mtu);
	*ppp_ifindex = 0;
	if (!dev || dev->type != ARPHRD_ETHER ||
	        path->mtu < ETH_MIN_MTU || path->mtu > ETH_DATA_LEN ||
	        !natflow_async_decode_l2(route, eth, &path->vlan_id, &path->pppoe_sid))
		return false;
	if (!path->pppoe_sid)
		return true;
	if (path->vlan_id || path->mtu + PPPOE_SES_HLEN > ETH_DATA_LEN)
		return false;

	*ppp_ifindex = READ_ONCE(nf->ppp[d]);
	return natflow_zte_pppoe(dev, eth, path, *ppp_ifindex);
}

static bool natflow_async_backend_path_valid(const struct natflow_async_backend_ticket *ticket,
        const natflow_t *nf, int d)
{
	const struct zte_nppt_natflow_path *old = &ticket->path[d];
	struct zte_nppt_natflow_path path;
	struct ethhdr eth;
	int ppp_ifindex;

	return READ_ONCE(nf->rroute[d].outdev) == ticket->dev[d] &&
	       natflow_zte_path(nf, d, &eth, &path, &ppp_ifindex) &&
	       path.vlan_id == old->vlan_id && path.pppoe_sid == old->pppoe_sid &&
	       path.mtu == old->mtu && ppp_ifindex == ticket->ppp_ifindex[d] &&
	       !memcmp(&eth, &ticket->eth[d], ETH_HLEN);
}

static bool natflow_async_backend_load_path(struct natflow_async_request *req,
        const natflow_t *nf, int d)
{
	return natflow_zte_path(nf, d, &req->native.eth[d], &req->native.path[d],
	                        &req->ppp_ifindex[d]);
}

static bool natflow_async_backend_save(struct natflow_async_backend_ticket *ticket,
                                       const struct natflow_async_request *req,
                                       const natflow_t *nf)
{
	int d;

	ticket->user = natflow_user_get(ticket->common.ct);
	if (!natflow_user_zte_allowed(ticket->user))
		return false;
	nf_conntrack_get(&ticket->user->ct_general);
	ticket->accounted_at = jiffies;
	for (d = 0; d < 2; d++) {
		ticket->path[d] = req->native.path[d];
		ticket->ppp_ifindex[d] = req->ppp_ifindex[d];
		ticket->eth[d] = req->native.eth[d];
		ticket->dev[d] = nf->rroute[d].outdev;
	}
	return true;
}

static void natflow_async_backend_put(struct natflow_async_backend_ticket *ticket)
{
	nf_ct_put(ticket->user);
}

static void natflow_zte_account(struct natflow_async_backend_ticket *ticket,
                                const struct natflow_async_stats *stats)
{
	struct nf_conn_acct *ct_acct = nf_conn_acct_find(ticket->common.ct);
	struct nf_conn_acct *user_acct = nf_conn_acct_find(ticket->user);
	struct fakeuser_data_t *fud = natflow_fakeuser_data(ticket->user);
	natflow_t *nf = natflow_session_get(ticket->common.ct);
	unsigned int now = jiffies;
	bool ppp_valid = false;
	int d;

	for (d = 0; nf && d < 2; d++) {
		if (ticket->ppp_ifindex[d] && natflow_async_backend_path_valid(ticket, nf, d))
			ppp_valid = true;
	}

	for (d = 0; d < 2; d++) {
		atomic_t *speed_time, *speed_bytes, *speed_packets;
		unsigned int last, bin, old_bin, delta;
		int up;

		if (!stats->packets[d])
			continue;
		if (ppp_valid)
			natflow_ppp_account(nf, d, stats->bytes[d], stats->packets[d],
			                    ticket->common.magic & NATFLOW_PATH_MAGIC_MASK, 0);
		up = ticket->user->tuplehash[0].tuple.src.u3.ip ==
		     ticket->common.ct->tuplehash[d].tuple.src.u3.ip;
		atomic64_add(stats->bytes[d], &ct_acct->counter[d].bytes);
		atomic64_add(stats->packets[d], &ct_acct->counter[d].packets);
		atomic64_add(stats->bytes[d], &user_acct->counter[up].bytes);
		atomic64_add(stats->packets[d], &user_acct->counter[up].packets);
		speed_time = up ? &fud->tx_speed_jiffies : &fud->rx_speed_jiffies;
		speed_bytes = up ? fud->tx_speed_bytes : fud->rx_speed_bytes;
		speed_packets = up ? fud->tx_speed_packets : fud->rx_speed_packets;
		last = atomic_xchg(speed_time, now);
		bin = now / (2 * HZ) % 4;
		old_bin = last / (2 * HZ) % 4;
		delta = now - last;
		if (delta >= 8 * HZ) {
			int i;

			for (i = 0; i < 4; i++) {
				atomic_set(&speed_bytes[i], 0);
				atomic_set(&speed_packets[i], 0);
			}
		} else {
			while (old_bin != bin) {
				old_bin = (old_bin + 1) % 4;
				atomic_set(&speed_bytes[old_bin], 0);
				atomic_set(&speed_packets[old_bin], 0);
			}
		}
		atomic_add(stats->bytes[d], &speed_bytes[bin]);
		atomic_add(stats->packets[d], &speed_packets[bin]);
	}
}

static void natflow_async_backend_account(struct natflow_async_backend_ticket *ticket,
        enum natflow_async_event event,
        const struct natflow_async_stats *stats)
{
	if (event == NATFLOW_ASYNC_STATS || event == NATFLOW_ASYNC_RELEASE)
		natflow_zte_account(ticket, stats);
	if (event == NATFLOW_ASYNC_RELEASE && atomic_read_acquire(&natflow_zte_policy_writers))
		clear_bit(NATFLOW_USER_BYPASS_BIT, &ticket->common.ct->status);
}

static int natflow_async_backend_keepalive(struct natflow_async_backend_ticket *backend,
        const struct natflow_async_stats *stats)
{
	const struct natflow_async_ticket *ticket = &backend->common;
	unsigned long now = jiffies;
	int d;

	for (d = 0; d < 2; d++)
		WRITE_ONCE(natflow_fast_nat_table[ticket->hash[d]].jiffies, now);
	natflow_update_ct_timeout(ticket->ct, now - backend->accounted_at);
	backend->accounted_at = now;
	natflow_user_keepalive(backend->user);
	return 0;
}

static int natflow_async_backend_submit(struct natflow_async_request *req)
{
	return natflow_zte_api->submit(&req->native);
}

#endif
