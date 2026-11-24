/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Qualcomm PPE adapter, included by natflow_async.h. */
#ifndef _NATFLOW_QCA_H_
#define _NATFLOW_QCA_H_

#define natflow_async_tuple qca_ppe_natflow_tuple
#define natflow_async_stats qca_ppe_natflow_stats
#define natflow_async_event qca_ppe_natflow_event
#define NATFLOW_ASYNC_READY QCA_PPE_NATFLOW_READY
#define NATFLOW_ASYNC_STATS QCA_PPE_NATFLOW_STATS
#define NATFLOW_ASYNC_RELEASE QCA_PPE_NATFLOW_RELEASE

struct natflow_async_request {
	struct qca_ppe_natflow_request native;
#if QCA_PPE_NATFLOW_API_VERSION >= 2
	struct qca_ppe_natflow_path path[2];
#endif
};

struct natflow_async_backend_ticket {
	struct natflow_async_ticket common;
#if QCA_PPE_NATFLOW_API_VERSION >= 2
	struct qca_ppe_natflow_path path[2];
	struct ethhdr eth[2];
	struct net_device *dev[2];
#endif
};

static bool natflow_async_backend_allowed(struct nf_conn *ct)
{
	natflow_fakeuser_t *user = natflow_user_get(ct);

	return !user || natflow_fakeuser_data(user)->auth_status != AUTH_BLOCK;
}

static bool natflow_async_backend_session_valid(const struct natflow_async_backend_ticket *ticket)
{
	return true;
}

#if QCA_PPE_NATFLOW_API_VERSION >= 2
static bool natflow_qca_path(const natflow_route_t *route, struct ethhdr *eth,
                             struct qca_ppe_natflow_path *path)
{
	*path = (struct qca_ppe_natflow_path) {};
	if (!route->outdev || route->outdev->type != ARPHRD_ETHER || route->mtu < 68 ||
	        !natflow_async_decode_l2(route, eth, &path->vlan_id, &path->pppoe_sid))
		return false;
	path->mtu = route->mtu;
	if (path->vlan_id) {
		path->flags |= QCA_PPE_NATFLOW_VLAN;
		path->vlan_proto = htons(ETH_P_8021Q);
	}
	if (path->pppoe_sid)
		path->flags |= QCA_PPE_NATFLOW_PPPOE;
	return true;
}

static bool natflow_async_backend_path_valid(const struct natflow_async_backend_ticket *ticket,
        const natflow_t *nf, int d)
{
	struct qca_ppe_natflow_path path;
	const struct qca_ppe_natflow_path *old = &ticket->path[d];
	struct ethhdr eth;

	return nf->rroute[d].outdev == ticket->dev[d] &&
	       natflow_qca_path(&nf->rroute[d], &eth, &path) &&
	       path.flags == old->flags && path.vlan_id == old->vlan_id &&
	       path.vlan_proto == old->vlan_proto && path.pppoe_sid == old->pppoe_sid &&
	       path.mtu == old->mtu && !memcmp(&eth, &ticket->eth[d], ETH_HLEN);
}

#else
static bool natflow_async_backend_path_valid(const struct natflow_async_backend_ticket *ticket,
        const natflow_t *nf, int d)
{
	return true;
}
#endif

static bool natflow_async_backend_load_path(struct natflow_async_request *req,
        const natflow_t *nf, int d)
{
	const natflow_route_t *route = &nf->rroute[d];

#if QCA_PPE_NATFLOW_API_VERSION >= 2
	return natflow_qca_path(route, &req->native.eth[d], &req->path[d]);
#else
	/* API v1 supports only unencapsulated Ethernet. */
	if (route->vlan_present || route->l2_head_len != ETH_HLEN ||
	        !route->outdev || route->outdev->type != ARPHRD_ETHER)
		return false;
	memcpy(&req->native.eth[d], route->l2_head, ETH_HLEN);
	return true;
#endif
}

static bool natflow_async_backend_save(struct natflow_async_backend_ticket *ticket,
                                       const struct natflow_async_request *req,
                                       const natflow_t *nf)
{
#if QCA_PPE_NATFLOW_API_VERSION >= 2
	int d;

	for (d = 0; d < 2; d++) {
		ticket->path[d] = req->path[d];
		ticket->eth[d] = req->native.eth[d];
		ticket->dev[d] = nf->rroute[d].outdev;
	}
#endif
	return true;
}

static void natflow_async_backend_put(struct natflow_async_backend_ticket *ticket) { }

static void natflow_async_backend_account(struct natflow_async_backend_ticket *ticket,
        enum natflow_async_event event,
        const struct natflow_async_stats *stats) { }

static int natflow_async_backend_keepalive(struct natflow_async_backend_ticket *backend,
        const struct natflow_async_stats *stats)
{
	const struct natflow_async_ticket *ticket = &backend->common;
	int d, ret;

	for (d = 0; d < 2; d++) {
		if (!(stats->active & BIT(d)))
			continue;
		/* PPE credits bridge/VLAN statistics. Natflow credits ct, user
		 * and PPP using the software hash for each direction.
		 */
		ret = natflow_offload_keepalive_ex(ticket->hash[d],
		                                   stats->bytes[d], stats->packets[d], NULL, NULL, 2,
		                                   jiffies, 0, ticket->ct);
		if (ret)
			return ret;
	}
	return 0;
}

static int natflow_async_backend_submit(struct natflow_async_request *req)
{
	req->native.owner = &natflow_async_slots;
#if QCA_PPE_NATFLOW_API_VERSION >= 2
	return qca_ppe_natflow_submit_encap(&req->native, req->path);
#else
	return qca_ppe_natflow_submit(&req->native);
#endif
}

static void natflow_async_backend_bind(void) { }
static void natflow_async_backend_unbind(void) { }

static int natflow_async_drain(bool disconnect)
{
	if (natflow_async_slots)
		qca_ppe_natflow_flush(&natflow_async_slots);
	return 0;
}

#endif
