#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/rbtree.h>
#include <linux/skbuff.h>
#include <net/dst.h>
#include <net/sock.h>
#include "natflow_qos.h"
#include "natflow_common.h"

#if NATFLOW_HAVE_QOS_BUFFER
struct natflow_qos_packet {
	struct rb_node node;
	struct list_head list;
	struct sk_buff *skb;
	struct net_device *dev;
	struct net_device *physin;
	struct net_device *physout;
	struct net_device *bridge_dev;
	struct nf_hook_state state;
	nf_hookfn *hook;
	struct natflow_qos_stamp stamp;
	unsigned int memory;
};

static DEFINE_SPINLOCK(qos_queue_lock);
static struct rb_root qos_queue = RB_ROOT;
static struct hrtimer qos_timer;
static struct tasklet_struct qos_tasklet;
static struct natflow_qos_stats qos_stats;
static u32 qos_generation = 1;
static bool qos_stopping;

static bool qos_dev_ready(struct net_device *dev)
{
	return !dev || (netif_running(dev) && netif_device_present(dev));
}

static void qos_packet_free(struct natflow_qos_packet *p)
{
	if (p->skb)
		kfree_skb(p->skb);
	if (p->dev)
		dev_put(p->dev);
	if (p->hook) {
		if (p->state.in)
			dev_put(p->state.in);
		if (p->state.out)
			dev_put(p->state.out);
		if (p->physin)
			dev_put(p->physin);
		if (p->physout)
			dev_put(p->physout);
		if (p->bridge_dev)
			dev_put(p->bridge_dev);
		if (p->state.sk)
			sock_gen_put(p->state.sk);
		put_net(p->state.net);
	}
	kfree(p);
}

/* Re-find our hook in the current RCU snapshot; saved indices can go stale. */
static void qos_post_resume(struct natflow_qos_packet *p)
{
	const struct nf_hook_entries *entries = NULL;
	struct nf_hook_state *state = &p->state;
	unsigned int i;

	rcu_read_lock();
#if NATFLOW_NF_HOOKS_HAVE_FAMILY_ARRAYS
	switch (state->pf) {
	case NFPROTO_IPV4:
		entries = rcu_dereference(state->net->nf.hooks_ipv4[state->hook]);
		break;
	case NFPROTO_IPV6:
		entries = rcu_dereference(state->net->nf.hooks_ipv6[state->hook]);
		break;
#ifdef CONFIG_NETFILTER_FAMILY_BRIDGE
	case NFPROTO_BRIDGE:
		entries = rcu_dereference(state->net->nf.hooks_bridge[state->hook]);
		break;
#endif
	}
#else
	entries = rcu_dereference(state->net->nf.hooks[state->pf][state->hook]);
#endif
	if (entries) {
		for (i = 0; i < entries->num_hook_entries; i++) {
			if (entries->hooks[i].hook != p->hook)
				continue;
			if (nf_hook_slow(p->skb, state, entries, i + 1) == 1)
				state->okfn(state->net, state->sk, p->skb);
			p->skb = NULL;
			break;
		}
	}
	rcu_read_unlock();
}

/* Networking continuations run in softirq, never in the hrtimer hardirq. */
static void qos_dequeue(unsigned long unused)
{
	unsigned int budget = 128;

	while (budget--) {
		struct natflow_qos_packet *p;
		struct rb_node *first;
		bool drop;
		u64 now = ktime_get_ns();

		spin_lock_bh(&qos_queue_lock);
		first = rb_first(&qos_queue);
		if (!first) {
			spin_unlock_bh(&qos_queue_lock);
			return;
		}
		p = rb_entry(first, struct natflow_qos_packet, node);
		if (p->stamp.time > now) {
			if (!qos_stopping)
				hrtimer_start(&qos_timer, ns_to_ktime(p->stamp.time), HRTIMER_MODE_ABS);
			spin_unlock_bh(&qos_queue_lock);
			return;
		}
		rb_erase(first, &qos_queue);
		qos_stats.packets--;
		qos_stats.memory -= p->memory;
		drop = qos_stopping || p->stamp.generation != qos_generation;
		spin_unlock_bh(&qos_queue_lock);

		if (!qos_dev_ready(p->dev) || !qos_dev_ready(p->state.in) ||
		        !qos_dev_ready(p->state.out) || !qos_dev_ready(p->physin) ||
		        !qos_dev_ready(p->physout) || !qos_dev_ready(p->bridge_dev))
			drop = true;
		if (!drop) {
			if (p->hook) {
				qos_post_resume(p);
			} else {
				dev_queue_xmit(p->skb);
				p->skb = NULL;
			}
		}
		spin_lock_bh(&qos_queue_lock);
		if (p->skb)
			qos_stats.dropped++;
		else
			qos_stats.sent++;
		spin_unlock_bh(&qos_queue_lock);
		qos_packet_free(p);
	}
	/* Yield between batches even if there are more overdue packets. */
	spin_lock_bh(&qos_queue_lock);
	if (!qos_stopping && !RB_EMPTY_ROOT(&qos_queue))
		hrtimer_start(&qos_timer, ns_to_ktime(ktime_get_ns() + 1000), HRTIMER_MODE_ABS);
	spin_unlock_bh(&qos_queue_lock);
}

static enum hrtimer_restart qos_timer_fn(struct hrtimer *timer)
{
	tasklet_schedule(&qos_tasklet);
	return HRTIMER_NORESTART;
}

/* On success the queue owns skb. On failure the caller still owns it. */
static bool qos_enqueue(struct sk_buff *skb, const struct nf_hook_state *state,
                        nf_hookfn *hook, const struct natflow_qos_stamp *stamp)
{
	struct natflow_qos_packet *p;
	struct rb_node **link, *parent = NULL;
	bool had_dst = skb_dst(skb) != NULL;
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	struct dst_entry *dst;
#endif

	if (skb->truesize > NATFLOW_QOS_QUEUE_MEMORY - sizeof(*p))
		goto failed;
	p = kzalloc(sizeof(*p), GFP_ATOMIC);
	if (!p)
		goto failed;
	/* Noref routes must survive the caller's RCU read-side critical section. */
	skb_dst_force(skb);
	if (had_dst && !skb_dst(skb))
		goto free_packet;
	p->stamp = *stamp;
	p->memory = skb->truesize + sizeof(*p);
	p->dev = skb->dev;
	if (p->dev)
		dev_hold(p->dev);
	if (state) {
		/* A dying socket must not be resurrected. */
		if (state->sk && !refcount_inc_not_zero(&state->sk->sk_refcnt))
			goto free_packet;
		p->hook = hook;
		p->state = *state;
		get_net(state->net);
		if (state->in)
			dev_hold(state->in);
		if (state->out)
			dev_hold(state->out);
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
		dst = skb_dst(skb);
		p->physin = nf_bridge_get_physindev_compat(skb);
		p->physout = nf_bridge_get_physoutdev(skb);
		if (p->physin)
			dev_hold(p->physin);
		if (p->physout)
			dev_hold(p->physout);
		/* A bridge fake rtable is embedded in the bridge's private storage. */
		if (state->pf == NFPROTO_BRIDGE && dst && (dst->flags & DST_FAKE_RTABLE)) {
			p->bridge_dev = READ_ONCE(dst->dev);
			if (p->bridge_dev)
				dev_hold(p->bridge_dev);
		}
#endif
	}
	spin_lock_bh(&qos_queue_lock);
	if (qos_stopping || stamp->generation != qos_generation ||
	        qos_stats.packets >= NATFLOW_QOS_QUEUE_PACKETS ||
	        p->memory > NATFLOW_QOS_QUEUE_MEMORY - qos_stats.memory) {
		spin_unlock_bh(&qos_queue_lock);
		goto free_packet;
	}
	link = &qos_queue.rb_node;
	while (*link) {
		struct natflow_qos_packet *other = rb_entry(*link, struct natflow_qos_packet, node);
		parent = *link;
		if (stamp->time < other->stamp.time)
			link = &(*link)->rb_left;
		else
			link = &(*link)->rb_right;
	}
	p->skb = skb;
	rb_link_node(&p->node, parent, link);
	rb_insert_color(&p->node, &qos_queue);
	qos_stats.packets++;
	qos_stats.memory += p->memory;
	qos_stats.queued++;
	if (rb_first(&qos_queue) == &p->node)
		hrtimer_start(&qos_timer, ns_to_ktime(stamp->time), HRTIMER_MODE_ABS);
	spin_unlock_bh(&qos_queue_lock);
	return true;

free_packet:
	qos_packet_free(p);
failed:
	natflow_qos_drop();
	return false;
}

void natflow_qos_drop(void)
{
	spin_lock_bh(&qos_queue_lock);
	qos_stats.dropped++;
	spin_unlock_bh(&qos_queue_lock);
}

void natflow_qos_queue_stats(struct natflow_qos_stats *stats)
{
	spin_lock_bh(&qos_queue_lock);
	*stats = qos_stats;
	spin_unlock_bh(&qos_queue_lock);
}

void natflow_qos_queue_reset(u32 generation)
{
	struct natflow_qos_packet *p, *next;
	struct rb_node *node;
	LIST_HEAD(discard);

	spin_lock_bh(&qos_queue_lock);
	qos_generation = generation;
	while ((node = rb_first(&qos_queue)) != NULL) {
		p = rb_entry(node, struct natflow_qos_packet, node);
		rb_erase(node, &qos_queue);
		list_add_tail(&p->list, &discard);
		qos_stats.dropped++;
	}
	qos_stats.packets = 0;
	qos_stats.memory = 0;
	spin_unlock_bh(&qos_queue_lock);
	list_for_each_entry_safe(p, next, &discard, list) {
		qos_packet_free(p);
	}
}

void natflow_qos_queue_init(void)
{
#if NATFLOW_HAVE_HRTIMER_SETUP
	hrtimer_setup(&qos_timer, qos_timer_fn, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
#else
	hrtimer_init(&qos_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
	qos_timer.function = qos_timer_fn;
#endif
	tasklet_init(&qos_tasklet, qos_dequeue, 0);
}

void natflow_qos_queue_exit(void)
{
	spin_lock_bh(&qos_queue_lock);
	qos_stopping = true;
	spin_unlock_bh(&qos_queue_lock);
	hrtimer_cancel(&qos_timer);
	tasklet_kill(&qos_tasklet);
	natflow_qos_queue_reset(qos_generation + 1);
}

unsigned int natflow_qos_post_queue(struct sk_buff *skb,
                                    const struct nf_hook_state *state, nf_hookfn *hook,
                                    const struct natflow_qos_stamp *stamp)
{
	if (!stamp->time)
		return NF_ACCEPT;
	return qos_enqueue(skb, state, hook, stamp) ? NF_STOLEN : NF_DROP;
}
#else
void natflow_qos_queue_init(void) {}
void natflow_qos_queue_exit(void) {}
void natflow_qos_queue_reset(u32 generation) {}
void natflow_qos_drop(void) {}
void natflow_qos_queue_stats(struct natflow_qos_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
}
#endif

void natflow_qos_xmit(struct sk_buff *skb, const struct natflow_qos_stamp *stamp)
{
#if NATFLOW_HAVE_QOS_BUFFER
	if (stamp->time) {
		if (!qos_enqueue(skb, NULL, NULL, stamp))
			kfree_skb(skb);
		return;
	}
#endif
	dev_queue_xmit(skb);
}
