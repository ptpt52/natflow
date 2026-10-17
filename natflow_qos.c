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
#include <linux/cpuhotplug.h>
#include <linux/percpu.h>

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
struct natflow_qos_cpu_queue {
	struct rb_root packets;
	struct hrtimer timer;
	struct tasklet_struct tasklet;
	unsigned int cpu;
	bool online;
};

/* Queues are CPU-local; the lock also protects global admission and resets. */
static DEFINE_PER_CPU(struct natflow_qos_cpu_queue, qos_cpu_queues);
static int qos_cpuhp_state = -1;
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

/* Caller holds qos_queue_lock. Release packet references after unlocking. */
static void qos_purge_cpu(struct natflow_qos_cpu_queue *q, struct list_head *discard)
{
	struct rb_node *node;

	while ((node = rb_first(&q->packets)) != NULL) {
		struct natflow_qos_packet *p = rb_entry(node, struct natflow_qos_packet, node);

		rb_erase(node, &q->packets);
		qos_stats.packets--;
		qos_stats.memory -= p->memory;
		qos_stats.dropped++;
		list_add_tail(&p->list, discard);
	}
}

static void qos_free_discard(struct list_head *discard)
{
	struct natflow_qos_packet *p, *next;

	list_for_each_entry_safe(p, next, discard, list) {
		qos_packet_free(p);
	}
}

/* Networking continuations run on the enqueue CPU, in softirq context. */
static void qos_dequeue(unsigned long data)
{
	struct natflow_qos_cpu_queue *q = (struct natflow_qos_cpu_queue *)data;
	unsigned int budget = 128;

	/* Never transmit a tasklet migrated during CPU teardown. */
	if (unlikely(q->cpu != smp_processor_id())) {
		LIST_HEAD(discard);

		spin_lock_bh(&qos_queue_lock);
		qos_purge_cpu(q, &discard);
		spin_unlock_bh(&qos_queue_lock);
		qos_free_discard(&discard);
		return;
	}
	while (budget--) {
		struct natflow_qos_packet *p;
		struct rb_node *first;
		bool drop;
		u64 now = ktime_get_ns();

		spin_lock_bh(&qos_queue_lock);
		if (qos_stopping || !q->online) {
			spin_unlock_bh(&qos_queue_lock);
			return;
		}
		first = rb_first(&q->packets);
		if (!first) {
			spin_unlock_bh(&qos_queue_lock);
			return;
		}
		p = rb_entry(first, struct natflow_qos_packet, node);
		if (p->stamp.time > now) {
			hrtimer_start(&q->timer, ns_to_ktime(p->stamp.time), HRTIMER_MODE_ABS_PINNED);
			spin_unlock_bh(&qos_queue_lock);
			return;
		}
		rb_erase(first, &q->packets);
		qos_stats.packets--;
		qos_stats.memory -= p->memory;
		drop = p->stamp.generation != qos_generation;
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
	if (!qos_stopping && q->online && !RB_EMPTY_ROOT(&q->packets))
		hrtimer_start(&q->timer, ns_to_ktime(ktime_get_ns() + 1000), HRTIMER_MODE_ABS_PINNED);
	spin_unlock_bh(&qos_queue_lock);
}

static enum hrtimer_restart qos_timer_fn(struct hrtimer *timer)
{
	struct natflow_qos_cpu_queue *q = container_of(timer, struct natflow_qos_cpu_queue, timer);

	tasklet_schedule(&q->tasklet);
	return HRTIMER_NORESTART;
}

/* On success the queue owns skb. On failure the caller still owns it. */
static bool qos_enqueue(struct sk_buff *skb, const struct nf_hook_state *state,
                        nf_hookfn *hook, const struct natflow_qos_stamp *stamp)
{
	struct natflow_qos_packet *p;
	struct natflow_qos_cpu_queue *q;
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
	/* BH exclusion pins both the queue selection and timer start to this CPU. */
	q = this_cpu_ptr(&qos_cpu_queues);
	if (qos_stopping || !q->online || stamp->generation != qos_generation ||
	        qos_stats.packets >= NATFLOW_QOS_QUEUE_PACKETS ||
	        p->memory > NATFLOW_QOS_QUEUE_MEMORY - qos_stats.memory) {
		spin_unlock_bh(&qos_queue_lock);
		goto free_packet;
	}
	link = &q->packets.rb_node;
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
	rb_insert_color(&p->node, &q->packets);
	qos_stats.packets++;
	qos_stats.memory += p->memory;
	qos_stats.queued++;
	if (rb_first(&q->packets) == &p->node)
		hrtimer_start(&q->timer, ns_to_ktime(stamp->time), HRTIMER_MODE_ABS_PINNED);
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
	unsigned int cpu;
	LIST_HEAD(discard);

	spin_lock_bh(&qos_queue_lock);
	qos_generation = generation;
	for_each_possible_cpu(cpu) {
		qos_purge_cpu(per_cpu_ptr(&qos_cpu_queues, cpu), &discard);
	}
	spin_unlock_bh(&qos_queue_lock);
	/* Existing timers can expire empty; do not rearm them from a remote CPU. */
	qos_free_discard(&discard);
}

static int qos_cpu_online(unsigned int cpu)
{
	struct natflow_qos_cpu_queue *q = per_cpu_ptr(&qos_cpu_queues, cpu);

	spin_lock_bh(&qos_queue_lock);
	q->online = true;
	spin_unlock_bh(&qos_queue_lock);
	return 0;
}

static int qos_cpu_offline(unsigned int cpu)
{
	struct natflow_qos_cpu_queue *q = per_cpu_ptr(&qos_cpu_queues, cpu);
	LIST_HEAD(discard);

	spin_lock_bh(&qos_queue_lock);
	q->online = false;
	spin_unlock_bh(&qos_queue_lock);
	/* Drain before the kernel can migrate this CPU's timers and tasklets. */
	hrtimer_cancel(&q->timer);
	tasklet_kill(&q->tasklet);
	spin_lock_bh(&qos_queue_lock);
	qos_purge_cpu(q, &discard);
	spin_unlock_bh(&qos_queue_lock);
	qos_free_discard(&discard);
	return 0;
}

int natflow_qos_queue_init(void)
{
	unsigned int cpu;
	int ret;

	for_each_possible_cpu(cpu) {
		struct natflow_qos_cpu_queue *q = per_cpu_ptr(&qos_cpu_queues, cpu);

		q->packets = RB_ROOT;
		q->cpu = cpu;
#if NATFLOW_HAVE_HRTIMER_SETUP
		hrtimer_setup(&q->timer, qos_timer_fn, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED);
#else
		hrtimer_init(&q->timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED);
		q->timer.function = qos_timer_fn;
#endif
		tasklet_init(&q->tasklet, qos_dequeue, (unsigned long)q);
	}
	ret = cpuhp_setup_state(CPUHP_AP_ONLINE_DYN, "net/natflow_qos:online",
	                        qos_cpu_online, qos_cpu_offline);
	if (ret < 0)
		return ret;
	qos_cpuhp_state = ret;
	return 0;
}

void natflow_qos_queue_exit(void)
{
	unsigned int cpu;

	spin_lock_bh(&qos_queue_lock);
	qos_stopping = true;
	spin_unlock_bh(&qos_queue_lock);
	/* Serialize with hotplug before cancelling even offline CPUs' work. */
	cpuhp_remove_state_nocalls(qos_cpuhp_state);
	for_each_possible_cpu(cpu) {
		qos_cpu_offline(cpu);
	}
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
int natflow_qos_queue_init(void)
{
	return 0;
}
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
