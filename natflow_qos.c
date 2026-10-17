#include <linux/hrtimer.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/netfilter_bridge.h>
#include <linux/notifier.h>
#include <linux/rbtree.h>
#include <linux/skbuff.h>
#include <net/dst.h>
#include <net/sock.h>
#include "natflow_qos.h"
#include "natflow_common.h"

#if NATFLOW_HAVE_QOS_BUFFER
#include <linux/atomic.h>
#include <linux/cpu.h>
#include <linux/cpuhotplug.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/u64_stats_sync.h>
#include <linux/workqueue.h>

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

struct natflow_qos_cpu_queue {
	struct rb_root packets;
	struct hrtimer timer;
	struct tasklet_struct tasklet;
	unsigned int cpu;
	u32 generation;
	u32 device_generation;
	bool online;
	struct u64_stats_sync stats_sync;
	u64 queued;
	u64 sent;
	u64 dropped;
};

/* Tree, generation and statistics writers run on the owner CPU with BH off. */
static DEFINE_PER_CPU(struct natflow_qos_cpu_queue, qos_cpu_queues);
static int qos_cpuhp_state = -1;
static atomic_t qos_packets = ATOMIC_INIT(0);
static atomic_t qos_memory = ATOMIC_INIT(0);
static atomic_t qos_device_generation = ATOMIC_INIT(1);
static u32 qos_generation = 1;
static bool qos_stopping;

/* Reserve without transiently exceeding the externally visible limits. */
static bool qos_charge(atomic_t *counter, unsigned int amount, unsigned int limit)
{
	int used = atomic_read(counter);

	for (;;) {
		int previous;

		if (amount > limit - used)
			return false;
		previous = atomic_cmpxchg(counter, used, used + amount);
		if (previous == used)
			return true;
		used = previous;
	}
}

static void qos_uncharge(struct natflow_qos_packet *p)
{
	atomic_sub(p->memory, &qos_memory);
	atomic_dec(&qos_packets);
}

/* No networking calls inside the stats sequence's non-preemptible writer. */
static void qos_count(struct natflow_qos_cpu_queue *q, unsigned int queued,
                      unsigned int sent, unsigned int dropped)
{
	u64_stats_update_begin(&q->stats_sync);
	q->queued += queued;
	q->sent += sent;
	q->dropped += dropped;
	u64_stats_update_end(&q->stats_sync);
}

static bool qos_dev_ready(struct net_device *dev)
{
	return !dev || (netif_running(dev) && netif_device_present(dev));
}

static bool qos_packet_ready(const struct natflow_qos_packet *p)
{
	return qos_dev_ready(p->dev) && qos_dev_ready(p->state.in) &&
	       qos_dev_ready(p->state.out) && qos_dev_ready(p->physin) &&
	       qos_dev_ready(p->physout) && qos_dev_ready(p->bridge_dev);
}

static void qos_packet_free(struct natflow_qos_packet *p)
{
	if (p->skb)
		kfree_skb(p->skb);
	if (p->dev)
		dev_put(p->dev);
	if (p->physin)
		dev_put(p->physin);
	if (p->physout)
		dev_put(p->physout);
	if (p->bridge_dev)
		dev_put(p->bridge_dev);
	if (p->hook) {
		if (p->state.in)
			dev_put(p->state.in);
		if (p->state.out)
			dev_put(p->state.out);
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

/* Owner CPU, BH disabled. Release detached packets outside the tree update. */
static void qos_purge_cpu(struct natflow_qos_cpu_queue *q, struct list_head *discard)
{
	struct rb_node *node;

	while ((node = rb_first(&q->packets)) != NULL) {
		struct natflow_qos_packet *p = rb_entry(node, struct natflow_qos_packet, node);

		rb_erase(node, &q->packets);
		qos_uncharge(p);
		qos_count(q, 0, 0, 1);
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

	local_bh_disable();
	/* Pair readiness/epoch checks and both continuations with synchronize_net(). */
	rcu_read_lock();
	/* CPU teardown drains before migration; never touch another CPU's tree. */
	if (unlikely(q->cpu != smp_processor_id()))
		goto out;
	while (budget--) {
		struct natflow_qos_packet *p;
		struct rb_node *first;
		bool drop;
		u64 now = ktime_get_ns();

		if (READ_ONCE(qos_stopping) || !q->online)
			goto out;
		first = rb_first(&q->packets);
		if (!first) {
			q->device_generation = (u32)atomic_read(&qos_device_generation);
			goto out;
		}
		p = rb_entry(first, struct natflow_qos_packet, node);
		drop = p->stamp.generation != q->generation ||
		       q->device_generation != (u32)atomic_read(&qos_device_generation);
		/* Invalidated queues drain now, including packets far in the future. */
		if (!drop && p->stamp.time > now) {
			hrtimer_start(&q->timer, ns_to_ktime(p->stamp.time), HRTIMER_MODE_ABS_PINNED);
			goto out;
		}
		rb_erase(first, &q->packets);
		qos_uncharge(p);
		if (!qos_packet_ready(p))
			drop = true;
		if (!drop) {
			if (p->hook) {
				qos_post_resume(p);
			} else {
				dev_queue_xmit(p->skb);
				p->skb = NULL;
			}
		}
		qos_count(q, 0, !p->skb, !!p->skb);
		qos_packet_free(p);
	}
	if (RB_EMPTY_ROOT(&q->packets))
		q->device_generation = (u32)atomic_read(&qos_device_generation);
	/* Yield between batches even if there are more overdue packets. */
	if (!READ_ONCE(qos_stopping) && q->online && !RB_EMPTY_ROOT(&q->packets))
		hrtimer_start(&q->timer, ns_to_ktime(ktime_get_ns() + 1000), HRTIMER_MODE_ABS_PINNED);
out:
	rcu_read_unlock();
	local_bh_enable();
}

static enum hrtimer_restart qos_timer_fn(struct hrtimer *timer)
{
	struct natflow_qos_cpu_queue *q = container_of(timer, struct natflow_qos_cpu_queue, timer);

	tasklet_schedule(&q->tasklet);
	return HRTIMER_NORESTART;
}

/* IPI context: only schedule; the owner CPU's tasklet mutates its tree. */
static void qos_schedule_cpu(void *unused)
{
	struct natflow_qos_cpu_queue *q = this_cpu_ptr(&qos_cpu_queues);

	(void)unused;
	/* An offline callback may already have killed this CPU's tasklet. */
	if (READ_ONCE(q->online) && !READ_ONCE(qos_stopping))
		tasklet_schedule(&q->tasklet);
}

static int qos_netdev_event(struct notifier_block *nb, unsigned long event, void *ptr)
{
	(void)nb;
	(void)ptr;
	if (event != NETDEV_GOING_DOWN && event != NETDEV_DOWN && event != NETDEV_UNREGISTER)
		return NOTIFY_DONE;
	/* Conservatively invalidate all buffered devices, without a device table. */
	atomic_inc(&qos_device_generation);
	/* Synchronous IPIs cannot outlive notifier unregistration/module teardown. */
	on_each_cpu(qos_schedule_cpu, NULL, 1);
	/* Selected packets must finish before device teardown or a namespace move. */
	synchronize_net();
	return NOTIFY_DONE;
}

static struct notifier_block qos_netdev_notifier = {
	.notifier_call = qos_netdev_event,
};

/* On success the queue owns skb. On failure the caller still owns it. */
static bool qos_enqueue(struct sk_buff *skb, const struct nf_hook_state *state,
                        nf_hookfn *hook, const struct natflow_qos_stamp *stamp)
{
	struct natflow_qos_packet *p;
	struct natflow_qos_cpu_queue *q;
	struct rb_node **link, *parent = NULL;
	bool had_dst = skb_dst(skb) != NULL;
	u32 device_generation = (u32)atomic_read(&qos_device_generation);
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
	}
#if IS_ENABLED(CONFIG_BRIDGE_NETFILTER)
	/* Fast packets can carry bridge metadata too, regardless of saved hook. */
	dst = skb_dst(skb);
#if NATFLOW_NF_BRIDGE_PHYSINDEV_TAKES_NET
	p->physin = nf_bridge_get_physindev(skb, state ? state->net : dev_net(skb->dev));
#else
	p->physin = nf_bridge_get_physindev_compat(skb);
#endif
	p->physout = nf_bridge_get_physoutdev(skb);
	if (p->physin)
		dev_hold(p->physin);
	if (p->physout)
		dev_hold(p->physout);
	/* A bridge fake rtable is embedded in the bridge's private storage. */
	if (dst && (dst->flags & DST_FAKE_RTABLE)) {
		p->bridge_dev = READ_ONCE(dst->dev);
		if (p->bridge_dev)
			dev_hold(p->bridge_dev);
	}
#endif
	local_bh_disable();
	q = this_cpu_ptr(&qos_cpu_queues);
	if (READ_ONCE(qos_stopping) || !q->online || stamp->generation != q->generation ||
	        device_generation != q->device_generation ||
	        device_generation != (u32)atomic_read(&qos_device_generation) ||
	        !qos_packet_ready(p) || !qos_charge(&qos_packets, 1, NATFLOW_QOS_QUEUE_PACKETS))
		goto enable_bh;
	if (!qos_charge(&qos_memory, p->memory, NATFLOW_QOS_QUEUE_MEMORY)) {
		atomic_dec(&qos_packets);
		goto enable_bh;
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
	qos_count(q, 1, 0, 0);
	if (rb_first(&q->packets) == &p->node)
		hrtimer_start(&q->timer, ns_to_ktime(stamp->time), HRTIMER_MODE_ABS_PINNED);
	local_bh_enable();
	return true;

enable_bh:
	local_bh_enable();
free_packet:
	qos_packet_free(p);
failed:
	natflow_qos_drop();
	return false;
}

void natflow_qos_drop(void)
{
	local_bh_disable();
	qos_count(this_cpu_ptr(&qos_cpu_queues), 0, 0, 1);
	local_bh_enable();
}

void natflow_qos_queue_stats(struct natflow_qos_stats *stats)
{
	unsigned int cpu;

	memset(stats, 0, sizeof(*stats));
	stats->packets = atomic_read(&qos_packets);
	stats->memory = atomic_read(&qos_memory);
	/* Also exclude local softirq writers on old 32-bit UP kernels. */
	local_bh_disable();
	for_each_possible_cpu(cpu) {
		struct natflow_qos_cpu_queue *q = per_cpu_ptr(&qos_cpu_queues, cpu);
		u64 queued, sent, dropped;
		unsigned int start;

		do {
			start = u64_stats_fetch_begin(&q->stats_sync);
			queued = READ_ONCE(q->queued);
			sent = READ_ONCE(q->sent);
			dropped = READ_ONCE(q->dropped);
		} while (u64_stats_fetch_retry(&q->stats_sync, start));
		stats->queued += queued;
		stats->sent += sent;
		stats->dropped += dropped;
	}
	local_bh_enable();
}

static long qos_reset_cpu(void *arg)
{
	struct natflow_qos_cpu_queue *q;
	LIST_HEAD(discard);

	local_bh_disable();
	q = this_cpu_ptr(&qos_cpu_queues);
	q->generation = *(u32 *)arg;
	qos_purge_cpu(q, &discard);
	q->device_generation = (u32)atomic_read(&qos_device_generation);
	local_bh_enable();
	/* Old timers may expire empty; never rearm from a remote CPU. */
	qos_free_discard(&discard);
	return 0;
}

/* Control path only, serialized by qos_conf_lock; completion precedes publish. */
void natflow_qos_queue_reset(u32 generation)
{
	unsigned int cpu;

	cpus_read_lock();
	WRITE_ONCE(qos_generation, generation);
	for_each_online_cpu(cpu) {
		work_on_cpu(cpu, qos_reset_cpu, &generation);
	}
	cpus_read_unlock();
}

static int qos_cpu_online(unsigned int cpu)
{
	struct natflow_qos_cpu_queue *q = per_cpu_ptr(&qos_cpu_queues, cpu);

	local_bh_disable();
	q->generation = READ_ONCE(qos_generation);
	WRITE_ONCE(q->online, true);
	/* An event racing the snapshot must see online and schedule its tasklet. */
	q->device_generation = (u32)atomic_read(&qos_device_generation);
	local_bh_enable();
	return 0;
}

static int qos_cpu_offline(unsigned int cpu)
{
	struct natflow_qos_cpu_queue *q = per_cpu_ptr(&qos_cpu_queues, cpu);
	LIST_HEAD(discard);

	local_bh_disable();
	WRITE_ONCE(q->online, false);
	local_bh_enable();
	/* Drain on this CPU before the kernel can migrate its timers and tasklets. */
	hrtimer_cancel(&q->timer);
	tasklet_kill(&q->tasklet);
	local_bh_disable();
	qos_purge_cpu(q, &discard);
	local_bh_enable();
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
		u64_stats_init(&q->stats_sync);
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
	ret = register_netdevice_notifier(&qos_netdev_notifier);
	if (ret) {
		cpuhp_remove_state(qos_cpuhp_state);
		return ret;
	}
	return 0;
}

void natflow_qos_queue_exit(void)
{
	WRITE_ONCE(qos_stopping, true);
	unregister_netdevice_notifier(&qos_netdev_notifier);
	/* Teardown callbacks run on each online CPU and serialize with hotplug. */
	cpuhp_remove_state(qos_cpuhp_state);
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
