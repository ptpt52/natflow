#include "cpu-mock.h"
#include "production-queue.h"

static void mock_tree_access(const struct rb_root *root)
{
	assert(mock_bh_depth);
	assert(!mock_in_ipi);
	assert(root == &qos_cpu_queues[mock_cpu].packets);
}

static struct natflow_qos_stats queue_stats(void)
{
	struct natflow_qos_stats stats;
	natflow_qos_queue_stats(&stats);
	return stats;
}

static struct net net = { .refs = 1 };
static struct net_device dev = { .running = true, .present = true, .refs = 1, .net = &net };
static struct sock sk = { .sk_refcnt = 1 };
static unsigned int continued;

static struct sk_buff *packet(unsigned int sequence, unsigned int size)
{
	struct sk_buff *skb = calloc(1, sizeof(*skb));
	assert(skb);
	skb->dev = &dev;
	skb->truesize = size;
	skb->enqueue_cpu = mock_cpu;
	skb->sequence = sequence;
	atomic_fetch_add(&skb_allocations, 1);
	return skb;
}

static struct natflow_qos_stamp stamp(u64 time)
{
	return (struct natflow_qos_stamp) {
		time, READ_ONCE(qos_generation)
	};
}

static void queue(unsigned int sequence, u64 time)
{
	struct natflow_qos_stamp s = stamp(time);
	natflow_qos_xmit(packet(sequence, 256), &s);
}

static void assert_empty(void)
{
	struct natflow_qos_stats stats;
	natflow_qos_queue_stats(&stats);
	assert(!stats.packets && !stats.memory);
	assert(!atomic_load(&allocations) && !atomic_load(&skb_allocations));
	assert(atomic_load(&dev.refs) == 1);
	assert(atomic_load(&dev.holds) == atomic_load(&dev.puts));
	assert(atomic_load(&net.refs) == 1 && atomic_load(&sk.sk_refcnt) == 1);
}

/* Fire only on the CPU to which the pinned timer was actually armed. */
static void poll_cpu(unsigned int cpu)
{
	struct natflow_qos_cpu_queue *q = &qos_cpu_queues[cpu];
	unsigned int saved = mock_cpu;

	mock_cpu = cpu;
	if (q->timer.active && q->timer.expires <= mock_now) {
		assert(q->timer.cpu == cpu);
		q->timer.active = false;
		q->timer.function(&q->timer);
	}
	if (q->tasklet.scheduled) {
		assert(q->tasklet.cpu == cpu);
		q->tasklet.scheduled = false;
		q->tasklet.function(q->tasklet.data);
	}
	mock_cpu = saved;
}

static unsigned int original(void *priv, struct sk_buff *skb,
                             const struct nf_hook_state *state)
{
	(void)priv;
	(void)skb;
	(void)state;
	assert(!"original hook must not run twice");
	return NF_DROP;
}

static unsigned int next_hook(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state)
{
	(void)priv;
	(void)state;
	assert(mock_cpu == skb->enqueue_cpu && mock_rcu_depth);
	continued++;
	return NF_ACCEPT;
}

static int okfn(struct net *n, struct sock *s, struct sk_buff *skb)
{
	assert(n == &net && s == &sk);
	assert(n == dev_net(skb->dev));
	dev_queue_xmit(skb);
	return 0;
}

static void test_affinity_and_continuation(void)
{
	struct nf_hook_entries entries = {
		.num_hook_entries = 2, .hooks = {{ .hook = original }, { .hook = next_hook }}
	};
	const unsigned int families[] = { NFPROTO_IPV4, NFPROTO_IPV6, NFPROTO_BRIDGE };
	struct dst_entry dst = { .dev = &dev, .flags = DST_FAKE_RTABLE };
	struct nf_hook_state state = {
		.hook = 4, .in = &dev, .out = &dev, .net = &net, .sk = &sk, .okfn = okfn
	};
	unsigned int sent = atomic_load(&xmitted);

	net.nf.hooks_ipv4[4] = net.nf.hooks_ipv6[4] = net.nf.hooks_bridge[4] = &entries;
	for (mock_cpu = 0; mock_cpu < 3; mock_cpu++) {
		struct natflow_qos_stamp s = stamp(mock_now + 100);
		struct sk_buff *skb = packet(0, 256);
		state.pf = families[mock_cpu];
		skb->physin = skb->physout = &dev;
		skb->dst = &dst;
		assert(natflow_qos_post_queue(skb, &state, original, &s) == NF_STOLEN);
		queue(0, mock_now + 200);
		assert(qos_cpu_queues[mock_cpu].timer.cpu == mock_cpu);
	}
	mock_cpu = 3; /* Control CPU must not own any queued packet or timer. */
	mock_now += 100;
	for (unsigned int cpu = 0; cpu < 3; cpu++) poll_cpu(cpu);
	assert(continued == 3 && atomic_load(&xmitted) == sent + 3);
	for (unsigned int cpu = 0; cpu < 3; cpu++)
		assert(qos_cpu_queues[cpu].timer.cpu == cpu);
	mock_now += 100;
	for (unsigned int cpu = 0; cpu < 3; cpu++) poll_cpu(cpu);
	assert(atomic_load(&xmitted) == sent + 6);
	assert_empty();
	net.nf.hooks_ipv4[4] = net.nf.hooks_ipv6[4] = net.nf.hooks_bridge[4] = NULL;
}

static void test_order_and_budget(void)
{
	unsigned int sent = atomic_load(&xmitted);
	check_sequence = true;
	mock_cpu = 1;
	/* Enqueue later deadlines first, then equal timestamps in FIFO order. */
	for (unsigned int i = 131; i <= 260; i++) queue(i, mock_now + 200);
	for (unsigned int i = 1; i <= 130; i++) queue(i, mock_now + 100);
	mock_now += 200;
	poll_cpu(1);
	assert(atomic_load(&xmitted) == sent + 128);
	assert(queue_stats().packets == 132);
	assert(qos_cpu_queues[1].timer.expires == mock_now + 1000);
	mock_now += 1000;
	poll_cpu(1);
	assert(atomic_load(&xmitted) == sent + 256);
	mock_now += 1000;
	poll_cpu(1);
	assert(last_sequence[1] == 260);
	check_sequence = false;
	assert_empty();
}

static void test_hotplug_and_reset(void)
{
	unsigned int sent = atomic_load(&xmitted);
	u64 dropped = queue_stats().dropped;
	mock_cpu = 0;
	queue(0, mock_now + 100);
	mock_cpu = 1;
	queue(0, mock_now + 100);
	/* Also kill a tasklet already scheduled on the CPU going offline. */
	qos_cpu_queues[1].timer.function(&qos_cpu_queues[1].timer);
	mock_hotplug_cpu(1, false);
	assert(!qos_cpu_queues[1].timer.active && !qos_cpu_queues[1].tasklet.scheduled);
	assert(queue_stats().packets == 1 && queue_stats().dropped == dropped + 1);
	queue(0, mock_now + 100); /* Admission after teardown must fail. */
	assert(queue_stats().dropped == dropped + 2);
	mock_cpu = 3;
	mock_now += 100;
	poll_cpu(0);
	poll_cpu(1);
	assert(atomic_load(&xmitted) == sent + 1);
	assert_empty();

	mock_cpu = 1;
	mock_hotplug_cpu(1, true);
	queue(0, mock_now + 100);
	mock_now += 100;
	poll_cpu(1);
	assert(atomic_load(&xmitted) == sent + 2);
	assert_empty();

	/* A migrated tasklet must neither send nor touch the remote tree. */
	queue(0, mock_now + 100);
	mock_cpu = 2;
	qos_dequeue((unsigned long)&qos_cpu_queues[1]);
	assert(atomic_load(&xmitted) == sent + 2);
	assert(queue_stats().packets == 1);
	mock_hotplug_cpu(1, false);
	assert_empty();
	mock_hotplug_cpu(1, true);
	mock_now += 100;
	poll_cpu(1);

	mock_cpu = 0;
	queue(0, mock_now + 100);
	mock_cpu = 1;
	queue(0, mock_now + 200);
	struct natflow_qos_stamp old = stamp(mock_now + 300);
	mock_cpu = 3;
	natflow_qos_queue_reset(qos_generation + 1);
	assert(qos_cpu_queues[0].timer.cpu == 0 && qos_cpu_queues[1].timer.cpu == 1);
	assert_empty();
	mock_cpu = 0;
	natflow_qos_xmit(packet(0, 256), &old);
	assert_empty();
	queue(0, mock_now + 50); /* Reuse with a deadline before the stale timer. */
	mock_now += 50;
	poll_cpu(0);
	assert(atomic_load(&xmitted) == sent + 3);
	assert_empty();
}

static void test_global_caps_and_failures(void)
{
	for (unsigned int i = 0; i < NATFLOW_QOS_QUEUE_PACKETS; i++) {
		mock_cpu = i % 3;
		queue(0, mock_now + 100);
	}
	assert(queue_stats().packets == NATFLOW_QOS_QUEUE_PACKETS);
	u64 dropped = queue_stats().dropped;
	queue(0, mock_now + 100);
	assert(queue_stats().packets == NATFLOW_QOS_QUEUE_PACKETS && queue_stats().dropped == dropped + 1);
	natflow_qos_queue_reset(qos_generation + 1);
	assert_empty();

	struct natflow_qos_stamp s = stamp(mock_now + 100);
	unsigned int size = NATFLOW_QOS_QUEUE_MEMORY / 2 - sizeof(struct natflow_qos_packet);
	mock_cpu = 0;
	natflow_qos_xmit(packet(0, size), &s);
	mock_cpu = 2;
	natflow_qos_xmit(packet(0, size), &s);
	assert(queue_stats().memory == NATFLOW_QOS_QUEUE_MEMORY && queue_stats().packets == 2);
	queue(0, mock_now + 100);
	assert(queue_stats().memory == NATFLOW_QOS_QUEUE_MEMORY && queue_stats().packets == 2);
	natflow_qos_queue_reset(qos_generation + 1);
	assert_empty();

	fail_alloc_at = 1;
	queue(0, mock_now + 100);
	assert_empty();
	s = stamp(mock_now + 100);
	struct dst_entry dst = { .dev = &dev };
	struct sk_buff *skb = packet(0, 256);
	skb->dst = &dst;
	skb->fail_dst = true;
	natflow_qos_xmit(skb, &s);
	assert_empty();

	struct nf_hook_state state = { .net = &net, .sk = &sk };
	atomic_store(&sk.sk_refcnt, 0);
	skb = packet(0, 256);
	assert(natflow_qos_post_queue(skb, &state, original, &s) == NF_DROP);
	kfree_skb(skb);
	atomic_store(&sk.sk_refcnt, 1);
	assert_empty();

	queue(0, mock_now + 100);
	atomic_store(&dev.running, false);
	mock_now += 100;
	poll_cpu(mock_cpu);
	atomic_store(&dev.running, true);
	assert_empty();
}

static void *producer(void *arg)
{
	mock_cpu = (uintptr_t)arg;
	for (unsigned int i = 1; i <= 800; i++) queue(i, mock_now + 100);
	return NULL;
}

static void test_concurrent_producers(void)
{
	pthread_t threads[3];
	memset(last_sequence, 0, sizeof(last_sequence));
	check_sequence = true;
	for (uintptr_t cpu = 0; cpu < 3; cpu++)
		assert(!pthread_create(&threads[cpu], NULL, producer, (void *)cpu));
	for (unsigned int cpu = 0; cpu < 3; cpu++) assert(!pthread_join(threads[cpu], NULL));
	assert(queue_stats().packets == 2400);
	mock_now += 100;
	while (queue_stats().packets) {
		for (unsigned int cpu = 0; cpu < 3; cpu++) poll_cpu(cpu);
		mock_now += 1000;
	}
	for (unsigned int cpu = 0; cpu < 3; cpu++) assert(last_sequence[cpu] == 800);
	check_sequence = false;
	assert_empty();
}

static pthread_barrier_t cap_start;
static atomic_uint cap_done;
struct cap_producer {
	unsigned int cpu, size;
};

static void *fill_capacity(void *arg)
{
	struct cap_producer *p = arg;
	mock_cpu = p->cpu;
	int ret = pthread_barrier_wait(&cap_start);
	assert(!ret || ret == PTHREAD_BARRIER_SERIAL_THREAD);
	for (unsigned int i = 0; i < 3000; i++) {
		struct natflow_qos_stamp s = stamp(mock_now + 100);
		natflow_qos_xmit(packet(0, p->size), &s);
	}
	atomic_fetch_add(&cap_done, 1);
	return NULL;
}

static void test_concurrent_capacity(void)
{
	for (unsigned int memory_limit = 0; memory_limit < 2; memory_limit++) {
		struct cap_producer args[3];
		pthread_t threads[3];
		unsigned int charge = memory_limit ? NATFLOW_QOS_QUEUE_MEMORY / 16 :
		                      256 + sizeof(struct natflow_qos_packet);
		unsigned int expected = memory_limit ? 16 : NATFLOW_QOS_QUEUE_PACKETS;
		struct natflow_qos_stats before = queue_stats();

		atomic_store(&cap_done, 0);
		assert(!pthread_barrier_init(&cap_start, NULL, 4));
		for (unsigned int cpu = 0; cpu < 3; cpu++) {
			args[cpu] = (struct cap_producer) {
				cpu, charge - sizeof(struct natflow_qos_packet)
			};
			assert(!pthread_create(&threads[cpu], NULL, fill_capacity, &args[cpu]));
		}
		mock_cpu = 3;
		int ret = pthread_barrier_wait(&cap_start);
		assert(!ret || ret == PTHREAD_BARRIER_SERIAL_THREAD);
		while (atomic_load(&cap_done) < 3) {
			struct natflow_qos_stats current = queue_stats();
			assert(current.packets <= NATFLOW_QOS_QUEUE_PACKETS);
			assert(current.memory <= NATFLOW_QOS_QUEUE_MEMORY);
			sched_yield();
		}
		for (unsigned int cpu = 0; cpu < 3; cpu++) assert(!pthread_join(threads[cpu], NULL));
		assert(!pthread_barrier_destroy(&cap_start));
		struct natflow_qos_stats after = queue_stats();
		assert(after.packets == expected && after.memory == charge * expected);
		assert(after.queued == before.queued + expected);
		assert(after.dropped == before.dropped + 9000 - expected);
		natflow_qos_queue_reset(qos_generation + 1);
		assert_empty();
	}
}

/* Pause enqueue between reserving its packet slot and its memory quota. */
static pthread_mutex_t reset_race_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t reset_race_cond = PTHREAD_COND_INITIALIZER;
static bool charge_paused, reset_waiting, release_charge;
static bool hotplug_started, hotplug_completed;
static struct natflow_qos_stamp reset_old_stamp;

static void pause_charge(atomic_t *counter)
{
	if (counter != &qos_packets || mock_cpu != 0) return;
	assert(mock_bh_depth);
	assert(!pthread_mutex_lock(&reset_race_lock));
	charge_paused = true;
	assert(!pthread_cond_broadcast(&reset_race_cond));
	while (!release_charge) assert(!pthread_cond_wait(&reset_race_cond, &reset_race_lock));
	assert(!pthread_mutex_unlock(&reset_race_lock));
}

static void signal_reset(unsigned int cpu)
{
	if (cpu) return;
	assert(!pthread_mutex_lock(&reset_race_lock));
	reset_waiting = true;
	assert(!pthread_cond_broadcast(&reset_race_cond));
	assert(!pthread_mutex_unlock(&reset_race_lock));
}

static void *paused_enqueue(void *arg)
{
	(void)arg;
	mock_cpu = 0;
	natflow_qos_xmit(packet(0, 256), &reset_old_stamp);
	return NULL;
}

static void *reset_control(void *arg)
{
	(void)arg;
	mock_cpu = 3;
	natflow_qos_queue_reset(reset_old_stamp.generation + 1);
	return NULL;
}

static void *hotplug_during_reset(void *arg)
{
	(void)arg;
	mock_cpu = 2;
	assert(!pthread_mutex_lock(&reset_race_lock));
	hotplug_started = true;
	assert(!pthread_cond_broadcast(&reset_race_cond));
	assert(!pthread_mutex_unlock(&reset_race_lock));
	mock_hotplug_cpu(2, false);
	assert(!pthread_mutex_lock(&reset_race_lock));
	hotplug_completed = true;
	assert(!pthread_cond_broadcast(&reset_race_cond));
	assert(!pthread_mutex_unlock(&reset_race_lock));
	return NULL;
}

static void test_reset_racing_enqueue(void)
{
	pthread_t producer_thread, reset_thread, hotplug_thread;
	struct natflow_qos_stats before = queue_stats();

	reset_old_stamp = stamp(mock_now + 100);
	mock_after_charge = pause_charge;
	mock_before_work = signal_reset;
	assert(!pthread_create(&producer_thread, NULL, paused_enqueue, NULL));
	assert(!pthread_mutex_lock(&reset_race_lock));
	while (!charge_paused) assert(!pthread_cond_wait(&reset_race_cond, &reset_race_lock));
	assert(!pthread_mutex_unlock(&reset_race_lock));
	assert(!pthread_create(&reset_thread, NULL, reset_control, NULL));
	assert(!pthread_mutex_lock(&reset_race_lock));
	while (!reset_waiting) assert(!pthread_cond_wait(&reset_race_cond, &reset_race_lock));
	assert(!pthread_mutex_unlock(&reset_race_lock));

	assert(!pthread_create(&hotplug_thread, NULL, hotplug_during_reset, NULL));
	assert(!pthread_mutex_lock(&reset_race_lock));
	while (!hotplug_started) assert(!pthread_cond_wait(&reset_race_cond, &reset_race_lock));
	assert(!hotplug_completed);
	assert(!pthread_mutex_unlock(&reset_race_lock));

	/* CPU 0 is blocked in enqueue; CPU 1 still admits its old config's packet. */
	mock_cpu = 1;
	natflow_qos_xmit(packet(0, 256), &reset_old_stamp);
	assert(queue_stats().packets == 2);
	assert(!pthread_mutex_lock(&reset_race_lock));
	release_charge = true;
	assert(!pthread_cond_broadcast(&reset_race_cond));
	assert(!pthread_mutex_unlock(&reset_race_lock));
	assert(!pthread_join(producer_thread, NULL));
	assert(!pthread_join(reset_thread, NULL));
	assert(!pthread_join(hotplug_thread, NULL));
	assert(hotplug_completed && !qos_cpu_queues[2].online);
	mock_hotplug_cpu(2, true);
	mock_after_charge = NULL;
	mock_before_work = NULL;
	assert_empty();
	struct natflow_qos_stats after = queue_stats();
	assert(after.queued == before.queued + 2 && after.dropped == before.dropped + 2);
	for (mock_cpu = 0; mock_cpu < MOCK_CPUS; mock_cpu++) {
		natflow_qos_xmit(packet(0, 256), &reset_old_stamp);
		assert_empty();
	}
}

static void test_reset_with_offline_cpu(void)
{
	mock_cpu = 3;
	mock_hotplug_cpu(1, false);
	struct natflow_qos_stamp old = stamp(mock_now + 100);
	unsigned int calls = mock_work_calls;
	natflow_qos_queue_reset(qos_generation + 1);
	assert(mock_work_calls == calls + MOCK_CPUS - 1);
	mock_hotplug_cpu(1, true);
	mock_cpu = 1;
	assert(qos_cpu_queues[1].generation == qos_generation);
	natflow_qos_xmit(packet(0, 256), &old);
	assert_empty();
	queue(0, mock_now + 100);
	mock_now += 100;
	poll_cpu(1);
	assert_empty();
}

static void assert_device_released(struct net_device *d)
{
	assert(atomic_load(&d->refs) == 1);
	assert(atomic_load(&d->holds) == atomic_load(&d->puts));
}

static void test_bridge_dependencies(void)
{
	struct net_device physin = { .running = true, .present = true, .refs = 1 };
	struct net_device physout = { .running = true, .present = true, .refs = 1 };
	struct net_device bridge = { .running = true, .present = true, .refs = 1 };
	struct dst_entry dst = { .dev = &bridge, .flags = DST_FAKE_RTABLE };
	struct nf_hook_entries entries = {
		.num_hook_entries = 2, .hooks = {{ .hook = original }, { .hook = next_hook }}
	};
	struct nf_hook_state state = {
		.pf = NFPROTO_IPV4, .hook = 4, .in = &dev, .out = &dev,
		.net = &net, .sk = &sk, .okfn = okfn
	};

	net.nf.hooks_ipv4[4] = &entries;
	for (unsigned int slow = 0; slow < 2; slow++) {
		for (unsigned int action = 0; action < 3; action++) {
			mock_cpu = 1;
			struct natflow_qos_stamp s = stamp(mock_now + 100);
			struct sk_buff *skb = packet(0, 256);
			skb->physin = &physin;
			skb->physout = &physout;
			skb->dst = &dst;
			/* Dependency readiness applies to admission, including fast packets. */
			if (action == 2) physin.running = false;
			if (slow) {
				unsigned int verdict = natflow_qos_post_queue(skb, &state, original, &s);
				assert(verdict == (action == 2 ? NF_DROP : NF_STOLEN));
				if (verdict == NF_DROP) kfree_skb(skb);
			} else natflow_qos_xmit(skb, &s);
			if (action != 2) {
				assert(atomic_load(&physin.refs) == 2);
				assert(atomic_load(&physout.refs) == 2);
				assert(atomic_load(&bridge.refs) == 2);
				if (action == 1) natflow_qos_queue_reset(qos_generation + 1);
				else {
					mock_now += 100;
					poll_cpu(1);
				}
			}
			physin.running = true;
			assert_empty();
			assert_device_released(&physin);
			assert_device_released(&physout);
			assert_device_released(&bridge);
		}
	}
	net.nf.hooks_ipv4[4] = NULL;
}

static void test_device_lifecycle(void)
{
	const unsigned long events[] = { NETDEV_GOING_DOWN, NETDEV_DOWN, NETDEV_UNREGISTER };
	struct net moved_net = { .refs = 1 };
	struct net_device other = { .running = true, .present = true, .refs = 1 };
	struct nf_hook_entries entries = {
		.num_hook_entries = 2, .hooks = {{ .hook = original }, { .hook = next_hook }}
	};
	struct nf_hook_state state = {
		.pf = NFPROTO_IPV4, .hook = 4, .in = &dev, .out = &dev,
		.net = &net, .sk = &sk, .okfn = okfn
	};

	net.nf.hooks_ipv4[4] = &entries;
	for (unsigned int i = 0; i < sizeof(events) / sizeof(events[0]); i++) {
		struct natflow_qos_stats before = queue_stats();
		unsigned int sent = atomic_load(&xmitted), hooks = continued;
		mock_cpu = 0;
		queue(0, mock_now + 1000000);
		mock_cpu = 1;
		struct natflow_qos_stamp s = stamp(mock_now + 1000000);
		assert(natflow_qos_post_queue(packet(0, 256), &state, original, &s) == NF_STOLEN);
		mock_cpu = 2;
		struct sk_buff *skb = packet(0, 256);
		skb->dev = &other;
		natflow_qos_xmit(skb, &s);
		mock_cpu = 3;
		/* REGISTER/UP must not disturb existing queues. */
		u32 epoch = atomic_read(&qos_device_generation);
		mock_netdev_event(NETDEV_REGISTER, &dev);
		mock_netdev_event(NETDEV_UP, &dev);
		assert((u32)atomic_read(&qos_device_generation) == epoch);
		mock_netdev_event(events[i], &dev);
		/* The same object is closed, moved and reopened before the old deadline. */
		dev.running = false;
		dev.net = &moved_net;
		dev.running = true;
		mock_cpu = 0;
		queue(0, mock_now + 100); /* Reject until this CPU has drained its old epoch. */
		assert(queue_stats().packets == 3);
		for (unsigned int cpu = 0; cpu < MOCK_CPUS; cpu++) poll_cpu(cpu);
		assert_empty();
		assert_device_released(&other);
		assert(continued == hooks && atomic_load(&xmitted) == sent);
		assert(queue_stats().dropped == before.dropped + 4);
		/* New packets can enter after the owner CPU acknowledges the new epoch. */
		queue(0, mock_now + 100);
		mock_now += 100;
		poll_cpu(0);
		assert(atomic_load(&xmitted) == sent + 1);
		assert_empty();
		dev.net = &net;
	}
	net.nf.hooks_ipv4[4] = NULL;

	/* Invalidation ignores future deadlines, while retaining the 128-packet budget. */
	mock_cpu = 2;
	unsigned int sent = atomic_load(&xmitted);
	for (unsigned int i = 0; i < 260; i++) queue(0, mock_now + 1000000);
	mock_cpu = 3;
	mock_netdev_event(NETDEV_DOWN, &other);
	poll_cpu(2);
	assert(queue_stats().packets == 132);
	mock_cpu = 2;
	queue(0, mock_now + 100);
	assert(queue_stats().packets == 132);
	mock_now += 1000;
	poll_cpu(2);
	assert(queue_stats().packets == 4);
	mock_now += 1000;
	poll_cpu(2);
	assert(atomic_load(&xmitted) == sent);
	for (unsigned int cpu = 0; cpu < MOCK_CPUS; cpu++) poll_cpu(cpu);
	assert_empty();

	/* IPIs must not resurrect a tasklet already killed by CPU teardown. */
	mock_hotplug_cpu(1, false);
	mock_cpu = 1;
	qos_schedule_cpu(NULL);
	assert(!qos_cpu_queues[1].tasklet.scheduled);
	mock_cpu = 3;
	mock_netdev_event(NETDEV_UNREGISTER, &other);
	assert(!qos_cpu_queues[1].tasklet.scheduled);
	mock_hotplug_cpu(1, true);
	for (unsigned int cpu = 0; cpu < MOCK_CPUS; cpu++) poll_cpu(cpu);
}

/* A device event must wait for a packet already selected for continuation. */
static pthread_mutex_t event_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t event_cond = PTHREAD_COND_INITIALIZER;
static bool xmit_paused, sync_waiting, release_xmit, event_done;

static void pause_xmit(void)
{
	assert(mock_cpu == 0 && mock_rcu_depth && mock_bh_depth);
	assert(!pthread_mutex_lock(&event_lock));
	xmit_paused = true;
	assert(!pthread_cond_broadcast(&event_cond));
	while (!release_xmit) assert(!pthread_cond_wait(&event_cond, &event_lock));
	assert(!pthread_mutex_unlock(&event_lock));
}

static void signal_sync_net(void)
{
	assert(!pthread_mutex_lock(&event_lock));
	sync_waiting = true;
	assert(!pthread_cond_broadcast(&event_cond));
	assert(!pthread_mutex_unlock(&event_lock));
}

static void *inflight_send(void *arg)
{
	(void)arg;
	mock_cpu = 0;
	poll_cpu(0);
	return NULL;
}

static void *device_event_control(void *arg)
{
	(void)arg;
	mock_cpu = 3;
	mock_netdev_event(NETDEV_GOING_DOWN, &dev);
	assert(!pthread_mutex_lock(&event_lock));
	event_done = true;
	assert(!pthread_cond_broadcast(&event_cond));
	assert(!pthread_mutex_unlock(&event_lock));
	return NULL;
}

static void test_inflight_device_event(void)
{
	pthread_t sender, notifier;
	unsigned int sent = atomic_load(&xmitted);

	mock_cpu = 0;
	queue(0, mock_now + 100);
	mock_now += 100;
	mock_before_xmit = pause_xmit;
	mock_before_sync_net = signal_sync_net;
	assert(!pthread_create(&sender, NULL, inflight_send, NULL));
	assert(!pthread_mutex_lock(&event_lock));
	while (!xmit_paused) assert(!pthread_cond_wait(&event_cond, &event_lock));
	assert(!pthread_mutex_unlock(&event_lock));
	assert(!pthread_create(&notifier, NULL, device_event_control, NULL));
	assert(!pthread_mutex_lock(&event_lock));
	while (!sync_waiting) assert(!pthread_cond_wait(&event_cond, &event_lock));
	assert(!event_done);
	release_xmit = true;
	assert(!pthread_cond_broadcast(&event_cond));
	assert(!pthread_mutex_unlock(&event_lock));
	assert(!pthread_join(sender, NULL));
	assert(!pthread_join(notifier, NULL));
	assert(event_done && atomic_load(&xmitted) == sent + 1);
	mock_before_xmit = NULL;
	mock_before_sync_net = NULL;
	for (unsigned int cpu = 0; cpu < MOCK_CPUS; cpu++) poll_cpu(cpu);
	assert_empty();
}

static void *online_device_event(void *arg)
{
	(void)arg;
	mock_cpu = 3;
	mock_netdev_event(NETDEV_DOWN, &dev);
	return NULL;
}

static void interrupt_online_snapshot(const atomic_t *counter)
{
	pthread_t notifier;

	if (counter != &qos_device_generation || mock_cpu != 1) return;
	assert(mock_bh_depth);
	mock_after_atomic_read = NULL;
	/* Advance the epoch and deliver the IPI before the old snapshot is stored. */
	assert(!pthread_create(&notifier, NULL, online_device_event, NULL));
	assert(!pthread_join(notifier, NULL));
}

static void test_online_racing_device_event(void)
{
	mock_cpu = 3;
	mock_hotplug_cpu(1, false);
	mock_after_atomic_read = interrupt_online_snapshot;
	mock_hotplug_cpu(1, true);
	assert(!mock_after_atomic_read);
	assert(qos_cpu_queues[1].tasklet.scheduled);
	for (unsigned int cpu = 0; cpu < MOCK_CPUS; cpu++) poll_cpu(cpu);
	mock_cpu = 1;
	queue(0, mock_now + 100);
	assert(queue_stats().packets == 1);
	mock_now += 100;
	poll_cpu(1);
	assert_empty();
}

int main(void)
{
	fail_cpuhp = 1;
	assert(natflow_qos_queue_init() == -ENOMEM);
	assert(!mock_startup && !mock_teardown);
	fail_cpuhp = 0;
	fail_notifier = true;
	assert(natflow_qos_queue_init() == -ENOMEM);
	assert(!mock_startup && !mock_teardown && !mock_netdev_notifier);
	for (unsigned int cpu = 0; cpu < MOCK_CPUS; cpu++) {
		assert(!qos_cpu_queues[cpu].online);
		assert(!qos_cpu_queues[cpu].timer.active);
		assert(!qos_cpu_queues[cpu].tasklet.scheduled);
	}
	fail_notifier = false;
	assert(!natflow_qos_queue_init());
	assert(!qos_cpu_queues[3].online);
	mock_cpu = 3;
	queue(0, mock_now + 100);
	assert_empty();
	mock_hotplug_cpu(3, true);
	test_affinity_and_continuation();
	test_order_and_budget();
	test_hotplug_and_reset();
	test_global_caps_and_failures();
	test_concurrent_producers();
	test_concurrent_capacity();
	test_reset_racing_enqueue();
	test_reset_with_offline_cpu();
	test_bridge_dependencies();
	test_device_lifecycle();
	test_inflight_device_event();
	test_online_racing_device_event();
	for (mock_cpu = 0; mock_cpu < 3; mock_cpu++) queue(0, mock_now + 100);
	mock_cpu = 0;
	natflow_qos_queue_exit();
	assert(!mock_startup && !mock_teardown);
	assert(!mock_netdev_notifier);
	for (unsigned int cpu = 0; cpu < MOCK_CPUS; cpu++) {
		assert(!qos_cpu_queues[cpu].timer.active);
		assert(!qos_cpu_queues[cpu].tasklet.scheduled);
	}
	assert_empty();
	queue(0, mock_now + 100);
	assert_empty();
	puts("QoS owner CPU, atomic limits, reset, hotplug, bridge references and device lifecycle: PASS");
	return 0;
}
