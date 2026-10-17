#include "cpu-mock.h"
#include "production-queue.h"

static struct net_device dev = { .running = true, .present = true, .refs = 1 };
static struct net net = { .refs = 1 };
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
		time, qos_generation
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
	assert(qos_stats.packets == 132);
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
	u64 dropped = qos_stats.dropped;
	mock_cpu = 0;
	queue(0, mock_now + 100);
	mock_cpu = 1;
	queue(0, mock_now + 100);
	/* Also kill a tasklet already scheduled on the CPU going offline. */
	qos_cpu_queues[1].timer.function(&qos_cpu_queues[1].timer);
	assert(!mock_teardown(1));
	mock_online[1] = false;
	assert(!qos_cpu_queues[1].timer.active && !qos_cpu_queues[1].tasklet.scheduled);
	assert(qos_stats.packets == 1 && qos_stats.dropped == dropped + 1);
	queue(0, mock_now + 100); /* Admission after teardown must fail. */
	assert(qos_stats.dropped == dropped + 2);
	mock_cpu = 3;
	mock_now += 100;
	poll_cpu(0);
	poll_cpu(1);
	assert(atomic_load(&xmitted) == sent + 1);
	assert_empty();

	mock_cpu = 1;
	mock_online[1] = true;
	assert(!mock_startup(1));
	queue(0, mock_now + 100);
	mock_now += 100;
	poll_cpu(1);
	assert(atomic_load(&xmitted) == sent + 2);
	assert_empty();

	/* Defend against an unexpected migrated tasklet: drop, never send. */
	queue(0, mock_now + 100);
	mock_cpu = 2;
	qos_dequeue((unsigned long)&qos_cpu_queues[1]);
	assert(atomic_load(&xmitted) == sent + 2);
	assert_empty();
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
	assert(qos_stats.packets == NATFLOW_QOS_QUEUE_PACKETS);
	u64 dropped = qos_stats.dropped;
	queue(0, mock_now + 100);
	assert(qos_stats.packets == NATFLOW_QOS_QUEUE_PACKETS && qos_stats.dropped == dropped + 1);
	natflow_qos_queue_reset(qos_generation + 1);
	assert_empty();

	struct natflow_qos_stamp s = stamp(mock_now + 100);
	unsigned int size = NATFLOW_QOS_QUEUE_MEMORY / 2 - sizeof(struct natflow_qos_packet);
	mock_cpu = 0;
	natflow_qos_xmit(packet(0, size), &s);
	mock_cpu = 2;
	natflow_qos_xmit(packet(0, size), &s);
	assert(qos_stats.memory == NATFLOW_QOS_QUEUE_MEMORY && qos_stats.packets == 2);
	queue(0, mock_now + 100);
	assert(qos_stats.memory == NATFLOW_QOS_QUEUE_MEMORY && qos_stats.packets == 2);
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
	assert(qos_stats.packets == 2400);
	mock_now += 100;
	while (qos_stats.packets) {
		for (unsigned int cpu = 0; cpu < 3; cpu++) poll_cpu(cpu);
		mock_now += 1000;
	}
	for (unsigned int cpu = 0; cpu < 3; cpu++) assert(last_sequence[cpu] == 800);
	check_sequence = false;
	assert_empty();
}

int main(void)
{
	fail_cpuhp = 1;
	assert(natflow_qos_queue_init() == -ENOMEM);
	assert(!mock_startup && !mock_teardown);
	fail_cpuhp = 0;
	assert(!natflow_qos_queue_init());
	assert(!qos_cpu_queues[3].online);
	mock_cpu = 3;
	queue(0, mock_now + 100);
	assert_empty();
	mock_online[3] = true;
	assert(!mock_startup(3));
	test_affinity_and_continuation();
	test_order_and_budget();
	test_hotplug_and_reset();
	test_global_caps_and_failures();
	test_concurrent_producers();
	for (mock_cpu = 0; mock_cpu < 3; mock_cpu++) queue(0, mock_now + 100);
	mock_cpu = 0;
	natflow_qos_queue_exit();
	assert(!mock_startup && !mock_teardown);
	for (unsigned int cpu = 0; cpu < MOCK_CPUS; cpu++) {
		assert(!qos_cpu_queues[cpu].timer.active);
		assert(!qos_cpu_queues[cpu].tasklet.scheduled);
	}
	assert_empty();
	queue(0, mock_now + 100);
	assert_empty();
	puts("QoS CPU affinity, continuation, hotplug, global limits and ownership: PASS");
	return 0;
}
