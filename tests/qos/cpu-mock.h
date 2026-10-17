/* Kernel model for the production per-CPU QoS queue regression. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint32_t u32;
typedef uint64_t u64;
#define NATFLOW_HAVE_QOS_BUFFER 1
#define NATFLOW_NF_HOOKS_HAVE_FAMILY_ARRAYS 1
#define NATFLOW_HAVE_HRTIMER_SETUP 0
#define NATFLOW_NF_BRIDGE_PHYSINDEV_TAKES_NET 1
#define CONFIG_NETFILTER_FAMILY_BRIDGE 1
#define CONFIG_BRIDGE_NETFILTER 1
#define IS_ENABLED(x) (x)
#define GFP_ATOMIC 0
#define HRTIMER_MODE_ABS 0
#define HRTIMER_MODE_ABS_PINNED 2
#define unlikely(x) (x)
#define MOCK_CPUS 4
static _Thread_local unsigned int mock_cpu;
static _Thread_local bool mock_in_ipi;
#define DEFINE_PER_CPU(type, name) type name[MOCK_CPUS]
#define per_cpu_ptr(ptr, cpu) (&(*(ptr))[cpu])
#define this_cpu_ptr(ptr) per_cpu_ptr(ptr, mock_cpu)
#define for_each_possible_cpu(cpu) for ((cpu) = 0; (cpu) < MOCK_CPUS; (cpu)++)
#define smp_processor_id() mock_cpu
#define READ_ONCE(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)
#define WRITE_ONCE(x, v) __atomic_store_n(&(x), (v), __ATOMIC_RELAXED)
#define container_of(p, type, member) ((type *)((char *)(p) - offsetof(type, member)))

/* Each logical CPU serializes BH sections independently of all other CPUs. */
static pthread_mutex_t mock_bh_locks[MOCK_CPUS] = {
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER,
	PTHREAD_MUTEX_INITIALIZER, PTHREAD_MUTEX_INITIALIZER
};
static _Thread_local unsigned int mock_bh_depth;
static void local_bh_disable(void)
{
	if (!mock_bh_depth++) assert(!pthread_mutex_lock(&mock_bh_locks[mock_cpu]));
}
static void local_bh_enable(void)
{
	assert(mock_bh_depth);
	if (!--mock_bh_depth) assert(!pthread_mutex_unlock(&mock_bh_locks[mock_cpu]));
}

typedef struct {
	atomic_int value;
} atomic_t;
#define ATOMIC_INIT(n) { ATOMIC_VAR_INIT(n) }
static void (*mock_after_atomic_read)(const atomic_t *);
static int atomic_read(const atomic_t *v) {
	int value = atomic_load(&v->value);
	if (mock_after_atomic_read) mock_after_atomic_read(v);
	return value;
}
static void (*mock_after_charge)(atomic_t *);
static int atomic_cmpxchg(atomic_t *v, int old, int n)
{
	if (atomic_compare_exchange_strong(&v->value, &old, n) && mock_after_charge)
		mock_after_charge(v);
	return old;
}
static void atomic_sub(int n, atomic_t *v)
{
	assert(atomic_fetch_sub(&v->value, n) >= n);
}
static void atomic_dec(atomic_t *v) {
	atomic_sub(1, v);
}
static void atomic_inc(atomic_t *v) {
	atomic_fetch_add(&v->value, 1);
}

/* This models reader/writer exclusion, not a real kernel seqcount. */
struct u64_stats_sync {
	pthread_rwlock_t lock;
	bool initialized;
};
static void u64_stats_init(struct u64_stats_sync *s)
{
	if (s->initialized) assert(!pthread_rwlock_destroy(&s->lock));
	assert(!pthread_rwlock_init(&s->lock, NULL));
	s->initialized = true;
}
static void u64_stats_update_begin(struct u64_stats_sync *s)
{
	assert(mock_bh_depth);
	assert(!pthread_rwlock_wrlock(&s->lock));
}
static void u64_stats_update_end(struct u64_stats_sync *s)
{
	assert(!pthread_rwlock_unlock(&s->lock));
}
static unsigned int u64_stats_fetch_begin(struct u64_stats_sync *s)
{
	assert(!pthread_rwlock_rdlock(&s->lock));
	return 0;
}
static bool u64_stats_fetch_retry(struct u64_stats_sync *s, unsigned int start)
{
	(void)start;
	assert(!pthread_rwlock_unlock(&s->lock));
	return false;
}

static pthread_rwlock_t mock_rcu = PTHREAD_RWLOCK_INITIALIZER;
static _Thread_local unsigned int mock_rcu_depth;
static void rcu_read_lock(void)
{
	if (!mock_rcu_depth++) assert(!pthread_rwlock_rdlock(&mock_rcu));
}
static void rcu_read_unlock(void)
{
	assert(mock_rcu_depth);
	if (!--mock_rcu_depth) assert(!pthread_rwlock_unlock(&mock_rcu));
}
#define rcu_read_lock_bh rcu_read_lock
#define rcu_read_unlock_bh rcu_read_unlock
#define rcu_dereference(p) (p)
static void (*mock_before_sync_net)(void);
static void synchronize_net(void)
{
	assert(!mock_rcu_depth && !mock_bh_depth);
	if (mock_before_sync_net) mock_before_sync_net();
	assert(!pthread_rwlock_wrlock(&mock_rcu));
	assert(!pthread_rwlock_unlock(&mock_rcu));
}

struct list_head {
	struct list_head *next, *prev;
};
#define LIST_HEAD(name) struct list_head name = { &name, &name }
static void list_add_tail(struct list_head *node, struct list_head *head)
{
	node->prev = head->prev;
	node->next = head;
	head->prev->next = node;
	head->prev = node;
}
#define list_for_each_entry_safe(p, n, head, member) \
	for ((p) = container_of((head)->next, __typeof__(*(p)), member), \
	     (n) = container_of((p)->member.next, __typeof__(*(p)), member); \
	     &(p)->member != (head); \
	     (p) = (n), (n) = container_of((n)->member.next, __typeof__(*(n)), member))

/* The mock tree is an unbalanced BST; the kernel provides RB balancing. */
struct rb_node {
	struct rb_node *left, *right, *parent;
};
struct rb_root {
	struct rb_node *rb_node;
};
#define RB_ROOT ((struct rb_root){ 0 })
#define RB_EMPTY_ROOT(root) (!(root)->rb_node)
#define rb_left left
#define rb_right right
#define rb_entry(p, type, member) container_of(p, type, member)
static void mock_tree_access(const struct rb_root *root);
static struct rb_node *rb_first(const struct rb_root *root)
{
	mock_tree_access(root);
	struct rb_node *n = root->rb_node;
	if (n) while (n->left) n = n->left;
	return n;
}
static void rb_link_node(struct rb_node *n, struct rb_node *parent, struct rb_node **link)
{
	n->parent = parent;
	n->left = n->right = NULL;
	*link = n;
}
static void rb_insert_color(struct rb_node *n, struct rb_root *root) {
	(void)n;
	mock_tree_access(root);
}
static void rb_replace(struct rb_root *root, struct rb_node *old, struct rb_node *n)
{
	if (!old->parent) root->rb_node = n;
	else if (old == old->parent->left) old->parent->left = n;
	else old->parent->right = n;
	if (n) n->parent = old->parent;
}
static void rb_erase(struct rb_node *n, struct rb_root *root)
{
	mock_tree_access(root);
	if (!n->left) rb_replace(root, n, n->right);
	else if (!n->right) rb_replace(root, n, n->left);
	else {
		struct rb_node *successor = n->right;
		while (successor->left) successor = successor->left;
		if (successor->parent != n) {
			rb_replace(root, successor, successor->right);
			successor->right = n->right;
			successor->right->parent = successor;
		}
		rb_replace(root, n, successor);
		successor->left = n->left;
		successor->left->parent = successor;
	}
}

static int fail_alloc_at, fail_cpuhp;
static atomic_uint allocations, skb_allocations;
static void *kzalloc(size_t size, int flags)
{
	(void)flags;
	if (fail_alloc_at && !--fail_alloc_at) return NULL;
	void *p = calloc(1, size);
	assert(p);
	atomic_fetch_add(&allocations, 1);
	return p;
}
static void kfree(void *p)
{
	if (p) {
		assert(atomic_fetch_sub(&allocations, 1));
		free(p);
	}
}
struct net_device {
	atomic_bool running, present;
	atomic_uint refs, holds, puts;
	struct net *net;
};
static struct net *dev_net(struct net_device *dev) {
	return dev->net;
}
static bool netif_running(const struct net_device *dev) {
	return atomic_load(&dev->running);
}
static bool netif_device_present(const struct net_device *dev) {
	return atomic_load(&dev->present);
}
static void dev_hold(struct net_device *dev)
{
	assert(atomic_fetch_add(&dev->refs, 1));
	atomic_fetch_add(&dev->holds, 1);
}
static void dev_put(struct net_device *dev)
{
	assert(atomic_fetch_sub(&dev->refs, 1) > 1);
	atomic_fetch_add(&dev->puts, 1);
}
struct sock {
	atomic_uint sk_refcnt;
};
static bool refcount_inc_not_zero(atomic_uint *refs)
{
	unsigned int old = atomic_load(refs);
	while (old && !atomic_compare_exchange_weak(refs, &old, old + 1)) {}
	return old != 0;
}
static void sock_gen_put(struct sock *sk) {
	assert(atomic_fetch_sub(&sk->sk_refcnt, 1) > 1);
}
struct dst_entry {
	struct net_device *dev;
	unsigned int flags;
};
#define DST_FAKE_RTABLE 1
struct sk_buff {
	struct net_device *dev, *physin, *physout;
	struct dst_entry *dst;
	unsigned int truesize;
	bool fail_dst;
	unsigned int enqueue_cpu, sequence;
};
static struct dst_entry *skb_dst(struct sk_buff *skb) {
	return skb->dst;
}
static void skb_dst_force(struct sk_buff *skb) {
	if (skb->fail_dst) skb->dst = NULL;
}
static struct net_device *nf_bridge_get_physindev(struct sk_buff *skb, struct net *net) {
	(void)net;
	return skb->physin;
}
static struct net_device *nf_bridge_get_physoutdev(struct sk_buff *skb) {
	return skb->physout;
}
static void kfree_skb(struct sk_buff *skb)
{
	if (skb->dst) assert(atomic_load(&skb->dst->dev->refs));
	if (skb->physin) assert(atomic_load(&skb->physin->refs));
	if (skb->physout) assert(atomic_load(&skb->physout->refs));
	assert(atomic_fetch_sub(&skb_allocations, 1));
	free(skb);
}
static atomic_uint xmitted;
static unsigned int last_sequence[MOCK_CPUS];
static bool check_sequence;
static void (*mock_before_xmit)(void);
static void dev_queue_xmit(struct sk_buff *skb)
{
	assert(mock_cpu == skb->enqueue_cpu);
	assert(atomic_load(&skb->dev->refs) > 1);
	if (mock_before_xmit) mock_before_xmit();
	if (check_sequence) {
		assert(skb->sequence == last_sequence[mock_cpu] + 1);
		last_sequence[mock_cpu] = skb->sequence;
	}
	atomic_fetch_add(&xmitted, 1);
	kfree_skb(skb);
}

#define NFPROTO_IPV4 2
#define NFPROTO_IPV6 10
#define NFPROTO_BRIDGE 7
#define NF_ACCEPT 1
#define NF_DROP 0
#define NF_STOLEN 2
struct nf_hook_state;
typedef unsigned int nf_hookfn(void *, struct sk_buff *, const struct nf_hook_state *);
struct nf_hook_entry {
	nf_hookfn *hook;
	void *priv;
};
struct nf_hook_entries {
	unsigned int num_hook_entries;
	struct nf_hook_entry hooks[4];
};
struct net {
	atomic_uint refs;
	struct {
		struct nf_hook_entries *hooks_ipv4[5], *hooks_ipv6[5], *hooks_bridge[5];
	} nf;
};
static void get_net(struct net *net) {
	assert(atomic_fetch_add(&net->refs, 1));
}
static void put_net(struct net *net) {
	assert(atomic_fetch_sub(&net->refs, 1) > 1);
}
struct nf_hook_state {
	u32 pf, hook;
	struct net_device *in, *out;
	struct sock *sk;
	struct net *net;
	int (*okfn)(struct net *, struct sock *, struct sk_buff *);
};
static int nf_hook_slow(struct sk_buff *skb, struct nf_hook_state *state,
                        const struct nf_hook_entries *entries, unsigned int i)
{
	assert(mock_rcu_depth);
	for (; i < entries->num_hook_entries; i++) {
		if (entries->hooks[i].hook(NULL, skb, state) == NF_DROP) {
			kfree_skb(skb);
			return -EPERM;
		}
	}
	return 1;
}

enum hrtimer_restart { HRTIMER_NORESTART };
struct hrtimer {
	enum hrtimer_restart (*function)(struct hrtimer *);
	u64 expires;
	unsigned int cpu;
	bool active;
};
struct tasklet_struct {
	void (*function)(unsigned long);
	unsigned long data;
	atomic_bool scheduled;
	atomic_uint cpu;
};
static u64 mock_now = 1000000000ULL;
static u64 ktime_get_ns(void) {
	return READ_ONCE(mock_now);
}
static u64 ns_to_ktime(u64 n) {
	return n;
}
static void hrtimer_init(struct hrtimer *t, int clock, int mode) {
	(void)clock;
	(void)mode;
	t->expires = 0;
	t->active = false;
}
static void hrtimer_start(struct hrtimer *t, u64 n, int mode) {
	assert(mode == HRTIMER_MODE_ABS_PINNED && mock_bh_depth);
	t->expires = n;
	t->cpu = mock_cpu;
	t->active = true;
}
static void hrtimer_cancel(struct hrtimer *t) {
	t->active = false;
	t->expires = 0;
}
static void tasklet_init(struct tasklet_struct *t, void (*fn)(unsigned long), unsigned long data)
{
	t->function = fn;
	t->data = data;
	t->scheduled = false;
}
static void tasklet_schedule(struct tasklet_struct *t) {
	t->cpu = mock_cpu;
	t->scheduled = true;
}
static void tasklet_kill(struct tasklet_struct *t) {
	t->scheduled = false;
}

#define CPUHP_AP_ONLINE_DYN 100
static bool mock_online[MOCK_CPUS] = { true, true, true, false };
static pthread_rwlock_t mock_hotplug_lock = PTHREAD_RWLOCK_INITIALIZER;
static _Thread_local bool mock_cpus_locked;
#define for_each_online_cpu(cpu) \
	for_each_possible_cpu(cpu) if (mock_online[cpu])
static void cpus_read_lock(void)
{
	assert(!mock_bh_depth && !mock_cpus_locked);
	assert(!pthread_rwlock_rdlock(&mock_hotplug_lock));
	mock_cpus_locked = true;
}
static void cpus_read_unlock(void)
{
	assert(mock_cpus_locked);
	mock_cpus_locked = false;
	assert(!pthread_rwlock_unlock(&mock_hotplug_lock));
}
static void (*mock_before_work)(unsigned int);
static unsigned int mock_work_calls;
static long work_on_cpu(unsigned int cpu, long (*fn)(void *), void *arg)
{
	unsigned int saved = mock_cpu;
	long ret;

	assert(mock_cpus_locked && mock_online[cpu] && !mock_bh_depth);
	if (mock_before_work) mock_before_work(cpu);
	mock_work_calls++;
	mock_cpu = cpu;
	ret = fn(arg);
	assert(!mock_bh_depth);
	mock_cpu = saved;
	return ret;
}
static int (*mock_startup)(unsigned int), (*mock_teardown)(unsigned int);
static void mock_hotplug_cpu(unsigned int cpu, bool online)
{
	unsigned int saved = mock_cpu;

	assert(!mock_bh_depth && !mock_cpus_locked);
	assert(!pthread_rwlock_wrlock(&mock_hotplug_lock));
	mock_cpu = cpu;
	if (online) {
		mock_online[cpu] = true;
		assert(!mock_startup(cpu));
	} else {
		assert(!mock_teardown(cpu));
		mock_online[cpu] = false;
	}
	mock_cpu = saved;
	assert(!pthread_rwlock_unlock(&mock_hotplug_lock));
}
static int cpuhp_setup_state(int state, const char *name,
                             int (*startup)(unsigned int), int (*teardown)(unsigned int))
{
	(void)name;
	assert(state == CPUHP_AP_ONLINE_DYN && !mock_startup);
	if (fail_cpuhp) return -ENOMEM;
	mock_startup = startup;
	mock_teardown = teardown;
	for (unsigned int cpu = 0; cpu < MOCK_CPUS; cpu++)
		if (mock_online[cpu]) mock_hotplug_cpu(cpu, true);
	return state + 1;
}
static void cpuhp_remove_state(int state)
{
	unsigned int saved = mock_cpu;

	assert(state == CPUHP_AP_ONLINE_DYN + 1 && mock_startup);
	/* Removing a callback does not physically offline the CPU. */
	for (unsigned int cpu = 0; cpu < MOCK_CPUS; cpu++) {
		if (!mock_online[cpu]) continue;
		mock_cpu = cpu;
		assert(!mock_teardown(cpu));
	}
	mock_cpu = saved;
	mock_startup = mock_teardown = NULL;
}

/* IPIs may interrupt BH-disabled code; they must never access the queue tree. */
static unsigned int mock_ipi_calls;
static void on_each_cpu(void (*fn)(void *), void *arg, int wait)
{
	unsigned int saved = mock_cpu;

	assert(wait == 1 && !mock_in_ipi);
	mock_in_ipi = true;
	for (unsigned int cpu = 0; cpu < MOCK_CPUS; cpu++) {
		if (!mock_online[cpu]) continue;
		mock_cpu = cpu;
		mock_ipi_calls++;
		fn(arg);
	}
	mock_cpu = saved;
	mock_in_ipi = false;
}
#define NETDEV_REGISTER 1
#define NETDEV_UP 2
#define NETDEV_GOING_DOWN 3
#define NETDEV_DOWN 4
#define NETDEV_UNREGISTER 5
#define NOTIFY_DONE 0
struct notifier_block {
	int (*notifier_call)(struct notifier_block *, unsigned long, void *);
};
static struct notifier_block *mock_netdev_notifier;
static bool fail_notifier;
static int register_netdevice_notifier(struct notifier_block *nb)
{
	assert(!mock_netdev_notifier);
	if (fail_notifier) return -ENOMEM;
	mock_netdev_notifier = nb;
	return 0;
}
static void unregister_netdevice_notifier(struct notifier_block *nb)
{
	assert(mock_netdev_notifier == nb);
	/* Like the kernel, replay removal events during unregistration. */
	nb->notifier_call(nb, NETDEV_DOWN, NULL);
	nb->notifier_call(nb, NETDEV_UNREGISTER, NULL);
	mock_netdev_notifier = NULL;
}
static void mock_netdev_event(unsigned long event, struct net_device *dev)
{
	assert(mock_netdev_notifier);
	assert(mock_netdev_notifier->notifier_call(mock_netdev_notifier, event, dev) == NOTIFY_DONE);
}
