/* Kernel model for the production per-CPU QoS queue regression. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
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
#define DEFINE_PER_CPU(type, name) type name[MOCK_CPUS]
#define per_cpu_ptr(ptr, cpu) (&(*(ptr))[cpu])
#define this_cpu_ptr(ptr) per_cpu_ptr(ptr, mock_cpu)
#define for_each_possible_cpu(cpu) for ((cpu) = 0; (cpu) < MOCK_CPUS; (cpu)++)
#define smp_processor_id() mock_cpu
#define READ_ONCE(x) (x)
#define container_of(p, type, member) ((type *)((char *)(p) - offsetof(type, member)))

typedef pthread_mutex_t spinlock_t;
#define DEFINE_SPINLOCK(name) spinlock_t name = PTHREAD_MUTEX_INITIALIZER
static void spin_lock_bh(spinlock_t *lock) {
	assert(!pthread_mutex_lock(lock));
}
static void spin_unlock_bh(spinlock_t *lock) {
	assert(!pthread_mutex_unlock(lock));
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
static struct rb_node *rb_first(const struct rb_root *root)
{
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
	(void)root;
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
};
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
static struct net_device *nf_bridge_get_physindev_compat(struct sk_buff *skb) {
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
static void dev_queue_xmit(struct sk_buff *skb)
{
	assert(mock_cpu == skb->enqueue_cpu);
	assert(atomic_load(&skb->dev->refs) > 1);
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
	bool scheduled;
	unsigned int cpu;
};
static u64 mock_now = 1000000000ULL;
static u64 ktime_get_ns(void) {
	return mock_now;
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
	assert(mode == HRTIMER_MODE_ABS_PINNED);
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
static int (*mock_startup)(unsigned int), (*mock_teardown)(unsigned int);
static int cpuhp_setup_state(int state, const char *name,
                             int (*startup)(unsigned int), int (*teardown)(unsigned int))
{
	unsigned int saved = mock_cpu;
	(void)name;
	assert(state == CPUHP_AP_ONLINE_DYN && !mock_startup);
	if (fail_cpuhp) return -ENOMEM;
	mock_startup = startup;
	mock_teardown = teardown;
	for (mock_cpu = 0; mock_cpu < MOCK_CPUS; mock_cpu++)
		if (mock_online[mock_cpu]) assert(!startup(mock_cpu));
	mock_cpu = saved;
	return state + 1;
}
static void cpuhp_remove_state_nocalls(int state)
{
	assert(state == CPUHP_AP_ONLINE_DYN + 1 && mock_startup);
	mock_startup = mock_teardown = NULL;
}
