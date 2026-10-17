/* Exercise the production reservation code; no module loading is needed. */
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t u64;
typedef uint32_t u32;
typedef pthread_mutex_t spinlock_t;
#define NATFLOW_HAVE_QOS_BUFFER 0
#define HZ 1000
#define NSEC_PER_SEC 1000000000ULL
#define NSEC_PER_MSEC 1000000ULL

struct sk_buff {
	int len;
};
struct qos_conf {
	unsigned int buffer_ms;
	u32 generation;
};
static u64 mock_now = NSEC_PER_SEC;
static atomic_uint drops;

static u64 ktime_get_ns(void)
{
	return mock_now;
}
static u64 div_u64(u64 dividend, u32 divisor)
{
	return dividend / divisor;
}
static int natflow_token_len(struct sk_buff *skb)
{
	return skb->len;
}
static void spin_lock_bh(spinlock_t *lock)
{
	assert(!pthread_mutex_lock(lock));
}
static void spin_unlock_bh(spinlock_t *lock)
{
	assert(!pthread_mutex_unlock(lock));
}
void natflow_qos_drop(void)
{
	atomic_fetch_add(&drops, 1);
}

#include "production.h"

static void bucket_init(struct token_ctrl *bucket, int rate)
{
	memset(bucket, 0, sizeof(*bucket));
	assert(!pthread_mutex_init(&bucket->lock, NULL));
	bucket->tokens_per_jiffy = rate;
}

static void test_burst_and_limits(void)
{
	struct token_ctrl group, user;
	struct qos_conf conf = { .buffer_ms = 100, .generation = 1 };
	struct sk_buff skb = { .len = 1500 };
	struct natflow_qos_stamp stamp = { 0 };
	u64 next;
	unsigned int i;

	bucket_init(&group, 0);
	bucket_init(&user, 0);
	assert(!natflow_token_schedule(&skb, NULL, 0, &user, &conf, &stamp));
	assert(!stamp.time && !user.next_send);
	for (i = 0; i < 9; i++) {
		assert(!natflow_token_schedule(&skb, &group, 125, &user, &conf, &stamp));
		assert(stamp.time == mock_now + i * 12 * NSEC_PER_MSEC);
	}
	next = group.next_send;
	assert(natflow_token_schedule(&skb, &group, 125, &user, &conf, &stamp) == -ENOBUFS);
	assert(group.next_send == next && !user.next_send);
	/* An idle period discards credit rather than accumulating a burst. */
	mock_now += NSEC_PER_SEC;
	assert(!natflow_token_schedule(&skb, &group, 125, &user, &conf, &stamp));
	assert(stamp.time == mock_now);
	/* Both limits constrain departure; rejection changes neither bucket. */
	user.tokens_per_jiffy = 1;
	conf.generation++;
	assert(!natflow_token_schedule(&skb, &group, 125, &user, &conf, &stamp));
	assert(stamp.time == mock_now && stamp.generation == conf.generation);
	next = group.next_send;
	assert(natflow_token_schedule(&skb, &group, 125, &user, &conf, &stamp) == -ENOBUFS);
	assert(group.next_send == next);
	assert(user.next_send == mock_now + 1500 * NSEC_PER_MSEC);
	skb.len = 0;
	stamp.time = 0;
	assert(!natflow_token_schedule(&skb, &group, 125, &user, &conf, &stamp));
	assert(!stamp.time && group.next_send == next);
	assert(!pthread_mutex_destroy(&group.lock));
	assert(!pthread_mutex_destroy(&user.lock));
}

static void test_boundaries(void)
{
	struct token_ctrl user;
	struct qos_conf conf = { .buffer_ms = 100, .generation = 1 };
	struct sk_buff skb = { .len = 1 };
	struct natflow_qos_stamp stamp = { 0 };
	u64 due = 0;

	assert(natflow_qos_reserve(mock_now, 100, mock_now + 100, 0, &due));
	assert(due == mock_now + 100);
	assert(!natflow_qos_reserve(mock_now, 100, 0, mock_now + 101, &due));
	bucket_init(&user, UINT_MAX / HZ);
	assert(!natflow_token_schedule(&skb, NULL, 0, &user, &conf, &stamp));
	assert(user.next_send == mock_now + 1);
	/* A new generation ignores an old reservation far into the future. */
	user.next_send = mock_now + 100 * NSEC_PER_SEC;
	conf.generation++;
	assert(!natflow_token_schedule(&skb, NULL, 0, &user, &conf, &stamp));
	assert(stamp.time == mock_now);
	assert(!pthread_mutex_destroy(&user.lock));
}

#define THREADS 8
#define PER_THREAD 100
static struct token_ctrl shared_group;
static u64 departures[THREADS][PER_THREAD];

static void *reserve_thread(void *arg)
{
	size_t thread = (size_t)arg;
	struct token_ctrl user;
	struct qos_conf conf = { .buffer_ms = 1000, .generation = 1 };
	struct sk_buff skb = { .len = 100 };
	struct natflow_qos_stamp stamp = { 0 };
	unsigned int i;

	bucket_init(&user, 0);
	for (i = 0; i < PER_THREAD; i++) {
		assert(!natflow_token_schedule(&skb, &shared_group, 1000, &user, &conf, &stamp));
		departures[thread][i] = stamp.time;
	}
	assert(!pthread_mutex_destroy(&user.lock));
	return NULL;
}

static int compare_time(const void *a, const void *b)
{
	u64 x = *(const u64 *)a, y = *(const u64 *)b;
	return (x > y) - (x < y);
}

static void test_concurrent_group(void)
{
	pthread_t threads[THREADS];
	u64 sorted[THREADS * PER_THREAD];
	unsigned int i;

	bucket_init(&shared_group, 0);
	for (i = 0; i < THREADS; i++)
		assert(!pthread_create(&threads[i], NULL, reserve_thread, (void *)(size_t)i));
	for (i = 0; i < THREADS; i++)
		assert(!pthread_join(threads[i], NULL));
	memcpy(sorted, departures, sizeof(sorted));
	qsort(sorted, THREADS * PER_THREAD, sizeof(u64), compare_time);
	for (i = 0; i < THREADS * PER_THREAD; i++)
		assert(sorted[i] == mock_now + i * 100000ULL);
	assert(!pthread_mutex_destroy(&shared_group.lock));
}

int main(void)
{
	test_burst_and_limits();
	test_boundaries();
	test_concurrent_group();
	assert(atomic_load(&drops) == 2);
	puts("QoS reservation tests passed (including 800 concurrent reservations)");
	return 0;
}
