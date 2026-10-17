#ifndef _NATFLOW_QOS_H_
#define _NATFLOW_QOS_H_

#include <linux/types.h>
#include "natflow_compat.h"

struct sk_buff;
struct nf_hook_state;

#define NATFLOW_QOS_BUFFER_DEFAULT (NATFLOW_HAVE_QOS_BUFFER ? 100 : 0)
#define NATFLOW_QOS_BUFFER_MAX 1000
#define NATFLOW_QOS_QUEUE_PACKETS 4096
#define NATFLOW_QOS_QUEUE_MEMORY (8 * 1024 * 1024)

struct natflow_qos_stamp {
	u64 time;
	u32 generation;
};

struct natflow_qos_stats {
	u32 packets;
	u32 memory;
	u64 queued;
	u64 sent;
	u64 dropped;
};

/* Both buckets reserve the same departure time. Caller holds their locks. */
static inline bool natflow_qos_reserve(u64 now, u64 limit,
                                       u64 group_next, u64 user_next, u64 *departure)
{
	u64 next = now;

	if (group_next > next)
		next = group_next;
	if (user_next > next)
		next = user_next;
	if (next - now > limit)
		return false;
	*departure = next;
	return true;
}

int natflow_qos_queue_init(void);
void natflow_qos_queue_exit(void);
void natflow_qos_queue_reset(u32 generation);
void natflow_qos_queue_stats(struct natflow_qos_stats *stats);
void natflow_qos_drop(void);
void natflow_qos_xmit(struct sk_buff *skb, const struct natflow_qos_stamp *stamp);

#if NATFLOW_HAVE_QOS_BUFFER
#include <linux/netfilter.h>
unsigned int natflow_qos_post_queue(struct sk_buff *skb,
                                    const struct nf_hook_state *state, nf_hookfn *hook,
                                    const struct natflow_qos_stamp *stamp);
#endif

#endif
