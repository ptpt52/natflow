/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Fri, 11 May 2018 14:20:46 +0800
 */
#ifndef _NATFLOW_H_
#define _NATFLOW_H_

#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/if_pppox.h>

typedef struct natflow_route_t {
	/* max L2 len supoorted
	 * mac + vlan + pppoe (=14 + 4 + 8)
	 */
#define NF_L2_MAX_LEN (14 + 4 + 8)
	unsigned short mtu;
	unsigned char l2_head[NF_L2_MAX_LEN];
	unsigned int l2_head_len;
	struct net_device *outdev;
} natflow_route_t;

#define NF_FF_OFFLOAD_BIT 0
#define NF_FF_OFFLOAD (1 << NF_FF_OFFLOAD_BIT)

#define NF_FF_ORIGINAL_BIT 8
#define NF_FF_ORIGINAL (1 << NF_FF_ORIGINAL_BIT)
#define NF_FF_REPLY_BIT 9
#define NF_FF_REPLY (1 << NF_FF_REPLY_BIT)
#define NF_FF_ORIGINAL_OK_BIT 10
#define NF_FF_ORIGINAL_OK (1 << NF_FF_ORIGINAL_OK_BIT)
#define NF_FF_REPLY_OK_BIT 11
#define NF_FF_REPLY_OK (1 << NF_FF_REPLY_OK_BIT)

typedef struct natflow_t {
	unsigned int magic;
	unsigned int status;
#define NF_FF_DIR_ORIGINAL 0
#define NF_FF_DIR_REPLY 1
#define NF_FF_DIR_MAX 2
	struct natflow_route_t rroute[NF_FF_DIR_MAX];
} natflow_t;

/*XXX don't change */
#define NATFLOW_MAGIC 0x464c4f57
struct nat_key_t {
	unsigned int magic;
	unsigned int ext_magic;
};
/*XXX refer to drivers/nos/src/nos.h */
#define IPS_NOS_TRACK_INIT_BIT 15
#define IPS_NOS_TRACK_INIT (1 << IPS_NOS_TRACK_INIT_BIT)
#define IPS_NATFLOW_USER_BIT 16
#define IPS_NATFLOW_USER (1 << IPS_NATFLOW_USER_BIT)
#define IPS_NATFLOW_STOP_BIT 18
#define IPS_NATFLOW_STOP (1 << IPS_NATFLOW_STOP_BIT)

#define IPS_NATFLOW_FF_BIT 14
#define IPS_NATFLOW_FF (1 << IPS_NATFLOW_FF_BIT)


static inline int simple_test_bit(int nr, const unsigned int *addr)
{
	return 1U & (addr[nr/32] >> (nr & (32-1)));
}

static inline void simple_clear_bit(int nr, unsigned int *addr)
{
	unsigned int mask = (1U << ((nr) % 32));
	unsigned int *p = ((unsigned int *)addr) + nr/32;
	*p &= ~mask;
}

static inline void simple_set_bit(int nr, unsigned int *addr)
{
	unsigned int mask = (1U << ((nr) % 32));
	unsigned int *p = ((unsigned int *)addr) + nr/32;
	*p |= mask;
}

static inline int simple_test_and_set_bit(int nr, unsigned int *addr)
{
	unsigned int mask = (1U << ((nr) % 32));
	unsigned int *p = ((unsigned int *)addr) + nr/32;
	unsigned int old;
	old = *p;
	*p |= mask;
	return (old & mask) != 0;
}

#endif /* _NATFLOW_H_ */
