/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 27 Jun 2018 22:13:17 +0800
 */
#ifndef _NATFLOW_USER_H_
#define _NATFLOW_USER_H_
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/atomic.h>
#include <linux/if_ether.h>
#include <net/netfilter/nf_conntrack.h>

typedef struct fakeuser_data_t {
	uint32_t timestamp;
	uint8_t macaddr[ETH_ALEN];
	uint8_t auth_type;
	uint8_t auth_status;
	uint16_t auth_rule_id;
	uint16_t auth_rule_magic;
} fakeuser_data_t;

typedef struct nf_conn natflow_fakeuser_t;

extern natflow_fakeuser_t *natflow_user_get(struct nf_conn *ct);
extern natflow_fakeuser_t *natflow_user_in(struct nf_conn *ct);

extern void natflow_user_timeout_touch(natflow_fakeuser_t *nfu);

extern int natflow_user_init(void);
extern void natflow_user_exit(void);

extern void natflow_user_disabled_set(int v);
extern int natflow_user_disabled_get(void);

static inline struct fakeuser_data_t *natflow_fakeuser_data(natflow_fakeuser_t *nfu)
{
	return (void *)nfu->ext + nfu->ext->len;
}
#define FAKEUSER_IPADDR(u) ((natflow_fakeuser_t *)(u)->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.u3.ip)

static inline unsigned int timestamp_offset(unsigned int a, unsigned int b)
{
	if (b > a)
		return b - a;
	return a - b;
}

#endif /* _NATFLOW_USER_H_ */
