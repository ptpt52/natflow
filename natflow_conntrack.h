/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 27 Jun 2018 22:13:17 +0800
 */
#ifndef _NATFLOW_CONNTRACK_H_
#define _NATFLOW_CONNTRACK_H_
#include <linux/types.h>
#include <linux/bitops.h>
#include <linux/compiler.h>
#include <linux/atomic.h>

extern int conntrackinfo_init(void);
extern void conntrackinfo_exit(void);

#endif /* _NATFLOW_CONNTRACK_H_ */
