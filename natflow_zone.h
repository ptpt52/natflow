/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Mon, 02 Jul 2018 15:36:09 +0800
 */
#ifndef _NATFLOW_ZONE_H_
#define _NATFLOW_ZONE_H_
#include <linux/netdevice.h>

#define INVALID_ZONE_ID 127
#define ZONE_ID_MASK 127
#define MAX_ZONE_ID (ZONE_ID_MASK - 1)

#define ZONE_TYPE_SHIFT 7
#define ZONE_TYPE_MASK (1 << ZONE_TYPE_SHIFT)

#define ZONE_TYPE_LAN 1
#define ZONE_TYPE_WAN 0

struct zone_match_t {
	struct list_head list;
	int type;
	int id;
	unsigned char if_name[IFNAMSIZ];
};

static inline int natflow_zone_id_get(const struct net_device *dev)
{
	if (strlen(dev->name) + 2 > IFNAMSIZ)
		return INVALID_ZONE_ID;
	return dev->name[IFNAMSIZ - 1] & ZONE_ID_MASK;
}

static inline int natflow_zone_id_set(struct net_device *dev, int id)
{
	if (strlen(dev->name) + 2 > IFNAMSIZ)
		return -1;
	dev->name[IFNAMSIZ - 1] = (dev->name[IFNAMSIZ - 1] & ZONE_TYPE_MASK) | (id & ZONE_ID_MASK);
	return 0;
}

static inline int natflow_zone_type_get(const struct net_device *dev)
{
	if (strlen(dev->name) + 2 > IFNAMSIZ)
		return INVALID_ZONE_ID;
	return (dev->name[IFNAMSIZ - 1] & ZONE_TYPE_MASK) >> ZONE_TYPE_SHIFT;
}

static inline int natflow_zone_type_set(struct net_device *dev, int type)
{
	if (strlen(dev->name) + 2 > IFNAMSIZ)
		return -1;
	dev->name[IFNAMSIZ - 1] = (dev->name[IFNAMSIZ - 1] & ZONE_ID_MASK) | ((type << ZONE_TYPE_SHIFT) & ZONE_TYPE_MASK);
	return 0;
}

int natflow_zone_init(void);
void natflow_zone_exit(void);

#endif /* _NATFLOW_ZONE_H_ */
