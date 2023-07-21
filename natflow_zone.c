/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Mon, 02 Jul 2018 15:36:09 +0800
 */
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include "natflow_zone.h"
#include "natflow_common.h"

static int natflow_zone_major = 0;
static int natflow_zone_minor = 0;
static int number_of_devices = 1;
static struct cdev natflow_zone_cdev;
const char *natflow_zone_dev_name = "natflow_zone_ctl";
static struct class *natflow_zone_class;
static struct device *natflow_zone_dev;

static DEFINE_RWLOCK(zone_match_lock);
static LIST_HEAD(zone_match_list);

static inline int natflow_zone_add_tail(const struct zone_match_t *zm)
{
	struct zone_match_t *new;

	new = kmalloc(sizeof(struct zone_match_t), GFP_KERNEL);
	if (new == NULL)
		return -ENOMEM;

	memcpy(new, zm, sizeof(*new));
	INIT_LIST_HEAD(&new->list);

	write_lock_bh(&zone_match_lock);
	list_add_tail(&new->list, &zone_match_list);
	write_unlock_bh(&zone_match_lock);

	return 0;
}

static inline void natflow_zone_cleanup(void)
{
	struct zone_match_t *zm, *n;

	write_lock_bh(&zone_match_lock);
	list_for_each_entry_safe(zm, n, &zone_match_list, list) {
		list_del(&zm->list);
		kfree(zm);
	}
	write_unlock_bh(&zone_match_lock);
}

static inline int natflow_if_name_match(const char *p, const char *n)
{
	int i;
	int p_len = strlen(p);
	int n_len = strlen(n);

	if (n_len < p_len)
		return -1;

	for (i = 0; i < p_len; i++) {
		if (p[i] == n[i])
			continue;
		if (p[i] == '+')
			return 0;
		else
			return -1;
	}
	if (n_len > p_len)
		return -1;

	return 0;
}

static inline void natflow_zone_match_update(struct net_device *dev)
{
	struct zone_match_t *zm;

	read_lock_bh(&zone_match_lock);

	list_for_each_entry(zm, &zone_match_list, list) {
		if (natflow_if_name_match(zm->if_name, dev->name) == 0) {
			if (natflow_zone_id_set(dev, zm->id) == 0 && natflow_zone_type_set(dev, zm->type) == 0) {
				read_unlock_bh(&zone_match_lock);
				return;
			}
		}
	}
	if (natflow_zone_id_set(dev, INVALID_ZONE_ID) != 0) {
		NATFLOW_ERROR(DEBUG_FMT_PREFIX "natflow_zone_id_set fail\n", DEBUG_ARG_PREFIX);
	}

	read_unlock_bh(&zone_match_lock);
}

static inline void natflow_zone_match_refresh(void)
{
	struct net_device *dev;

	dev = first_net_device(&init_net);
	while (dev) {
		natflow_zone_match_update(dev);
		NATFLOW_INFO(DEBUG_FMT_PREFIX "dev=%s set zone=%u type=%u\n", DEBUG_ARG_PREFIX,
		             dev->name, natflow_zone_id_get(dev), natflow_zone_type_get(dev));
		dev = next_net_device(dev);
	}
}

//must lock by caller
static inline struct zone_match_t *natflow_zone_match_get(int idx)
{
	int i = 0;
	struct zone_match_t *zm;

	//lock by caller
	list_for_each_entry(zm, &zone_match_list, list) {
		if (i == idx)
			return zm;
		i++;
	}

	return NULL;
}

static int natflow_zone_ctl_buffer_use = 0;
static char *natflow_zone_ctl_buffer = NULL;
static void *natflow_zone_start(struct seq_file *m, loff_t *pos)
{
	int n = 0;

	if ((*pos) == 0) {
		n = snprintf(natflow_zone_ctl_buffer,
		             PAGE_SIZE - 1,
		             "# Usage:\n"
		             "#    lan_zone <id>=<if_name> -- set interface lan_zone\n"
		             "#    wan_zone <id>=<if_name> -- set interface wan_zone\n"
		             "#    clean -- clear all existing zone(s)\n"
		             "#    update_match -- refresh netdev zone match settings\n"
		             "#\n"
		             "# Info:"
		             "#  VALID ZONE ID RANGE: 0~%u\n"
		             "#\n"
		             "# Reload cmd:\n"
		             "\n"
		             "clean\n"
		             "\n",
		             MAX_ZONE_ID
		            );
		natflow_zone_ctl_buffer[n] = 0;
		return natflow_zone_ctl_buffer;
	} else if ((*pos) > 0) {
		struct zone_match_t *zm;

		read_lock_bh(&zone_match_lock);
		zm = (struct zone_match_t *)natflow_zone_match_get((*pos) - 1);
		if (zm) {
			natflow_zone_ctl_buffer[0] = 0;
			n = snprintf(natflow_zone_ctl_buffer,
			             PAGE_SIZE - 1,
			             "%s %u=%s\n",
			             zm->type == ZONE_TYPE_LAN ? "lan_zone" : "wan_zone",
			             zm->id, zm->if_name);
			natflow_zone_ctl_buffer[n] = 0;
			read_unlock_bh(&zone_match_lock);
			return natflow_zone_ctl_buffer;
		}
		read_unlock_bh(&zone_match_lock);
	}

	return NULL;
}

static void *natflow_zone_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	if ((*pos) > 0) {
		return natflow_zone_start(m, pos);
	}
	return NULL;
}

static void natflow_zone_stop(struct seq_file *m, void *v)
{
}

static int natflow_zone_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
	return 0;
}

const struct seq_operations natflow_zone_seq_ops = {
	.start = natflow_zone_start,
	.next = natflow_zone_next,
	.stop = natflow_zone_stop,
	.show = natflow_zone_show,
};

static ssize_t natflow_zone_read(struct file *file, char __user *buf, size_t buf_len, loff_t *offset)
{
	return seq_read(file, buf, buf_len, offset);
}

static ssize_t natflow_zone_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
{
	int err = 0;
	int n, l;
	int cnt = MAX_IOCTL_LEN;
	struct zone_match_t zm;
	static char data[MAX_IOCTL_LEN];
	static int data_left = 0;

	cnt -= data_left;
	if (buf_len < cnt)
		cnt = buf_len;

	if (copy_from_user(data + data_left, buf, cnt) != 0)
		return -EACCES;

	n = 0;
	while(n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t')) n++;
	if (n) {
		*offset += n;
		data_left = 0;
		return n;
	}

	//make sure line ended with '\n' and line len <= MAX_IOCTL_LEN
	l = 0;
	while (l < cnt && data[l + data_left] != '\n') l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= MAX_IOCTL_LEN) {
			NATFLOW_println("err: too long a line");
			data_left = 0;
			return -EINVAL;
		}
		goto done;
	} else {
		data[l + data_left] = '\0';
		data_left = 0;
		l++;
	}

	if (strncmp(data, "clean", 5) == 0) {
		natflow_zone_cleanup();
		goto done;
	} else if (strncmp(data, "lan_zone ", 9) == 0) {
		n = sscanf(data, "lan_zone %u=%s\n", &zm.id, zm.if_name);
		if (n == 2) {
			zm.type = ZONE_TYPE_LAN;
			if ((err = natflow_zone_add_tail(&zm)) == 0)
				goto done;
			NATFLOW_println("natflow_zone_add_tail() failed ret=%d", err);
		}
	} else if (strncmp(data, "wan_zone ", 9) == 0) {
		n = sscanf(data, "wan_zone %u=%s\n", &zm.id, zm.if_name);
		if (n == 2) {
			zm.type = ZONE_TYPE_WAN;
			if ((err = natflow_zone_add_tail(&zm)) == 0)
				goto done;
			NATFLOW_println("natflow_zone_add_tail() failed ret=%d", err);
		}
	} else if (strncmp(data, "update_match", 12) == 0) {
		natflow_zone_match_refresh();
		goto done;
	}

	NATFLOW_println("ignoring line[%s]", data);
	if (err != 0) {
		return err;
	}

done:
	*offset += l;
	return l;
}

static int natflow_zone_open(struct inode *inode, struct file *file)
{
	int ret;
	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	if (natflow_zone_ctl_buffer_use++ == 0) {
		natflow_zone_ctl_buffer = kmalloc(PAGE_SIZE, GFP_KERNEL);
		if (natflow_zone_ctl_buffer == NULL) {
			natflow_zone_ctl_buffer_use--;
			return -ENOMEM;
		}
	}

	ret = seq_open(file, &natflow_zone_seq_ops);
	if (ret)
		return ret;
	return 0;
}

static int natflow_zone_release(struct inode *inode, struct file *file)
{
	int ret = seq_release(inode, file);

	if (--natflow_zone_ctl_buffer_use == 0) {
		kfree(natflow_zone_ctl_buffer);
		natflow_zone_ctl_buffer = NULL;
	}

	return ret;
}

static struct file_operations natflow_zone_fops = {
	.owner = THIS_MODULE,
	.open = natflow_zone_open,
	.release = natflow_zone_release,
	.read = natflow_zone_read,
	.write = natflow_zone_write,
	.llseek  = seq_lseek,
};

static int zone_netdev_event(struct notifier_block *this, unsigned long event, void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (event != NETDEV_UP)
		return NOTIFY_DONE;

	NATFLOW_DEBUG("catch (NETDEV_UP) event for dev=%s\n", dev ? dev->name : "(null)");

	natflow_zone_match_update(dev);
	NATFLOW_WARN(DEBUG_FMT_PREFIX "dev=%s set zone=%u type=%u\n", DEBUG_ARG_PREFIX,
	             dev->name, natflow_zone_id_get(dev), natflow_zone_type_get(dev));

	return NOTIFY_DONE;
}

static struct notifier_block zone_netdev_notifier = {
	.notifier_call  = zone_netdev_event,
};

int natflow_zone_init(void)
{
	int retval = 0;
	dev_t devno;

	if (natflow_zone_major > 0) {
		devno = MKDEV(natflow_zone_major, natflow_zone_minor);
		retval = register_chrdev_region(devno, number_of_devices, natflow_zone_dev_name);
	} else {
		retval = alloc_chrdev_region(&devno, natflow_zone_minor, number_of_devices, natflow_zone_dev_name);
	}
	if (retval < 0) {
		NATFLOW_println("alloc_chrdev_region failed!");
		return retval;
	}
	natflow_zone_major = MAJOR(devno);
	natflow_zone_minor = MINOR(devno);
	NATFLOW_println("natflow_zone_major=%d, natflow_zone_minor=%d", natflow_zone_major, natflow_zone_minor);

	cdev_init(&natflow_zone_cdev, &natflow_zone_fops);
	natflow_zone_cdev.owner = THIS_MODULE;
	natflow_zone_cdev.ops = &natflow_zone_fops;

	retval = cdev_add(&natflow_zone_cdev, devno, 1);
	if (retval) {
		NATFLOW_println("adding chardev, error=%d", retval);
		goto cdev_add_failed;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	natflow_zone_class = class_create(THIS_MODULE, "natflow_zone_class");
#else
	natflow_zone_class = class_create("natflow_zone_class");
#endif
	if (IS_ERR(natflow_zone_class)) {
		NATFLOW_println("failed in creating class");
		retval = -EINVAL;
		goto class_create_failed;
	}

	natflow_zone_dev = device_create(natflow_zone_class, NULL, devno, NULL, natflow_zone_dev_name);
	if (!natflow_zone_dev) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	register_netdevice_notifier(&zone_netdev_notifier);
	natflow_zone_match_refresh();

	return 0;

	//device_destroy(natflow_zone_class, devno);
device_create_failed:
	class_destroy(natflow_zone_class);
class_create_failed:
	cdev_del(&natflow_zone_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, number_of_devices);

	return retval;
}

void natflow_zone_exit(void)
{
	dev_t devno;

	unregister_netdevice_notifier(&zone_netdev_notifier);

	devno = MKDEV(natflow_zone_major, natflow_zone_minor);
	device_destroy(natflow_zone_class, devno);
	class_destroy(natflow_zone_class);
	cdev_del(&natflow_zone_cdev);
	unregister_chrdev_region(devno, number_of_devices);

	natflow_zone_cleanup();
	return;
}
