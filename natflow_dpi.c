/*
 * Natflow DPI control and event skeleton.
 *
 * This file intentionally does not classify traffic yet. It only provides
 * the disabled-by-default control plane and a versioned event ABI shell.
 */
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include "natflow_common.h"
#include "natflow_dpi.h"

enum natflow_dpi_state {
	NATFLOW_DPI_STATE_DISABLED = 0,
	NATFLOW_DPI_STATE_ENABLED = 1,
};

static int natflow_dpi_ctl_major = 0;
static int natflow_dpi_ctl_minor = 0;
static struct cdev natflow_dpi_ctl_cdev;
static const char * const natflow_dpi_ctl_dev_name = "natflow_dpi_ctl";
static struct class *natflow_dpi_ctl_class;
static struct device *natflow_dpi_ctl_dev;

static int natflow_dpi_queue_major = 0;
static int natflow_dpi_queue_minor = 0;
static struct cdev natflow_dpi_queue_cdev;
static const char * const natflow_dpi_queue_dev_name = "natflow_dpi_queue";
static struct class *natflow_dpi_queue_class;
static struct device *natflow_dpi_queue_dev;

static DEFINE_MUTEX(natflow_dpi_lock);
static wait_queue_head_t natflow_dpi_wait;
static unsigned int natflow_dpi_state = NATFLOW_DPI_STATE_DISABLED;
static unsigned int natflow_dpi_txn_active;
static unsigned int natflow_dpi_rules;
static unsigned int natflow_dpi_generation = 1;
static unsigned long long natflow_dpi_events;
static unsigned long long natflow_dpi_events_lost;

static const char *natflow_dpi_state_name(unsigned int state)
{
	switch (state) {
	case NATFLOW_DPI_STATE_ENABLED:
		return "enabled";
	case NATFLOW_DPI_STATE_DISABLED:
	default:
		return "disabled";
	}
}

static void *natflow_dpi_ctl_start(struct seq_file *m, loff_t *pos)
{
	char *buffer = m->private;
	int n;

	if (*pos != 0)
		return NULL;

	mutex_lock(&natflow_dpi_lock);
	n = snprintf(buffer, PAGE_SIZE - 1,
	             "# Version: %s\n"
	             "# Usage:\n"
	             "#    enable=0|1\n"
	             "#    rules_begin\n"
	             "#    rules_commit\n"
	             "#    rules_abort\n"
	             "#    rules_clear\n"
	             "# Event ABI:\n"
	             "#    version=%u header_len=%u\n"
	             "\n"
	             "state=%s\n"
	             "enable=%u\n"
	             "generation=%u\n"
	             "rules=%u\n"
	             "txn_active=%u\n"
	             "events=%llu\n"
	             "events_lost=%llu\n",
	             NATFLOW_VERSION,
	             NATFLOW_DPI_EVENT_VERSION,
	             (unsigned int)sizeof(struct natflow_dpi_event_hdr),
	             natflow_dpi_state_name(natflow_dpi_state),
	             natflow_dpi_state == NATFLOW_DPI_STATE_ENABLED,
	             natflow_dpi_generation,
	             natflow_dpi_rules,
	             natflow_dpi_txn_active,
	             natflow_dpi_events,
	             natflow_dpi_events_lost);
	mutex_unlock(&natflow_dpi_lock);

	if (n < 0)
		return NULL;
	if (n >= PAGE_SIZE)
		n = PAGE_SIZE - 1;
	buffer[n] = 0;
	return buffer;
}

static void *natflow_dpi_ctl_next(struct seq_file *m, void *v, loff_t *pos)
{
	(*pos)++;
	return NULL;
}

static void natflow_dpi_ctl_stop(struct seq_file *m, void *v)
{
}

static int natflow_dpi_ctl_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
	return 0;
}

static const struct seq_operations natflow_dpi_ctl_seq_ops = {
	.start = natflow_dpi_ctl_start,
	.next  = natflow_dpi_ctl_next,
	.stop  = natflow_dpi_ctl_stop,
	.show  = natflow_dpi_ctl_show,
};

static int natflow_dpi_ctl_open(struct inode *inode, struct file *file)
{
	return seq_open_private(file, &natflow_dpi_ctl_seq_ops, PAGE_SIZE);
}

static int natflow_dpi_ctl_release(struct inode *inode, struct file *file)
{
	return seq_release_private(inode, file);
}

static int natflow_dpi_ctl_apply_line(char *data)
{
	int err = 0;

	mutex_lock(&natflow_dpi_lock);
	if (strcmp(data, "enable=1") == 0 || strcmp(data, "enable") == 0) {
		natflow_dpi_state = NATFLOW_DPI_STATE_ENABLED;
	} else if (strcmp(data, "enable=0") == 0 || strcmp(data, "disable") == 0) {
		natflow_dpi_state = NATFLOW_DPI_STATE_DISABLED;
		wake_up_interruptible(&natflow_dpi_wait);
	} else if (strcmp(data, "rules_begin") == 0) {
		if (natflow_dpi_txn_active) {
			err = -EBUSY;
			goto out;
		}
		natflow_dpi_txn_active = 1;
	} else if (strcmp(data, "rules_commit") == 0) {
		if (!natflow_dpi_txn_active) {
			err = -EINVAL;
			goto out;
		}
		natflow_dpi_generation++;
		natflow_dpi_rules = 0;
		natflow_dpi_txn_active = 0;
	} else if (strcmp(data, "rules_abort") == 0) {
		natflow_dpi_txn_active = 0;
	} else if (strcmp(data, "rules_clear") == 0) {
		natflow_dpi_generation++;
		natflow_dpi_rules = 0;
		natflow_dpi_txn_active = 0;
	} else {
		err = -EINVAL;
	}

out:
	mutex_unlock(&natflow_dpi_lock);
	return err;
}

static ssize_t natflow_dpi_ctl_write(struct file *file, const char __user *buf,
                                     size_t buf_len, loff_t *offset)
{
	int err;
	int n, l;
	int cnt = NATFLOW_DPI_CTL_MAX_LINE;
	static char data[NATFLOW_DPI_CTL_MAX_LINE];
	static int data_left = 0;

	cnt -= data_left;
	if (buf_len < cnt)
		cnt = buf_len;

	if (copy_from_user(data + data_left, buf, cnt) != 0)
		return -EACCES;

	n = 0;
	while (n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t'))
		n++;
	if (n) {
		*offset += n;
		data_left = 0;
		return n;
	}

	l = 0;
	while (l < cnt && data[l + data_left] != '\n')
		l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= NATFLOW_DPI_CTL_MAX_LINE) {
			data_left = 0;
			return -EINVAL;
		}
		goto done;
	}

	data[l + data_left] = 0;
	data_left = 0;
	l++;

	err = natflow_dpi_ctl_apply_line(data);
	if (err != 0)
		return err;

done:
	*offset += l;
	return l;
}

static const struct file_operations natflow_dpi_ctl_fops = {
	.owner = THIS_MODULE,
	.open = natflow_dpi_ctl_open,
	.release = natflow_dpi_ctl_release,
	.read = seq_read,
	.write = natflow_dpi_ctl_write,
	.llseek = seq_lseek,
};

static ssize_t natflow_dpi_queue_read(struct file *file, char __user *buf,
                                      size_t count, loff_t *ppos)
{
	return 0;
}

static unsigned int natflow_dpi_queue_poll(struct file *file, poll_table *wait)
{
	poll_wait(file, &natflow_dpi_wait, wait);
	return 0;
}

static const struct file_operations natflow_dpi_queue_fops = {
	.owner = THIS_MODULE,
	.read = natflow_dpi_queue_read,
	.poll = natflow_dpi_queue_poll,
	.llseek = no_llseek,
};

static int natflow_dpi_ctl_device_init(void)
{
	int ret;
	dev_t devno;

	if (natflow_dpi_ctl_major > 0) {
		devno = MKDEV(natflow_dpi_ctl_major, natflow_dpi_ctl_minor);
		ret = register_chrdev_region(devno, 1, natflow_dpi_ctl_dev_name);
	} else {
		ret = alloc_chrdev_region(&devno, natflow_dpi_ctl_minor, 1, natflow_dpi_ctl_dev_name);
	}
	if (ret < 0)
		return ret;

	natflow_dpi_ctl_major = MAJOR(devno);
	natflow_dpi_ctl_minor = MINOR(devno);
	NATFLOW_println("natflow_dpi_ctl_major=%d, natflow_dpi_ctl_minor=%d",
	                natflow_dpi_ctl_major, natflow_dpi_ctl_minor);

	cdev_init(&natflow_dpi_ctl_cdev, &natflow_dpi_ctl_fops);
	natflow_dpi_ctl_cdev.owner = THIS_MODULE;
	ret = cdev_add(&natflow_dpi_ctl_cdev, devno, 1);
	if (ret)
		goto cdev_add_failed;

	natflow_dpi_ctl_class = natflow_class_create("natflow_dpi_ctl_class");
	if (IS_ERR(natflow_dpi_ctl_class)) {
		ret = -EINVAL;
		goto class_create_failed;
	}

	natflow_dpi_ctl_dev = device_create(natflow_dpi_ctl_class, NULL, devno,
	                                    NULL, natflow_dpi_ctl_dev_name);
	if (IS_ERR(natflow_dpi_ctl_dev)) {
		ret = -EINVAL;
		goto device_create_failed;
	}

	return 0;

device_create_failed:
	class_destroy(natflow_dpi_ctl_class);
class_create_failed:
	cdev_del(&natflow_dpi_ctl_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, 1);
	return ret;
}

static void natflow_dpi_ctl_device_exit(void)
{
	dev_t devno = MKDEV(natflow_dpi_ctl_major, natflow_dpi_ctl_minor);

	device_destroy(natflow_dpi_ctl_class, devno);
	class_destroy(natflow_dpi_ctl_class);
	cdev_del(&natflow_dpi_ctl_cdev);
	unregister_chrdev_region(devno, 1);
}

static int natflow_dpi_queue_device_init(void)
{
	int ret;
	dev_t devno;

	if (natflow_dpi_queue_major > 0) {
		devno = MKDEV(natflow_dpi_queue_major, natflow_dpi_queue_minor);
		ret = register_chrdev_region(devno, 1, natflow_dpi_queue_dev_name);
	} else {
		ret = alloc_chrdev_region(&devno, natflow_dpi_queue_minor, 1, natflow_dpi_queue_dev_name);
	}
	if (ret < 0)
		return ret;

	natflow_dpi_queue_major = MAJOR(devno);
	natflow_dpi_queue_minor = MINOR(devno);
	NATFLOW_println("natflow_dpi_queue_major=%d, natflow_dpi_queue_minor=%d",
	                natflow_dpi_queue_major, natflow_dpi_queue_minor);

	cdev_init(&natflow_dpi_queue_cdev, &natflow_dpi_queue_fops);
	natflow_dpi_queue_cdev.owner = THIS_MODULE;
	ret = cdev_add(&natflow_dpi_queue_cdev, devno, 1);
	if (ret)
		goto cdev_add_failed;

	natflow_dpi_queue_class = natflow_class_create("natflow_dpi_queue_class");
	if (IS_ERR(natflow_dpi_queue_class)) {
		ret = -EINVAL;
		goto class_create_failed;
	}

	natflow_dpi_queue_dev = device_create(natflow_dpi_queue_class, NULL, devno,
	                                      NULL, natflow_dpi_queue_dev_name);
	if (IS_ERR(natflow_dpi_queue_dev)) {
		ret = -EINVAL;
		goto device_create_failed;
	}

	return 0;

device_create_failed:
	class_destroy(natflow_dpi_queue_class);
class_create_failed:
	cdev_del(&natflow_dpi_queue_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, 1);
	return ret;
}

static void natflow_dpi_queue_device_exit(void)
{
	dev_t devno = MKDEV(natflow_dpi_queue_major, natflow_dpi_queue_minor);

	device_destroy(natflow_dpi_queue_class, devno);
	class_destroy(natflow_dpi_queue_class);
	cdev_del(&natflow_dpi_queue_cdev);
	unregister_chrdev_region(devno, 1);
}

int natflow_dpi_init(void)
{
	int ret;

	ret = natflow_ct_ext_layout_validate();
	if (ret != 0)
		return ret;

	init_waitqueue_head(&natflow_dpi_wait);

	ret = natflow_dpi_ctl_device_init();
	if (ret != 0)
		return ret;

	ret = natflow_dpi_queue_device_init();
	if (ret != 0)
		goto queue_device_init_failed;

	return 0;

queue_device_init_failed:
	natflow_dpi_ctl_device_exit();
	return ret;
}

void natflow_dpi_exit(void)
{
	mutex_lock(&natflow_dpi_lock);
	natflow_dpi_state = NATFLOW_DPI_STATE_DISABLED;
	natflow_dpi_txn_active = 0;
	mutex_unlock(&natflow_dpi_lock);

	wake_up_interruptible(&natflow_dpi_wait);
	natflow_dpi_queue_device_exit();
	natflow_dpi_ctl_device_exit();
}
