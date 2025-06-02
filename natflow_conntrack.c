/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 27 Jun 2018 22:13:17 +0800
 */
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/device.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/version.h>
#include <linux/spinlock.h>
#include <linux/seqlock.h>
#include <linux/netdevice.h>
#include <linux/bitops.h>
#include <linux/timer.h>
#include <linux/vmalloc.h>
#include <linux/highmem.h>
#include <linux/netfilter.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_acct.h>
#include "natflow.h"
#include "natflow_common.h"
#include "natflow_conntrack.h"

static int number_of_devices = 1;

struct conntrackinfo {
	struct list_head list;
	unsigned int len;
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
	unsigned char data[];
#else
	unsigned char data[0];
#endif
};
#define CONNTRACKINFO_MEMSIZE ALIGN(sizeof(struct conntrackinfo), 4096)
#define CONNTRACKINFO_DATALEN (CONNTRACKINFO_MEMSIZE - sizeof(struct conntrackinfo))

struct conntrackinfo_user {
	struct mutex lock;
	struct list_head head;
	unsigned int next_bucket;
	unsigned int count;
	unsigned int status;
};

static ssize_t conntrackinfo_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
{
	int err = 0;
	int n, l;
	int cnt = MAX_IOCTL_LEN;
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

	if (strncmp(data, "kickall", 7) == 0) {
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


static const char *const sctp_conntrack_names[] = {
	"NONE",
	"CLOSED",
	"COOKIE_WAIT",
	"COOKIE_ECHOED",
	"ESTABLISHED",
	"SHUTDOWN_SENT",
	"SHUTDOWN_RECD",
	"SHUTDOWN_ACK_SENT",
	"HEARTBEAT_SENT",
	"HEARTBEAT_ACKED",
};

static const char * const dccp_state_names[] = {
	[CT_DCCP_NONE]          = "NONE",
	[CT_DCCP_REQUEST]       = "REQUEST",
	[CT_DCCP_RESPOND]       = "RESPOND",
	[CT_DCCP_PARTOPEN]      = "PARTOPEN",
	[CT_DCCP_OPEN]          = "OPEN",
	[CT_DCCP_CLOSEREQ]      = "CLOSEREQ",
	[CT_DCCP_CLOSING]       = "CLOSING",
	[CT_DCCP_TIMEWAIT]      = "TIMEWAIT",
	[CT_DCCP_IGNORE]        = "IGNORE",
	[CT_DCCP_INVALID]       = "INVALID",
};

static const char *const tcp_conntrack_names[] = {
	"NONE",
	"SYN_SENT",
	"SYN_RECV",
	"ESTABLISHED",
	"FIN_WAIT",
	"CLOSE_WAIT",
	"LAST_ACK",
	"TIME_WAIT",
	"CLOSE",
	"SYN_SENT2",
};

static const char* l3proto_name(u16 proto)
{
	switch (proto) {
	case AF_INET:
		return "ipv4";
	case AF_INET6:
		return "ipv6";
	}

	return "unknown";
}

static const char* l4proto_name(u16 proto)
{
	switch (proto) {
	case IPPROTO_ICMP:
		return "icmp";
	case IPPROTO_TCP:
		return "tcp";
	case IPPROTO_UDP:
		return "udp";
	case IPPROTO_DCCP:
		return "dccp";
	case IPPROTO_GRE:
		return "gre";
	case IPPROTO_SCTP:
		return "sctp";
	case IPPROTO_UDPLITE:
		return "udplite";
	case IPPROTO_ICMPV6:
		return "icmpv6";
	}

	return "unknown";
}


/* read one and clear one */
static ssize_t conntrackinfo_read(struct file *file, char __user *buf,
                                  size_t count, loff_t *ppos)
{
	unsigned long end_time = jiffies + msecs_to_jiffies(100);
	ssize_t ret;
	struct conntrackinfo *ct_i = NULL;
	struct conntrackinfo_user *user = file->private_data;

	if (!user)
		return -EBADF;

	ret = mutex_lock_interruptible(&user->lock);
	if (ret != 0)
		return -EAGAIN;
	if (user->status == 0 && list_empty(&user->head)) {
		unsigned int i, hashsz;
		struct nf_conntrack_tuple_hash *h;
		struct hlist_nulls_head *ct_hash;
		struct hlist_nulls_node *n;
		struct nf_conn *ct;
		const struct nf_conntrack_l4proto *l4proto;
		const struct nf_conntrack_tuple *tuple;
		struct nf_conn_acct *acct;
		struct nf_conn_counter *counter;

		user->status = 1;
		rcu_read_lock();

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 7, 0)
		ct_hash = init_net.ct.hash;
		hashsz = init_net.ct.htable_size;
#else
		ct_hash = nf_conntrack_hash;
		hashsz = nf_conntrack_htable_size;
#endif
		for (i = user->next_bucket; i < hashsz; i++) {
			hlist_nulls_for_each_entry_rcu(h, n, &ct_hash[i], hnnode) {
				ct = nf_ct_tuplehash_to_ctrack(h);
				if (unlikely(!REFCOUNT_inc_not_zero(&ct->ct_general.use)))
					continue;

				/* we only want to print DIR_ORIGINAL */
				if (NF_CT_DIRECTION(h)) {
					nf_ct_put(ct);
					continue;
				}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 9, 0)
				if (nf_ct_is_expired(ct)) {
					nf_ct_put(ct);
					continue;
				}
#endif
				if ((IPS_NATFLOW_USER & ct->status) || (IPS_NATCAP_PEER & ct->status)) {
					nf_ct_put(ct);
					continue;
				}

				if (!ct_i || ct_i->len + 448 > CONNTRACKINFO_DATALEN) {
					ct_i = kmalloc(CONNTRACKINFO_MEMSIZE, GFP_ATOMIC);
					if (!ct_i) {
						nf_ct_put(ct);
						ret = -ENOMEM;
						goto out;
					}
					INIT_LIST_HEAD(&ct_i->list);
					ct_i->len = 0;
					list_add_tail(&ct_i->list, &user->head);
					user->count++;
				}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 1, 0)
				l4proto = nf_ct_l4proto_find(nf_ct_protonum(ct));
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(4, 20, 0)
				l4proto = __nf_ct_l4proto_find(nf_ct_protonum(ct));
#else
				l4proto = __nf_ct_l4proto_find(nf_ct_l3num(ct), nf_ct_protonum(ct));
#endif

				ct_i->len += sprintf(ct_i->data + ct_i->len, "%-8s %u %-8s %u ",
				                     l3proto_name(nf_ct_l3num(ct)), nf_ct_l3num(ct),
				                     l4proto_name(l4proto->l4proto), nf_ct_protonum(ct));
				ct_i->len += sprintf(ct_i->data + ct_i->len, "%ld ", nf_ct_expires(ct) / HZ);

				acct = nf_conn_acct_find(ct);

				tuple = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
				switch (l4proto->l4proto) {
				case IPPROTO_ICMP:
					switch (tuple->src.l3num) {
					case NFPROTO_IPV4:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI4 dst=%pI4 ",
						                     &tuple->src.u3.ip, &tuple->dst.u3.ip);
						break;
					case NFPROTO_IPV6:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI6 dst=%pI6 ",
						                     tuple->src.u3.ip6, tuple->dst.u3.ip6);
						break;
					default:
						break;
					}
					ct_i->len += sprintf(ct_i->data + ct_i->len, "type=%u code=%u id=%u ",
					                     tuple->dst.u.icmp.type,
					                     tuple->dst.u.icmp.code,
					                     ntohs(tuple->src.u.icmp.id));
					break;
				case IPPROTO_TCP:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "%s ", tcp_conntrack_names[ct->proto.tcp.state]);
					switch (tuple->src.l3num) {
					case NFPROTO_IPV4:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI4 dst=%pI4 ",
						                     &tuple->src.u3.ip, &tuple->dst.u3.ip);
						break;
					case NFPROTO_IPV6:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI6 dst=%pI6 ",
						                     tuple->src.u3.ip6, tuple->dst.u3.ip6);
						break;
					default:
						break;
					}
					ct_i->len += sprintf(ct_i->data + ct_i->len, "sport=%hu dport=%hu ",
					                     ntohs(tuple->src.u.tcp.port),
					                     ntohs(tuple->dst.u.tcp.port));
					break;
				case IPPROTO_UDPLITE:
				case IPPROTO_UDP:
					switch (tuple->src.l3num) {
					case NFPROTO_IPV4:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI4 dst=%pI4 ",
						                     &tuple->src.u3.ip, &tuple->dst.u3.ip);
						break;
					case NFPROTO_IPV6:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI6 dst=%pI6 ",
						                     tuple->src.u3.ip6, tuple->dst.u3.ip6);
						break;
					default:
						break;
					}
					ct_i->len += sprintf(ct_i->data + ct_i->len, "sport=%hu dport=%hu ",
					                     ntohs(tuple->src.u.udp.port),
					                     ntohs(tuple->dst.u.udp.port));
					break;
				case IPPROTO_DCCP:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "%s ", dccp_state_names[ct->proto.tcp.state]);
					switch (tuple->src.l3num) {
					case NFPROTO_IPV4:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI4 dst=%pI4 ",
						                     &tuple->src.u3.ip, &tuple->dst.u3.ip);
						break;
					case NFPROTO_IPV6:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI6 dst=%pI6 ",
						                     tuple->src.u3.ip6, tuple->dst.u3.ip6);
						break;
					default:
						break;
					}
					ct_i->len += sprintf(ct_i->data + ct_i->len, "sport=%hu dport=%hu ",
					                     ntohs(tuple->src.u.dccp.port),
					                     ntohs(tuple->dst.u.dccp.port));
					break;
				case IPPROTO_SCTP:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "%s ", sctp_conntrack_names[ct->proto.tcp.state]);
					switch (tuple->src.l3num) {
					case NFPROTO_IPV4:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI4 dst=%pI4 ",
						                     &tuple->src.u3.ip, &tuple->dst.u3.ip);
						break;
					case NFPROTO_IPV6:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI6 dst=%pI6 ",
						                     tuple->src.u3.ip6, tuple->dst.u3.ip6);
						break;
					default:
						break;
					}
					ct_i->len += sprintf(ct_i->data + ct_i->len, "sport=%hu dport=%hu ",
					                     ntohs(tuple->src.u.sctp.port),
					                     ntohs(tuple->dst.u.sctp.port));
					break;
				case IPPROTO_ICMPV6:
					switch (tuple->src.l3num) {
					case NFPROTO_IPV4:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI4 dst=%pI4 ",
						                     &tuple->src.u3.ip, &tuple->dst.u3.ip);
						break;
					case NFPROTO_IPV6:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI6 dst=%pI6 ",
						                     tuple->src.u3.ip6, tuple->dst.u3.ip6);
						break;
					default:
						break;
					}
					ct_i->len += sprintf(ct_i->data + ct_i->len, "type=%u code=%u id=%u ",
					                     tuple->dst.u.icmp.type,
					                     tuple->dst.u.icmp.code,
					                     ntohs(tuple->src.u.icmp.id));
					break;
				case IPPROTO_GRE:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "timeout=%u, stream_timeout=%u ",
					                     (ct->proto.gre.timeout / HZ),
					                     (ct->proto.gre.stream_timeout / HZ));
					switch (tuple->src.l3num) {
					case NFPROTO_IPV4:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI4 dst=%pI4 ",
						                     &tuple->src.u3.ip, &tuple->dst.u3.ip);
						break;
					case NFPROTO_IPV6:
						ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI6 dst=%pI6 ",
						                     tuple->src.u3.ip6, tuple->dst.u3.ip6);
						break;
					default:
						break;
					}
					ct_i->len += sprintf(ct_i->data + ct_i->len, "srckey=0x%x dstkey=0x%x ",
					                     ntohs(tuple->src.u.gre.key),
					                     ntohs(tuple->dst.u.gre.key));
					break;
				default:
					break;
				}
				if (acct) {
					counter = acct->counter;
					ct_i->len += sprintf(ct_i->data + ct_i->len, "packets=%llu bytes=%llu ",
					                     (unsigned long long)atomic64_read(&counter[IP_CT_DIR_ORIGINAL].packets),
					                     (unsigned long long)atomic64_read(&counter[IP_CT_DIR_ORIGINAL].bytes));
				}

				if (!(test_bit(IPS_SEEN_REPLY_BIT, &ct->status)))
					ct_i->len += sprintf(ct_i->data + ct_i->len, "[UNREPLIED] ");

				tuple = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
				switch (tuple->src.l3num) {
				case NFPROTO_IPV4:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI4 dst=%pI4 ",
					                     &tuple->src.u3.ip, &tuple->dst.u3.ip);
					break;
				case NFPROTO_IPV6:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "src=%pI6 dst=%pI6 ",
					                     tuple->src.u3.ip6, tuple->dst.u3.ip6);
					break;
				default:
					break;
				}
				switch (l4proto->l4proto) {
				case IPPROTO_ICMP:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "type=%u code=%u id=%u ",
					                     tuple->dst.u.icmp.type,
					                     tuple->dst.u.icmp.code,
					                     ntohs(tuple->src.u.icmp.id));
					break;
				case IPPROTO_TCP:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "sport=%hu dport=%hu ",
					                     ntohs(tuple->src.u.tcp.port),
					                     ntohs(tuple->dst.u.tcp.port));
					break;
				case IPPROTO_UDPLITE:
				case IPPROTO_UDP:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "sport=%hu dport=%hu ",
					                     ntohs(tuple->src.u.udp.port),
					                     ntohs(tuple->dst.u.udp.port));
					break;
				case IPPROTO_DCCP:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "sport=%hu dport=%hu ",
					                     ntohs(tuple->src.u.dccp.port),
					                     ntohs(tuple->dst.u.dccp.port));
					break;
				case IPPROTO_SCTP:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "sport=%hu dport=%hu ",
					                     ntohs(tuple->src.u.sctp.port),
					                     ntohs(tuple->dst.u.sctp.port));
					break;
				case IPPROTO_ICMPV6:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "type=%u code=%u id=%u ",
					                     tuple->dst.u.icmp.type,
					                     tuple->dst.u.icmp.code,
					                     ntohs(tuple->src.u.icmp.id));
					break;
				case IPPROTO_GRE:
					ct_i->len += sprintf(ct_i->data + ct_i->len, "srckey=0x%x dstkey=0x%x ",
					                     ntohs(tuple->src.u.gre.key),
					                     ntohs(tuple->dst.u.gre.key));
					break;
				default:
					break;
				}
				if (acct) {
					counter = acct->counter;
					ct_i->len += sprintf(ct_i->data + ct_i->len, "packets=%llu bytes=%llu ",
					                     (unsigned long long)atomic64_read(&counter[IP_CT_DIR_REPLY].packets),
					                     (unsigned long long)atomic64_read(&counter[IP_CT_DIR_REPLY].bytes));
				}

				if (test_bit(IPS_ASSURED_BIT, &ct->status))
					ct_i->len += sprintf(ct_i->data + ct_i->len, "[ASSURED] ");

#ifdef CONFIG_NF_CONNTRACK_MARK
				ct_i->len += sprintf(ct_i->data + ct_i->len, "mark=%u ", ct->mark);
#endif

				ct_i->len += sprintf(ct_i->data + ct_i->len, "use=%u\n", REFCOUNT_read(&ct->ct_general.use));

				nf_ct_put(ct);
			}

			/* limit memory usage: 256 x 4096 = 1Mbytes */
			if ((time_after(jiffies, end_time) || user->count >= 256) && i < hashsz) {
				user->next_bucket = i + 1;
				user->status = 0;
				break;
			}
		}

		rcu_read_unlock();
	}

	ct_i = list_first_entry_or_null(&user->head, struct conntrackinfo, list);
	if (ct_i) {
		if (ct_i->len > count) {
			if (copy_to_user(buf, ct_i->data, count)) {
				ret = -EFAULT;
				goto out;
			}
			ct_i->len -= count;
			memmove(ct_i->data, ct_i->data + count, ct_i->len);
			ret = count;
		} else {
			if (copy_to_user(buf, ct_i->data, ct_i->len)) {
				ret = -EFAULT;
				goto out;
			}
			ret = ct_i->len;
			list_del(&ct_i->list);
			kfree(ct_i);
			user->count--;
		}
	} else if (user->status == 0) {
		ret = -EAGAIN;
	} else {
		user->status = 0;
		ret = 0;
	}

out:
	mutex_unlock(&user->lock);

	return ret;
}

static int conntrackinfo_open(struct inode *inode, struct file *file)
{
	struct conntrackinfo_user *user;

	user = kmalloc(sizeof(struct conntrackinfo_user), GFP_KERNEL);
	if (!user)
		return -ENOMEM;

	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	mutex_init(&user->lock);
	user->next_bucket = 0;
	user->count = 0;
	user->status = 0;
	INIT_LIST_HEAD(&user->head);

	file->private_data = user;
	return 0;
}

static int conntrackinfo_release(struct inode *inode, struct file *file)
{
	struct conntrackinfo *ct_i;
	struct conntrackinfo_user *user = file->private_data;

	if (!user)
		return 0;

	while ((ct_i = list_first_entry_or_null(&user->head, struct conntrackinfo, list))) {
		list_del(&ct_i->list);
		kfree(ct_i);
	}

	mutex_destroy(&user->lock);
	kfree(user);
	return 0;
}

const struct file_operations conntrackinfo_fops = {
	.open = conntrackinfo_open,
	.read = conntrackinfo_read,
	.write = conntrackinfo_write,
	.release = conntrackinfo_release,
};

static int conntrackinfo_major = 0;
static int conntrackinfo_minor = 0;
static struct cdev conntrackinfo_cdev;
const char *conntrackinfo_dev_name = "conntrackinfo_ctl";
static struct class *conntrackinfo_class;
static struct device *conntrackinfo_dev;

int conntrackinfo_init(void)
{
	int retval = 0;
	dev_t devno;

	if (conntrackinfo_major > 0) {
		devno = MKDEV(conntrackinfo_major, conntrackinfo_minor);
		retval = register_chrdev_region(devno, number_of_devices, conntrackinfo_dev_name);
	} else {
		retval = alloc_chrdev_region(&devno, conntrackinfo_minor, number_of_devices, conntrackinfo_dev_name);
	}
	if (retval < 0) {
		NATFLOW_println("alloc_chrdev_region failed!");
		goto chrdev_region_failed;
	}
	conntrackinfo_major = MAJOR(devno);
	conntrackinfo_minor = MINOR(devno);
	NATFLOW_println("conntrackinfo_major=%d, conntrackinfo_minor=%d", conntrackinfo_major, conntrackinfo_minor);

	cdev_init(&conntrackinfo_cdev, &conntrackinfo_fops);
	conntrackinfo_cdev.owner = THIS_MODULE;
	conntrackinfo_cdev.ops = &conntrackinfo_fops;

	retval = cdev_add(&conntrackinfo_cdev, devno, 1);
	if (retval) {
		NATFLOW_println("adding chardev, error=%d", retval);
		goto cdev_add_failed;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	conntrackinfo_class = class_create(THIS_MODULE, "conntrackinfo_class");
#else
	conntrackinfo_class = class_create("conntrackinfo_class");
#endif
	if (IS_ERR(conntrackinfo_class)) {
		NATFLOW_println("failed in creating class");
		retval = -EINVAL;
		goto class_create_failed;
	}

	conntrackinfo_dev = device_create(conntrackinfo_class, NULL, devno, NULL, conntrackinfo_dev_name);
	if (IS_ERR(conntrackinfo_dev)) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	return 0;

	//device_destroy(conntrackinfo_class, devno);
device_create_failed:
	class_destroy(conntrackinfo_class);
class_create_failed:
	cdev_del(&conntrackinfo_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, number_of_devices);
chrdev_region_failed:
	return retval;
}

void conntrackinfo_exit(void)
{
	dev_t devno;

	devno = MKDEV(conntrackinfo_major, conntrackinfo_minor);
	device_destroy(conntrackinfo_class, devno);
	class_destroy(conntrackinfo_class);
	cdev_del(&conntrackinfo_cdev);
	unregister_chrdev_region(devno, number_of_devices);
}
