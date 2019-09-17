/*
 * Author: Chen Minqiang <ptpt52@gmail.com>
 *  Date : Wed, 19 Dec 2012 09:52:21 +0800
 */
#include <linux/ctype.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/inetdevice.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/tcp.h>
#include <linux/uaccess.h>
#include <linux/unistd.h>
#include <linux/version.h>
#include <linux/mman.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/highmem.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_nat.h>
#include <linux/inetdevice.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#include "natflow_common.h"

static inline unsigned char get_byte1(const unsigned char *p)
{
	return p[0];
}

static inline unsigned short get_byte2(const unsigned char *p)
{
	unsigned short v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static inline unsigned int get_byte4(const unsigned char *p)
{
	unsigned int v;
	memcpy(&v, p, sizeof(v));
	return v;
}

static inline void set_byte1(unsigned char *p, unsigned char v)
{
	p[0] = v;
}

static inline void set_byte2(unsigned char *p, unsigned short v)
{
	memcpy(p, &v, sizeof(v));
}

static inline void set_byte4(unsigned char *p, unsigned int v)
{
	memcpy(p, &v, sizeof(v));
}

static inline void set_byte6(unsigned char *p, const unsigned char *pv)
{
	memcpy(p, pv, 6);
}

static inline void get_byte6(const unsigned char *p, unsigned char *pv)
{
	memcpy(pv, p, 6);
}

static inline int inet_is_local(const struct net_device *dev, __be32 ip)
{
	struct in_device *in_dev;

	if (dev == NULL)
		return 0;

	rcu_read_lock();
	in_dev = __in_dev_get_rcu(dev);
	if (!in_dev) {
		rcu_read_unlock();
		return 0;
	}
	for_ifa(in_dev) {
		if (ifa->ifa_local == ip) {
			rcu_read_unlock();
			return 1;
		}
	} endfor_ifa(in_dev);
	rcu_read_unlock();

	return 0;
}

static int natflow_ktun_major = 0;
static int natflow_ktun_minor = 0;
static int number_of_devices = 1;
static struct cdev natflow_ktun_cdev;
const char *natflow_ktun_dev_name = "natflow_ktun_ctl";
static struct class *natflow_ktun_class;
static struct device *natflow_ktun_dev;

static char natflow_ktun_ctl_buffer[PAGE_SIZE];
static void *natflow_ktun_start(struct seq_file *m, loff_t *pos)
{
	int n = 0;

	if ((*pos) == 0) {
		n = snprintf(natflow_ktun_ctl_buffer,
				sizeof(natflow_ktun_ctl_buffer) - 1,
				"# Usage:\n"
				"#    hsts_host=hostname -- set hostname\n"
				"#\n"
				"# Info:\n"
				"#    ...\n"
				"#\n"
				"# Reload cmd:\n"
				"\n"
				"\n"
				);
		natflow_ktun_ctl_buffer[n] = 0;
		return natflow_ktun_ctl_buffer;
	}

	return NULL;
}

static void *natflow_ktun_next(struct seq_file *m, void *v, loff_t *pos)
{
	return NULL;
}

static void natflow_ktun_stop(struct seq_file *m, void *v)
{
}

static int natflow_ktun_show(struct seq_file *m, void *v)
{
	seq_printf(m, "%s", (char *)v);
	return 0;
}

const struct seq_operations natflow_ktun_seq_ops = {
	.start = natflow_ktun_start,
	.next = natflow_ktun_next,
	.stop = natflow_ktun_stop,
	.show = natflow_ktun_show,
};

static ssize_t natflow_ktun_read(struct file *file, char __user *buf, size_t buf_len, loff_t *offset)
{
	return seq_read(file, buf, buf_len, offset);
}

static ssize_t natflow_ktun_write(struct file *file, const char __user *buf, size_t buf_len, loff_t *offset)
{
	int err = 0;
	int n, l;
	int cnt = 256;
	static char data[256];
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

	//make sure line ended with '\n' and line len <=256
	l = 0;
	while (l < cnt && data[l + data_left] != '\n') l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= 256) {
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

	NATFLOW_println("ignoring line[%s]", data);
	if (err != 0) {
		return err;
	}

done:
	*offset += l;
	return l;
}

static int natflow_ktun_open(struct inode *inode, struct file *file)
{
	int ret = seq_open(file, &natflow_ktun_seq_ops);
	if (ret)
		return ret;
	//set nonseekable
	file->f_mode &= ~(FMODE_LSEEK | FMODE_PREAD | FMODE_PWRITE);

	return 0;
}

static int natflow_ktun_release(struct inode *inode, struct file *file)
{
	return seq_release(inode, file);
}

static struct file_operations natflow_ktun_fops = {
	.owner = THIS_MODULE,
	.open = natflow_ktun_open,
	.release = natflow_ktun_release,
	.read = natflow_ktun_read,
	.write = natflow_ktun_write,
	.llseek  = seq_lseek,
};

int skb_rcsum_tcpudp(struct sk_buff *skb)
{
	struct iphdr *iph = ip_hdr(skb);
	int len = ntohs(iph->tot_len);

	if (skb->len < len) {
		return -1;
	} else if (len < (iph->ihl * 4)) {
		return -1;
	}

	if (iph->protocol == IPPROTO_TCP) {
		struct tcphdr *tcph = (struct tcphdr *)((void *)iph + iph->ihl*4);

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			tcph->check = 0;
			tcph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_TCP, 0);
			skb->csum_start = (unsigned char *)tcph - skb->head;
			skb->csum_offset = offsetof(struct tcphdr, check);
		} else {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			skb->csum = 0;
			tcph->check = 0;
			skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
			tcph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);
			if (skb->ip_summed == CHECKSUM_COMPLETE) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}
		}
	} else if (iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph = (struct udphdr *)((void *)iph + iph->ihl*4);

		if (skb->ip_summed == CHECKSUM_PARTIAL) {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			udph->check = 0;
			udph->check = ~csum_tcpudp_magic(iph->saddr, iph->daddr, skb->len - iph->ihl * 4, IPPROTO_UDP, 0);
			skb->csum_start = (unsigned char *)udph - skb->head;
			skb->csum_offset = offsetof(struct udphdr, check);
		} else {
			iph->check = 0;
			iph->check = ip_fast_csum(iph, iph->ihl);
			if (udph->check) {
				skb->csum = 0;
				udph->check = 0;
				skb->csum = skb_checksum(skb, iph->ihl * 4, len - iph->ihl * 4, 0);
				udph->check = csum_tcpudp_magic(iph->saddr, iph->daddr, len - iph->ihl * 4, iph->protocol, skb->csum);
				if (udph->check == 0)
					udph->check = CSUM_MANGLED_0;
			}
			if (skb->ip_summed == CHECKSUM_COMPLETE) {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
			}
		}
	} else {
		return -1;
	}

	return 0;
}

static unsigned int __natflow_ktun_nat_setup(struct nf_conn *ct, __be32 addr, __be16 man_proto, int type)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
    struct nf_nat_range range;
    if (nf_nat_initialized(ct, type == 0 ? IP_NAT_MANIP_DST : IP_NAT_MANIP_SRC)) {
        return NF_ACCEPT;
    }
    memset(&range.min_ip, 0, sizeof(range.min_ip));
    memset(&range.max_ip, 0, sizeof(range.max_ip));
    range.flags = IP_NAT_RANGE_MAP_IPS | IP_NAT_RANGE_PROTO_SPECIFIED;
    range.min_ip = addr;
    range.max_ip = addr;
    range.min.all = man_proto;
    range.max.all = man_proto;
    return nf_nat_setup_info(ct, &range, type == 0 ? IP_NAT_MANIP_DST : IP_NAT_MANIP_SRC);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3, 7, 0)
    struct nf_nat_ipv4_range range;
    if (nf_nat_initialized(ct, type == 0 ? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC)) {
        return NF_ACCEPT;
    }
    memset(&range.min_ip, 0, sizeof(range.min_ip));
    memset(&range.max_ip, 0, sizeof(range.max_ip));
    range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
    range.min_ip = addr;
    range.max_ip = addr;
    range.min.all = man_proto;
    range.max.all = man_proto;
    return nf_nat_setup_info(ct, &range, type == 0 ? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 18, 0)
    struct nf_nat_range range;
    if (nf_nat_initialized(ct, type == 0 ? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC)) {
        return NF_ACCEPT;
    }
    memset(&range.min_addr, 0, sizeof(range.min_addr));
    memset(&range.max_addr, 0, sizeof(range.max_addr));
    range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
    range.min_addr.ip = addr;
    range.max_addr.ip = addr;
    range.min_proto.all = man_proto;
    range.max_proto.all = man_proto;
    return nf_nat_setup_info(ct, &range, type == 0 ? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC);
#else
    struct nf_nat_range2 range;
    if (nf_nat_initialized(ct, type == 0 ? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC)) {
        return NF_ACCEPT;
    }
    memset(&range.min_addr, 0, sizeof(range.min_addr));
    memset(&range.max_addr, 0, sizeof(range.max_addr));
    range.flags = NF_NAT_RANGE_MAP_IPS | NF_NAT_RANGE_PROTO_SPECIFIED;
    range.min_addr.ip = addr;
    range.max_addr.ip = addr;
    range.min_proto.all = man_proto;
    range.max_proto.all = man_proto;
    memset(&range.base_proto, 0, sizeof(range.base_proto));
    return nf_nat_setup_info(ct, &range, type == 0 ? NF_NAT_MANIP_DST : NF_NAT_MANIP_SRC);
#endif
}

unsigned int natflow_ktun_dnat_setup(struct nf_conn *ct, __be32 addr, __be16 man_proto)
{
    return __natflow_ktun_nat_setup(ct, addr, man_proto, 0);
}

unsigned int natflow_ktun_snat_setup(struct nf_conn *ct, __be32 addr, __be16 man_proto)
{
    return __natflow_ktun_nat_setup(ct, addr, man_proto, 1);
}

#define KTUN_FAKEUSER_DADDR __constant_htonl(0x7ffffffe)
#define KTUN_FAKEUSER_PORT __constant_htons(65534)

#define TCPH(t) ((struct tcphdr *)(t))
#define UDPH(u) ((struct udphdr *)(u))

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
static unsigned natflow_ktun_hook(unsigned int hooknum,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 1, 0)
static unsigned int natflow_ktun_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct net_device *in,
		const struct net_device *out,
		int (*okfn)(struct sk_buff *))
{
	//unsigned int hooknum = ops->hooknum;
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
static unsigned int natflow_ktun_hook(const struct nf_hook_ops *ops,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
#else
static unsigned int natflow_ktun_hook(void *priv,
		struct sk_buff *skb,
		const struct nf_hook_state *state)
{
	//unsigned int hooknum = state->hook;
	const struct net_device *in = state->in;
#endif
	int ret = 0;
	enum ip_conntrack_info ctinfo;
	struct net *net = &init_net;
	struct nf_conn *ct;
	struct iphdr *iph;
	void *l4;
	unsigned char *data;
	int data_len;
	unsigned char smac[6];
	unsigned char dmac[6];

    if (in) {
        net = dev_net(in);
	}

	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP) {
		return NF_ACCEPT;
	}

	l4 = (void *)iph + iph->ihl * 4;
	if (UDPH(l4)->dest != __constant_htons(910)) {
		return NF_ACCEPT;
	}

	if (!inet_is_local(in, iph->daddr)) {
		return NF_ACCEPT;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (NULL == ct) {
		return NF_ACCEPT;
	}
	if (CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL) {
		return NF_ACCEPT;
	}

	if (!skb_make_writable(skb, iph->ihl * 4 + sizeof(struct udphdr) + 4) ||
			get_byte4((void *)UDPH(l4) + sizeof(struct udphdr)) != __constant_htonl(0xfffd0099)) {
		return NF_ACCEPT;
	}
	if (!skb_make_writable(skb, skb->len)) {
		return NF_DROP;
	}
	iph = ip_hdr(skb);
	l4 = (void *)iph + iph->ihl * 4;

	data = (void *)UDPH(l4) + sizeof(struct udphdr);
	data_len = skb->len - (iph->ihl * 4 + sizeof(struct udphdr));

	if (data_len >= 14 && get_byte4(data + 4) == __constant_htonl(0x00000001)) { //bcast mac
		get_byte6(data + 8, smac);
	} else if (data_len >= 20 && get_byte4(data + 4) == __constant_htonl(0x00000002)) { //bcast mac and connect to mac
		get_byte6(data + 8, smac);
		get_byte6(data + 14, dmac);
	} else {
		return NF_DROP;
	}

	if (!nf_ct_is_confirmed(ct)) {
		struct nf_conn *user;
		struct nf_conntrack_tuple_hash *h;
		struct nf_conntrack_tuple tuple;
		
		memset(&tuple, 0, sizeof(tuple));
		tuple.src.u3.ip = KTUN_FAKEUSER_DADDR;
		tuple.src.u.udp.port = KTUN_FAKEUSER_PORT;
		tuple.dst.u3.ip = get_byte4(smac);
		tuple.dst.u.udp.port = get_byte2(smac + 4);
		tuple.src.l3num = PF_INET;
		tuple.dst.protonum = IPPROTO_UDP;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 3, 0)
        h = nf_conntrack_find_get(net, NF_CT_DEFAULT_ZONE, &tuple);
#else
        h = nf_conntrack_find_get(net, &nf_ct_zone_dflt, &tuple);
#endif
        if (h) {
			user = nf_ct_tuplehash_to_ctrack(h);
			nf_ct_delete(user, 0, 0);
            nf_ct_put(user);
        }
		//lookup exist user? force drop it?

		natflow_ktun_dnat_setup(ct, KTUN_FAKEUSER_DADDR, KTUN_FAKEUSER_PORT);
		//DNAT setup

		natflow_ktun_snat_setup(ct, get_byte4(smac), get_byte2(smac + 4));
		//SNAT setup
	}

	ret = nf_conntrack_confirm(skb);
	if (ret != NF_ACCEPT) {
		return ret;
	}

	if (get_byte4(data + 4) == __constant_htonl(0x00000001)) {
		//reply
		//0x10010001: resp=1, ret=001, code=0001 bcast fail
		//0x10020001: resp=1, ret=002, code=0001 bcast ok
	} else if (get_byte4(data + 4) == __constant_htonl(0x00000002)) {
		//reply
		//0x10010002: resp=1, ret=001, code=0002 bcast fail and connect fail
		//0x10020002: resp=1, ret=002, code=0002 bcast ok but connect fail
		//0x10030002: resp=1, ret=003, code=0002 bcast ok and connect ok
	}

	consume_skb(skb);
	return NF_STOLEN;
}

static struct nf_hook_ops natflow_ktun_hooks[] = {
	{    
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0)
		.owner = THIS_MODULE,
#endif
		.hook = natflow_ktun_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_PRE_ROUTING,
		.priority = NF_IP_PRI_NAT_DST - 30,
	},
};

int natflow_ktun_init(void) {
	int retval = 0;
	dev_t devno;

	if (natflow_ktun_major>0) {
		devno = MKDEV(natflow_ktun_major, natflow_ktun_minor);
		retval = register_chrdev_region(devno, number_of_devices, natflow_ktun_dev_name);
	} else {
		retval = alloc_chrdev_region(&devno, natflow_ktun_minor, number_of_devices, natflow_ktun_dev_name);
	}
	if (retval < 0) {
		NATFLOW_println("alloc_chrdev_region failed!");
		return retval;
	}
	natflow_ktun_major = MAJOR(devno);
	natflow_ktun_minor = MINOR(devno);
	NATFLOW_println("natflow_ktun_major=%d, natflow_ktun_minor=%d", natflow_ktun_major, natflow_ktun_minor);

	cdev_init(&natflow_ktun_cdev, &natflow_ktun_fops);
	natflow_ktun_cdev.owner = THIS_MODULE;
	natflow_ktun_cdev.ops = &natflow_ktun_fops;

	retval = cdev_add(&natflow_ktun_cdev, devno, 1);
	if (retval) {
		NATFLOW_println("adding chardev, error=%d", retval);
		goto cdev_add_failed;
	}

	natflow_ktun_class = class_create(THIS_MODULE,"natflow_ktun_class");
	if (IS_ERR(natflow_ktun_class)) {
		NATFLOW_println("failed in creating class");
		retval = -EINVAL;
		goto class_create_failed;
	}

	natflow_ktun_dev = device_create(natflow_ktun_class, NULL, devno, NULL, natflow_ktun_dev_name);
	if (!natflow_ktun_dev) {
		retval = -EINVAL;
		goto device_create_failed;
	}

	retval = nf_register_hooks(natflow_ktun_hooks, ARRAY_SIZE(natflow_ktun_hooks));
	if (retval) {
		goto err0;
	}

	return 0;

	//nf_unregister_hooks(natflow_ktun_hooks, ARRAY_SIZE(natflow_ktun_hooks));
err0:
	device_destroy(natflow_ktun_class, devno);
device_create_failed:
	class_destroy(natflow_ktun_class);
class_create_failed:
	cdev_del(&natflow_ktun_cdev);
cdev_add_failed:
	unregister_chrdev_region(devno, number_of_devices);

	return retval;
}

void natflow_ktun_exit(void) {
	dev_t devno;

	nf_unregister_hooks(natflow_ktun_hooks, ARRAY_SIZE(natflow_ktun_hooks));

	devno = MKDEV(natflow_ktun_major, natflow_ktun_minor);
	device_destroy(natflow_ktun_class, devno);
	class_destroy(natflow_ktun_class);
	cdev_del(&natflow_ktun_cdev);
	unregister_chrdev_region(devno, number_of_devices);
	return;
}
