/*
 * Natflow DPI control, domain rules, and event queue.
 */
#include <linux/atomic.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/poll.h>
#include <linux/rcupdate.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/uaccess.h>
#include <linux/wait.h>
#include <net/netfilter/nf_conntrack.h>
#include "natflow_common.h"
#include "natflow_dpi.h"

enum natflow_dpi_state {
	NATFLOW_DPI_STATE_DISABLED = 0,
	NATFLOW_DPI_STATE_ENABLED = 1,
};

#define NATFLOW_DPI_DOMAIN_RULE_MAX 128
#define NATFLOW_DPI_PROTO_RULE_MAX 32
#define NATFLOW_DPI_EVENT_MAX 1024

enum natflow_dpi_domain_kind {
	NATFLOW_DPI_DOMAIN_EXACT = 0,
	NATFLOW_DPI_DOMAIN_SUFFIX = 1,
};

enum natflow_dpi_proto {
	NATFLOW_DPI_PROTO_DNS = 1,
	NATFLOW_DPI_PROTO_SSH = 2,
	NATFLOW_DPI_PROTO_WIREGUARD = 3,
};

struct natflow_dpi_domain_rule {
	unsigned int rule_id;
	unsigned int app_id;
	unsigned char kind;
	unsigned short host_len;
	unsigned char host[NATFLOW_DPI_HOST_MAX_LEN + 1];
};

struct natflow_dpi_proto_rule {
	unsigned int rule_id;
	unsigned int app_id;
	unsigned char proto;
};

struct natflow_dpi_ruleset {
	struct rcu_head rcu;
	unsigned int generation;
	unsigned int domain_count;
	unsigned int proto_count;
	struct natflow_dpi_domain_rule domain[NATFLOW_DPI_DOMAIN_RULE_MAX];
	struct natflow_dpi_proto_rule proto[NATFLOW_DPI_PROTO_RULE_MAX];
};

struct natflow_dpi_event_node {
	struct list_head list;
	struct natflow_dpi_event_hdr hdr;
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
static DEFINE_MUTEX(natflow_dpi_write_lock);
static wait_queue_head_t natflow_dpi_wait;
static LIST_HEAD(natflow_dpi_event_list);
static DEFINE_SPINLOCK(natflow_dpi_event_lock);
static unsigned int natflow_dpi_event_count;
static struct natflow_dpi_ruleset __rcu *natflow_dpi_active_ruleset;
static struct natflow_dpi_ruleset *natflow_dpi_pending_ruleset;
static unsigned int natflow_dpi_state = NATFLOW_DPI_STATE_DISABLED;
static unsigned int natflow_dpi_txn_active;
static unsigned int natflow_dpi_rules;
static unsigned int natflow_dpi_generation = 1;
static atomic64_t natflow_dpi_events;
static atomic64_t natflow_dpi_events_lost;

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

static inline int natflow_dpi_host_char_valid(unsigned char c)
{
	return (c >= 'a' && c <= 'z') ||
	       (c >= '0' && c <= '9') ||
	       c == '-' ||
	       c == '.';
}

static int natflow_dpi_host_normalize(unsigned char *dst,
                                      const unsigned char *src,
                                      unsigned int len)
{
	unsigned int i;
	unsigned int out = 0;
	unsigned int label_len = 0;
	unsigned char last = 0;

	if (!src || len == 0)
		return -EINVAL;
	if (len > NATFLOW_DPI_HOST_MAX_LEN)
		return -EINVAL;

	if (src[len - 1] == '.')
		len--;
	if (len == 0 || len > NATFLOW_DPI_HOST_MAX_LEN)
		return -EINVAL;

	for (i = 0; i < len; i++) {
		unsigned char c = src[i];

		if (c >= 'A' && c <= 'Z')
			c = c - 'A' + 'a';
		if (!natflow_dpi_host_char_valid(c))
			return -EINVAL;

		if (c == '.') {
			if (label_len == 0 || label_len > 63 || (out > 0 && last == '-'))
				return -EINVAL;
			if (dst)
				dst[out] = c;
			out++;
			last = c;
			label_len = 0;
			continue;
		}

		if (label_len == 0 && c == '-')
			return -EINVAL;
		label_len++;
		if (label_len > 63)
			return -EINVAL;
		if (dst)
			dst[out] = c;
		out++;
		last = c;
	}

	if (label_len == 0 || (out > 0 && last == '-'))
		return -EINVAL;
	if (dst)
		dst[out] = 0;
	return out;
}

static struct natflow_dpi_ruleset *natflow_dpi_ruleset_alloc(unsigned int generation)
{
	struct natflow_dpi_ruleset *ruleset;

	ruleset = kzalloc(sizeof(*ruleset), GFP_KERNEL);
	if (!ruleset)
		return NULL;
	ruleset->generation = generation;
	return ruleset;
}

static void natflow_dpi_ruleset_free_rcu(struct rcu_head *rcu)
{
	kfree(container_of(rcu, struct natflow_dpi_ruleset, rcu));
}

static void natflow_dpi_ruleset_free(struct natflow_dpi_ruleset *ruleset)
{
	kfree(ruleset);
}

static void natflow_dpi_pending_free(void)
{
	natflow_dpi_ruleset_free(natflow_dpi_pending_ruleset);
	natflow_dpi_pending_ruleset = NULL;
}

static unsigned int natflow_dpi_ruleset_count(const struct natflow_dpi_ruleset *ruleset)
{
	if (!ruleset)
		return 0;
	return ruleset->domain_count + ruleset->proto_count;
}

static bool natflow_dpi_pending_rule_id_exists(unsigned int rule_id)
{
	unsigned int i;

	if (!natflow_dpi_pending_ruleset)
		return false;

	for (i = 0; i < natflow_dpi_pending_ruleset->domain_count; i++) {
		if (natflow_dpi_pending_ruleset->domain[i].rule_id == rule_id)
			return true;
	}
	for (i = 0; i < natflow_dpi_pending_ruleset->proto_count; i++) {
		if (natflow_dpi_pending_ruleset->proto[i].rule_id == rule_id)
			return true;
	}
	return false;
}

static int natflow_dpi_proto_parse(const char *name, unsigned char *proto)
{
	if (strcmp(name, "dns") == 0) {
		*proto = NATFLOW_DPI_PROTO_DNS;
		return 0;
	}
	if (strcmp(name, "ssh") == 0) {
		*proto = NATFLOW_DPI_PROTO_SSH;
		return 0;
	}
	if (strcmp(name, "wireguard") == 0 || strcmp(name, "wg") == 0) {
		*proto = NATFLOW_DPI_PROTO_WIREGUARD;
		return 0;
	}
	return -EINVAL;
}

static int natflow_dpi_ruleset_domain_add(char *data)
{
	struct natflow_dpi_domain_rule *rule;
	unsigned char host[NATFLOW_DPI_HOST_MAX_LEN + 1];
	unsigned int rule_id = 0;
	unsigned int app_id = 0;
	unsigned char kind = NATFLOW_DPI_DOMAIN_EXACT;
	unsigned int host_len = 0;
	bool have_id = false;
	bool have_app = false;
	bool have_kind = false;
	bool have_host = false;
	char *p = data + strlen("domain");

	if (!natflow_dpi_txn_active || !natflow_dpi_pending_ruleset)
		return -EINVAL;
	if (natflow_dpi_pending_ruleset->domain_count >= NATFLOW_DPI_DOMAIN_RULE_MAX)
		return -ENOSPC;

	while (*p != 0) {
		char *token;
		char *next;

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == 0)
			break;
		token = p;
		while (*p != 0 && *p != ' ' && *p != '\t')
			p++;
		next = p;
		if (*next != 0)
			*next++ = 0;

		if (strncmp(token, "id=", 3) == 0) {
			if (have_id || kstrtouint(token + 3, 0, &rule_id) != 0 || rule_id == 0)
				return -EINVAL;
			have_id = true;
		} else if (strncmp(token, "app=", 4) == 0) {
			if (have_app || kstrtouint(token + 4, 0, &app_id) != 0 || app_id == 0)
				return -EINVAL;
			have_app = true;
		} else if (strncmp(token, "kind=", 5) == 0) {
			if (have_kind)
				return -EINVAL;
			if (strcmp(token + 5, "exact") == 0)
				kind = NATFLOW_DPI_DOMAIN_EXACT;
			else if (strcmp(token + 5, "suffix") == 0)
				kind = NATFLOW_DPI_DOMAIN_SUFFIX;
			else
				return -EINVAL;
			have_kind = true;
		} else if (strncmp(token, "host=", 5) == 0) {
			int normalized_len;

			if (have_host)
				return -EINVAL;
			normalized_len = natflow_dpi_host_normalize(host, token + 5, strlen(token + 5));
			if (normalized_len <= 0)
				return -EINVAL;
			host_len = normalized_len;
			have_host = true;
		} else {
			return -EINVAL;
		}

		p = next;
	}

	if (!have_id || !have_app || !have_kind || !have_host)
		return -EINVAL;

	if (natflow_dpi_pending_rule_id_exists(rule_id))
		return -EEXIST;

	rule = &natflow_dpi_pending_ruleset->domain[natflow_dpi_pending_ruleset->domain_count++];
	rule->rule_id = rule_id;
	rule->app_id = app_id;
	rule->kind = kind;
	rule->host_len = host_len;
	memcpy(rule->host, host, host_len + 1);
	return 0;
}

static int natflow_dpi_ruleset_proto_add(char *data)
{
	struct natflow_dpi_proto_rule *rule;
	unsigned int rule_id = 0;
	unsigned int app_id = 0;
	unsigned char proto = 0;
	bool have_id = false;
	bool have_app = false;
	bool have_proto = false;
	char *p = data + strlen("proto");

	if (!natflow_dpi_txn_active || !natflow_dpi_pending_ruleset)
		return -EINVAL;
	if (natflow_dpi_pending_ruleset->proto_count >= NATFLOW_DPI_PROTO_RULE_MAX)
		return -ENOSPC;

	while (*p != 0) {
		char *token;
		char *next;

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p == 0)
			break;
		token = p;
		while (*p != 0 && *p != ' ' && *p != '\t')
			p++;
		next = p;
		if (*next != 0)
			*next++ = 0;

		if (strncmp(token, "id=", 3) == 0) {
			if (have_id || kstrtouint(token + 3, 0, &rule_id) != 0 || rule_id == 0)
				return -EINVAL;
			have_id = true;
		} else if (strncmp(token, "app=", 4) == 0) {
			if (have_app || kstrtouint(token + 4, 0, &app_id) != 0 || app_id == 0)
				return -EINVAL;
			have_app = true;
		} else if (strncmp(token, "proto=", 6) == 0) {
			if (have_proto || natflow_dpi_proto_parse(token + 6, &proto) != 0)
				return -EINVAL;
			have_proto = true;
		} else {
			return -EINVAL;
		}

		p = next;
	}

	if (!have_id || !have_app || !have_proto)
		return -EINVAL;
	if (natflow_dpi_pending_rule_id_exists(rule_id))
		return -EEXIST;

	rule = &natflow_dpi_pending_ruleset->proto[natflow_dpi_pending_ruleset->proto_count++];
	rule->rule_id = rule_id;
	rule->app_id = app_id;
	rule->proto = proto;
	return 0;
}

static bool natflow_dpi_domain_rule_match(const struct natflow_dpi_domain_rule *rule,
        const unsigned char *host, unsigned int host_len)
{
	if (rule->host_len == host_len && memcmp(rule->host, host, host_len) == 0)
		return true;

	if (rule->kind != NATFLOW_DPI_DOMAIN_SUFFIX)
		return false;
	if (host_len <= rule->host_len)
		return false;
	if (host[host_len - rule->host_len - 1] != '.')
		return false;
	return memcmp(host + host_len - rule->host_len, rule->host, rule->host_len) == 0;
}

static void natflow_dpi_event_queue(unsigned int reason, unsigned int generation,
                                    unsigned int app_id, unsigned int rule_id,
                                    unsigned int flags)
{
	struct natflow_dpi_event_node *node;

	node = kzalloc(sizeof(*node), GFP_ATOMIC);
	if (!node) {
		atomic64_inc(&natflow_dpi_events_lost);
		return;
	}

	node->hdr.version = NATFLOW_DPI_EVENT_VERSION;
	node->hdr.header_len = sizeof(struct natflow_dpi_event_hdr);
	node->hdr.record_len = sizeof(struct natflow_dpi_event_hdr);
	node->hdr.reason = reason;
	node->hdr.generation = generation;
	node->hdr.app_id = app_id;
	node->hdr.category_id = 0;
	node->hdr.rule_id = rule_id;
	node->hdr.flags = flags;
	node->hdr.timestamp = ktime_get_ns();

	spin_lock_bh(&natflow_dpi_event_lock);
	if (natflow_dpi_event_count >= NATFLOW_DPI_EVENT_MAX) {
		spin_unlock_bh(&natflow_dpi_event_lock);
		kfree(node);
		atomic64_inc(&natflow_dpi_events_lost);
		return;
	}
	list_add_tail(&node->list, &natflow_dpi_event_list);
	natflow_dpi_event_count++;
	spin_unlock_bh(&natflow_dpi_event_lock);

	atomic64_inc(&natflow_dpi_events);
	wake_up_interruptible(&natflow_dpi_wait);
}

static void natflow_dpi_event_purge(void)
{
	struct natflow_dpi_event_node *node;
	struct natflow_dpi_event_node *tmp;
	LIST_HEAD(free_list);

	spin_lock_bh(&natflow_dpi_event_lock);
	list_splice_init(&natflow_dpi_event_list, &free_list);
	natflow_dpi_event_count = 0;
	spin_unlock_bh(&natflow_dpi_event_lock);

	list_for_each_entry_safe(node, tmp, &free_list, list)
		kfree(node);
}

static int natflow_dpi_rules_begin(void)
{
	struct natflow_dpi_ruleset *pending;

	if (natflow_dpi_txn_active)
		return -EBUSY;

	pending = natflow_dpi_ruleset_alloc(natflow_dpi_generation + 1);
	if (!pending)
		return -ENOMEM;

	natflow_dpi_pending_ruleset = pending;
	natflow_dpi_txn_active = 1;
	return 0;
}

static int natflow_dpi_rules_commit(void)
{
	struct natflow_dpi_ruleset *old_ruleset;
	struct natflow_dpi_ruleset *new_ruleset;

	if (!natflow_dpi_txn_active || !natflow_dpi_pending_ruleset)
		return -EINVAL;

	new_ruleset = natflow_dpi_pending_ruleset;
	natflow_dpi_pending_ruleset = NULL;
	natflow_dpi_txn_active = 0;
	old_ruleset = rcu_dereference_protected(natflow_dpi_active_ruleset, 1);
	rcu_assign_pointer(natflow_dpi_active_ruleset, new_ruleset);
	natflow_dpi_generation = new_ruleset->generation;
	natflow_dpi_rules = natflow_dpi_ruleset_count(new_ruleset);
	if (old_ruleset)
		call_rcu(&old_ruleset->rcu, natflow_dpi_ruleset_free_rcu);
	return 0;
}

static int natflow_dpi_rules_clear(void)
{
	struct natflow_dpi_ruleset *old_ruleset;
	struct natflow_dpi_ruleset *new_ruleset;

	new_ruleset = natflow_dpi_ruleset_alloc(natflow_dpi_generation + 1);
	if (!new_ruleset)
		return -ENOMEM;

	natflow_dpi_pending_free();
	natflow_dpi_txn_active = 0;
	old_ruleset = rcu_dereference_protected(natflow_dpi_active_ruleset, 1);
	rcu_assign_pointer(natflow_dpi_active_ruleset, new_ruleset);
	natflow_dpi_generation = new_ruleset->generation;
	natflow_dpi_rules = 0;
	if (old_ruleset)
		call_rcu(&old_ruleset->rcu, natflow_dpi_ruleset_free_rcu);
	return 0;
}

void natflow_dpi_classify_host(struct nf_conn *ct, const unsigned char *host,
                               unsigned short host_len, unsigned int source)
{
	const struct natflow_dpi_domain_rule *rule;
	struct natflow_dpi_ruleset *ruleset;
	unsigned char normalized[NATFLOW_DPI_HOST_MAX_LEN + 1];
	natflow_t *nf;
	int normalized_len;
	unsigned int i;

	if (!ct || !host || host_len == 0)
		return;
	if (READ_ONCE(natflow_dpi_state) != NATFLOW_DPI_STATE_ENABLED)
		return;

	normalized_len = natflow_dpi_host_normalize(normalized, host, host_len);
	if (normalized_len <= 0)
		return;

	rcu_read_lock();
	ruleset = rcu_dereference(natflow_dpi_active_ruleset);
	if (!ruleset) {
		rcu_read_unlock();
		return;
	}

	for (i = 0; i < ruleset->domain_count; i++) {
		rule = &ruleset->domain[i];
		if (!natflow_dpi_domain_rule_match(rule, normalized, normalized_len))
			continue;

		nf = natflow_session_get(ct);
		if (nf)
			WRITE_ONCE(nf->app_id, rule->app_id);
		natflow_dpi_event_queue(NATFLOW_DPI_REASON_MATCHED,
		                        ruleset->generation, rule->app_id,
		                        rule->rule_id, source);
		break;
	}
	rcu_read_unlock();
}

static unsigned int natflow_dpi_proto_event_source(unsigned int proto)
{
	switch (proto) {
	case NATFLOW_DPI_PROTO_DNS:
		return NATFLOW_DPI_EVENT_SOURCE_DNS;
	case NATFLOW_DPI_PROTO_SSH:
		return NATFLOW_DPI_EVENT_SOURCE_SSH;
	case NATFLOW_DPI_PROTO_WIREGUARD:
		return NATFLOW_DPI_EVENT_SOURCE_WIREGUARD;
	default:
		return 0;
	}
}

static void natflow_dpi_classify_proto(struct nf_conn *ct, unsigned int proto)
{
	const struct natflow_dpi_proto_rule *rule;
	struct natflow_dpi_ruleset *ruleset;
	natflow_t *nf;
	unsigned int i;
	unsigned int source;

	if (!ct || proto == 0)
		return;
	if (READ_ONCE(natflow_dpi_state) != NATFLOW_DPI_STATE_ENABLED)
		return;

	nf = natflow_session_get(ct);
	if (!nf || READ_ONCE(nf->app_id) != 0)
		return;

	source = natflow_dpi_proto_event_source(proto);
	if (source == 0)
		return;

	rcu_read_lock();
	ruleset = rcu_dereference(natflow_dpi_active_ruleset);
	if (!ruleset) {
		rcu_read_unlock();
		return;
	}

	for (i = 0; i < ruleset->proto_count; i++) {
		rule = &ruleset->proto[i];
		if (rule->proto != proto)
			continue;

		WRITE_ONCE(nf->app_id, rule->app_id);
		natflow_dpi_event_queue(NATFLOW_DPI_REASON_MATCHED,
		                        ruleset->generation, rule->app_id,
		                        rule->rule_id, source);
		break;
	}
	rcu_read_unlock();
}

static void *natflow_dpi_ctl_start(struct seq_file *m, loff_t *pos)
{
	char *buffer = m->private;
	struct natflow_dpi_ruleset *ruleset;
	unsigned int domain_rules = 0;
	unsigned int proto_rules = 0;
	int n;

	if (*pos != 0)
		return NULL;

	mutex_lock(&natflow_dpi_lock);
	ruleset = rcu_dereference_protected(natflow_dpi_active_ruleset, 1);
	if (ruleset) {
		domain_rules = ruleset->domain_count;
		proto_rules = ruleset->proto_count;
	}
	n = snprintf(buffer, PAGE_SIZE - 1,
	             "# Version: %s\n"
	             "# Usage:\n"
	             "#    enable=0|1\n"
	             "#    rules_begin\n"
	             "#    domain id=<rule_id> app=<app_id> kind=exact|suffix host=<host>\n"
	             "#    proto id=<rule_id> app=<app_id> proto=dns|ssh|wireguard\n"
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
	             "domain_rules=%u\n"
	             "proto_rules=%u\n"
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
	             domain_rules,
	             proto_rules,
	             natflow_dpi_txn_active,
	             (unsigned long long)atomic64_read(&natflow_dpi_events),
	             (unsigned long long)atomic64_read(&natflow_dpi_events_lost));
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
		WRITE_ONCE(natflow_dpi_state, NATFLOW_DPI_STATE_ENABLED);
	} else if (strcmp(data, "enable=0") == 0 || strcmp(data, "disable") == 0) {
		WRITE_ONCE(natflow_dpi_state, NATFLOW_DPI_STATE_DISABLED);
		wake_up_interruptible(&natflow_dpi_wait);
	} else if (strcmp(data, "rules_begin") == 0) {
		err = natflow_dpi_rules_begin();
		if (err != 0)
			goto out;
	} else if (strncmp(data, "domain ", strlen("domain ")) == 0) {
		err = natflow_dpi_ruleset_domain_add(data);
		if (err != 0)
			goto out;
	} else if (strncmp(data, "proto ", strlen("proto ")) == 0) {
		err = natflow_dpi_ruleset_proto_add(data);
		if (err != 0)
			goto out;
	} else if (strcmp(data, "rules_commit") == 0) {
		err = natflow_dpi_rules_commit();
		if (err != 0)
			goto out;
	} else if (strcmp(data, "rules_abort") == 0) {
		natflow_dpi_pending_free();
		natflow_dpi_txn_active = 0;
	} else if (strcmp(data, "rules_clear") == 0) {
		err = natflow_dpi_rules_clear();
		if (err != 0)
			goto out;
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
	ssize_t ret;
	int err;
	int n, l;
	int cnt = NATFLOW_DPI_CTL_MAX_LINE;
	static char data[NATFLOW_DPI_CTL_MAX_LINE];
	static int data_left = 0;
	int old_data_left;

	mutex_lock(&natflow_dpi_write_lock);
	old_data_left = data_left;
	cnt -= data_left;
	if (buf_len < cnt)
		cnt = buf_len;

	if (copy_from_user(data + data_left, buf, cnt) != 0) {
		ret = -EACCES;
		goto out_unlock;
	}

	n = 0;
	if (old_data_left == 0) {
		while (n < cnt && (data[n] == ' ' || data[n] == '\n' || data[n] == '\t'))
			n++;
	}
	if (n) {
		*offset += n;
		data_left = 0;
		ret = n;
		goto out_unlock;
	}

	l = 0;
	while (l < cnt && data[l + data_left] != '\n')
		l++;
	if (l >= cnt) {
		data_left += l;
		if (data_left >= NATFLOW_DPI_CTL_MAX_LINE) {
			data_left = 0;
			ret = -EINVAL;
			goto out_unlock;
		}
		goto done;
	}

	data[l + data_left] = 0;
	data_left = 0;
	l++;

	err = natflow_dpi_ctl_apply_line(data);
	if (err != 0) {
		ret = err;
		goto out_unlock;
	}

done:
	*offset += l;
	ret = l;
out_unlock:
	mutex_unlock(&natflow_dpi_write_lock);
	return ret;
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
	struct natflow_dpi_event_node *node;
	ssize_t ret;

	if (count < sizeof(struct natflow_dpi_event_hdr))
		return -EINVAL;

	spin_lock_bh(&natflow_dpi_event_lock);
	if (list_empty(&natflow_dpi_event_list)) {
		spin_unlock_bh(&natflow_dpi_event_lock);
		return 0;
	}

	node = list_first_entry(&natflow_dpi_event_list,
	                        struct natflow_dpi_event_node, list);
	list_del(&node->list);
	natflow_dpi_event_count--;
	spin_unlock_bh(&natflow_dpi_event_lock);

	if (copy_to_user(buf, &node->hdr, sizeof(node->hdr)) != 0)
		ret = -EFAULT;
	else
		ret = sizeof(node->hdr);
	kfree(node);
	return ret;
}

static unsigned int natflow_dpi_queue_poll(struct file *file, poll_table *wait)
{
	unsigned int mask = 0;

	poll_wait(file, &natflow_dpi_wait, wait);
	spin_lock_bh(&natflow_dpi_event_lock);
	if (!list_empty(&natflow_dpi_event_list))
		mask = POLLIN | POLLRDNORM;
	spin_unlock_bh(&natflow_dpi_event_lock);
	return mask;
}

static const struct file_operations natflow_dpi_queue_fops = {
	.owner = THIS_MODULE,
	.read = natflow_dpi_queue_read,
	.poll = natflow_dpi_queue_poll,
	.llseek = no_llseek,
};

static unsigned int natflow_dpi_detect_tcp(__be16 dport)
{
	if (dport == __constant_htons(53))
		return NATFLOW_DPI_PROTO_DNS;
	if (dport == __constant_htons(22))
		return NATFLOW_DPI_PROTO_SSH;
	return 0;
}

static unsigned int natflow_dpi_detect_udp(__be16 dport)
{
	if (dport == __constant_htons(53))
		return NATFLOW_DPI_PROTO_DNS;
	if (dport == __constant_htons(51820))
		return NATFLOW_DPI_PROTO_WIREGUARD;
	return 0;
}

static void natflow_dpi_detect_ipv4(struct sk_buff *skb, struct nf_conn *ct)
{
	struct iphdr *iph;
	void *l4;
	unsigned int ihl;
	unsigned int proto = 0;

	if (!pskb_may_pull(skb, sizeof(struct iphdr)))
		return;

	iph = ip_hdr(skb);
	if (iph->version != 4 || iph->ihl < 5)
		return;
	ihl = iph->ihl * 4;
	if (!pskb_may_pull(skb, ihl))
		return;

	iph = ip_hdr(skb);
	if (iph->protocol == IPPROTO_TCP) {
		if (!pskb_may_pull(skb, ihl + sizeof(struct tcphdr)))
			return;
		iph = ip_hdr(skb);
		l4 = (void *)iph + ihl;
		if (TCPH(l4)->doff < 5)
			return;
		if (!pskb_may_pull(skb, ihl + TCPH(l4)->doff * 4))
			return;
		iph = ip_hdr(skb);
		l4 = (void *)iph + ihl;
		proto = natflow_dpi_detect_tcp(TCPH(l4)->dest);
	} else if (iph->protocol == IPPROTO_UDP) {
		if (!pskb_may_pull(skb, ihl + sizeof(struct udphdr)))
			return;
		iph = ip_hdr(skb);
		l4 = (void *)iph + ihl;
		if (ntohs(UDPH(l4)->len) < sizeof(struct udphdr))
			return;
		proto = natflow_dpi_detect_udp(UDPH(l4)->dest);
	}

	if (proto)
		natflow_dpi_classify_proto(ct, proto);
}

static void natflow_dpi_detect_ipv6(struct sk_buff *skb, struct nf_conn *ct)
{
	struct ipv6hdr *ip6h;
	void *l4;
	unsigned int proto = 0;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
		return;

	ip6h = ipv6_hdr(skb);
	if (ip6h->version != 6)
		return;
	if (ip6h->nexthdr == IPPROTO_TCP) {
		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct tcphdr)))
			return;
		ip6h = ipv6_hdr(skb);
		l4 = (void *)ip6h + sizeof(struct ipv6hdr);
		if (TCPH(l4)->doff < 5)
			return;
		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + TCPH(l4)->doff * 4))
			return;
		ip6h = ipv6_hdr(skb);
		l4 = (void *)ip6h + sizeof(struct ipv6hdr);
		proto = natflow_dpi_detect_tcp(TCPH(l4)->dest);
	} else if (ip6h->nexthdr == IPPROTO_UDP) {
		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct udphdr)))
			return;
		ip6h = ipv6_hdr(skb);
		l4 = (void *)ip6h + sizeof(struct ipv6hdr);
		if (ntohs(UDPH(l4)->len) < sizeof(struct udphdr))
			return;
		proto = natflow_dpi_detect_udp(UDPH(l4)->dest);
	}

	if (proto)
		natflow_dpi_classify_proto(ct, proto);
}

#if NATFLOW_NF_HOOK_OPS_HAVE_HOOKNUM_ARG
static unsigned int natflow_dpi_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif NATFLOW_NF_HOOK_OPS_HAVE_DEV_ARGS
static unsigned int natflow_dpi_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
#elif NATFLOW_NF_HOOK_OPS_HAVE_STATE_ARG
static unsigned int natflow_dpi_hook(const struct nf_hook_ops *ops,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
#else
static unsigned int natflow_dpi_hook(void *priv,
        struct sk_buff *skb,
        const struct nf_hook_state *state)
{
#endif
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	int bridge = 0;

	if (READ_ONCE(natflow_dpi_state) != NATFLOW_DPI_STATE_ENABLED ||
	        READ_ONCE(natflow_dpi_rules) == 0)
		return NF_ACCEPT;

	if (skb->protocol == __constant_htons(ETH_P_PPP_SES)) {
		if (!pskb_may_pull(skb, PPPOE_SES_HLEN))
			return NF_ACCEPT;

		if (pppoe_proto(skb) == __constant_htons(PPP_IP)) {
			skb_pull(skb, PPPOE_SES_HLEN);
			skb->protocol = __constant_htons(ETH_P_IP);
			skb->network_header += PPPOE_SES_HLEN;
			bridge = 1;
		} else if (pppoe_proto(skb) == __constant_htons(PPP_IPV6)) {
			skb_pull(skb, PPPOE_SES_HLEN);
			skb->protocol = __constant_htons(ETH_P_IPV6);
			skb->network_header += PPPOE_SES_HLEN;
			bridge = 1;
		} else {
			return NF_ACCEPT;
		}
	} else if (skb->protocol != __constant_htons(ETH_P_IP) &&
	           skb->protocol != __constant_htons(ETH_P_IPV6)) {
		return NF_ACCEPT;
	}

	ct = nf_ct_get(skb, &ctinfo);
	if (!ct || CTINFO2DIR(ctinfo) != IP_CT_DIR_ORIGINAL)
		goto out;

	if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num == AF_INET6)
		natflow_dpi_detect_ipv6(skb, ct);
	else if (ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple.src.l3num == AF_INET)
		natflow_dpi_detect_ipv4(skb, ct);

out:
	if (bridge) {
		skb->network_header -= PPPOE_SES_HLEN;
		skb->protocol = __constant_htons(ETH_P_PPP_SES);
		skb_push(skb, PPPOE_SES_HLEN);
	}
	return NF_ACCEPT;
}

static struct nf_hook_ops natflow_dpi_hooks[] = {
	{
#if NATFLOW_NF_HOOK_OPS_HAVE_OWNER
		.owner = THIS_MODULE,
#endif
		.hook = natflow_dpi_hook,
		.pf = PF_INET,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER + 6,
	},
	{
#if NATFLOW_NF_HOOK_OPS_HAVE_OWNER
		.owner = THIS_MODULE,
#endif
		.hook = natflow_dpi_hook,
		.pf = AF_INET6,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER + 6,
	},
	{
#if NATFLOW_NF_HOOK_OPS_HAVE_OWNER
		.owner = THIS_MODULE,
#endif
		.hook = natflow_dpi_hook,
		.pf = NFPROTO_BRIDGE,
		.hooknum = NF_INET_FORWARD,
		.priority = NF_IP_PRI_FILTER + 6,
	},
};

static int natflow_dpi_hooks_started;

static int natflow_dpi_hooks_register(void)
{
	int ret;

	ret = nf_register_hooks(natflow_dpi_hooks, ARRAY_SIZE(natflow_dpi_hooks));
	if (ret == 0)
		natflow_dpi_hooks_started = 1;
	return ret;
}

static void natflow_dpi_hooks_unregister(void)
{
	if (!natflow_dpi_hooks_started)
		return;

	nf_unregister_hooks(natflow_dpi_hooks, ARRAY_SIZE(natflow_dpi_hooks));
	natflow_dpi_hooks_started = 0;
}

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
	struct natflow_dpi_ruleset *ruleset;
	int ret;

	ret = natflow_ct_ext_layout_validate();
	if (ret != 0)
		return ret;

	init_waitqueue_head(&natflow_dpi_wait);
	atomic64_set(&natflow_dpi_events, 0);
	atomic64_set(&natflow_dpi_events_lost, 0);
	natflow_dpi_generation = 1;
	natflow_dpi_rules = 0;
	natflow_dpi_txn_active = 0;
	WRITE_ONCE(natflow_dpi_state, NATFLOW_DPI_STATE_DISABLED);

	ruleset = natflow_dpi_ruleset_alloc(natflow_dpi_generation);
	if (!ruleset)
		return -ENOMEM;
	rcu_assign_pointer(natflow_dpi_active_ruleset, ruleset);

	ret = natflow_dpi_ctl_device_init();
	if (ret != 0)
		goto ctl_device_init_failed;

	ret = natflow_dpi_queue_device_init();
	if (ret != 0)
		goto queue_device_init_failed;

	ret = natflow_dpi_hooks_register();
	if (ret != 0)
		goto hooks_register_failed;

	return 0;

hooks_register_failed:
	natflow_dpi_queue_device_exit();
queue_device_init_failed:
	natflow_dpi_ctl_device_exit();
ctl_device_init_failed:
	rcu_assign_pointer(natflow_dpi_active_ruleset, NULL);
	synchronize_rcu();
	natflow_dpi_ruleset_free(ruleset);
	return ret;
}

void natflow_dpi_exit(void)
{
	struct natflow_dpi_ruleset *ruleset;

	natflow_dpi_hooks_unregister();

	mutex_lock(&natflow_dpi_lock);
	WRITE_ONCE(natflow_dpi_state, NATFLOW_DPI_STATE_DISABLED);
	natflow_dpi_pending_free();
	natflow_dpi_txn_active = 0;
	ruleset = rcu_dereference_protected(natflow_dpi_active_ruleset, 1);
	rcu_assign_pointer(natflow_dpi_active_ruleset, NULL);
	natflow_dpi_generation = 1;
	natflow_dpi_rules = 0;
	mutex_unlock(&natflow_dpi_lock);

	wake_up_interruptible(&natflow_dpi_wait);
	natflow_dpi_queue_device_exit();
	natflow_dpi_ctl_device_exit();
	natflow_dpi_event_purge();
	synchronize_rcu();
	natflow_dpi_ruleset_free(ruleset);
	rcu_barrier();
}
