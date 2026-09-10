/* Per-open, newline-delimited control input. */
#ifndef _NATFLOW_CONTROL_H_
#define _NATFLOW_CONTROL_H_

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include "natflow.h"

struct natflow_ctl_input {
	struct mutex lock;
	size_t len;
	size_t limit;
	/* Ordinary controls accept 256 bytes; the DPI control accepts 512. */
	char data[512];
};

struct natflow_ctl_seq {
	struct natflow_ctl_input input;
	/* The main control reader also stores an unsigned long here. */
	char buffer[PAGE_SIZE] __aligned(sizeof(unsigned long));
};

static inline void natflow_ctl_input_init(struct natflow_ctl_input *input)
{
	mutex_init(&input->lock);
	input->len = 0;
	BUILD_BUG_ON(MAX_IOCTL_LEN > sizeof(input->data));
	input->limit = MAX_IOCTL_LEN;
}

static inline ssize_t natflow_ctl_write(struct natflow_ctl_input *input,
                                        struct file *file, const char __user *buf,
                                        size_t count, loff_t *offset,
                                        int (*apply)(struct file *, char *))
{
	size_t cnt, n;
	ssize_t ret;

	mutex_lock(&input->lock);
	cnt = min_t(size_t, count, input->limit - input->len);
	if (!cnt) {
		ret = 0;
		goto out;
	}
	if (copy_from_user(input->data + input->len, buf, cnt)) {
		ret = -EACCES;
		goto out;
	}

	/* Do not trim a continuation: whitespace may belong to the command. */
	n = 0;
	if (!input->len) {
		while (n < cnt && (input->data[n] == ' ' ||
		                   input->data[n] == '\n' || input->data[n] == '\t'))
			n++;
	}
	if (n)
		goto consumed;
	while (n < cnt && input->data[input->len + n] != '\n')
		n++;
	if (n == cnt) {
		input->len += n;
		if (input->len == input->limit) {
			input->len = 0;
			ret = -EINVAL;
			goto out;
		}
		goto consumed;
	}
	input->data[input->len + n] = '\0';
	input->len = 0;
	n++;
	/* Errors discard this line; EAGAIN callers retry the complete command. */
	ret = apply(file, input->data);
	if (ret)
		goto out;
consumed:
	*offset += n;
	ret = n;
out:
	mutex_unlock(&input->lock);
	return ret;
}

static inline int natflow_ctl_seq_open(struct file *file,
                                       const struct seq_operations *ops)
{
	struct seq_file *m;
	struct natflow_ctl_seq *ctl;
	int ret = seq_open_private(file, ops, sizeof(*ctl));

	if (ret)
		return ret;
	m = file->private_data;
	ctl = m->private;
	natflow_ctl_input_init(&ctl->input);
	return 0;
}

static inline int natflow_ctl_seq_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	struct natflow_ctl_seq *ctl = m->private;

	mutex_destroy(&ctl->input.lock);
	return seq_release_private(inode, file);
}

static inline char *natflow_ctl_seq_buffer(struct seq_file *m)
{
	struct natflow_ctl_seq *ctl = m->private;

	return ctl->buffer;
}

static inline ssize_t natflow_ctl_seq_write(struct file *file,
        const char __user *buf, size_t count,
        loff_t *offset,
        int (*apply)(struct file *, char *))
{
	struct seq_file *m = file->private_data;
	struct natflow_ctl_seq *ctl = m->private;

	return natflow_ctl_write(&ctl->input, file, buf, count, offset, apply);
}

#endif
