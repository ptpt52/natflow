/* Userspace harness for the actual natflow_control.h implementation.
 * Only kernel allocation, mutex and uaccess primitives are substituted.
 */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#define MAX_IOCTL_LEN 256
#define PAGE_SIZE 4096
#define __user
#define __aligned(n) __attribute__((aligned(n)))
#define BUILD_BUG_ON(expr) _Static_assert(!(expr), #expr)
#define min_t(type, a, b) ((type)(a) < (type)(b) ? (type)(a) : (type)(b))

struct mutex {
	pthread_mutex_t native;
};
struct result {
	char last[512];
	unsigned int calls;
	unsigned int thread_calls[8];
	int error;
};
struct file {
	void *private_data;
	struct result result;
	loff_t offset;
};
struct inode {
	int unused;
};
struct seq_file {
	void *private;
};
struct seq_operations {
	int unused;
};

static int fail_alloc, fail_copy;

static void mutex_init(struct mutex *m)
{
	assert(!pthread_mutex_init(&m->native, NULL));
}

static void mutex_destroy(struct mutex *m)
{
	assert(!pthread_mutex_destroy(&m->native));
}

static void mutex_lock(struct mutex *m)
{
	assert(!pthread_mutex_lock(&m->native));
}

static void mutex_unlock(struct mutex *m)
{
	assert(!pthread_mutex_unlock(&m->native));
}

static int seq_open_private(struct file *file, const struct seq_operations *ops,
                            size_t size)
{
	struct seq_file *m;
	(void)ops;
	if (fail_alloc)
		return -ENOMEM;
	m = calloc(1, sizeof(*m));
	assert(m);
	m->private = calloc(1, size);
	assert(m->private);
	file->private_data = m;
	return 0;
}

static int seq_release_private(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	(void)inode;
	free(m->private);
	free(m);
	file->private_data = NULL;
	return 0;
}

static size_t copy_from_user(void *dst, const void *src, size_t count)
{
	if (fail_copy) {
		memcpy(dst, src, count / 2);
		return count - count / 2;
	}
	memcpy(dst, src, count);
	return 0;
}

/* Generated from the production header by removing only #include lines. */
#include "natflow_control_test.h"

static int apply(struct file *file, char *data)
{
	struct result *result = &file->result;

	assert(strlen(data) < sizeof(result->last));
	strcpy(result->last, data);
	result->calls++;
	if (!strncmp(data, "thread", 6)) {
		assert(strlen(data) == 7 && data[6] >= '0' && data[6] <= '7');
		result->thread_calls[data[6] - '0']++;
	}
	return result->error;
}

static ssize_t put(struct file *file, const char *data, size_t count)
{
	return natflow_ctl_seq_write(file, data, count, &file->offset, apply);
}

static struct natflow_ctl_input *input(struct file *file)
{
	struct seq_file *m = file->private_data;
	struct natflow_ctl_seq *ctl = m->private;

	return &ctl->input;
}

struct worker {
	struct file *file;
	unsigned int id;
};

static void *writer(void *arg)
{
	struct worker *w = arg;
	char command[16];
	unsigned int i;
	int n = snprintf(command, sizeof(command), "thread%u\n", w->id);

	for (i = 0; i < 2000; i++)
		assert(put(w->file, command, n) == n);
	return NULL;
}

int main(void)
{
	struct file a = {0}, b = {0};
	pthread_t threads[8];
	struct worker workers[8];
	char line[513];
	loff_t offset;
	unsigned int i;

	fail_alloc = 1;
	assert(natflow_ctl_seq_open(&a, NULL) == -ENOMEM);
	fail_alloc = 0;
	assert(!natflow_ctl_seq_open(&a, NULL));
	assert(!natflow_ctl_seq_open(&b, NULL));
	assert((uintptr_t)natflow_ctl_seq_buffer(a.private_data) % sizeof(unsigned long) == 0);
	strcpy(natflow_ctl_seq_buffer(a.private_data), "read-buffer");

	assert(put(&a, "alpha", 5) == 5);
	assert(put(&b, "beta\n", 5) == 5);
	assert(put(&a, " tail\n", 6) == 6);
	assert(!strcmp(a.result.last, "alpha tail"));
	assert(!strcmp(b.result.last, "beta"));
	assert(!strcmp(natflow_ctl_seq_buffer(a.private_data), "read-buffer"));
	assert(put(&a, " \t\ncmd\n", 7) == 3);
	assert(put(&a, "cmd\n", 4) == 4);
	assert(put(&a, "one\ntwo\n", 8) == 4);
	assert(!strcmp(a.result.last, "one"));
	assert(put(&a, "two\n", 4) == 4);
	assert(!strcmp(a.result.last, "two"));

	assert(put(&a, "prefix", 6) == 6);
	assert(put(&a, "", 0) == 0 && input(&a)->len == 6);
	fail_copy = 1;
	offset = a.offset;
	assert(put(&a, "broken\n", 7) == -EACCES);
	assert(input(&a)->len == 6 && a.offset == offset);
	fail_copy = 0;
	assert(put(&a, "-ok\n", 4) == 4);
	assert(!strcmp(a.result.last, "prefix-ok"));

	assert(put(&a, "retry", 5) == 5);
	a.result.error = -EAGAIN;
	offset = a.offset;
	assert(put(&a, "\n", 1) == -EAGAIN);
	assert(!input(&a)->len && a.offset == offset);
	a.result.error = 0;
	assert(put(&a, "retry\n", 6) == 6);
	assert(!strcmp(a.result.last, "retry"));
	a.result.error = -EINVAL;
	assert(put(&a, "invalid\n", 8) == -EINVAL);
	a.result.error = 0;

	for (i = 256; i <= 512; i += 256) {
		input(&a)->limit = i;
		memset(line, 'x', sizeof(line));
		line[i - 1] = '\n';
		assert(put(&a, line, i) == (ssize_t)i);
		assert(strlen(a.result.last) == i - 1);
		assert(put(&a, line, i - 1) == (ssize_t)i - 1);
		assert(put(&a, "\n", 1) == 1);
		memset(line, 'x', sizeof(line));
		assert(put(&a, line, i - 1) == (ssize_t)i - 1);
		assert(put(&a, "x", 1) == -EINVAL && !input(&a)->len);
		assert(put(&a, line, i) == -EINVAL && !input(&a)->len);
		assert(put(&a, "ok\n", 3) == 3);
	}
	input(&a)->limit = MAX_IOCTL_LEN;

	assert(put(&a, "discard-on-close", 16) == 16);
	assert(!natflow_ctl_seq_release(NULL, &a));
	assert(!natflow_ctl_seq_open(&a, NULL));
	assert(!input(&a)->len);
	assert(put(&a, "new\n", 4) == 4);
	assert(!strcmp(a.result.last, "new"));
	assert(put(&a, "", 0) == 0);
	offset = a.offset;
	for (i = 0; i < 8; i++) {
		workers[i].file = &a;
		workers[i].id = i;
		assert(!pthread_create(&threads[i], NULL, writer, &workers[i]));
	}
	for (i = 0; i < 8; i++) {
		assert(!pthread_join(threads[i], NULL));
		assert(a.result.thread_calls[i] == 2000);
	}
	assert(a.offset == offset + 8 * 2000 * 8);
	assert(!natflow_ctl_seq_release(NULL, &a));
	assert(!natflow_ctl_seq_release(NULL, &b));
	puts("PASS: control input boundaries, isolation, faults, retry and 16000 concurrent writes");
	return 0;
}
