#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "natflow-dpi-event.h"

#define DPI_QUEUE_DEFAULT "/dev/natflow_dpi_queue"
#define DPI_CACHE_DEFAULT 16U
#define DPI_READ_BATCH 32U
#define DPI_EMPTY_POLL_MS 20

static const char *queue_path = DPI_QUEUE_DEFAULT;

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
	        "Usage: %s [-d queue] [-c cache] [-w timeout-ms]\n"
	        "  -d queue       queue device (default: %s)\n"
	        "  -c cache       live-event cache limit (default: %u)\n"
	        "  -w timeout-ms  require and validate an event within timeout\n",
	        program, DPI_QUEUE_DEFAULT, DPI_CACHE_DEFAULT);
}

static void fail(const char *operation)
{
	fprintf(stderr, "FAIL: %s: %s\n", operation, strerror(errno));
	exit(EXIT_FAILURE);
}

static void fail_message(const char *message)
{
	fprintf(stderr, "FAIL: %s\n", message);
	exit(EXIT_FAILURE);
}

static int parse_uint(const char *value, unsigned int *result)
{
	char *end;
	unsigned long number;

	errno = 0;
	number = strtoul(value, &end, 10);
	if (errno || *value == '\0' || *end != '\0' || number > UINT_MAX)
		return -1;

	*result = (unsigned int)number;
	return 0;
}

static int open_queue(void)
{
	int fd = open(queue_path, O_RDWR | O_CLOEXEC);

	if (fd < 0)
		fail("open queue");
	return fd;
}

static void write_command(int fd, const char *command)
{
	ssize_t length = (ssize_t)strlen(command);
	ssize_t written;

	errno = 0;
	written = write(fd, command, (size_t)length);
	if (written < 0)
		fail("write queue command");
	if (written != length) {
		errno = EIO;
		fail("short queue command write");
	}
}

static void set_cache_limit(int fd, unsigned int cache)
{
	char command[32];
	int length;

	length = snprintf(command, sizeof(command), "cache=%u\n", cache);
	if (length < 0 || (size_t)length >= sizeof(command))
		fail_message("cache command overflow");
	write_command(fd, command);
}

static int poll_queue(int fd, int timeout_ms)
{
	struct pollfd pfd = {
		.fd = fd,
		.events = POLLIN | POLLRDNORM,
	};
	int result;

	do {
		result = poll(&pfd, 1, timeout_ms);
	} while (result < 0 && errno == EINTR);
	if (result < 0)
		fail("poll queue");
	if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
		errno = EIO;
		fail("poll queue revents");
	}
	if (result > 0 && !(pfd.revents & (POLLIN | POLLRDNORM))) {
		errno = EIO;
		fail("unexpected poll queue revents");
	}
	return result;
}

static void expect_empty_queue(int fd)
{
	struct natflow_dpi_event_hdr event;
	ssize_t length;

	length = read(fd, &event, sizeof(event));
	if (length < 0)
		fail("read empty queue");
	if (length != 0)
		fail_message("queue is not empty");
	if (poll_queue(fd, DPI_EMPTY_POLL_MS) != 0)
		fail_message("empty queue is poll-readable");
}

static void test_exclusive_open(void)
{
	int second_fd;

	errno = 0;
	second_fd = open(queue_path, O_RDWR | O_CLOEXEC);
	if (second_fd >= 0) {
		close(second_fd);
		fail_message("second reader open unexpectedly succeeded");
	}
	if (errno != EBUSY)
		fail("second reader open returned unexpected error");
}

static void test_no_seek(int fd)
{
	errno = 0;
	if (lseek(fd, 0, SEEK_SET) != (off_t)-1)
		fail_message("queue seek unexpectedly succeeded");
	if (errno != ESPIPE)
		fail("queue seek returned unexpected error");
}

static void test_small_read(int fd)
{
	unsigned char buffer[NATFLOW_DPI_EVENT_HEADER_LEN - 1];

	errno = 0;
	if (read(fd, buffer, sizeof(buffer)) != -1)
		fail_message("small queue read unexpectedly succeeded");
	if (errno != EINVAL)
		fail("small queue read returned unexpected error");
}

static void test_invalid_command(int fd)
{
	static const char command[] = "invalid-command\n";

	errno = 0;
	if (write(fd, command, sizeof(command) - 1) != -1)
		fail_message("invalid queue command unexpectedly succeeded");
	if (errno != EINVAL)
		fail("invalid queue command returned unexpected error");
}

static void validate_event(const struct natflow_dpi_event_hdr *event)
{
	if (event->version != NATFLOW_DPI_EVENT_VERSION ||
	        event->header_len != sizeof(*event) ||
	        event->record_len != sizeof(*event))
		fail_message("event has unsupported version or length");
	if (event->family != AF_INET && event->family != AF_INET6)
		fail_message("event has unsupported address family");
	if (event->tuple_dir != 0 || event->evidence_dir > 1)
		fail_message("event has invalid direction");
	if (event->reason != NATFLOW_DPI_REASON_MATCHED)
		fail_message("event reason is not MATCHED");
	if (event->app_id == 0 || event->rule_id == 0)
		fail_message("event has an empty app or rule id");
	if (event->flags < NATFLOW_DPI_EVENT_SOURCE_HTTP ||
	        event->flags > NATFLOW_DPI_EVENT_SOURCE_BITTORRENT)
		fail_message("event has an unknown source");
}

static void test_live_event(int fd, unsigned int timeout_ms)
{
	struct natflow_dpi_event_hdr events[DPI_READ_BATCH];
	ssize_t length;
	size_t count;
	size_t i;

	printf("WAIT: generate matching traffic within %u ms\n", timeout_ms);
	if (poll_queue(fd, (int)timeout_ms) == 0)
		fail_message("timed out waiting for a DPI event");

	length = read(fd, events, sizeof(events));
	if (length < 0)
		fail("read live queue event");
	if (length == 0 || (size_t)length % sizeof(events[0]) != 0)
		fail_message("live queue returned an empty or partial batch");

	count = (size_t)length / sizeof(events[0]);
	for (i = 0; i < count; i++)
		validate_event(&events[i]);
	printf("PASS: validated %zu v%u event(s)\n", count,
	       NATFLOW_DPI_EVENT_VERSION);
}

int main(int argc, char **argv)
{
	unsigned int cache = DPI_CACHE_DEFAULT;
	unsigned int wait_ms = 0;
	int option;
	int fd;

	while ((option = getopt(argc, argv, "d:c:w:h")) != -1) {
		switch (option) {
		case 'd':
			queue_path = optarg;
			break;
		case 'c':
			if (parse_uint(optarg, &cache) || cache == 0) {
				fprintf(stderr, "invalid cache value: %s\n", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'w':
			if (parse_uint(optarg, &wait_ms) || wait_ms == 0 ||
			        wait_ms > INT_MAX) {
				fprintf(stderr, "invalid event timeout: %s\n", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'h':
			usage(stdout, argv[0]);
			return EXIT_SUCCESS;
		default:
			usage(stderr, argv[0]);
			return EXIT_FAILURE;
		}
	}
	if (optind != argc) {
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}

	fd = open_queue();
	test_exclusive_open();
	test_no_seek(fd);
	test_small_read(fd);
	expect_empty_queue(fd);
	test_invalid_command(fd);
	set_cache_limit(fd, cache);
	if (wait_ms != 0)
		test_live_event(fd, wait_ms);
	set_cache_limit(fd, 0);
	expect_empty_queue(fd);
	if (close(fd) != 0)
		fail("close queue");

	fd = open_queue();
	expect_empty_queue(fd);
	if (close(fd) != 0)
		fail("close reopened queue");

	printf("PASS: DPI queue structural ABI smoke test\n");
	return EXIT_SUCCESS;
}
