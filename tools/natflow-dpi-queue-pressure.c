#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "natflow-dpi-event.h"

#define DPI_QUEUE_DEFAULT "/dev/natflow_dpi_queue"
#define DPI_READ_BATCH 32U
#define DPI_POLL_SLICE_MS 100

struct pressure_expectation {
	struct in_addr source_address;
	struct in_addr destination_address;
	const char *queue;
	unsigned int cache;
	unsigned int generated;
	unsigned int app_id;
	unsigned int rule_id;
	unsigned int first_port;
	unsigned int stream_timeout_ms;
};

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
	        "Usage: %s -c cache -n generated -S src -T dst -p first-port "
	        "-a app -r rule [-d queue] [-w timeout-ms] "
	        "-- command [args...]\n"
	        "  Without -w, pause reading and require generated > cache.\n"
	        "  With -w, poll/read concurrently and require every event.\n",
	        program);
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

static int64_t monotonic_milliseconds(void)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		fail("clock_gettime");
	return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

static void configure_queue(int fd, unsigned int cache)
{
	char command[32];
	int length;
	ssize_t written;

	length = snprintf(command, sizeof(command), "cache=%u\n", cache);
	if (length < 0 || (size_t)length >= sizeof(command))
		fail_message("cache command overflow");
	written = write(fd, command, (size_t)length);
	if (written < 0)
		fail("configure DPI queue");
	if (written != length)
		fail_message("short DPI queue command write");
}

static pid_t start_injector(char **command)
{
	pid_t child;

	child = fork();
	if (child < 0)
		fail("fork injector");
	if (child == 0) {
		execvp(command[0], command);
		fprintf(stderr, "FAIL: exec %s: %s\n", command[0],
		        strerror(errno));
		_exit(127);
	}
	return child;
}

static void check_injector_status(int status)
{
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		fail_message("traffic injector failed");
}

static void wait_injector(pid_t child)
{
	pid_t waited;
	int status;

	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited < 0)
		fail("wait for injector");
	check_injector_status(status);
}

static void run_injector(char **command)
{
	wait_injector(start_injector(command));
}

static unsigned int validate_event(
    const struct natflow_dpi_event_hdr *event,
    const struct pressure_expectation *expectation)
{
	if (event->version != NATFLOW_DPI_EVENT_VERSION ||
	        event->header_len != sizeof(*event) ||
	        event->record_len != sizeof(*event))
		fail_message("queue returned an unsupported event ABI");
	if (event->family != AF_INET || event->l4proto != IPPROTO_UDP ||
	        event->tuple_dir != 0 ||
	        event->evidence_dir != 0 ||
	        event->reason != NATFLOW_DPI_REASON_MATCHED)
		fail_message("queue returned an event with unexpected metadata");
	if (event->dport < expectation->first_port ||
	        event->dport >= expectation->first_port + expectation->generated)
		fail_message("queue returned an event outside the test port range");
	if (event->flags != NATFLOW_DPI_EVENT_SOURCE_STUN ||
	        event->app_id != expectation->app_id ||
	        event->rule_id != expectation->rule_id)
		fail_message("queue returned an unexpected classification");
	if (memcmp(event->sip, &expectation->source_address,
	           sizeof(expectation->source_address)) != 0 ||
	        memcmp(event->dip, &expectation->destination_address,
	               sizeof(expectation->destination_address)) != 0)
		fail_message("queue returned an event outside the test tuple");
	return event->dport - expectation->first_port;
}

static unsigned int drain_queue(
    int fd, const struct pressure_expectation *expectation)
{
	struct natflow_dpi_event_hdr events[DPI_READ_BATCH];
	unsigned char *seen;
	unsigned int total = 0;

	seen = calloc(expectation->generated, sizeof(*seen));
	if (!seen)
		fail("allocate event bitmap");
	for (;;) {
		ssize_t length = read(fd, events, sizeof(events));
		size_t count;
		size_t i;

		if (length < 0)
			fail("read DPI queue");
		if (length == 0)
			break;
		if ((size_t)length % sizeof(events[0]) != 0)
			fail_message("DPI queue returned a partial event batch");

		count = (size_t)length / sizeof(events[0]);
		for (i = 0; i < count; i++) {
			unsigned int index = validate_event(&events[i], expectation);

			if (seen[index])
				fail_message("queue returned a duplicate test event");
			seen[index] = 1;
		}
		if (total > UINT_MAX - count)
			fail_message("DPI event count overflow");
		total += (unsigned int)count;
		if (total > expectation->cache)
			fail_message("queue retained more events than its cache limit");
	}
	free(seen);
	return total;
}

static unsigned int read_stream_batch(
    int fd, const struct pressure_expectation *expectation,
    unsigned char *seen)
{
	struct natflow_dpi_event_hdr events[DPI_READ_BATCH];
	ssize_t length;
	size_t count;
	size_t i;

	length = read(fd, events, sizeof(events));
	if (length < 0)
		fail("read DPI queue");
	if (length == 0)
		return 0;
	if ((size_t)length % sizeof(events[0]) != 0)
		fail_message("DPI queue returned a partial event batch");

	count = (size_t)length / sizeof(events[0]);
	for (i = 0; i < count; i++) {
		unsigned int index = validate_event(&events[i], expectation);

		if (seen[index])
			fail_message("queue returned a duplicate test event");
		seen[index] = 1;
	}
	return (unsigned int)count;
}

static void stream_queue(
    int fd, const struct pressure_expectation *expectation, char **command)
{
	unsigned char *seen;
	int64_t deadline;
	unsigned int poll_wakeups = 0;
	unsigned int read_calls = 0;
	unsigned int total = 0;
	int child_done = 0;
	pid_t child;

	seen = calloc(expectation->generated, sizeof(*seen));
	if (!seen)
		fail("allocate event bitmap");
	child = start_injector(command);
	deadline = monotonic_milliseconds() + expectation->stream_timeout_ms;

	while (total < expectation->generated) {
		struct pollfd pfd = {
			.fd = fd,
			.events = POLLIN | POLLRDNORM,
		};
		int64_t remaining = deadline - monotonic_milliseconds();
		int timeout;
		int ready;

		if (remaining <= 0) {
			if (!child_done) {
				kill(child, SIGTERM);
				waitpid(child, NULL, 0);
			}
			fail_message("timed out reading concurrent DPI events");
		}
		timeout = remaining < DPI_POLL_SLICE_MS ?
		          (int)remaining : DPI_POLL_SLICE_MS;
		do {
			ready = poll(&pfd, 1, timeout);
		} while (ready < 0 && errno == EINTR);
		if (ready < 0)
			fail("poll DPI queue");
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			fail_message("DPI queue poll returned an error");
		if (ready > 0) {
			unsigned int count;

			if (!(pfd.revents & (POLLIN | POLLRDNORM)))
				fail_message("DPI queue poll returned unexpected events");
			poll_wakeups++;
			count = read_stream_batch(fd, expectation, seen);
			if (count == 0)
				fail_message("poll-readable DPI queue returned no events");
			if (count > expectation->generated - total)
				fail_message("queue returned too many test events");
			total += count;
			read_calls++;
		}

		if (!child_done) {
			int status;
			pid_t waited = waitpid(child, &status, WNOHANG);

			if (waited < 0)
				fail("poll traffic injector");
			if (waited == child) {
				check_injector_status(status);
				child_done = 1;
			}
		}
		if (child_done && ready == 0)
			fail_message("injector completed before all events were read");
	}

	if (!child_done)
		wait_injector(child);
	if (read_stream_batch(fd, expectation, seen) != 0)
		fail_message("queue returned events beyond the generated set");
	free(seen);
	printf("PASS: streamed %u DPI events with %u poll wakeup(s) "
	       "and %u read(s)\n",
	       total, poll_wakeups, read_calls);
}

int main(int argc, char **argv)
{
	struct pressure_expectation expectation = {
		.queue = DPI_QUEUE_DEFAULT,
	};
	int have_source_address = 0;
	int have_destination_address = 0;
	int have_cache = 0;
	int have_generated = 0;
	int have_app = 0;
	int have_rule = 0;
	int have_first_port = 0;
	unsigned int retained;
	int option;
	int fd;

	while ((option = getopt(argc, argv, "d:c:n:S:T:p:a:r:w:h")) != -1) {
		switch (option) {
		case 'd':
			expectation.queue = optarg;
			break;
		case 'c':
			have_cache = parse_uint(optarg, &expectation.cache) == 0;
			break;
		case 'n':
			have_generated =
			    parse_uint(optarg, &expectation.generated) == 0;
			break;
		case 'S':
			have_source_address =
			    inet_pton(AF_INET, optarg,
			              &expectation.source_address) == 1;
			break;
		case 'T':
			have_destination_address =
			    inet_pton(AF_INET, optarg,
			              &expectation.destination_address) == 1;
			break;
		case 'p':
			have_first_port =
			    parse_uint(optarg, &expectation.first_port) == 0;
			break;
		case 'a':
			have_app = parse_uint(optarg, &expectation.app_id) == 0;
			break;
		case 'r':
			have_rule = parse_uint(optarg, &expectation.rule_id) == 0;
			break;
		case 'w':
			if (parse_uint(optarg, &expectation.stream_timeout_ms) != 0 ||
			        expectation.stream_timeout_ms == 0 ||
			        expectation.stream_timeout_ms > INT_MAX)
				fail_message("invalid stream timeout");
			break;
		case 'h':
			usage(stdout, argv[0]);
			return EXIT_SUCCESS;
		default:
			usage(stderr, argv[0]);
			return EXIT_FAILURE;
		}
	}

	if (!have_source_address || !have_destination_address ||
	        !have_cache || !have_generated || !have_app || !have_rule ||
	        !have_first_port ||
	        expectation.cache == 0 ||
	        expectation.generated == 0 ||
	        (expectation.stream_timeout_ms == 0 &&
	         expectation.generated <= expectation.cache) ||
	        expectation.app_id == 0 || expectation.rule_id == 0 ||
	        expectation.first_port == 0 ||
	        expectation.generated > 65536U - expectation.first_port ||
	        optind >= argc) {
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}

	fd = open(expectation.queue, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		fail("open DPI queue");
	configure_queue(fd, expectation.cache);
	if (expectation.stream_timeout_ms != 0) {
		stream_queue(fd, &expectation, &argv[optind]);
	} else {
		run_injector(&argv[optind]);
		retained = drain_queue(fd, &expectation);
		if (retained != expectation.cache)
			fail_message("queue retained fewer events than its cache limit");
		printf("PASS: retained %u of %u generated DPI events\n",
		       retained, expectation.generated);
	}
	if (close(fd) != 0)
		fail("close DPI queue");

	return EXIT_SUCCESS;
}
