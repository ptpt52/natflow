#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
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
#define DPI_TIMEOUT_DEFAULT 500U

struct corpus_expectation {
	struct in_addr source_address;
	struct in_addr destination_address;
	const char *queue;
	unsigned int app_id;
	unsigned int rule_id;
	unsigned int source;
	unsigned int evidence_dir;
	unsigned int l4proto;
	unsigned int destination_port;
	unsigned int timeout_ms;
	int negative;
};

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
	        "Usage: %s -S src -T dst -P tcp|udp -p port -s source "
	        "-D original|reply -a app -r rule [-N] [-t ms] "
	        "[-d queue] -- command [args...]\n",
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

static void configure_queue(int fd)
{
	static const char command[] = "cache=64\n";
	ssize_t written;

	written = write(fd, command, sizeof(command) - 1);
	if (written < 0)
		fail("configure DPI queue");
	if ((size_t)written != sizeof(command) - 1)
		fail_message("short DPI queue command write");
}

static void run_injector(char **command)
{
	pid_t child;
	pid_t waited;
	int status;

	child = fork();
	if (child < 0)
		fail("fork injector");
	if (child == 0) {
		execvp(command[0], command);
		fprintf(stderr, "FAIL: exec %s: %s\n", command[0],
		        strerror(errno));
		_exit(127);
	}

	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited < 0)
		fail("wait for injector");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		fail_message("traffic injector failed");
}

static int event_tuple_matches(const struct natflow_dpi_event_hdr *event,
                               const struct corpus_expectation *expectation)
{
	return event->family == AF_INET &&
	       event->l4proto == expectation->l4proto &&
	       event->dport == expectation->destination_port &&
	       memcmp(event->sip, &expectation->source_address,
	              sizeof(expectation->source_address)) == 0 &&
	       memcmp(event->dip, &expectation->destination_address,
	              sizeof(expectation->destination_address)) == 0;
}

static void validate_event_abi(const struct natflow_dpi_event_hdr *event)
{
	if (event->version != NATFLOW_DPI_EVENT_VERSION ||
	        event->header_len != sizeof(*event) ||
	        event->record_len != sizeof(*event))
		fail_message("queue returned an unsupported event ABI");
}

static void validate_matching_event(
    const struct natflow_dpi_event_hdr *event,
    const struct corpus_expectation *expectation)
{
	if (expectation->negative)
		fail_message("negative case produced a DPI match event");
	if (event->tuple_dir != 0 ||
	        event->evidence_dir != expectation->evidence_dir)
		fail_message("event direction does not match expectation");
	if (event->reason != NATFLOW_DPI_REASON_MATCHED ||
	        event->flags != expectation->source ||
	        event->app_id != expectation->app_id ||
	        event->rule_id != expectation->rule_id)
		fail_message("event classification does not match expectation");
}

static int wait_for_result(int fd,
                           const struct corpus_expectation *expectation)
{
	struct natflow_dpi_event_hdr events[DPI_READ_BATCH];
	int64_t deadline = monotonic_milliseconds() + expectation->timeout_ms;

	for (;;) {
		struct pollfd pfd = {
			.fd = fd,
			.events = POLLIN | POLLRDNORM,
		};
		int64_t remaining = deadline - monotonic_milliseconds();
		ssize_t length;
		size_t count;
		size_t i;
		int ready;

		if (remaining <= 0)
			break;
		ready = poll(&pfd, 1, (int)remaining);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			fail("poll DPI queue");
		}
		if (ready == 0)
			break;
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
			fail_message("DPI queue poll returned an error");
		if (!(pfd.revents & (POLLIN | POLLRDNORM)))
			continue;

		length = read(fd, events, sizeof(events));
		if (length < 0)
			fail("read DPI queue");
		if (length == 0)
			continue;
		if ((size_t)length % sizeof(events[0]) != 0)
			fail_message("DPI queue returned a partial event batch");

		count = (size_t)length / sizeof(events[0]);
		for (i = 0; i < count; i++) {
			validate_event_abi(&events[i]);
			if (!event_tuple_matches(&events[i], expectation))
				continue;
			validate_matching_event(&events[i], expectation);
			return 1;
		}
	}
	return 0;
}

int main(int argc, char **argv)
{
	struct corpus_expectation expectation = {
		.queue = DPI_QUEUE_DEFAULT,
		.timeout_ms = DPI_TIMEOUT_DEFAULT,
	};
	int have_source_address = 0;
	int have_destination_address = 0;
	int have_protocol = 0;
	int have_port = 0;
	int have_source = 0;
	int have_direction = 0;
	int have_app = 0;
	int have_rule = 0;
	int option;
	int fd;
	int matched;

	while ((option = getopt(argc, argv, "d:S:T:P:p:s:D:a:r:t:Nh")) != -1) {
		switch (option) {
		case 'd':
			expectation.queue = optarg;
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
		case 'P':
			if (strcmp(optarg, "tcp") == 0)
				expectation.l4proto = IPPROTO_TCP;
			else if (strcmp(optarg, "udp") == 0)
				expectation.l4proto = IPPROTO_UDP;
			else
				fail_message("invalid transport protocol");
			have_protocol = 1;
			break;
		case 'p':
			have_port = parse_uint(optarg,
			                       &expectation.destination_port) == 0 &&
			            expectation.destination_port > 0 &&
			            expectation.destination_port <= 65535;
			break;
		case 's':
			have_source = parse_uint(optarg, &expectation.source) == 0;
			break;
		case 'D':
			if (strcmp(optarg, "original") == 0)
				expectation.evidence_dir = 0;
			else if (strcmp(optarg, "reply") == 0)
				expectation.evidence_dir = 1;
			else
				fail_message("invalid evidence direction");
			have_direction = 1;
			break;
		case 'a':
			have_app = parse_uint(optarg, &expectation.app_id) == 0;
			break;
		case 'r':
			have_rule = parse_uint(optarg, &expectation.rule_id) == 0;
			break;
		case 't':
			if (parse_uint(optarg, &expectation.timeout_ms) != 0 ||
			        expectation.timeout_ms == 0 ||
			        expectation.timeout_ms > INT_MAX)
				fail_message("invalid timeout");
			break;
		case 'N':
			expectation.negative = 1;
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
	        !have_protocol || !have_port || !have_source || !have_direction ||
	        !have_app || !have_rule || optind >= argc) {
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}
	if (expectation.source < NATFLOW_DPI_EVENT_SOURCE_HTTP ||
	        expectation.source > NATFLOW_DPI_EVENT_SOURCE_BITTORRENT ||
	        expectation.app_id == 0 || expectation.rule_id == 0)
		fail_message("invalid classification expectation");

	fd = open(expectation.queue, O_RDWR | O_CLOEXEC);
	if (fd < 0)
		fail("open DPI queue");
	configure_queue(fd);
	run_injector(&argv[optind]);
	matched = wait_for_result(fd, &expectation);
	if (!expectation.negative && !matched)
		fail_message("positive case did not produce a DPI event");
	if (expectation.negative && matched)
		fail_message("negative case unexpectedly matched");

	if (close(fd) != 0)
		fail("close DPI queue");
	printf("PASS: %s corpus case\n",
	       expectation.negative ? "negative" : "positive");
	return EXIT_SUCCESS;
}
