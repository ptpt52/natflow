#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "natflow-dpi-event.h"

#define DPI_QUEUE_DEFAULT "/dev/natflow_dpi_queue"
#define DPI_CACHE_DEFAULT 256U
#define DPI_READ_BATCH 32U

static volatile sig_atomic_t stop;

static void handle_signal(int signo)
{
	(void)signo;
	stop = 1;
}

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
	        "Usage: %s [-d queue] [-c cache] [-n count]\n"
	        "  -d queue  queue device (default: %s)\n"
	        "  -c cache  maximum queued events (default: %u)\n"
	        "  -n count  stop after count events; 0 means unlimited\n",
	        program, DPI_QUEUE_DEFAULT, DPI_CACHE_DEFAULT);
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

static const char *source_name(uint32_t flags)
{
	switch (flags) {
	case NATFLOW_DPI_EVENT_SOURCE_HTTP:
		return "http";
	case NATFLOW_DPI_EVENT_SOURCE_TLS:
		return "tls";
	case NATFLOW_DPI_EVENT_SOURCE_QUIC:
		return "quic";
	case NATFLOW_DPI_EVENT_SOURCE_DNS:
		return "dns";
	case NATFLOW_DPI_EVENT_SOURCE_SSH:
		return "ssh";
	case NATFLOW_DPI_EVENT_SOURCE_WIREGUARD:
		return "wireguard";
	case NATFLOW_DPI_EVENT_SOURCE_STUN:
		return "stun";
	case NATFLOW_DPI_EVENT_SOURCE_TURN:
		return "turn";
	case NATFLOW_DPI_EVENT_SOURCE_BITTORRENT:
		return "bittorrent";
	default:
		return "unknown";
	}
}

static int format_address(uint16_t family, const uint8_t address[16],
                          char *output, size_t output_len)
{
	const void *source;

	if (family == AF_INET)
		source = address;
	else if (family == AF_INET6)
		source = address;
	else
		return -1;

	return inet_ntop(family, source, output, output_len) ? 0 : -1;
}

static void print_event(const struct natflow_dpi_event_hdr *event)
{
	char source_address[INET6_ADDRSTRLEN];
	char destination_address[INET6_ADDRSTRLEN];

	if (format_address(event->family, event->sip, source_address,
	                   sizeof(source_address)) ||
	        format_address(event->family, event->dip, destination_address,
	                       sizeof(destination_address))) {
		fprintf(stderr, "unsupported address family: %u\n", event->family);
		return;
	}

	printf("time=%" PRIu64 " source=%s generation=%" PRIu32
	       " app=%" PRIu32 " rule=%" PRIu32 " reason=%u"
	       " tuple_dir=%u evidence_dir=%u proto=%u "
	       "%s:%u -> %s:%u\n",
	       event->timestamp, source_name(event->flags), event->generation,
	       event->app_id, event->rule_id, event->reason, event->tuple_dir,
	       event->evidence_dir, event->l4proto, source_address, event->sport,
	       destination_address, event->dport);
}

int main(int argc, char **argv)
{
	struct natflow_dpi_event_hdr events[DPI_READ_BATCH];
	const char *queue = DPI_QUEUE_DEFAULT;
	unsigned int cache = DPI_CACHE_DEFAULT;
	unsigned int limit = 0;
	unsigned int consumed = 0;
	struct sigaction action = { .sa_handler = handle_signal };
	struct pollfd pollfd;
	char command[32];
	int option;
	int fd;
	int length;

	while ((option = getopt(argc, argv, "d:c:n:h")) != -1) {
		switch (option) {
		case 'd':
			queue = optarg;
			break;
		case 'c':
			if (parse_uint(optarg, &cache) || cache == 0) {
				fprintf(stderr, "invalid cache value: %s\n", optarg);
				return EXIT_FAILURE;
			}
			break;
		case 'n':
			if (parse_uint(optarg, &limit)) {
				fprintf(stderr, "invalid event count: %s\n", optarg);
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

	fd = open(queue, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "open %s: %s\n", queue, strerror(errno));
		return EXIT_FAILURE;
	}

	length = snprintf(command, sizeof(command), "cache=%u\n", cache);
	if (length < 0 || (size_t)length >= sizeof(command) ||
	        write(fd, command, (size_t)length) != length) {
		fprintf(stderr, "configure %s: %s\n", queue,
		        errno ? strerror(errno) : "short write");
		close(fd);
		return EXIT_FAILURE;
	}

	sigemptyset(&action.sa_mask);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGTERM, &action, NULL);
	pollfd.fd = fd;
	pollfd.events = POLLIN;

	while (!stop && (!limit || consumed < limit)) {
		ssize_t bytes;
		size_t read_size = sizeof(events);
		size_t count;
		size_t i;
		int ready;

		if (limit && limit - consumed < DPI_READ_BATCH)
			read_size = (limit - consumed) * sizeof(events[0]);

		ready = poll(&pollfd, 1, -1);
		if (ready < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "poll %s: %s\n", queue, strerror(errno));
			close(fd);
			return EXIT_FAILURE;
		}
		if (pollfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			fprintf(stderr, "poll %s: revents=0x%x\n", queue,
			        pollfd.revents);
			close(fd);
			return EXIT_FAILURE;
		}
		if (!(pollfd.revents & POLLIN))
			continue;

		bytes = read(fd, events, read_size);
		if (bytes < 0) {
			if (errno == EINTR)
				continue;
			fprintf(stderr, "read %s: %s\n", queue, strerror(errno));
			close(fd);
			return EXIT_FAILURE;
		}
		if (bytes == 0)
			continue;
		if ((size_t)bytes % sizeof(events[0])) {
			fprintf(stderr, "partial DPI event batch: %zd bytes\n", bytes);
			close(fd);
			return EXIT_FAILURE;
		}

		count = (size_t)bytes / sizeof(events[0]);
		for (i = 0; i < count && (!limit || consumed < limit); i++) {
			if (events[i].version != NATFLOW_DPI_EVENT_VERSION ||
			        events[i].header_len != sizeof(events[i]) ||
			        events[i].record_len != sizeof(events[i])) {
				fprintf(stderr,
				        "unsupported DPI event ABI: version=%u header=%u record=%u\n",
				        events[i].version, events[i].header_len,
				        events[i].record_len);
				close(fd);
				return EXIT_FAILURE;
			}
			print_event(&events[i]);
			consumed++;
		}
	}

	close(fd);
	return EXIT_SUCCESS;
}
