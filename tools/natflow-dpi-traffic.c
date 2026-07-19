#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define TRAFFIC_PAYLOAD_MAX 2048U
#define TRAFFIC_TIMEOUT_SECONDS 3

enum traffic_role {
	TRAFFIC_SERVER,
	TRAFFIC_CLIENT,
};

enum traffic_direction {
	TRAFFIC_ORIGINAL,
	TRAFFIC_REPLY,
};

static void usage(FILE *stream, const char *program)
{
	fprintf(stream,
	        "Usage: %s server tcp|udp bind-ip port original|reply hex ready-file\n"
	        "       %s client tcp|udp server-ip port original|reply hex\n",
	        program, program);
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

static unsigned int parse_port(const char *value)
{
	char *end;
	unsigned long port;

	errno = 0;
	port = strtoul(value, &end, 10);
	if (errno || *value == '\0' || *end != '\0' || port == 0 || port > 65535)
		fail_message("invalid port");
	return (unsigned int)port;
}

static int hex_digit(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	if (value >= 'A' && value <= 'F')
		return value - 'A' + 10;
	return -1;
}

static size_t parse_payload(const char *hex, unsigned char *payload)
{
	size_t hex_length = strlen(hex);
	size_t payload_length;
	size_t i;

	if (hex_length == 0 || (hex_length & 1) != 0)
		fail_message("payload hex must contain complete bytes");
	payload_length = hex_length / 2;
	if (payload_length > TRAFFIC_PAYLOAD_MAX)
		fail_message("payload exceeds traffic helper limit");

	for (i = 0; i < payload_length; i++) {
		int high = hex_digit(hex[i * 2]);
		int low = hex_digit(hex[i * 2 + 1]);

		if (high < 0 || low < 0)
			fail_message("payload contains a non-hex character");
		payload[i] = (unsigned char)((high << 4) | low);
	}
	return payload_length;
}

static struct sockaddr_in parse_address(const char *address,
                                        unsigned int port)
{
	struct sockaddr_in socket_address;

	memset(&socket_address, 0, sizeof(socket_address));
	socket_address.sin_family = AF_INET;
	socket_address.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, address, &socket_address.sin_addr) != 1)
		fail_message("invalid IPv4 address");
	return socket_address;
}

static void configure_socket(int fd)
{
	struct timeval timeout = {
		.tv_sec = TRAFFIC_TIMEOUT_SECONDS,
	};
	int enabled = 1;

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled,
	               sizeof(enabled)) != 0 ||
	        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
	                   sizeof(timeout)) != 0 ||
	        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout,
	                   sizeof(timeout)) != 0)
		fail("configure socket");
}

static void mark_ready(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

	if (fd < 0)
		fail("create ready file");
	if (close(fd) != 0)
		fail("close ready file");
}

static void send_all(int fd, const unsigned char *payload, size_t length)
{
	size_t sent = 0;

	while (sent < length) {
		ssize_t result = send(fd, payload + sent, length - sent, 0);

		if (result < 0) {
			if (errno == EINTR)
				continue;
			fail("send payload");
		}
		if (result == 0)
			fail_message("send returned zero");
		sent += (size_t)result;
	}
}

static void receive_exact(int fd, const unsigned char *expected, size_t length)
{
	unsigned char received[TRAFFIC_PAYLOAD_MAX];
	size_t total = 0;

	while (total < length) {
		ssize_t result = recv(fd, received + total, length - total, 0);

		if (result < 0) {
			if (errno == EINTR)
				continue;
			fail("receive payload");
		}
		if (result == 0)
			fail_message("connection closed before complete payload");
		total += (size_t)result;
	}
	if (memcmp(received, expected, length) != 0)
		fail_message("received payload differs from fixture");
}

static void run_tcp_server(const struct sockaddr_in *address,
                           enum traffic_direction direction,
                           const unsigned char *payload, size_t payload_length,
                           const char *ready_file)
{
	int listener = socket(AF_INET, SOCK_STREAM, 0);
	int connection;

	if (listener < 0)
		fail("create TCP listener");
	configure_socket(listener);
	if (bind(listener, (const struct sockaddr *)address, sizeof(*address)) != 0)
		fail("bind TCP listener");
	if (listen(listener, 1) != 0)
		fail("listen TCP");
	mark_ready(ready_file);
	connection = accept(listener, NULL, NULL);
	if (connection < 0)
		fail("accept TCP connection");
	configure_socket(connection);
	if (direction == TRAFFIC_ORIGINAL)
		receive_exact(connection, payload, payload_length);
	else
		send_all(connection, payload, payload_length);
	close(connection);
	close(listener);
}

static void run_tcp_client(const struct sockaddr_in *address,
                           enum traffic_direction direction,
                           const unsigned char *payload, size_t payload_length)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);

	if (fd < 0)
		fail("create TCP client");
	configure_socket(fd);
	if (connect(fd, (const struct sockaddr *)address, sizeof(*address)) != 0)
		fail("connect TCP client");
	if (direction == TRAFFIC_ORIGINAL)
		send_all(fd, payload, payload_length);
	else
		receive_exact(fd, payload, payload_length);
	close(fd);
}

static void run_udp_server(const struct sockaddr_in *address,
                           enum traffic_direction direction,
                           const unsigned char *payload, size_t payload_length,
                           const char *ready_file)
{
	unsigned char received[TRAFFIC_PAYLOAD_MAX];
	struct sockaddr_in peer;
	socklen_t peer_length = sizeof(peer);
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ssize_t length;

	if (fd < 0)
		fail("create UDP server");
	configure_socket(fd);
	if (bind(fd, (const struct sockaddr *)address, sizeof(*address)) != 0)
		fail("bind UDP server");
	mark_ready(ready_file);
	length = recvfrom(fd, received, sizeof(received), 0,
	                  (struct sockaddr *)&peer, &peer_length);
	if (length < 0)
		fail("receive UDP payload");
	if (direction == TRAFFIC_ORIGINAL) {
		if ((size_t)length != payload_length ||
		        memcmp(received, payload, payload_length) != 0)
			fail_message("received UDP payload differs from fixture");
	} else {
		if (sendto(fd, payload, payload_length, 0,
		           (const struct sockaddr *)&peer, peer_length) !=
		        (ssize_t)payload_length)
			fail("send UDP reply");
	}
	close(fd);
}

static void run_udp_client(const struct sockaddr_in *address,
                           enum traffic_direction direction,
                           const unsigned char *payload, size_t payload_length)
{
	static const unsigned char probe = 0;
	unsigned char received[TRAFFIC_PAYLOAD_MAX];
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	ssize_t length;

	if (fd < 0)
		fail("create UDP client");
	configure_socket(fd);
	if (connect(fd, (const struct sockaddr *)address, sizeof(*address)) != 0)
		fail("connect UDP client");
	if (direction == TRAFFIC_ORIGINAL) {
		if (send(fd, payload, payload_length, 0) != (ssize_t)payload_length)
			fail("send UDP payload");
	} else {
		if (send(fd, &probe, sizeof(probe), 0) != sizeof(probe))
			fail("send UDP probe");
		length = recv(fd, received, sizeof(received), 0);
		if (length < 0)
			fail("receive UDP reply");
		if ((size_t)length != payload_length ||
		        memcmp(received, payload, payload_length) != 0)
			fail_message("received UDP reply differs from fixture");
	}
	close(fd);
}

int main(int argc, char **argv)
{
	unsigned char payload[TRAFFIC_PAYLOAD_MAX];
	struct sockaddr_in address;
	enum traffic_role role;
	enum traffic_direction direction;
	size_t payload_length;
	unsigned int port;
	int protocol;

	if (argc != 7 && argc != 8) {
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}
	if (strcmp(argv[1], "server") == 0 && argc == 8)
		role = TRAFFIC_SERVER;
	else if (strcmp(argv[1], "client") == 0 && argc == 7)
		role = TRAFFIC_CLIENT;
	else {
		usage(stderr, argv[0]);
		return EXIT_FAILURE;
	}
	if (strcmp(argv[2], "tcp") == 0)
		protocol = IPPROTO_TCP;
	else if (strcmp(argv[2], "udp") == 0)
		protocol = IPPROTO_UDP;
	else
		fail_message("invalid transport protocol");
	port = parse_port(argv[4]);
	if (strcmp(argv[5], "original") == 0)
		direction = TRAFFIC_ORIGINAL;
	else if (strcmp(argv[5], "reply") == 0)
		direction = TRAFFIC_REPLY;
	else
		fail_message("invalid traffic direction");
	payload_length = parse_payload(argv[6], payload);
	address = parse_address(argv[3], port);
	signal(SIGPIPE, SIG_IGN);

	if (role == TRAFFIC_SERVER && protocol == IPPROTO_TCP)
		run_tcp_server(&address, direction, payload, payload_length, argv[7]);
	else if (role == TRAFFIC_CLIENT && protocol == IPPROTO_TCP)
		run_tcp_client(&address, direction, payload, payload_length);
	else if (role == TRAFFIC_SERVER)
		run_udp_server(&address, direction, payload, payload_length, argv[7]);
	else
		run_udp_client(&address, direction, payload, payload_length);

	return EXIT_SUCCESS;
}
