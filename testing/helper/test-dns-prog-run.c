// SPDX-License-Identifier: BSD-2-Clause
/*
 * Run exact DNS packets through an already-loaded Linux-observability
 * cgroup/skb program.  The helper intentionally uses only the raw bpf()
 * syscall: target VMs do not need libbpf or bpftool at runtime.
 *
 * Input is a little-endian batch stream:
 *
 *   batch header:  u32 magic, u16 version, u16 reserved, u32 records
 *   each record:   u16 frame_len, u8 direction (0=query, 1=response),
 *                  u8 flags, u16 transaction_id, u16 reserved, frame bytes
 *
 * The frame includes an Ethernet header.  BPF_PROG_TEST_RUN strips it before
 * invoking a cgroup/skb program, matching the L3 view used on a real cgroup.
 * One JSON object is written for every record.
 */

#include <errno.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#define DNS_BATCH_MAGIC 0x31534e44u /* "DNS1" little-endian */
#define DNS_BATCH_VERSION 1u
#define DNS_BATCH_MAX_RECORDS 100000u
#define DNS_BATCH_MAX_FRAME 65535u
#define DNS_DEBUG_COUNTERS 41u
#define DNS_NAME_BYTES 256u
#define DNS_ETH_HEADER_BYTES 14u
#define DNS_ETH_P_IP 0x0800u
#define DNS_ETH_P_IPV6 0x86ddu
#define DNS_IPPROTO_UDP 17u

#ifndef SO_NETNS_COOKIE
#define SO_NETNS_COOKIE 71
#endif

enum dns_direction {
	DNS_DIRECTION_QUERY = 0,
	DNS_DIRECTION_RESPONSE = 1,
};

struct dns_batch_header {
	uint32_t magic;
	uint16_t version;
	uint16_t reserved;
	uint32_t records;
} __attribute__((packed));

struct dns_batch_record {
	uint16_t frame_len;
	uint8_t direction;
	uint8_t flags;
	uint16_t transaction_id;
	uint16_t reserved;
} __attribute__((packed));

struct dns_exec_uid {
	uint64_t ino;
	uint32_t dev;
	uint32_t pad;
};

struct dns_request {
	struct dns_exec_uid uid;
	uint64_t cgroup;
	char name[DNS_NAME_BYTES];
	uint16_t qtype;
	uint16_t pad;
	uint32_t pad2;
};

struct dns_request_key {
	uint64_t netns_cookie;
	uint32_t client_addr[4];
	uint32_t resolver_addr[4];
	uint16_t id;
	uint16_t client_port;
	uint16_t resolver_port;
	uint8_t family;
	uint8_t pad;
};

_Static_assert(sizeof(struct dns_request_key) == 48,
	       "DNS request key layout must match the BPF program");

static int sys_bpf(enum bpf_cmd cmd, union bpf_attr *attr)
{
	return (int)syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

static int read_full(void *buffer, size_t size)
{
	unsigned char *p = buffer;

	while (size) {
		size_t got = fread(p, 1, size, stdin);

		if (got == 0) {
			if (ferror(stdin))
				return -EIO;
			return -ENODATA;
		}
		p += got;
		size -= got;
	}
	return 0;
}

static bool object_name_equal(const char actual[BPF_OBJ_NAME_LEN],
			      const char *wanted)
{
	char expected[BPF_OBJ_NAME_LEN] = {};

	strncpy(expected, wanted, sizeof(expected) - 1);
	return memcmp(actual, expected, sizeof(expected)) == 0;
}

static int find_prog_fd(const char *name)
{
	uint32_t id = 0;

	for (;;) {
		union bpf_attr next = {};
		union bpf_attr get = {};
		union bpf_attr info_attr = {};
		struct bpf_prog_info info = {};
		uint32_t info_len = sizeof(info);
		int fd;

		next.start_id = id;
		if (sys_bpf(BPF_PROG_GET_NEXT_ID, &next) < 0) {
			if (errno == ENOENT)
				break;
			return -errno;
		}
		id = next.next_id;
		get.prog_id = id;
		fd = sys_bpf(BPF_PROG_GET_FD_BY_ID, &get);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			return -errno;
		}
		info_attr.info.bpf_fd = fd;
		info_attr.info.info_len = info_len;
		info_attr.info.info = (uint64_t)(uintptr_t)&info;
		if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &info_attr) < 0) {
			int saved = errno;

			close(fd);
			return -saved;
		}
		if (object_name_equal(info.name, name))
			return fd;
		close(fd);
	}
	return -ENOENT;
}

static int find_map_fd(const char *name)
{
	uint32_t id = 0;

	for (;;) {
		union bpf_attr next = {};
		union bpf_attr get = {};
		union bpf_attr info_attr = {};
		struct bpf_map_info info = {};
		uint32_t info_len = sizeof(info);
		int fd;

		next.start_id = id;
		if (sys_bpf(BPF_MAP_GET_NEXT_ID, &next) < 0) {
			if (errno == ENOENT)
				break;
			return -errno;
		}
		id = next.next_id;
		get.map_id = id;
		fd = sys_bpf(BPF_MAP_GET_FD_BY_ID, &get);
		if (fd < 0) {
			if (errno == ENOENT)
				continue;
			return -errno;
		}
		info_attr.info.bpf_fd = fd;
		info_attr.info.info_len = info_len;
		info_attr.info.info = (uint64_t)(uintptr_t)&info;
		if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &info_attr) < 0) {
			int saved = errno;

			close(fd);
			return -saved;
		}
		if (object_name_equal(info.name, name))
			return fd;
		close(fd);
	}
	return -ENOENT;
}

static int map_lookup(int fd, const void *key, void *value)
{
	union bpf_attr attr = {};

	attr.map_fd = fd;
	attr.key = (uint64_t)(uintptr_t)key;
	attr.value = (uint64_t)(uintptr_t)value;
	if (sys_bpf(BPF_MAP_LOOKUP_ELEM, &attr) < 0)
		return -errno;
	return 0;
}

static int validate_request_map(int fd)
{
	union bpf_attr attr = {};
	struct bpf_map_info info = {};
	uint32_t info_len = sizeof(info);

	attr.info.bpf_fd = fd;
	attr.info.info_len = info_len;
	attr.info.info = (uint64_t)(uintptr_t)&info;
	if (sys_bpf(BPF_OBJ_GET_INFO_BY_FD, &attr) < 0)
		return -errno;
	if (info.key_size != sizeof(struct dns_request_key) ||
	    info.value_size != sizeof(struct dns_request))
		return -EINVAL;
	return 0;
}

static uint16_t read_be16(const unsigned char *p)
{
	return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static int current_netns_cookie(uint64_t *cookie)
{
	socklen_t size = sizeof(*cookie);
	int fd, rc = 0;

	fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	if (getsockopt(fd, SOL_SOCKET, SO_NETNS_COOKIE, cookie, &size) < 0)
		rc = -errno;
	else if (size != sizeof(*cookie))
		rc = -EINVAL;
	close(fd);
	return rc;
}

static bool request_key_from_frame(const unsigned char *frame, size_t frame_len,
				   uint8_t direction, uint16_t id,
				   uint64_t netns_cookie,
				   struct dns_request_key *key)
{
	const unsigned char *ip, *udp;
	size_t ip_len;
	uint16_t ethertype;

	memset(key, 0, sizeof(*key));
	if (frame_len < DNS_ETH_HEADER_BYTES)
		return false;
	ethertype = read_be16(frame + 12);
	ip = frame + DNS_ETH_HEADER_BYTES;
	ip_len = frame_len - DNS_ETH_HEADER_BYTES;

	if (ethertype == DNS_ETH_P_IP) {
		size_t ihl;

		if (ip_len < 20 || ip[9] != DNS_IPPROTO_UDP)
			return false;
		ihl = (size_t)(ip[0] & 0x0f) * 4;
		if (ihl < 20 || ihl > 60 || ip_len < ihl + 8)
			return false;
		key->family = AF_INET;
		if (direction == DNS_DIRECTION_QUERY) {
			memcpy(&key->client_addr[0], ip + 12, 4);
			memcpy(&key->resolver_addr[0], ip + 16, 4);
		} else {
			memcpy(&key->client_addr[0], ip + 16, 4);
			memcpy(&key->resolver_addr[0], ip + 12, 4);
		}
		udp = ip + ihl;
	} else if (ethertype == DNS_ETH_P_IPV6) {
		if (ip_len < 48 || ip[6] != DNS_IPPROTO_UDP)
			return false;
		key->family = AF_INET6;
		if (direction == DNS_DIRECTION_QUERY) {
			memcpy(key->client_addr, ip + 8, 16);
			memcpy(key->resolver_addr, ip + 24, 16);
		} else {
			memcpy(key->client_addr, ip + 24, 16);
			memcpy(key->resolver_addr, ip + 8, 16);
		}
		udp = ip + 40;
	} else {
		return false;
	}

	if (direction == DNS_DIRECTION_QUERY) {
		memcpy(&key->client_port, udp, sizeof(key->client_port));
		memcpy(&key->resolver_port, udp + 2,
		       sizeof(key->resolver_port));
	} else {
		memcpy(&key->client_port, udp + 2,
		       sizeof(key->client_port));
		memcpy(&key->resolver_port, udp,
		       sizeof(key->resolver_port));
	}
	key->netns_cookie = netns_cookie;
	key->id = id;
	return true;
}

static int read_counters(int map_fd, uint64_t values[DNS_DEBUG_COUNTERS])
{
	uint32_t i;

	for (i = 0; i < DNS_DEBUG_COUNTERS; i++) {
		uint32_t key = i;
		int rc;

		rc = map_lookup(map_fd, &key, &values[i]);
		if (rc)
			return rc;
	}
	return 0;
}

static int run_packet(int prog_fd, const void *frame, uint32_t frame_len,
		      uint32_t *retval)
{
	union bpf_attr attr = {};

	attr.test.prog_fd = prog_fd;
	attr.test.data_size_in = frame_len;
	attr.test.data_in = (uint64_t)(uintptr_t)frame;
	attr.test.repeat = 1;
	if (sys_bpf(BPF_PROG_TEST_RUN, &attr) < 0)
		return -errno;
	*retval = attr.test.retval;
	return 0;
}

static void print_name_hex(const char name[DNS_NAME_BYTES])
{
	uint32_t i;

	for (i = 0; i < DNS_NAME_BYTES && name[i]; i++)
		printf("%02x", (unsigned char)name[i]);
}

static void print_result(uint32_t index, int rc, uint32_t retval,
			 int request_rc, const struct dns_request *request,
			 const uint64_t before[DNS_DEBUG_COUNTERS],
			 const uint64_t after[DNS_DEBUG_COUNTERS])
{
	uint32_t i;

	printf("{\"index\":%u,\"rc\":%d,\"retval\":%u,", index, rc,
	       retval);
	if (request_rc == 0) {
		printf("\"request\":true,\"request_qtype\":%u,"
		       "\"request_name_hex\":\"", request->qtype);
		print_name_hex(request->name);
		printf("\",");
	} else {
		printf("\"request\":false,\"request_qtype\":0,"
		       "\"request_name_hex\":\"\",");
	}
	printf("\"counter_delta\":[");
	for (i = 0; i < DNS_DEBUG_COUNTERS; i++) {
		if (i)
			putchar(',');
		printf("%" PRIu64, after[i] - before[i]);
	}
	printf("]}\n");
}

int main(void)
{
	struct dns_batch_header header;
	uint64_t before[DNS_DEBUG_COUNTERS], after[DNS_DEBUG_COUNTERS];
	int query_fd = -1, response_fd = -1, debug_fd = -1, request_fd = -1;
	unsigned char *frame = NULL;
	uint64_t netns_cookie;
	uint32_t i;
	int rc = 1;

	if (read_full(&header, sizeof(header))) {
		fprintf(stderr, "dns batch: short header\n");
		return 1;
	}
	if (header.magic != DNS_BATCH_MAGIC ||
	    header.version != DNS_BATCH_VERSION || header.reserved != 0 ||
	    header.records > DNS_BATCH_MAX_RECORDS) {
		fprintf(stderr, "dns batch: invalid header\n");
		return 1;
	}

	query_fd = find_prog_fd("track_dns_query");
	response_fd = find_prog_fd("track_dns_respo");
	debug_fd = find_map_fd("obs_i_dns_dbg");
	request_fd = find_map_fd("obs_i_dns_req");
	if (query_fd < 0 || response_fd < 0 || debug_fd < 0 || request_fd < 0) {
		fprintf(stderr,
			"dns batch: required objects unavailable: query=%d response=%d debug=%d request=%d\n",
			query_fd, response_fd, debug_fd, request_fd);
		goto out;
	}
	if (validate_request_map(request_fd)) {
		fprintf(stderr, "dns batch: request map layout does not match helper\n");
		goto out;
	}
	if (current_netns_cookie(&netns_cookie)) {
		fprintf(stderr, "dns batch: cannot read network namespace cookie\n");
		goto out;
	}

	frame = malloc(DNS_BATCH_MAX_FRAME);
	if (!frame) {
		fprintf(stderr, "dns batch: out of memory\n");
		goto out;
	}

	for (i = 0; i < header.records; i++) {
		struct dns_batch_record record;
		struct dns_request_key key;
		struct dns_request request = {};
		uint32_t retval = 0;
		int run_rc, request_rc;

		if (read_full(&record, sizeof(record)) ||
		    record.direction > DNS_DIRECTION_RESPONSE || record.flags != 0 ||
		    record.reserved != 0 ||
		    read_full(frame, record.frame_len)) {
			fprintf(stderr, "dns batch: invalid record %u\n", i);
			goto out;
		}
		if (read_counters(debug_fd, before)) {
			fprintf(stderr, "dns batch: cannot read counters before record %u\n", i);
			goto out;
		}
		run_rc = run_packet(record.direction == DNS_DIRECTION_QUERY ?
				    query_fd : response_fd,
				    frame, record.frame_len, &retval);
		if (read_counters(debug_fd, after)) {
			fprintf(stderr, "dns batch: cannot read counters after record %u\n", i);
			goto out;
		}
		if (request_key_from_frame(frame, record.frame_len,
					   record.direction,
					   record.transaction_id,
					   netns_cookie, &key))
			request_rc = map_lookup(request_fd, &key, &request);
		else
			request_rc = -ENOENT;
		if (request_rc != 0 && request_rc != -ENOENT) {
			fprintf(stderr, "dns batch: request lookup failed for record %u: %d\n",
				i, request_rc);
			goto out;
		}
		print_result(i, run_rc, retval, request_rc, &request,
			     before, after);
	}

	if (fgetc(stdin) != EOF) {
		fprintf(stderr, "dns batch: trailing input\n");
		goto out;
	}
	rc = 0;
out:
	free(frame);
	if (query_fd >= 0)
		close(query_fd);
	if (response_fd >= 0)
		close(response_fd);
	if (debug_fd >= 0)
		close(debug_fd);
	if (request_fd >= 0)
		close(request_fd);
	return rc;
}
