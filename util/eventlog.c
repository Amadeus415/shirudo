// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * /var/lib/shirudo/eventlog appender. Append-only JSON-lines, one
 * line per TPM chain extension. The eventlog and the NV chain must
 * stay in lockstep: replaying the log must reproduce the live chain
 * value, so a caller only appends here after a successful NV-extend.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "chain.h"
#include "eventlog.h"
#include "io.h"
#include "json.h"
#include "log.h"
#include "malloc.h"
#include "paths.h"
#include "seal.h"

int shirudo_eventlog_append(const char *json_line)
{
	size_t len = strlen(json_line);
	int fd, rc;

	fd = open(SHIRUDO_EVENTLOG_PATH, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0) {
		pr_err("eventlog: open %s: %s", SHIRUDO_EVENTLOG_PATH,
		       strerror(errno));
		return -errno;
	}

	rc = shirudo_write_all(fd, json_line, len);
	if (!rc && (len == 0 || json_line[len - 1] != '\n'))
		rc = shirudo_write_all(fd, "\n", 1);
	if (!rc && fsync(fd) != 0)
		rc = -errno;

	if (close(fd) != 0 && !rc)
		rc = -errno;
	if (rc) {
		pr_err("eventlog: append: %s", strerror(-rc));
		return rc;
	}
	/* Keep the eventlog sealed (idempotent; no-op if seal not yet up). */
	if (shirudo_seal_label(SHIRUDO_EVENTLOG_PATH) != 0)
		pr_warn("eventlog: could not seal-label %s: %s",
			SHIRUDO_EVENTLOG_PATH, strerror(errno));
	return 0;
}

int shirudo_eventlog_would_exceed(unsigned long max_bytes)
{
	unsigned long cur = 0;
	struct stat st;

	if (max_bytes == 0)
		return 0;	/* unlimited */
	if (stat(SHIRUDO_EVENTLOG_PATH, &st) == 0)
		cur = (unsigned long)st.st_size;
	return cur + SHIRUDO_EVENTLOG_LINE_MAX > max_bytes;
}

/*
 * Replay the eventlog: fold each event's recorded extension digest into
 * a chain (chain = SHA256(chain || digest)) starting from all-zeros,
 * the same way the TPM NV-extend index accumulates. The result must
 * equal the live NV value on an untampered target. Returns 0 with the
 * folded value in out, -ENOENT if there is no eventlog, -EINVAL on a
 * malformed line (tamper / corruption), or another -errno on I/O.
 */
int shirudo_eventlog_replay(uint8_t out[32])
{
	char *buf, *line, *save;
	uint8_t chain[32] = {};
	struct stat st;
	int fd, rc = 0;
	ssize_t got;

	fd = open(SHIRUDO_EVENTLOG_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) != 0) {
		rc = -errno;
		close(fd);
		return rc;
	}
	if (st.st_size > (off_t)SHIRUDO_JSON_MAX_BYTES) {
		close(fd);
		return -EFBIG;
	}
	buf = xmalloc((size_t)st.st_size + 1);
	if (!buf) {
		close(fd);
		return -ENOMEM;
	}
	got = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (got != st.st_size) {
		xfree(buf, (size_t)st.st_size + 1);
		return -EIO;
	}
	buf[got] = '\0';

	for (line = strtok_r(buf, "\n", &save); line && !rc;
	     line = strtok_r(NULL, "\n", &save)) {
		char digest_hex[2 * 32 + 1];
		struct shirudo_json_field f[] = {
			{ "digest", SHIRUDO_JSON_T_STRING, digest_hex,
			  sizeof(digest_hex), 0, NULL, 0 },
		};
		uint8_t digest[32], cat[64];

		rc = shirudo_json_parse(line, strlen(line), f, 1);
		if (rc || !f[0].seen ||
		    shirudo_hex_decode(digest_hex, digest, sizeof(digest))) {
			rc = -EINVAL;
			break;
		}
		memcpy(cat, chain, 32);
		memcpy(cat + 32, digest, 32);
		shirudo_sha256(cat, sizeof(cat), chain);
	}

	xfree(buf, (size_t)st.st_size + 1);
	if (!rc)
		memcpy(out, chain, 32);
	return rc;
}

void shirudo_eventlog_timestamp(char *out, size_t cap)
{
	time_t now = time(NULL);
	struct tm tm;

	gmtime_r(&now, &tm);
	strftime(out, cap, "%Y-%m-%dT%H:%M:%SZ", &tm);
}

void shirudo_eventlog_boot_id(char *out, size_t cap)
{
	ssize_t n;
	int fd;

	out[0] = '\0';
	fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = read(fd, out, cap - 1);
	close(fd);
	if (n <= 0) {
		out[0] = '\0';
		return;
	}
	out[n] = '\0';
	while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
		out[--n] = '\0';
}
