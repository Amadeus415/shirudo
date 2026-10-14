// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * /var/lib/shirudo/eventlog appender. Append-only JSON-lines, one
 * line per register extension. The eventlog and the register must
 * stay in lockstep: replaying this boot's records must reproduce the
 * live value, so a caller only appends here after a successful extend.
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

const char *shirudo_eventlog_path(void)
{
	const char *env = getenv("SHIRUDO_EVENTLOG_PATH");

	return env && *env ? env : SHIRUDO_EVENTLOG_PATH;
}

int shirudo_eventlog_append(const char *json_line)
{
	const char *path = shirudo_eventlog_path();
	size_t len = strlen(json_line);
	int fd, rc;

	fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0600);
	if (fd < 0) {
		pr_err("eventlog: open %s: %s", path, strerror(errno));
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
	if (shirudo_seal_label(path) != 0)
		pr_warn("eventlog: could not seal-label %s: %s", path,
			strerror(errno));
	return 0;
}

int shirudo_eventlog_would_exceed(unsigned long max_bytes)
{
	unsigned long cur = 0;
	struct stat st;

	if (max_bytes == 0)
		return 0;	/* unlimited */
	if (stat(shirudo_eventlog_path(), &st) == 0)
		cur = (unsigned long)st.st_size;
	return cur + SHIRUDO_EVENTLOG_LINE_MAX > max_bytes;
}

static int read_log(char **out, size_t *out_len)
{
	struct stat st;
	ssize_t got;
	char *buf;
	int fd, rc;

	fd = open(shirudo_eventlog_path(), O_RDONLY | O_CLOEXEC);
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
	*out = buf;
	*out_len = (size_t)st.st_size;
	return 0;
}

/*
 * Walk this boot's records: every line whose boot_id is the running
 * boot's, from the last "init" line on. The callback learns whether a
 * line is that init so a replay can start over from zero. -ENOENT when
 * no init of this boot exists.
 */
static int walk_boot(int (*cb)(const char *line, size_t len, bool is_init,
			       void *ctx), void *ctx)
{
	char boot_id[64], line_boot[64], type[32];
	char *buf = NULL, *line, *save;
	bool in_boot = false;
	size_t len = 0;
	int rc;

	shirudo_eventlog_boot_id(boot_id, sizeof(boot_id));
	rc = read_log(&buf, &len);
	if (rc)
		return rc;
	for (line = strtok_r(buf, "\n", &save); line && !rc;
	     line = strtok_r(NULL, "\n", &save)) {
		struct shirudo_json_field f[] = {
			{ "boot_id", SHIRUDO_JSON_T_STRING, line_boot,
			  sizeof(line_boot), 0, NULL, 0 },
			{ "type", SHIRUDO_JSON_T_STRING, type, sizeof(type),
			  0, NULL, 0 },
		};
		bool is_init;

		line_boot[0] = '\0';
		type[0] = '\0';
		if (shirudo_json_parse(line, strlen(line), f, 2)) {
			rc = -EINVAL;
			break;
		}
		if (!f[0].seen || !boot_id[0] || strcmp(line_boot, boot_id))
			continue;
		is_init = f[1].seen && strcmp(type, "init") == 0;
		if (is_init)
			in_boot = true;
		if (!in_boot)
			continue;
		rc = cb(line, strlen(line), is_init, ctx);
	}
	xfree(buf, len + 1);
	if (!rc && !in_boot)
		return -ENOENT;
	return rc;
}

static int replay_line(const char *line, size_t len, bool is_init, void *ctx)
{
	char digest_hex[2 * 32 + 1];
	struct shirudo_json_field f[] = {
		{ "digest", SHIRUDO_JSON_T_STRING, digest_hex,
		  sizeof(digest_hex), 0, NULL, 0 },
	};
	uint8_t digest[32], cat[64];
	uint8_t *chain = ctx;

	if (shirudo_json_parse(line, len, f, 1) || !f[0].seen ||
	    shirudo_hex_decode(digest_hex, digest, sizeof(digest)))
		return -EINVAL;
	if (is_init)
		memset(chain, 0, 32);
	memcpy(cat, chain, 32);
	memcpy(cat + 32, digest, 32);
	shirudo_sha256(cat, sizeof(cat), chain);
	return 0;
}

int shirudo_eventlog_replay(uint8_t out[32])
{
	uint8_t chain[32] = {};
	int rc;

	rc = walk_boot(replay_line, chain);
	if (!rc)
		memcpy(out, chain, 32);
	return rc;
}

static int init_line(const char *line, size_t len, bool is_init, void *ctx)
{
	char pcr_before[2 * 32 + 1], name[2 * SHIRUDO_TPM_NAME_LEN + 1];
	char phase_before[2 * 32 + 1], anchor[2 * 32 + 1], bound_in[8];
	struct shirudo_eventlog_init *out = ctx;
	int64_t pcr = -1, reset_count = -1;
	struct shirudo_json_field f[] = {
		{ "pcr_before", SHIRUDO_JSON_T_STRING, pcr_before,
		  sizeof(pcr_before), 0, NULL, 0 },
		{ "nv_name", SHIRUDO_JSON_T_STRING, name, sizeof(name), 0,
		  NULL, 0 },
		{ "anchor_digest", SHIRUDO_JSON_T_STRING, anchor,
		  sizeof(anchor), 0, NULL, 0 },
		{ "pcr", SHIRUDO_JSON_T_INT, &pcr, 0, 0, NULL, 0 },
		{ "tpm_reset_count", SHIRUDO_JSON_T_INT, &reset_count, 0, 0,
		  NULL, 0 },
		{ "phase_before", SHIRUDO_JSON_T_STRING, phase_before,
		  sizeof(phase_before), 0, NULL, 0 },
		{ "bound_in", SHIRUDO_JSON_T_STRING, bound_in, sizeof(bound_in),
		  0, NULL, 0 },
	};
	bool have_reset_count;

	if (!is_init)
		return 0;
	bound_in[0] = '\0';
	if (shirudo_json_parse(line, len, f, 7) || !f[0].seen || !f[1].seen ||
	    !f[2].seen || !f[3].seen || !f[5].seen || pcr < 0 || pcr >= 24 ||
	    (f[4].seen && (reset_count < 0 || reset_count > UINT32_MAX)) ||
	    strlen(name) != 2 * SHIRUDO_TPM_NAME_LEN ||
	    shirudo_hex_decode(pcr_before, out->pcr_before, 32) ||
	    shirudo_hex_decode(phase_before, out->phase_before, 32) ||
	    shirudo_hex_decode(name, out->name, SHIRUDO_TPM_NAME_LEN) ||
	    shirudo_hex_decode(anchor, out->anchor_digest, 32))
		return -EINVAL;
	out->initrd = f[6].seen && !strcmp(bound_in, "initrd");
	/*
	 * Records are of one TPM reset unless both carry a count and
	 * the counts differ; a record without one cannot vouch for a
	 * reset in between.
	 */
	have_reset_count = f[4].seen;
	out->records++;
	if (out->records == 1 ||
	    (have_reset_count && out->have_reset_count &&
	     (uint32_t)reset_count != out->reset_count))
		out->records_epoch = 1;
	else
		out->records_epoch++;
	out->have_reset_count = have_reset_count;
	out->reset_count = (uint32_t)reset_count;
	out->name_len = SHIRUDO_TPM_NAME_LEN;
	out->pcr = (unsigned int)pcr;
	return 0;
}

int shirudo_eventlog_boot_init(struct shirudo_eventlog_init *out)
{
	memset(out, 0, sizeof(*out));
	return walk_boot(init_line, out);
}

struct lines_ctx {
	int	(*cb)(const char *line, size_t len, void *ctx);
	void	*ctx;
};

static int lines_line(const char *line, size_t len, bool is_init, void *ctx)
{
	struct lines_ctx *l = ctx;

	return l->cb(line, len, l->ctx);
}

int shirudo_eventlog_boot_lines(int (*cb)(const char *line, size_t len,
					  void *ctx), void *ctx)
{
	struct lines_ctx l = { cb, ctx };

	return walk_boot(lines_line, &l);
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
