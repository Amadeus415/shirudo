// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Measurement-chain helpers shared by the init extend path and the
 * upatch-load pre-flight read path.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "chain.h"
#include "crypto.h"
#include "malloc.h"
#include "paths.h"
#include "tpm.h"

void shirudo_sha256(const void *data, size_t len, uint8_t out[32])
{
	if (shirudo_sha256_buffer(data, len, out) != 0)
		memset(out, 0, 32);
}

void shirudo_sha256_2(const void *a, size_t a_len,
		      const void *b, size_t b_len, uint8_t out[32])
{
	struct shirudo_sha256_ctx ctx;

	if (shirudo_sha256_init(&ctx) != 0) {
		memset(out, 0, 32);
		return;
	}
	if (shirudo_sha256_update(&ctx, a, a_len) != 0 ||
	    (b_len && shirudo_sha256_update(&ctx, b, b_len) != 0) ||
	    shirudo_sha256_final(&ctx, out) != 0) {
		memset(out, 0, 32);
		shirudo_sha256_free(&ctx);
	}
}

void shirudo_hex_encode(const uint8_t *in, size_t n, char *out)
{
	static const char d[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) {
		out[2 * i] = d[in[i] >> 4];
		out[2 * i + 1] = d[in[i] & 0xf];
	}
	out[2 * n] = '\0';
}

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int shirudo_hex_decode(const char *hex, uint8_t *out, size_t n)
{
	size_t i;

	if (strlen(hex) != 2 * n)
		return -EINVAL;
	for (i = 0; i < n; i++) {
		int hi = hex_nibble(hex[2 * i]);
		int lo = hex_nibble(hex[2 * i + 1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

int shirudo_ct_eq(const void *a, const void *b, size_t n)
{
	const uint8_t *pa = a, *pb = b;
	uint8_t diff = 0;
	size_t i;

	for (i = 0; i < n; i++)
		diff |= pa[i] ^ pb[i];
	return diff == 0;
}

int shirudo_chain_cert_sha256(uint8_t out[32])
{
	unsigned char *buf;
	struct stat st;
	int fd, rc = 0;
	ssize_t got;

	fd = open(SHIRUDO_CERT_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) < 0 || st.st_size <= 0 ||
	    st.st_size > 1024 * 1024) {
		close(fd);
		return -EINVAL;
	}
	buf = xmalloc((size_t)st.st_size);
	if (!buf) {
		close(fd);
		return -ENOMEM;
	}
	got = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (got != st.st_size)
		rc = -EIO;
	else
		shirudo_sha256(buf, (size_t)st.st_size, out);
	xfree(buf, (size_t)st.st_size);
	return rc;
}

void shirudo_chain_auth_value(const uint8_t cert_sha[32], uint8_t out[32])
{
	uint8_t buf[sizeof("shirudo-nv-auth") + 32];
	size_t taglen = sizeof("shirudo-nv-auth");	/* includes NUL */

	memcpy(buf, "shirudo-nv-auth", taglen);
	memcpy(buf + taglen, cert_sha, 32);
	shirudo_sha256(buf, taglen + 32, out);
}

int shirudo_chain_read(uint8_t out[32])
{
	uint8_t cert_sha[32], auth[32];
	struct shirudo_tpm *tpm = NULL;
	int rc;

	rc = shirudo_chain_cert_sha256(cert_sha);
	if (rc)
		return rc;
	shirudo_chain_auth_value(cert_sha, auth);

	rc = shirudo_tpm_open(&tpm);
	if (rc)
		return -ENODEV;

	rc = shirudo_tpm_nv_read(tpm, SHIRUDO_NV_INDEX, auth, out);
	shirudo_tpm_close(tpm);
	if (rc)
		return -ENODEV;
	return 0;
}

int shirudo_chain_extend(const uint8_t event[32], uint8_t out_chain[32])
{
	uint8_t cert_sha[32], auth[32], probe[32];
	struct shirudo_tpm *tpm = NULL;
	int rc;

	rc = shirudo_chain_cert_sha256(cert_sha);
	if (rc)
		return rc;
	shirudo_chain_auth_value(cert_sha, auth);

	rc = shirudo_tpm_open(&tpm);
	if (rc)
		return -ENODEV;		/* no TPM -- degraded */

	/*
	 * Probe first: the index must already exist and be readable
	 * (init defines + writes it). If not, there is no chain to
	 * extend -- degrade rather than treating it as a hard error.
	 */
	rc = shirudo_tpm_nv_read(tpm, SHIRUDO_NV_INDEX, auth, probe);
	if (rc) {
		shirudo_tpm_close(tpm);
		return -ENODEV;		/* index undefined/unwritten */
	}

	rc = shirudo_tpm_nv_extend(tpm, SHIRUDO_NV_INDEX, auth, event);
	if (rc) {
		shirudo_tpm_close(tpm);
		return -EIO;		/* tpm_error: existed but extend failed */
	}
	if (out_chain)
		rc = shirudo_tpm_nv_read(tpm, SHIRUDO_NV_INDEX, auth, out_chain);
	shirudo_tpm_close(tpm);
	return rc ? -EIO : 0;
}
