// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo-quote-check: rows of keepalive quotes on standard input, one
 * JSON verdict per row on standard output, for as long as rows come.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "io.h"
#include "malloc.h"
#include "row.h"

static void usage(FILE *fp)
{
	fprintf(fp,
		"usage: shirudo-quote-check\n"
		"\n"
		"Reads TabSeparated rows from standard input until it ends:\n"
		"  <attest>\\t<sig>\\t<ak>\\t<body_sha256>\n"
		"attest, sig and ak are a keepalive quote's TPMS_ATTEST and\n"
		"TPMT_SIGNATURE and the signing key's TPMT_PUBLIC, in standard\n"
		"base64. body_sha256 is the SHA-256 of the record's body, 64\n"
		"hex digits. Writes one JSON line per row, in order:\n"
		"  {\"ok\":1,\"ak_name\":\"<hex>\",\"ak_public\":\"<base64>\",\n"
		"   \"reset_count\":<n>,\"clock\":<n>}\n"
		"  {\"ok\":0,\"reason\":\"bad_signature\"|\"body_mismatch\"|\n"
		"   \"malformed\"}\n");
}

/* got is what read_text_line() returned for line, never 0. */
static int line_check(const char *line, int got, struct quote_result *res)
{
	size_t len;

	/* A NUL in the line, or more bytes than the longest row has. */
	if (got == -EINVAL || got == -E2BIG) {
		*res = (struct quote_result){ .verdict = QUOTE_MALFORMED };
		return 0;
	}
	if (got < 0)
		return got;
	len = strlen(line);
	if (len && line[len - 1] == '\n')
		len--;
	return quote_row_check(line, len, res);
}

static int verdict_write(const struct quote_result *res)
{
	char json[QUOTE_LINE_MAX];
	int ret;

	ret = quote_row_emit(res, json, sizeof(json));
	if (ret)
		return ret;
	/* The caller waits for each row's answer before it sends the next. */
	if (puts(json) == EOF || fflush(stdout) == EOF)
		return -EIO;
	return 0;
}

int main(int argc, char **argv)
{
	struct quote_result res;
	char *line = NULL;
	size_t cap = 0;
	int got, ret = 0;

	if (argc == 2 && (!strcmp(argv[1], "--help") || !strcmp(argv[1], "-h"))) {
		usage(stdout);
		return 0;
	}
	if (argc != 1) {
		usage(stderr);
		return 2;
	}

	do {
		got = read_text_line(stdin, &line, &cap, QUOTE_ROW_MAX);
		if (!got)
			break;
		ret = line_check(line, got, &res);
		if (!ret)
			ret = verdict_write(&res);
	} while (!ret);
	libc_free(line);
	if (ret) {
		fprintf(stderr, "shirudo-quote-check: %s\n", strerror(-ret));
		return 1;
	}
	return 0;
}
