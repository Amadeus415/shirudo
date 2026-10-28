// SPDX-License-Identifier: BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */

/*
 * Drives util/string.c for t0049. The text under test sits in a buffer of
 * exactly the length given, so a read past it shows up under ASan.
 *
 *   test-string digits <text>
 *   test-string u64|x64 <max> <text> [<len>]
 *   test-string s64 <min> <max> <text> [<len>]
 *   test-string strscpy <size> <text>
 *   test-string strsprintf <size> <text>
 *   test-string xasprintf <text>
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <shirudo/string.h>

#include "util/malloc.h"

static int bound_u64(const char *s, __u64 *out)
{
	return parse_u64(s, strlen(s), UINT64_MAX, out);
}

static int bound_s64(const char *s, __s64 *out)
{
	return parse_s64(s, strlen(s), INT64_MIN, INT64_MAX, out);
}

/* The text in a buffer of its own, len bytes long and unterminated. */
static char *exact(const char *text, const char *len_arg, size_t *len)
{
	__u64 n = strlen(text);
	char *buf;

	if (len_arg && (bound_u64(len_arg, &n) || n > strlen(text)))
		return NULL;
	buf = xmalloc(n ? n : 1);
	if (buf)
		memcpy(buf, text, n);
	*len = n;
	return buf;
}

int main(int argc, char **argv)
{
	const char *op = argc > 1 ? argv[1] : "";
	__s64 min, smax, s = 0;
	__u64 max, u = 0;
	size_t len;
	char *buf;
	int rc;

	if (!strcmp(op, "digits") && argc == 3) {
		printf("n=%zu\n", digits(argv[2], strlen(argv[2])));
		return 0;
	}
	if ((!strcmp(op, "u64") || !strcmp(op, "x64")) &&
	    (argc == 4 || argc == 5)) {
		if (bound_u64(argv[2], &max))
			return 2;
		buf = exact(argv[3], argc == 5 ? argv[4] : NULL, &len);
		if (!buf)
			return 2;
		rc = op[0] == 'u' ? parse_u64(buf, len, max, &u) :
				    parse_x64(buf, len, max, &u);
		printf("rc=%d v=%llu\n", rc, u);
		xfree(buf, len ? len : 1);
		return 0;
	}
	if (!strcmp(op, "s64") && (argc == 5 || argc == 6)) {
		if (bound_s64(argv[2], &min) || bound_s64(argv[3], &smax))
			return 2;
		buf = exact(argv[4], argc == 6 ? argv[5] : NULL, &len);
		if (!buf)
			return 2;
		rc = parse_s64(buf, len, min, smax, &s);
		printf("rc=%d v=%lld\n", rc, s);
		xfree(buf, len ? len : 1);
		return 0;
	}
	if (!strcmp(op, "strscpy") && argc == 4) {
		ssize_t n;

		if (bound_u64(argv[2], &max))
			return 2;
		buf = xmalloc(max ? max : 1);
		if (!buf)
			return 2;
		n = strscpy(buf, argv[3], max);
		printf("rc=%zd dst=%s\n", n, max ? buf : "-");
		xfree(buf, max ? max : 1);
		return 0;
	}
	if (!strcmp(op, "strsprintf") && argc == 4) {
		int n;

		if (bound_u64(argv[2], &max))
			return 2;
		buf = xmalloc(max ? max : 1);
		if (!buf)
			return 2;
		buf[0] = 'x';
		n = strsprintf(buf, max, "<%s>", argv[3]);
		printf("rc=%d buf=%s\n", n, max ? buf : "-");
		xfree(buf, max ? max : 1);
		return 0;
	}
	if (!strcmp(op, "xasprintf") && argc == 3) {
		char *str = xasprintf("<%s|%d>", argv[2], 42);

		if (!str)
			return 2;
		printf("s=%s\n", str);
		xstrfree(str);
		return 0;
	}
	fprintf(stderr, "usage: test-string digits|u64|x64|s64|strscpy|strsprintf|xasprintf ...\n");
	return 2;
}
