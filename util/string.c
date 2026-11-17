// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Formatting into a bounded buffer. The other helpers of
 * <shirudo/string.h> are in rust/src/text.rs; a C-variadic function is
 * C's to define.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>

/* Implements the wrappers; opt out of the poison in <shirudo/string.h>. */
#define STRING_INTERNAL
#include <shirudo/string.h>

int vstrsprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
	int n = vsnprintf(buf, size, fmt, ap);

	if (n >= 0 && (size_t)n < size)
		return n;
	if (size)
		buf[0] = '\0';
	return -E2BIG;
}

int strsprintf(char *buf, size_t size, const char *fmt, ...)
{
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vstrsprintf(buf, size, fmt, ap);
	va_end(ap);
	return n;
}
