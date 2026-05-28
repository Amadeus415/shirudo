// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Zeroing allocator (see util/malloc.h).
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Implements the wrappers; opt out of the poison pragma in malloc.h. */
#define SHIRUDO_MALLOC_INTERNAL
#include "malloc.h"

void *xmalloc(size_t size)
{
	/*
	 * calloc zero-initialises. Treat a zero request as one byte so a
	 * NULL return means out-of-memory and nothing else.
	 */
	return calloc(1, size ? size : 1);
}

void *xcalloc(size_t nmemb, size_t size)
{
	/*
	 * Reject a multiply that would wrap before it reaches the
	 * allocator -- a caller computing nmemb * size itself would miss
	 * it. xmalloc() zero-initialises and handles the zero case.
	 */
	if (nmemb && size && nmemb > SIZE_MAX / size)
		return NULL;
	return xmalloc(nmemb * size);
}

void *xreallocarray(void *ptr, size_t old_nmemb, size_t new_nmemb,
		    size_t size)
{
	size_t old_size, new_size, copy;
	void *out;

	if (size && (new_nmemb > SIZE_MAX / size ||
		     old_nmemb > SIZE_MAX / size))
		return NULL;		/* overflow -- leave ptr untouched */
	old_size = old_nmemb * size;
	new_size = new_nmemb * size;

	out = xmalloc(new_size);	/* zeroed; the grown tail starts at 0 */
	if (!out)
		return NULL;		/* failure -- leave ptr untouched */
	if (ptr) {
		copy = old_size < new_size ? old_size : new_size;
		memcpy(out, ptr, copy);
		xfree(ptr, old_size);	/* scrub old block before release */
	}
	return out;
}

char *xstrdup(const char *s)
{
	size_t n;
	char *p;

	if (!s)
		return NULL;
	n = strlen(s) + 1;
	p = malloc(n);
	if (p)
		memcpy(p, s, n);
	return p;
}

char *xstrndup(const char *s, size_t n)
{
	size_t len;
	char *p;

	if (!s)
		return NULL;
	len = strnlen(s, n);
	p = malloc(len + 1);
	if (!p)
		return NULL;
	memcpy(p, s, len);
	p[len] = '\0';
	return p;
}

void xfree(void *ptr, size_t size)
{
	if (!ptr)
		return;
	explicit_bzero(ptr, size);
	free(ptr);
}

void xstrfree(char *s)
{
	if (!s)
		return;
	explicit_bzero(s, strlen(s) + 1);
	free(s);
}

void shirudo_libc_free(void *p)
{
	free(p);
}
