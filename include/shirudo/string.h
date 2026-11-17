/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Bounded number parsing and string copies, file name suffixes, DNS
 * names, UTF-8 characters and text for a terminal, from rust/src/text.rs,
 * and the scrub and compare for secrets.
 */

#ifndef SHIRUDO_STRING_H
#define SHIRUDO_STRING_H

#include <inttypes.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <shirudo/misc.h>

/* How many of the len bytes at s, from the first, are decimal digits. */
size_t digits(const char *s, size_t len);

/*
 * The number the len bytes at s spell, decimal for u64 and s64 and
 * hexadecimal for x64, within the bounds given: digits only, s64 with an
 * optional leading '-', and no blank, '+' or base prefix. Nothing past
 * len is read, so s need not be terminated. -EINVAL when the bytes are
 * not such a number, -ERANGE when it is out of bounds; *out is only
 * written on success.
 */
int parse_u64(const char *s, size_t len, __u64 max, __u64 *out);
int parse_x64(const char *s, size_t len, __u64 max, __u64 *out);
int parse_s64(const char *s, size_t len, __s64 min, __s64 max, __s64 *out);

/*
 * Copy the string src into the size bytes at dst, terminated whenever
 * size is not 0: its length, or -E2BIG when it did not fit and dst holds
 * as much of it as did.
 */
ssize_t strscpy(char *dst, const char *src, size_t size);

/*
 * Whether the len bytes at name are a stem of at least one byte and then
 * suffix, as a file name and its extension are.
 */
bool name_has_suffix(const char *name, size_t len, const char *suffix);

/*
 * A DNS host name: labels of letters, digits and inner hyphens, 1 to 63
 * bytes each and 253 in all. A name whose labels are all decimal or 0x
 * numbers is refused, as an IPv4 parser would read it as an address.
 */
bool dns_name_valid(const char *name);

/*
 * The length, 1 to 4, of the well-formed UTF-8 character the n bytes at
 * s start with, or 0 when they start none: a stray or cut byte, an
 * overlong form, a surrogate or a code point past U+10FFFF. Nothing past
 * n is read.
 */
size_t utf8_width(const char *s, size_t n);

/*
 * Make the len bytes at s, text from outside, safe to print on a
 * terminal: each byte of a control character, C0, DEL or C1 alike, and
 * each byte that starts no well-formed UTF-8 character becomes '?',
 * but for a tab and a line feed where lines is set, and there a carriage
 * return before a line feed. The length stays as it was.
 */
void text_sanitize(char *s, size_t len, bool lines);

/*
 * Zero the count bytes at s even when nothing reads them afterwards, as
 * when a secret is scrubbed before it goes out of scope or is freed,
 * where the compiler may drop a plain memset() as a dead store.
 */
static inline void memzero_explicit(void *s, size_t count)
{
	memset(s, 0, count);
	barrier_data(s);
}

/*
 * 0 when the size bytes at a and b are equal and 1 when they differ, in
 * a time that depends on size alone, for comparing a secret or a value
 * derived from one, where memcmp() returns at the first difference.
 */
static inline int memneq_explicit(const void *a, const void *b, size_t size)
{
	const __u8 *pa = a, *pb = b;
	__u8 neq = 0;
	size_t i;

	for (i = 0; i < size; i++) {
		neq |= pa[i] ^ pb[i];
		OPTIMIZER_HIDE_VAR(neq);
	}
	return neq != 0;
}

/*
 * What the functions above replace, refused once the headers included
 * above have declared it, so that a later include of those still works;
 * a file that must name one opts out with STRING_INTERNAL. sprintf() and
 * vsprintf() write past any buffer; snprintf() bounds itself.
 */
#ifndef STRING_INTERNAL
# pragma GCC poison strtol strtoll strtoul strtoull strtoimax strtoumax
# pragma GCC poison strtod strtof strtold atoi atol atoll atof
# pragma GCC poison strcpy strncpy strcat strncat strlcpy
/* Fortified glibc makes these macros for clang; poison the names alone. */
# undef sprintf
# pragma GCC poison sprintf vsprintf
# pragma GCC poison explicit_bzero
#endif

#endif /* SHIRUDO_STRING_H */
