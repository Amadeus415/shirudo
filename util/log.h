/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * syslog(3) wrappers under LOG_AUTHPRIV.
 */

#ifndef SHIRUDO_LOG_H
#define SHIRUDO_LOG_H

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

void log_init(void);

void pr_err(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));
void pr_warn(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));
void pr_info(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));
void pr_audit(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

/*
 * What to check or run next, after the pr_err() or pr_warn() it follows.
 * Keep the literal on one line so `git grep pr_hint` lists every hint.
 */
void pr_hint(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

/* Lets a catch-all tell whether a failure has been explained already. */
size_t pr_err_count(void);

/*
 * lead then text, wrapped to a terminal's width under an indent of that
 * many spaces; anything but a terminal gets one line.
 */
void print_wrapped(FILE *fp, const char *lead, const char *text,
		   size_t indent);

/* The same at a given width, 0 for one line. */
void print_wrapped_to(FILE *fp, size_t width, const char *lead,
		      const char *text, size_t indent);

#endif /* SHIRUDO_LOG_H */
