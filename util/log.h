/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * syslog(3) wrappers under LOG_AUTHPRIV.
 */

#ifndef SHIRUDO_LOG_H
#define SHIRUDO_LOG_H

#include <stdarg.h>

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

#endif /* SHIRUDO_LOG_H */
