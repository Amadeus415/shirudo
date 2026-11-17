/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * syslog(3) wrappers under LOG_AUTHPRIV.
 */

#ifndef SHIRUDO_LOG_H
#define SHIRUDO_LOG_H

#include <stdarg.h>

#include <shirudo/compiler.h>

void log_init(void);

/*
 * In rust/src/log.rs: the message msg logged at syslog priority, escaped,
 * to syslog and stderr.
 */
void log_emit(int priority, const char *msg);

void pr_err(const char *fmt, ...)
	__printf(1, 2);
void pr_warn(const char *fmt, ...)
	__printf(1, 2);
void pr_info(const char *fmt, ...)
	__printf(1, 2);
void pr_audit(const char *fmt, ...)
	__printf(1, 2);

#endif /* SHIRUDO_LOG_H */
