// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * syslog(3) wrappers under LOG_AUTHPRIV.
 */

#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include "log.h"

void shirudo_log_init(void)
{
	openlog("shirudo", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);
}

static void emit(int priority, const char *fmt, va_list ap)
{
	va_list ap2;

	va_copy(ap2, ap);
	vsyslog(priority, fmt, ap);
	vfprintf(stderr, fmt, ap2);
	fputc('\n', stderr);
	va_end(ap2);
}

#define PR_DEFINE(name, prio)					\
	void name(const char *fmt, ...)				\
	{							\
		va_list ap;					\
		va_start(ap, fmt);				\
		emit((prio), fmt, ap);				\
		va_end(ap);					\
	}

PR_DEFINE(pr_err,   LOG_ERR)
PR_DEFINE(pr_warn,  LOG_WARNING)
PR_DEFINE(pr_info,  LOG_INFO)
PR_DEFINE(pr_audit, LOG_NOTICE)
