// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * syslog(3) wrappers under LOG_AUTHPRIV.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "log.h"

#define LOG_MSG_MAX	8192

void log_init(void)
{
	openlog("shirudo", LOG_PID | LOG_NDELAY, LOG_AUTHPRIV);
}

/*
 * A message can carry text from outside, a registry's error body or a
 * name from a package, and with it terminal escape sequences or line
 * breaks that forge records. Keep printable ASCII, double a backslash and
 * write every other byte as a backslash and three octal digits.
 */
static void escape(char *dst, size_t cap, const char *src)
{
	size_t n = 0;

	for (; *src && n + 5 <= cap; src++) {
		__u8 c = *src;

		if (c == '\\') {
			dst[n++] = '\\';
			dst[n++] = '\\';
		} else if (c >= 0x20 && c < 0x7f) {
			dst[n++] = c;
		} else {
			dst[n++] = '\\';
			dst[n++] = '0' + (c >> 6);
			dst[n++] = '0' + ((c >> 3) & 7);
			dst[n++] = '0' + (c & 7);
		}
	}
	dst[n] = '\0';
}

/*
 * Callers report a failure and then return -errno; syslog(3) and stdio
 * may change errno on the way (no /dev/log in an early initrd), so it
 * is kept for them.
 */
static void emit(int priority, const char *prefix, const char *fmt,
		 va_list ap)
{
	char msg[LOG_MSG_MAX], out[4 * LOG_MSG_MAX + 1];
	int saved_errno = errno;

	if (vstrsprintf(msg, sizeof(msg), fmt, ap) < 0)
		strscpy(msg, fmt, sizeof(msg));
	escape(out, sizeof(out), msg);
	syslog(priority, "%s%s", prefix, out);
	fprintf(stderr, "%s%s\n", prefix, out);
	errno = saved_errno;
}

#define PR_DEFINE(name, prio, prefix)				\
	void name(const char *fmt, ...)				\
	{							\
		va_list ap;					\
		va_start(ap, fmt);				\
		emit((prio), (prefix), fmt, ap);		\
		va_end(ap);					\
	}

PR_DEFINE(pr_err,   LOG_ERR,     "")
PR_DEFINE(pr_warn,  LOG_WARNING, "")
PR_DEFINE(pr_info,  LOG_INFO,    "")
PR_DEFINE(pr_audit, LOG_NOTICE,  "")
PR_DEFINE(pr_hint,  LOG_INFO,    "hint: ")
