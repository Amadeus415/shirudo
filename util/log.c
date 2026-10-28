// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * syslog(3) wrappers under LOG_AUTHPRIV.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <sys/ioctl.h>

#include <shirudo/misc.h>
#include <shirudo/string.h>

#include "log.h"

#define LOG_MSG_MAX	8192

static size_t n_errors;

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

static size_t terminal_width(FILE *fp)
{
	struct winsize ws;
	int fd = fileno(fp);

	if (fd < 0 || !isatty(fd))
		return 0;
	if (ioctl(fd, TIOCGWINSZ, &ws) || ws.ws_col < 40)
		return 80;
	return ws.ws_col;
}

/*
 * The last space that fits, or the last clause break when it fills most
 * of the line; a word longer than the line, a path say, is never cut.
 */
static size_t break_at(const char *text, size_t len, size_t avail)
{
	size_t i, space = 0, clause = 0;

	for (i = 1; i <= avail && i < len; i++) {
		if (text[i] != ' ')
			continue;
		space = i;
		if (strchr(":;,", text[i - 1]) && i >= avail * 3 / 5)
			clause = i;
	}
	if (clause)
		return clause;
	if (space)
		return space;
	while (i < len && text[i] != ' ')
		i++;
	return i;
}

void print_wrapped_to(FILE *fp, size_t width, const char *lead,
		      const char *text, size_t indent)
{
	size_t col = strlen(lead), len = strlen(text), cut;

	if (indent > width / 2)
		indent = 4;
	if (col + 20 > width)
		width = 0;
	fputs(lead, fp);
	while (width && col + len > width) {
		cut = break_at(text, len, width - col);
		fwrite(text, 1, cut, fp);
		text += cut;
		len -= cut;
		while (*text == ' ') {
			text++;
			len--;
		}
		if (!len)
			break;
		fprintf(fp, "\n%*s", (int)indent, "");
		col = indent;
	}
	fputs(text, fp);
	fputc('\n', fp);
}

void print_wrapped(FILE *fp, const char *lead, const char *text,
		   size_t indent)
{
	print_wrapped_to(fp, terminal_width(fp), lead, text, indent);
}

/* Continuation lines start under the text after a short "command: " prefix. */
static size_t message_indent(const char *msg)
{
	const char *colon = strstr(msg, ": ");

	return colon && colon - msg < 24 ? (size_t)(colon - msg) + 2 : 2;
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
	if (priority == LOG_ERR)
		n_errors++;
	syslog(priority, "%s%s", prefix, out);
	print_wrapped(stderr, prefix, out,
		      prefix[0] ? strlen(prefix) : message_indent(out));
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

size_t pr_err_count(void)
{
	return n_errors;
}
