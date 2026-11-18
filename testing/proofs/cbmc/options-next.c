// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * opt_next() of util/options.c from every state a run of calls reaches,
 * on every command line of up to ARGS_MAX arguments of up to LEN bytes,
 * against a table with an option of each kind: each call takes at least
 * one argument, so a run ends, what it hands back lies in an argument, a
 * flag has no value, a value is there and not empty unless the option
 * allows it, and no option comes back twice unless it repeats.
 */

#include <errno.h>
#include <stdbool.h>

#include "proof.h"
#include "../../../util/options.c"

#define ARGS_MAX	3

enum { P_A, P_BB, P_C, P_D, P_N, P_COUNT };

static const struct opt_spec specs[] = {
	[P_A]  = { "--a", 'a', 0, "<v>", "a value" },
	[P_BB] = { "--bb", 0, 0, NULL, "a flag" },
	[P_C]  = { "--c", 0, OPT_OPTIONAL, "<v>", "a value after = or none" },
	[P_D]  = { "--d", 0, OPT_REPEAT | OPT_EMPTY, "<v>", "repeats, may be empty" },
	[P_N]  = { "--n", 0, 0, "<n>", "a number" },
};

void pr_err(const char *fmt, ...)
{
}

/* The messages are not read here; the format proofs cover the text. */
int vstrsprintf(char *buf, size_t size, const char *fmt, va_list ap)
{
	if (size)
		buf[0] = '\0';
	return 0;
}

/* The contract string-number proves: a number up to max, or an error. */
int parse_u64(const char *s, size_t len, __u64 max, __u64 *out)
{
	__u64 v;
	int ret;

	__CPROVER_assert(__CPROVER_r_ok(s, len), "the digits are readable");
	if (ret)
		return ret < 0 ? ret : -EINVAL;
	__CPROVER_assume(v <= max);
	*out = v;
	return 0;
}

void print_help(const struct help *h)
{
}

/* As util/help.c has it. */
int is_list_cmds(const char *arg)
{
	return arg && strcmp(arg, "--list-cmds") == 0;
}

void help_suggest(const char *bad, const char *const *names, size_t n_names)
{
	__CPROVER_assert(n_names <= OPT_MAX, "the names fit");
	__CPROVER_assert(strlen(bad) <= SIMILAR_MAX_LEN, "the word fits");
}

static const char *argv[ARGS_MAX];
static size_t lens[ARGS_MAX];

static const char *any_string(size_t *len)
{
	char *s;

	__CPROVER_assume(*len <= LEN);
	s = any_bytes(*len + 1);
	__CPROVER_assume(!s[*len] && strnlen(s, *len) == *len);
	return s;
}

static bool in_args(const char *v, int argc)
{
	int k;

	for (k = 0; k < argc; k++)
		if (__CPROVER_same_object(v, argv[k]) &&
		    __CPROVER_POINTER_OFFSET(v) <= lens[k])
			return true;
	return false;
}

void harness(void)
{
	bool checked, args_only;
	const struct opt_spec *s;
	int argc, i, next, opt;
	__u64 given_before, n;
	struct opt_parser p;

	__CPROVER_assume(argc >= 0 && argc <= ARGS_MAX);
	for (i = 0; i < argc; i++) {
		size_t len;

		argv[i] = any_string(&len);
		lens[i] = len;
	}
	OPT_INIT(&p, "proof", specs, NULL, argc, argv, 0);
	/* Any state a run of calls reaches: the next argument, what came. */
	__CPROVER_assume(next >= 0 && next <= argc);
	__CPROVER_assume(!(given_before >> P_COUNT));
	p.next = next;
	p.given = given_before;
	p.checked = checked;
	p.args_only = args_only;

	opt = opt_next(&p);
	__CPROVER_assert(p.next <= argc, "never past the arguments");
	if (opt == OPT_END) {
		__CPROVER_assert(p.next == argc,
				 "the end only where no argument is left");
		return;
	}
	if (opt == OPT_DONE || opt == OPT_USAGE)
		return;
	__CPROVER_assert(p.next > next, "every call takes an argument");
	if (opt == OPT_ARG) {
		__CPROVER_assert(p.value == argv[p.next - 1],
				 "an argument is the one it took");
		return;
	}
	__CPROVER_assert(opt >= 0 && opt < P_COUNT, "an option of the table");
	__CPROVER_assert(opt_given(&p, opt), "what comes back is marked given");
	s = &specs[opt];
	if (!s->metavar)
		__CPROVER_assert(!p.value, "a flag has no value");
	else if (p.value)
		__CPROVER_assert(in_args(p.value, argc) &&
				 (*p.value || (s->flags & OPT_EMPTY)),
				 "a value in an argument, empty only where allowed");
	else
		__CPROVER_assert(s->flags & OPT_OPTIONAL,
				 "only an optional value may be left out");
	__CPROVER_assert(!(given_before & (1ULL << opt)) ||
			 (s->flags & OPT_REPEAT),
			 "an option comes once unless it repeats");
	if (opt == P_N && !opt_u64(&p, 1, 512, &n))
		__CPROVER_assert(n >= 1 && n <= 512, "a number in bounds");
}
