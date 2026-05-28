// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo rollout -- push one or more signed .upatch files to a set of
 * registered targets (explicit names or a label --selector) over
 * libssh, then apply each on the target. By default the target's
 * current chain is read first and threaded back as --expect-chain so a
 * concurrently-changed target refuses. Per-target results are
 * aggregated into an optional --report JSON document.
 *
 * There is no separate `rollback` verb: a removal is just a rollout of
 * a signed UNLOAD-directive .upatch. Each file's DIRECTIVE_UNLOAD flag
 * selects `upatch load` vs `upatch unload` on the target, so one
 * command -- and one mental model -- covers deploy and remove.
 */

#include <errno.h>
#include <fnmatch.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "builtin.h"
#include "util/chain.h"
#include "util/help.h"
#include "util/json.h"
#include "util/macros.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/remotes.h"
#include "util/report.h"
#include "util/selector.h"
#include "util/ssh.h"
#include "util/upatch.h"

#define MAX_FILES	64

enum tres { R_UNREACHABLE, R_OK, R_OK_DRYRUN, R_FAILED };

struct target_result {
	const char	*name;
	enum tres	result;
	char		chain_before[80];
	int		chain_before_seen;
	char		chain_after[80];
	int		chain_after_seen;
	char		message[256];
	/* Parsed from the remote per-upatch report (empty if unavailable). */
	char		category[48];
	char		phase[32];
	char		errno_name[32];
	char		*verifier_log;	/* heap; non-NULL only on a failure */
};

extern const char shirudo_version_id[];

/*
 * A chain value must be a non-empty run of hex digits before it is
 * spliced into the remote `--expect-chain=<hex>` argument. The chain
 * comes from the target's own status JSON (untrusted: a compromised
 * target controls it) or an operator override, and is placed in the
 * command string unquoted -- validating the charset here forecloses
 * any shell-metacharacter injection through it. Length is bounded to
 * the 80-byte capture buffer.
 */
static bool chain_is_hex(const char *s)
{
	size_t i;

	if (!s || !*s)
		return false;
	for (i = 0; s[i]; i++) {
		if (i >= 78)
			return false;
		if (!((s[i] >= '0' && s[i] <= '9') ||
		      (s[i] >= 'a' && s[i] <= 'f') ||
		      (s[i] >= 'A' && s[i] <= 'F')))
			return false;
	}
	return true;
}

/*
 * Read `status --json --include-tpm` from a session; capture the chain
 * and the target's SHIRUDO_VERSION_ID (for the version-skew gate).
 */
static int remote_chain(struct shirudo_ssh_session *s, char chain[80],
			int *chain_seen, int *lsm, char version[80])
{
	char *out = NULL;
	size_t len = 0;
	int rc;

	chain[0] = '\0';
	*chain_seen = 0;
	*lsm = 0;
	version[0] = '\0';

	rc = shirudo_ssh_exec(s, "shirudo status --json --include-tpm",
			      &out, &len);
	if (rc < 0 || !out) {
		xfree(out, len);
		return rc < 0 ? rc : -EIO;
	}
	{
		struct shirudo_json_field tpm[] = {
			{ "chain", SHIRUDO_JSON_T_STRING, chain, 80, 0, NULL, 0 },
		};
		struct shirudo_json_field top[] = {
			{ "lsm_attached", SHIRUDO_JSON_T_BOOL, lsm, 0, 0,
			  NULL, 0 },
			{ "version_id", SHIRUDO_JSON_T_STRING, version, 80, 0,
			  NULL, 0 },
			{ "tpm", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, tpm, 1 },
		};

		rc = shirudo_json_parse(out, len, top, 3);
		if (rc == 0)
			*chain_seen = tpm[0].seen;
		/*
		 * Reject a non-hex chain the target returned: it is reused
		 * unquoted in the next remote command. Treat it as "not
		 * seen" so the rollout proceeds without --expect-chain
		 * rather than splicing attacker-controlled bytes.
		 */
		if (*chain_seen && !chain_is_hex(chain)) {
			chain[0] = '\0';
			*chain_seen = 0;
		}
	}
	xfree(out, len);
	return rc;
}

/*
 * Parse the remote per-upatch report (the JSON `upatch load/unload
 * --report=-` writes to stdout) into t. vlog is a scratch buffer for
 * the verifier_log field (copied into t->verifier_log if non-empty).
 * Returns 1 if the report says "ok", 0 if "failed", -1 if unparseable
 * (e.g. an older remote that emits no report).
 */
static int parse_remote_report(const char *out, size_t len,
			       char *vlog, size_t vcap,
			       struct target_result *t)
{
	char result[16] = {};
	struct shirudo_json_field tpm[] = {
		{ "chain_after", SHIRUDO_JSON_T_STRING, t->chain_after,
		  sizeof(t->chain_after), 0, NULL, 0 },
	};
	struct shirudo_json_field top[] = {
		{ "result", SHIRUDO_JSON_T_STRING, result, sizeof(result),
		  0, NULL, 0 },
		{ "category", SHIRUDO_JSON_T_STRING, t->category,
		  sizeof(t->category), 0, NULL, 0 },
		{ "phase", SHIRUDO_JSON_T_STRING, t->phase, sizeof(t->phase),
		  0, NULL, 0 },
		{ "errno_name", SHIRUDO_JSON_T_STRING, t->errno_name,
		  sizeof(t->errno_name), 0, NULL, 0 },
		{ "message", SHIRUDO_JSON_T_STRING, t->message,
		  sizeof(t->message), 0, NULL, 0 },
		{ "verifier_log", SHIRUDO_JSON_T_STRING, vlog, vcap, 0,
		  NULL, 0 },
		{ "tpm", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, tpm, 1 },
	};

	vlog[0] = '\0';
	if (shirudo_json_parse(out, len, top, 7) != 0 || !top[0].seen)
		return -1;
	if (top[6].seen && tpm[0].seen)
		t->chain_after_seen = 1;
	if (vlog[0]) {
		xstrfree(t->verifier_log);
		/* vlog is remote-sourced -- bound the copy, never strlen it. */
		t->verifier_log = xstrndup(vlog, vcap);
	}
	return strcmp(result, "ok") == 0 ? 1 : 0;
}

/* Classify a positional arg; returns 1 if it is an .upatch file. */
static bool is_upatch_arg(const char *a)
{
	size_t n = strlen(a);

	return n > 7 && strcmp(a + n - 7, ".upatch") == 0;
}

static const char *base_name(const char *path)
{
	const char *s = strrchr(path, '/');

	return s ? s + 1 : path;
}

static void set_msg(struct target_result *t, const char *m)
{
	snprintf(t->message, sizeof(t->message), "%s", m);
}

/*
 * Push every file and run the right remote verb per file (upatch load
 * for LOAD artifacts, upatch unload for UNLOAD directives -- the
 * .upatch's flag decides). Fills one target_result.
 */
static void apply_target(const struct shirudo_remote *r,
			 const char *const *files, const bool *is_unload,
			 size_t nfiles, const char *expect_override,
			 const char *expect_version_id, bool no_version_check,
			 bool no_precheck, bool dry_run, bool sudo,
			 struct target_result *t)
{
	struct shirudo_ssh_session *s;
	int chain_seen, lsm, rc;
	char chain[80], version[80], verflag[128], *vlog;
	const char *expect;
	size_t i;

	t->name = r->name;
	t->result = R_UNREACHABLE;

	s = shirudo_ssh_connect(r->user, r->host, r->port);
	if (!s) {
		set_msg(t, "ssh connect failed");
		return;
	}

	/* Pre-check: capture the current chain + the target's version-id. */
	if (remote_chain(s, chain, &chain_seen, &lsm, version) == 0) {
		if (chain_seen) {
			memcpy(t->chain_before, chain, sizeof(t->chain_before));
			t->chain_before_seen = 1;
		}
	}
	expect = expect_override ? expect_override :
		 (t->chain_before_seen ? t->chain_before : NULL);

	/*
	 * Version-skew gate, threaded to the target as the first pre-flight
	 * check. Same value for every file (it is the operator's identity,
	 * unlike the chain, which advances).
	 */
	if (no_version_check)
		snprintf(verflag, sizeof(verflag), " --no-version-check");
	else if (expect_version_id)
		snprintf(verflag, sizeof(verflag), " --expect-version-id=%s",
			 expect_version_id);
	else
		verflag[0] = '\0';

	if (dry_run) {
		if (!no_version_check && version[0] && expect_version_id &&
		    strcmp(version, expect_version_id) != 0) {
			t->result = R_FAILED;
			snprintf(t->message, sizeof(t->message),
				 "version mismatch: target %s != operator %s",
				 version, expect_version_id);
			shirudo_ssh_close(s);
			return;
		}
		t->result = R_OK_DRYRUN;
		set_msg(t, "pre-flight ok (dry-run)");
		shirudo_ssh_close(s);
		return;
	}

	vlog = xmalloc(SHIRUDO_VERIFIER_LOG_MAX);
	if (!vlog) {
		t->result = R_FAILED;
		set_msg(t, "out of memory");
		shirudo_ssh_close(s);
		return;
	}

	for (i = 0; i < nfiles; i++) {
		char remote[512], cmd[1024], *out = NULL;
		size_t len = 0;
		const char *bn = base_name(files[i]);
		const char *verb = is_unload[i] ? "upatch unload"
						: "upatch load";
		int pr;

		snprintf(remote, sizeof(remote), "%s/%s",
			 SHIRUDO_INCOMING_DIR, bn);
		rc = shirudo_ssh_sftp_push(s, files[i], remote);
		if (rc) {
			t->result = R_FAILED;
			snprintf(t->message, sizeof(t->message),
				 "sftp push %s failed: %s", bn, strerror(-rc));
			break;
		}

		snprintf(cmd, sizeof(cmd),
			 "%sshirudo %s --report=- %s%s%s%s '%s'",
			 sudo ? "sudo " : "", verb,
			 expect ? "--expect-chain=" : "", expect ? expect : "",
			 verflag,
			 no_precheck ? " --no-precheck" : "",
			 remote);
		/*
		 * After the first file the chain has advanced; only the
		 * first invocation can carry the operator's expected
		 * value. Subsequent files in the same batch skip the
		 * chain check (the operator batched them as one intent).
		 */
		expect = NULL;
		no_precheck = true;

		rc = shirudo_ssh_exec(s, cmd, &out, &len);
		if (rc < 0) {
			t->result = R_FAILED;
			snprintf(t->message, sizeof(t->message),
				 "ssh exec %s %s failed", verb, bn);
			xfree(out, len);
			break;
		}

		/* Consume the remote's structured per-upatch report. */
		pr = out ? parse_remote_report(out, len, vlog,
					       SHIRUDO_VERIFIER_LOG_MAX, t) : -1;
		xfree(out, len);
		if (pr == 0) {		/* report says failed */
			t->result = R_FAILED;
			break;
		}
		if (pr < 0 && rc != 0) {	/* no report + nonzero exit */
			t->result = R_FAILED;
			snprintf(t->message, sizeof(t->message),
				 "%s %s exit=%d (no report)", verb, bn, rc);
			break;
		}
		/* ok (parsed ok, or no report but exit 0) -- next file */
	}

	if (t->result != R_FAILED) {
		t->result = R_OK;
		if (!t->message[0])
			set_msg(t, "applied");
	}
	xfree(vlog, SHIRUDO_VERIFIER_LOG_MAX);
	shirudo_ssh_close(s);
}

static const char *res_str(enum tres r)
{
	switch (r) {
	case R_OK:		return "ok";
	case R_OK_DRYRUN:	return "ok-dryrun";
	case R_FAILED:		return "failed";
	default:		return "unreachable";
	}
}

static int emit_report(const char *path, bool dry_run,
		       const char *const *files, size_t nfiles,
		       const struct target_result *t, size_t n)
{
	size_t i, ok = 0, failed = 0, unreach = 0, cap = 16384;
	struct shirudo_json_emit e;
	char *buf;
	FILE *f;

	/* Size for the embedded verifier_logs (escaped) plus slack. */
	for (i = 0; i < n; i++)
		if (t[i].verifier_log)
			cap += strlen(t[i].verifier_log) * 6 + 1024;
	buf = xmalloc(cap);
	if (!buf)
		return -1;
	e = (struct shirudo_json_emit){ .buf = buf, .cap = cap };

	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_kv_string(&e, "op", "rollout");
	shirudo_json_kv_bool(&e, "dry_run", dry_run);
	shirudo_json_arr_open(&e, "upatches");
	for (i = 0; i < nfiles; i++)
		shirudo_json_str(&e, base_name(files[i]));
	shirudo_json_arr_close(&e);
	shirudo_json_arr_open(&e, "targets");
	for (i = 0; i < n; i++) {
		shirudo_json_obj_open(&e);
		shirudo_json_kv_string(&e, "name", t[i].name);
		shirudo_json_kv_string(&e, "result", res_str(t[i].result));
		if (t[i].category[0])
			shirudo_json_kv_string(&e, "category", t[i].category);
		if (t[i].phase[0])
			shirudo_json_kv_string(&e, "phase", t[i].phase);
		if (t[i].errno_name[0])
			shirudo_json_kv_string(&e, "errno_name",
					       t[i].errno_name);
		if (t[i].chain_before_seen)
			shirudo_json_kv_string(&e, "chain_before",
					       t[i].chain_before);
		else
			shirudo_json_kv_null(&e, "chain_before");
		if (t[i].chain_after_seen)
			shirudo_json_kv_string(&e, "chain_after",
					       t[i].chain_after);
		else
			shirudo_json_kv_null(&e, "chain_after");
		shirudo_json_kv_string(&e, "message", t[i].message);
		if (t[i].verifier_log)
			shirudo_json_kv_string(&e, "verifier_log",
					       t[i].verifier_log);
		shirudo_json_obj_close(&e);
		if (t[i].result == R_OK || t[i].result == R_OK_DRYRUN)
			ok++;
		else if (t[i].result == R_FAILED)
			failed++;
		else
			unreach++;
	}
	shirudo_json_arr_close(&e);
	shirudo_json_obj_open_key(&e, "summary");
	shirudo_json_kv_int(&e, "total", (int64_t)n);
	shirudo_json_kv_int(&e, "ok", (int64_t)ok);
	shirudo_json_kv_int(&e, "failed", (int64_t)failed);
	shirudo_json_kv_int(&e, "unreachable", (int64_t)unreach);
	shirudo_json_obj_close(&e);
	shirudo_json_obj_close(&e);

	if (e.err) {
		pr_err("rollout: report encode failed: %s", strerror(-e.err));
		xfree(buf, cap);
		return -1;
	}
	if (strcmp(path, "-") == 0) {
		printf("%s\n", buf);
		xfree(buf, cap);
		return 0;
	}
	f = fopen(path, "w");
	if (!f) {
		pr_err("rollout: open report %s: %s", path, strerror(errno));
		xfree(buf, cap);
		return -1;
	}
	fprintf(f, "%s\n", buf);
	fclose(f);
	xfree(buf, cap);
	return 0;
}

static const struct shirudo_help_item rollout_options[] = {
	{ "--filter=<glob>",         "select targets by name (shell-glob, fnmatch(3))" },
	{ "--selector=<expr>",       "select targets by label expression" },
	{ "--expect-chain=<hex>",    "pin the expected NV chain (auto-derived if omitted)" },
	{ "--expect-version-id=<x>", "pin the expected target SHIRUDO_VERSION_ID" },
	{ "--no-precheck",           "skip the pre-flight chain/version check" },
	{ "--no-version-check",      "skip just the version-id half of pre-flight" },
	{ "--report=<path>",         "emit aggregate JSON report ('-' = stdout)" },
	{ "--dry-run",               "pre-flight only; no SFTP upload, no load" },
	{ "--sudo",                  "wrap the remote shirudo invocation in sudo" },
};

static const struct shirudo_help_section rollout_help_sections[] = {
	{ "options:", rollout_options,
	  ARRAY_SIZE(rollout_options) },
};

static const struct shirudo_help rollout_help = {
	.usage   = "shirudo rollout <upatch>... { <name>... | --filter=<glob> | --selector=<expr> } [options]",
	.summary = "Push one or more signed .upatch files to one or more "
		   "registered remotes\nvia SFTP, then apply each over an "
		   "SSH exec channel. A LOAD upatch runs\n`upatch load` on "
		   "the target; an UNLOAD directive runs `upatch unload`.",
	.sections   = rollout_help_sections,
	.n_sections = ARRAY_SIZE(rollout_help_sections),
	.footer  =
"--filter=<glob> matches the registry name via shell-glob (fnmatch(3)):\n"
"  shirudo rollout foo.upatch --filter='prod-*'\n"
"  shirudo rollout foo.upatch --filter='*-edge-?\?'\n"
"  shirudo rollout foo.upatch --filter='db[0-9][0-9]'\n"
"\n"
"--selector=<expr> matches the remote's labels:\n"
"  atoms: k=v, k!=v, k (exists), !k (absent)\n"
"  combine with &&, ||, (), where && binds tighter than ||\n"
"  shirudo rollout foo.upatch --selector='env=production'\n"
"  shirudo rollout foo.upatch --selector='env=prod && tier=edge'\n"
"  shirudo rollout foo.upatch --selector=\"(role=db || role=cache) && env!=staging\"\n"
"\n"
"Rollout has two selection forms, mutually exclusive:\n"
"  - positional <name>... (each must be a registered remote)\n"
"  - the predicate form, --filter and/or --selector. When both are\n"
"    given they intersect (a remote must satisfy both).\n"
"An empty match set is an error. Literal user@host arguments are\n"
"refused; targets must be registered first with `shirudo remote add`.",
};

int cmd_rollout(int argc, const char **argv)
{
	const char *report = NULL, *expect_override = NULL, *selexpr = NULL;
	const char *expect_version_override = NULL, *expect_version_id;
	const char *filter = NULL;
	bool dry_run = false, no_precheck = false, sudo = false;
	bool no_version_check = false;
	const char *files[MAX_FILES], *names[MAX_FILES];
	size_t nfiles = 0, nnames = 0, i, j, n = 0;
	struct shirudo_remote *remotes = NULL;
	struct shirudo_selector *sel = NULL;
	struct target_result *res = NULL;
	bool is_unload[MAX_FILES];
	size_t n_remotes = 0;
	int ret = 0;

	for (i = 1; i < (size_t)argc; i++) {
		const char *a = argv[i];

		if (shirudo_is_help(a)) {
			shirudo_print_help(&rollout_help);
			return 0;
		} else if (strncmp(a, "--report=", 9) == 0)
			report = a + 9;
		else if (strncmp(a, "--filter=", 9) == 0)
			filter = a + 9;
		else if (strncmp(a, "--selector=", 11) == 0)
			selexpr = a + 11;
		else if (strncmp(a, "--expect-chain=", 15) == 0) {
			expect_override = a + 15;
			if (!chain_is_hex(expect_override)) {
				fprintf(stderr, "rollout: --expect-chain must "
					"be hex digits\n");
				return 2;
			}
		}
		else if (strcmp(a, "--no-precheck") == 0)
			no_precheck = true;
		else if (strcmp(a, "--dry-run") == 0)
			dry_run = true;
		else if (strcmp(a, "--sudo") == 0)
			sudo = true;
		else if (strncmp(a, "--expect-version-id=", 20) == 0)
			expect_version_override = a + 20;
		else if (strcmp(a, "--no-version-check") == 0)
			no_version_check = true;
		else if (a[0] == '-') {
			fprintf(stderr, "rollout: unknown option '%s'\n", a);
			return 2;
		} else if (is_upatch_arg(a)) {
			if (nfiles >= MAX_FILES) {
				fprintf(stderr, "rollout: too many files\n");
				return 2;
			}
			files[nfiles++] = a;
		} else if (strchr(a, '@')) {
			fprintf(stderr, "rollout: '%s' looks like user@host; "
				"register it first with `shirudo remote add`\n",
				a);
			return 2;
		} else {
			if (nnames >= MAX_FILES) {
				fprintf(stderr, "rollout: too many targets\n");
				return 2;
			}
			names[nnames++] = a;
		}
	}

	if (nfiles == 0) {
		shirudo_print_help(&rollout_help);
		return 2;
	}
	if (selexpr && nnames) {
		fprintf(stderr, "rollout: pass either names or --selector, "
			"not both\n");
		return 2;
	}

	/*
	 * Validate each .upatch and record its flavour. The file's
	 * DIRECTIVE_UNLOAD flag -- not a separate verb -- decides whether
	 * the target runs `upatch load` or `upatch unload`, so a single
	 * rollout can mix loads and removals.
	 */
	for (i = 0; i < nfiles; i++) {
		struct shirudo_upatch u;

		/* The basename becomes a single-quoted remote shell arg. */
		if (strchr(base_name(files[i]), '\'')) {
			fprintf(stderr, "rollout: refusing filename containing "
				"a single quote: %s\n", files[i]);
			return 1;
		}
		if (shirudo_upatch_open(files[i], &u) != 0) {
			fprintf(stderr, "rollout: cannot open %s\n", files[i]);
			return 1;
		}
		is_unload[i] = shirudo_upatch_is_unload(&u);
		shirudo_upatch_close(&u);
	}

	if (selexpr) {
		sel = shirudo_selector_parse(selexpr);
		if (!sel) {
			pr_err("rollout: invalid --selector expression");
			return 2;
		}
	}

	shirudo_remotes_load_all(&remotes, &n_remotes);
	res = xcalloc(n_remotes ? n_remotes : 1, sizeof(*res));
	if (!res) {
		shirudo_remotes_free(remotes, n_remotes);
		shirudo_selector_free(sel);
		return 1;
	}

	/*
	 * The version-skew gate defaults to the operator's own
	 * SHIRUDO_VERSION_ID ("the target must be the same shirudo as me");
	 * --expect-version-id overrides, --no-version-check disables.
	 */
	expect_version_id = expect_version_override ? expect_version_override
						    : shirudo_version_id;

	/*
	 * Rollout has two forms: an explicit positional <name>... list, or
	 * a predicate form combining --filter and/or --selector. The two
	 * forms are mutually exclusive (a positional name list is already
	 * unambiguous; mixing it with predicates would invite the "I named
	 * X but my filter excluded it, did it run?" footgun). Inside the
	 * predicate form, --filter and --selector intersect.
	 *
	 * Bare rollout with no selection is rejected; rollout is
	 * destructive and must never silently target every registered
	 * remote.
	 */
	if (nnames && (filter || selexpr)) {
		pr_err("rollout: <name>... and --filter/--selector are "
		       "mutually exclusive -- pick the named form or the "
		       "predicate form");
		ret = 2;
		goto out;
	}
	if (!nnames && !filter && !selexpr) {
		pr_err("rollout: need a target -- one of <name>..., "
		       "--filter, or --selector");
		ret = 2;
		goto out;
	}

	if (nnames) {
		for (j = 0; j < nnames; j++) {
			struct shirudo_remote *r = NULL;

			for (i = 0; i < n_remotes; i++)
				if (strcmp(remotes[i].name, names[j]) == 0) {
					r = &remotes[i];
					break;
				}
			if (!r) {
				fprintf(stderr, "rollout: '%s' is not a "
					"registered remote\n", names[j]);
				ret = 1;
				goto out;
			}
			apply_target(r, files, is_unload, nfiles,
				     expect_override, expect_version_id,
				     no_version_check, no_precheck, dry_run,
				     sudo, &res[n++]);
		}
	} else {
		for (i = 0; i < n_remotes; i++) {
			if (filter &&
			    fnmatch(filter, remotes[i].name, 0) != 0)
				continue;
			if (sel &&
			    !shirudo_selector_match(sel, remotes[i].labels))
				continue;
			apply_target(&remotes[i], files, is_unload, nfiles,
				     expect_override, expect_version_id,
				     no_version_check, no_precheck, dry_run,
				     sudo, &res[n++]);
		}
	}

	if (n == 0) {
		pr_err("rollout: name/filter/selector matched zero "
		       "registered remotes");
		ret = 1;
		goto out;
	}

	if (report)
		emit_report(report, dry_run, files, nfiles, res, n);

	/* Human progress to stderr; --report JSON owns stdout. */
	for (i = 0; i < n; i++) {
		fprintf(stderr, "%-20s %s%s%s\n", res[i].name,
			res_str(res[i].result),
			res[i].message[0] ? " -- " : "", res[i].message);
		if (res[i].result == R_FAILED || res[i].result == R_UNREACHABLE)
			ret = 1;
	}

out:
	for (i = 0; i < n; i++)
		xstrfree(res[i].verifier_log);
	xfree(res, (size_t)(n_remotes ? n_remotes : 1) * sizeof(*res));
	shirudo_remotes_free(remotes, n_remotes);
	shirudo_selector_free(sel);
	return ret;
}
