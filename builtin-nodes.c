// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * shirudo nodes -- operator fleet observability. Iterates the
 * registered remote set (optionally filtered by name glob and/or a
 * label selector), runs `shirudo status --json --include-tpm` on each
 * over an SSH exec channel, and prints a drift table (human or --json).
 * Local-only registry; the only network is the per-node SSH.
 */

#include <errno.h>
#include <fnmatch.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "builtin.h"
#include "util/config.h"
#include "util/help.h"
#include "util/icmp.h"
#include "util/json.h"
#include "util/log.h"
#include "util/macros.h"
#include "util/similar.h"
#include "util/malloc.h"
#include "util/remotes.h"
#include "util/selector.h"
#include "util/ssh.h"
#include "util/sysinfo.h"
#include "util/timefmt.h"

#define SHOW_CMD \
	"shirudo status --json --include-tpm --include-system --include-eventlog"

/*
 * Compact PING column for the drift table: best-RTT in ms when OK,
 * a short status word otherwise. The per-node `shirudo nodes show`
 * stanza prints the full picture.
 */
static const char *ping_str(enum shirudo_icmp_status st, uint64_t rtt_us,
			    char *buf, size_t n)
{
	switch (st) {
	case SHIRUDO_ICMP_OK:
		snprintf(buf, n, "%.1fms", (double)rtt_us / 1000.0);
		return buf;
	case SHIRUDO_ICMP_TIMEOUT:
		return "blocked";
	case SHIRUDO_ICMP_NO_ROUTE:
		return "no-route";
	case SHIRUDO_ICMP_DNS_FAIL:
		return "dns?";
	case SHIRUDO_ICMP_NO_PRIVILEGE:
		return "n/a";
	case SHIRUDO_ICMP_ERROR:
	default:
		return "err";
	}
}

/* ---- shirudo nodes show <name>: per-node describe ----------------- */

static const struct shirudo_help_item nodes_subcmds[] = {
	{ "list", "drift table across registered remotes (default if omitted)" },
	{ "show", "kubectl-describe-style per-node deep dive: show [--json] <name>..." },
};

static const struct shirudo_help_item nodes_options[] = {
	{ "--json",            "machine-readable drift table" },
	{ "--filter=<glob>",   "filter remotes by name (shell-glob)" },
	{ "--selector=<expr>", "filter by label expression (k=v, !k, &&, ||, ...)" },
};

static const struct shirudo_help_section nodes_help_sections[] = {
	{ "subcommands:", nodes_subcmds,
	  ARRAY_SIZE(nodes_subcmds) },
	{ "options (drift-table form):", nodes_options,
	  ARRAY_SIZE(nodes_options) },
};

static const struct shirudo_help nodes_help = {
	.usage      = "shirudo nodes [list] [--json] [--filter=<glob>] [--selector=<expr>]\n"
		      "       shirudo nodes show [--json] <name>...",
	.summary    = "Operator-side fleet observability over registered "
		      "remotes. Bare\n`shirudo nodes` prints the drift table; "
		      "`shirudo nodes show <name>` runs a\nper-node deep dive.",
	.sections   = nodes_help_sections,
	.n_sections = ARRAY_SIZE(nodes_help_sections),
	.footer     =
"--filter=<glob> matches the registry name via shell-glob (fnmatch(3)):\n"
"  shirudo nodes --filter='prod-*'\n"
"  shirudo nodes --filter='*-edge-?\?'\n"
"  shirudo nodes --filter='db[0-9][0-9]'\n"
"\n"
"--selector=<expr> matches the remote's labels:\n"
"  atoms: k=v, k!=v, k (exists), !k (absent)\n"
"  combine with &&, ||, (), where && binds tighter than ||\n"
"  shirudo nodes --selector='env=production'\n"
"  shirudo nodes --selector='env=prod && tier=edge'\n"
"  shirudo nodes --selector=\"(role=db || role=cache) && env!=staging\"\n"
"\n"
"--filter and --selector may be combined; when both are given a remote\n"
"must satisfy both to be queried (intersection). An empty match set is\n"
"an error. Use `shirudo nodes show <name>` for a per-node deep dive.",
};


/* Projection of one eventlog event, parsed out of the fetched status. */
struct ev_row {
	char	ts[40];
	char	type[24];
	char	digest[65];
	char	set_digest[65];
	char	up_name[128];
	char	up_payload[65];
};

/*
 * Everything `nodes show` knows about one node: the operator-local
 * registry entry plus the fields parsed back from its `shirudo status`
 * over SSH. Nullable status fields carry a *_seen flag because JSON
 * null leaves the value untouched.
 */
struct node_detail {
	const struct shirudo_remote	*r;
	const char			*unreach;	/* set if !reachable */
	bool				reachable;
	bool				parsed;

	enum shirudo_icmp_status	icmp_status;
	uint64_t			icmp_rtt_us;
	char				resolved_ip[64];

	char		version_id[80];
	int		is_target, is_operator, lsm_attached;
	int		keyring_present, cert_present, signing_key_present;
	int64_t		keyring_serial, keyring_serial_pinned;
	int		keyring_serial_matches;
	int		ks_seen, ksp_seen, ksm_seen;

	char		up_scratch[128];
	char		(*upatches)[128];
	size_t		n_up, cap_up;

	struct shirudo_sysinfo	sys;

	char		nv_index[24];
	char		chain[80];
	int		chain_matches;
	int		chain_seen, cm_seen;
	int		ev_present;
	int64_t		ev_entries, ev_bytes;

	struct ev_row	ev_scratch;
	struct ev_row	*events;
	size_t		n_ev, cap_ev;
};

static int up_on_elem(void *ctx)
{
	struct node_detail *d = ctx;

	if (d->n_up == d->cap_up) {
		size_t nc = d->cap_up ? d->cap_up * 2 : 16;
		void *p = xreallocarray(d->upatches, d->cap_up, nc,
					sizeof(d->upatches[0]));

		if (!p)
			return -ENOMEM;
		d->upatches = p;
		d->cap_up = nc;
	}
	snprintf(d->upatches[d->n_up], sizeof(d->upatches[0]), "%s",
		 d->up_scratch);
	d->n_up++;
	return 0;
}

static int ev_on_elem(void *ctx)
{
	struct node_detail *d = ctx;

	if (d->n_ev == d->cap_ev) {
		size_t nc = d->cap_ev ? d->cap_ev * 2 : 16;
		void *p = xreallocarray(d->events, d->cap_ev, nc,
					sizeof(d->events[0]));

		if (!p)
			return -ENOMEM;
		d->events = p;
		d->cap_ev = nc;
	}
	d->events[d->n_ev++] = d->ev_scratch;
	d->ev_scratch = (struct ev_row){};	/* clear stale fields */
	return 0;
}

static void node_detail_free(struct node_detail *d)
{
	xfree(d->upatches, d->cap_up * sizeof(d->upatches[0]));
	xfree(d->events, d->cap_ev * sizeof(d->events[0]));
}

/* Parse one `shirudo status --json ...` document into *d. 0 / -errno. */
static int parse_node_detail(const char *out, size_t len,
			     struct node_detail *d)
{
	struct shirudo_json_array up_sink = { up_on_elem, d };
	struct shirudo_json_field up_elem[] = {
		{ "", SHIRUDO_JSON_T_STRING, d->up_scratch,
		  sizeof(d->up_scratch), 0, NULL, 0 },
	};
	struct shirudo_json_array ev_sink = { ev_on_elem, d };
	struct shirudo_json_field ev_upatch[] = {
		{ "name", SHIRUDO_JSON_T_STRING, d->ev_scratch.up_name,
		  sizeof(d->ev_scratch.up_name), 0, NULL, 0 },
		{ "payload_sha256", SHIRUDO_JSON_T_STRING,
		  d->ev_scratch.up_payload, sizeof(d->ev_scratch.up_payload),
		  0, NULL, 0 },
	};
	struct shirudo_json_field ev_elem[] = {
		{ "ts", SHIRUDO_JSON_T_STRING, d->ev_scratch.ts,
		  sizeof(d->ev_scratch.ts), 0, NULL, 0 },
		{ "type", SHIRUDO_JSON_T_STRING, d->ev_scratch.type,
		  sizeof(d->ev_scratch.type), 0, NULL, 0 },
		{ "digest", SHIRUDO_JSON_T_STRING, d->ev_scratch.digest,
		  sizeof(d->ev_scratch.digest), 0, NULL, 0 },
		{ "set_digest", SHIRUDO_JSON_T_STRING, d->ev_scratch.set_digest,
		  sizeof(d->ev_scratch.set_digest), 0, NULL, 0 },
		{ "upatch", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, ev_upatch, 2 },
	};
	struct shirudo_json_field el_sub[] = {
		{ "present", SHIRUDO_JSON_T_BOOL, &d->ev_present, 0, 0,
		  NULL, 0 },
		{ "entries", SHIRUDO_JSON_T_INT, &d->ev_entries, 0, 0,
		  NULL, 0 },
		{ "bytes", SHIRUDO_JSON_T_INT, &d->ev_bytes, 0, 0, NULL, 0 },
		{ "events", SHIRUDO_JSON_T_ARRAY, &ev_sink, 0, 0, ev_elem, 5 },
	};
	struct shirudo_json_field tpm_sub[] = {
		{ "nv_index", SHIRUDO_JSON_T_STRING, d->nv_index,
		  sizeof(d->nv_index), 0, NULL, 0 },
		{ "chain", SHIRUDO_JSON_T_STRING, d->chain, sizeof(d->chain),
		  0, NULL, 0 },
		{ "chain_matches_eventlog", SHIRUDO_JSON_T_BOOL,
		  &d->chain_matches, 0, 0, NULL, 0 },
		{ "eventlog", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, el_sub, 4 },
	};
	struct shirudo_json_field sys_sub[] = {
		{ "hostname", SHIRUDO_JSON_T_STRING, d->sys.hostname,
		  sizeof(d->sys.hostname), 0, NULL, 0 },
		{ "os", SHIRUDO_JSON_T_STRING, d->sys.os_pretty,
		  sizeof(d->sys.os_pretty), 0, NULL, 0 },
		{ "kernel_release", SHIRUDO_JSON_T_STRING, d->sys.kernel_release,
		  sizeof(d->sys.kernel_release), 0, NULL, 0 },
		{ "kernel_version", SHIRUDO_JSON_T_STRING, d->sys.kernel_version,
		  sizeof(d->sys.kernel_version), 0, NULL, 0 },
		{ "architecture", SHIRUDO_JSON_T_STRING, d->sys.machine,
		  sizeof(d->sys.machine), 0, NULL, 0 },
		{ "machine_id", SHIRUDO_JSON_T_STRING, d->sys.machine_id,
		  sizeof(d->sys.machine_id), 0, NULL, 0 },
		{ "boot_id", SHIRUDO_JSON_T_STRING, d->sys.boot_id,
		  sizeof(d->sys.boot_id), 0, NULL, 0 },
		/* int64_t == long on LP64 (shirudo's only ABIs). */
		{ "nproc", SHIRUDO_JSON_T_INT, &d->sys.nproc, 0, 0, NULL, 0 },
		{ "mem_total_kb", SHIRUDO_JSON_T_INT, &d->sys.mem_total_kb,
		  0, 0, NULL, 0 },
		{ "uptime_seconds", SHIRUDO_JSON_T_INT, &d->sys.uptime_sec,
		  0, 0, NULL, 0 },
	};
	struct shirudo_json_field top[] = {
		{ "version_id", SHIRUDO_JSON_T_STRING, d->version_id,
		  sizeof(d->version_id), 0, NULL, 0 },
		{ "is_target", SHIRUDO_JSON_T_BOOL, &d->is_target, 0, 0,
		  NULL, 0 },
		{ "is_operator", SHIRUDO_JSON_T_BOOL, &d->is_operator, 0, 0,
		  NULL, 0 },
		{ "lsm_attached", SHIRUDO_JSON_T_BOOL, &d->lsm_attached, 0, 0,
		  NULL, 0 },
		{ "keyring_present", SHIRUDO_JSON_T_BOOL, &d->keyring_present,
		  0, 0, NULL, 0 },
		{ "keyring_serial", SHIRUDO_JSON_T_INT, &d->keyring_serial,
		  0, 0, NULL, 0 },
		{ "keyring_serial_pinned", SHIRUDO_JSON_T_INT,
		  &d->keyring_serial_pinned, 0, 0, NULL, 0 },
		{ "keyring_serial_matches", SHIRUDO_JSON_T_BOOL,
		  &d->keyring_serial_matches, 0, 0, NULL, 0 },
		{ "cert_present", SHIRUDO_JSON_T_BOOL, &d->cert_present, 0, 0,
		  NULL, 0 },
		{ "signing_key_present", SHIRUDO_JSON_T_BOOL,
		  &d->signing_key_present, 0, 0, NULL, 0 },
		{ "upatches_loaded", SHIRUDO_JSON_T_ARRAY, &up_sink, 0, 0,
		  up_elem, 1 },
		{ "system", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, sys_sub, 10 },
		{ "tpm", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, tpm_sub, 4 },
	};
	int rc;

	rc = shirudo_json_parse(out, len, top, ARRAY_SIZE(top));
	if (rc)
		return rc;
	d->ks_seen = top[5].seen;
	d->ksp_seen = top[6].seen;
	d->ksm_seen = top[7].seen;
	d->chain_seen = tpm_sub[1].seen;
	d->cm_seen = tpm_sub[2].seen;
	return 0;
}

static void fetch_node(const struct shirudo_remote *r,
		       const struct shirudo_config *cfg,
		       struct node_detail *d)
{
	struct shirudo_ssh_session *sess;
	char *out = NULL;
	size_t len = 0;
	int rc;

	d->r = r;
	d->icmp_status = shirudo_icmp_ping(r->host,
					   cfg->nodes_icmp_timeout_ms,
					   cfg->nodes_icmp_probes,
					   &d->icmp_rtt_us,
					   d->resolved_ip,
					   sizeof(d->resolved_ip));
	sess = shirudo_ssh_connect(r->user, r->host, r->port);
	if (!sess) {
		d->unreach = "ssh connect failed";
		return;
	}
	rc = shirudo_ssh_exec(sess, SHOW_CMD, &out, &len);
	shirudo_ssh_close(sess);
	if (rc < 0 || !out) {
		xfree(out, len);
		d->unreach = "status exec failed";
		return;
	}
	d->reachable = true;
	if (parse_node_detail(out, len, d) == 0)
		d->parsed = true;
	else
		d->unreach = "status JSON unparseable";
	xfree(out, len);
}

struct cond {
	const char	*type;
	const char	*status;
	char		detail[192];
};

/* Derive the security-operator health conditions from a parsed node. */
static size_t compute_conditions(const struct node_detail *d,
				 struct cond *c, size_t max)
{
	size_t n = 0;

	if (n < max) {
		c[n].type = "LsmAttached";
		c[n].status = d->lsm_attached ? "OK" : "ALERT";
		snprintf(c[n].detail, sizeof(c[n].detail), "%s",
			 d->lsm_attached ? "lsm/bpf link present and pinned"
					 : "lsm/bpf absent -- enforcement OFF");
		n++;
	}
	if (n < max) {
		c[n].type = "KeyringSealed";
		if (!d->keyring_present) {
			c[n].status = "WARN";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "shirudo keyring absent (not init'd?)");
		} else if (d->ksm_seen && !d->keyring_serial_matches) {
			c[n].status = "ALERT";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "pin serial=%lld != live serial=%lld (swapped?)",
				 (long long)d->keyring_serial_pinned,
				 (long long)d->keyring_serial);
		} else {
			c[n].status = "OK";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "serial=%lld, %s", (long long)d->keyring_serial,
				 d->ksp_seen ? "pin matches"
					     : "no pin recorded");
		}
		n++;
	}
	if (n < max) {
		c[n].type = "ChainIntact";
		if (!d->chain_seen) {
			c[n].status = "WARN";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "no TPM chain (degraded / --no-tpm)");
		} else if (d->cm_seen && d->chain_matches) {
			c[n].status = "OK";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "live NV chain == eventlog replay");
		} else if (d->cm_seen) {
			c[n].status = "ALERT";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "live NV chain != eventlog replay (tamper?)");
		} else {
			c[n].status = "WARN";
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "chain present, replay not evaluated");
		}
		n++;
	}
	if (n < max) {
		c[n].type = "TpmMeasured";
		c[n].status = d->chain_seen ? "OK" : "WARN";
		if (d->chain_seen)
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "NV index %s readable", d->nv_index);
		else
			snprintf(c[n].detail, sizeof(c[n].detail),
				 "not measured");
		n++;
	}
	return n;
}

static const char *role_str(const struct node_detail *d)
{
	if (d->is_target && d->is_operator)
		return "target,operator";
	if (d->is_operator)
		return "operator";
	if (d->is_target)
		return "target";
	return "unknown";
}

static void ev_detail(const struct ev_row *ev, char *out, size_t cap)
{
	if (ev->up_name[0])
		snprintf(out, cap, "%s payload=%.12s..", ev->up_name,
			 ev->up_payload);
	else if (ev->set_digest[0])
		snprintf(out, cap, "set_digest=%.12s..", ev->set_digest);
	else
		out[0] = '\0';
}

/* Most recent upatch_load event for <name>, or NULL. */
static const struct ev_row *last_load_event_for(const struct node_detail *d,
						const char *name)
{
	size_t i = d->n_ev;

	while (i--) {
		const struct ev_row *e = &d->events[i];

		if (strcmp(e->type, "upatch_load") == 0 &&
		    strcmp(e->up_name, name) == 0)
			return e;
	}
	return NULL;
}

/*
 * Most recent upatch_load OR upatch_unload event on this node, or
 * NULL if none. Eventlog is appended chronologically, so iterating
 * backwards yields most-recent-first.
 */
static const struct ev_row *last_upatch_event(const struct node_detail *d)
{
	size_t i = d->n_ev;

	while (i--) {
		const struct ev_row *e = &d->events[i];

		if (strcmp(e->type, "upatch_load") == 0 ||
		    strcmp(e->type, "upatch_unload") == 0)
			return e;
	}
	return NULL;
}

/*
 * Aggregate "health" verdict for the STATUS column / Status: line.
 * Severity order (worst -> best) so a single label tells operators
 * what to look at; the full Conditions block gives the breakdown.
 */
static const char *status_str(const struct node_detail *d)
{
	if (!d->r)
		return "?";
	if (!d->reachable)
		return "unreachable";
	if (!d->parsed)
		return "unparseable";
	if ((d->cm_seen && !d->chain_matches) ||
	    (d->ksm_seen && !d->keyring_serial_matches))
		return "tampered";
	if (!d->lsm_attached)
		return "lsm-off";
	if (!d->keyring_present)
		return "init-pending";
	if (!d->chain_seen)
		return "degraded";
	return "ok";
}

/*
 * Short parenthetical reason (without parens) for the non-ok statuses,
 * surfaced inline on the `nodes show` Status: line. Empty when status
 * is ok (no extra noise) or unreachable (the SSH error already says
 * what happened).
 */
static void status_reason(const struct node_detail *d, char *buf, size_t cap)
{
	const char *s = status_str(d);

	buf[0] = '\0';
	if (strcmp(s, "unreachable") == 0) {
		if (d->unreach)
			snprintf(buf, cap, "%s", d->unreach);
	} else if (strcmp(s, "unparseable") == 0) {
		snprintf(buf, cap, "status JSON unparseable");
	} else if (strcmp(s, "tampered") == 0) {
		if (d->cm_seen && !d->chain_matches)
			snprintf(buf, cap, "live NV chain != eventlog replay");
		else
			snprintf(buf, cap, "keyring serial swap detected");
	} else if (strcmp(s, "lsm-off") == 0) {
		snprintf(buf, cap, "LSM not attached -- enforcement OFF");
	} else if (strcmp(s, "init-pending") == 0) {
		snprintf(buf, cap, "target hasn't been `shirudo init`'d");
	} else if (strcmp(s, "degraded") == 0) {
		snprintf(buf, cap, "no TPM chain (unmeasured)");
	}
}

/*
 * Fleet-table UPATCHES cell: live-loaded count, plus the verb / name /
 * age of the most recent upatch_load or upatch_unload event. The verb
 * matters -- "2 (unload:old-x, 3d)" means "2 currently loaded, last
 * change was unloading old-x 3 days ago," which reads differently from
 * "2 (load:cve-..., 3d)".
 */
static void upatches_summary(const struct node_detail *d, char *buf, size_t cap)
{
	const struct ev_row *last = last_upatch_event(d);
	const char *verb;
	char age[16] = "?";
	char nm[20];

	if (!last) {
		snprintf(buf, cap, "%zu", d->n_up);
		return;
	}
	{
		struct tm tm = {};

		if (strptime(last->ts, "%Y-%m-%dT%H:%M:%SZ", &tm))
			shirudo_format_duration(
				(long)(time(NULL) - timegm(&tm)),
				age, sizeof(age));
	}
	verb = strcmp(last->type, "upatch_unload") == 0 ? "unload" : "load";
	if (strlen(last->up_name) > 14)
		snprintf(nm, sizeof(nm), "%.14s..", last->up_name);
	else
		snprintf(nm, sizeof(nm), "%s", last->up_name);
	snprintf(buf, cap, "%zu (%s:%s, %s)", d->n_up, verb, nm, age);
}

/* kubectl-describe-style report for one node. */
static void print_describe(const struct node_detail *d)
{
	const struct shirudo_remote *r = d->r;
	struct cond conds[4];
	char endpoint[320];
	size_t nl, nc, i;

	shirudo_remote_endpoint(r, endpoint, sizeof(endpoint));

	printf("Name:              %s\n", r->name);
	printf("Endpoint:          %s\n", endpoint);
	{
		char reason[160];
		const char *s = status_str(d);

		status_reason(d, reason, sizeof(reason));
		if (d->reachable && d->parsed) {
			printf("Role:              %s\n", role_str(d));
			printf("Reachable:         yes\n");
			if (reason[0])
				printf("Status:            %s  (%s)\n",
				       s, reason);
			else
				printf("Status:            %s\n", s);
			printf("Version-ID:        %s\n", d->version_id);
		} else {
			printf("Role:              target (registered)\n");
			printf("Reachable:         %s\n",
			       d->reachable ? "yes (status JSON unparseable)"
					    : "NO");
			if (reason[0])
				printf("Status:            %s  (%s)\n",
				       s, reason);
			else
				printf("Status:            %s\n", s);
		}
	}

	nl = shirudo_labels_count(r->labels);
	printf("Labels:            ");
	if (!nl)
		printf("<none>\n");
	for (i = 0; i < nl; i++) {
		const char *k, *v;

		shirudo_labels_at(r->labels, i, &k, &v);
		printf("%s%s=%s\n", i ? "                   " : "", k, v);
	}

	printf("\nReachability:\n");
	printf("  %-14s %s\n", "Endpoint:", endpoint);
	if (d->resolved_ip[0])
		printf("  %-14s %s\n", "Resolved IP:", d->resolved_ip);
	switch (d->icmp_status) {
	case SHIRUDO_ICMP_OK:
		printf("  %-14s yes  (%.1f ms)\n", "ICMP:",
		       (double)d->icmp_rtt_us / 1000.0);
		break;
	case SHIRUDO_ICMP_TIMEOUT:
		printf("  %-14s no   (no reply within budget; firewall?)\n",
		       "ICMP:");
		break;
	case SHIRUDO_ICMP_NO_ROUTE:
		printf("  %-14s no   (no route to host)\n", "ICMP:");
		break;
	case SHIRUDO_ICMP_DNS_FAIL:
		printf("  %-14s n/a  (DNS resolution failed)\n", "ICMP:");
		break;
	case SHIRUDO_ICMP_NO_PRIVILEGE:
		printf("  %-14s n/a  (operator gid not in "
		       "net.ipv4.ping_group_range)\n", "ICMP:");
		break;
	case SHIRUDO_ICMP_ERROR:
	default:
		printf("  %-14s err\n", "ICMP:");
		break;
	}
	if (d->reachable && d->parsed)
		printf("  %-14s yes  (status JSON parsed)\n", "SSH:");
	else if (d->reachable)
		printf("  %-14s yes  (status JSON unparseable)\n", "SSH:");
	else
		printf("  %-14s no   (%s)\n", "SSH:",
		       d->unreach ? d->unreach : "unreachable");

	if (!d->reachable || !d->parsed) {
		printf("\n");
		return;
	}

	nc = compute_conditions(d, conds, 4);
	printf("\nConditions:\n");
	printf("  %-16s %-7s %s\n", "TYPE", "STATUS", "DETAIL");
	for (i = 0; i < nc; i++)
		printf("  %-16s %-7s %s\n", conds[i].type, conds[i].status,
		       conds[i].detail);

	printf("\nAddresses:\n");
	printf("  %-12s %s\n", "Endpoint:", endpoint);
	if (d->sys.hostname[0])
		printf("  %-12s %s\n", "Hostname:", d->sys.hostname);

	printf("\nSystem Info:\n");
	printf("  %-16s %s\n", "OS:", d->sys.os_pretty);
	printf("  %-16s %s\n", "Kernel:", d->sys.kernel_release);
	if (d->sys.kernel_version[0])
		printf("  %-16s %s\n", "Kernel Version:", d->sys.kernel_version);
	printf("  %-16s %s\n", "Architecture:", d->sys.machine);
	if (d->sys.nproc > 0)
		printf("  %-16s %ld\n", "CPUs:", d->sys.nproc);
	if (d->sys.mem_total_kb > 0)
		printf("  %-16s %ld kB\n", "Memory:", d->sys.mem_total_kb);
	if (d->sys.uptime_sec >= 0)
		printf("  %-16s %ldd %ldh %ldm\n", "Uptime:",
		       d->sys.uptime_sec / 86400,
		       (d->sys.uptime_sec % 86400) / 3600,
		       (d->sys.uptime_sec % 3600) / 60);
	if (d->sys.machine_id[0])
		printf("  %-16s %s\n", "Machine ID:", d->sys.machine_id);
	if (d->sys.boot_id[0])
		printf("  %-16s %s\n", "Boot ID:", d->sys.boot_id);

	printf("\nUpatches loaded (%zu):\n", d->n_up);
	if (d->n_up) {
		printf("  %-30s %-18s %s\n", "NAME", "PAYLOAD-SHA256",
		       "APPLIED");
		for (i = 0; i < d->n_up; i++) {
			const struct ev_row *ev =
				last_load_event_for(d, d->upatches[i]);
			char age[16] = "?";
			char pay[20];

			if (ev) {
				struct tm tm = {};

				snprintf(pay, sizeof(pay), "%.16s..",
					 ev->up_payload);
				if (strptime(ev->ts, "%Y-%m-%dT%H:%M:%SZ",
					     &tm))
					shirudo_format_duration(
						(long)(time(NULL) -
						       timegm(&tm)),
						age, sizeof(age));
			} else {
				snprintf(pay, sizeof(pay), "-");
			}
			printf("  %-30s %-18s %s\n", d->upatches[i], pay, age);
		}
	}

	printf("\nTPM Measurement:\n");
	printf("  %-18s %s\n", "NV index:",
	       d->nv_index[0] ? d->nv_index : "-");
	printf("  %-18s %s\n", "Chain:",
	       d->chain_seen ? d->chain : "unavailable (no TPM)");
	printf("  %-18s %s\n", "Chain vs eventlog:",
	       !d->cm_seen ? "n/a" :
	       d->chain_matches ? "matches" : "MISMATCH (tamper?)");
	if (d->ev_present)
		printf("  %-18s %lld entries, %lld bytes\n", "Eventlog:",
		       (long long)d->ev_entries, (long long)d->ev_bytes);
	else
		printf("  %-18s %s\n", "Eventlog:", "absent");

	if (d->n_ev) {
		printf("\nEventlog (audit trail):\n");
		printf("  %-20s %-13s %-13s %s\n", "TIME", "TYPE", "DIGEST",
		       "DETAIL");
		for (i = 0; i < d->n_ev; i++) {
			char detail[192];

			ev_detail(&d->events[i], detail, sizeof(detail));
			printf("  %-20s %-13s %-13.12s %s\n", d->events[i].ts,
			       d->events[i].type,
			       d->events[i].digest[0] ? d->events[i].digest
						      : "-", detail);
		}
	}
	printf("\n");
}

static void emit_node_json(struct shirudo_json_emit *e,
			   const struct node_detail *d)
{
	char endpoint[320];
	size_t nl, i;

	shirudo_remote_endpoint(d->r, endpoint, sizeof(endpoint));
	shirudo_json_obj_open(e);
	shirudo_json_kv_string(e, "name", d->r->name);
	shirudo_json_kv_string(e, "endpoint", endpoint);
	shirudo_json_kv_bool(e, "reachable", d->reachable);
	shirudo_json_kv_string(e, "status", status_str(d));
	if (!d->reachable || !d->parsed)
		shirudo_json_kv_string(e, "error",
				       d->unreach ? d->unreach
						  : "status JSON unparseable");
	shirudo_json_obj_open_key(e, "reachability");
	if (d->resolved_ip[0])
		shirudo_json_kv_string(e, "resolved_ip", d->resolved_ip);
	else
		shirudo_json_kv_null(e, "resolved_ip");
	shirudo_json_obj_open_key(e, "icmp");
	shirudo_json_kv_bool(e, "ok",
			     d->icmp_status == SHIRUDO_ICMP_OK);
	if (d->icmp_status == SHIRUDO_ICMP_OK)
		shirudo_json_kv_int(e, "rtt_us", (int64_t)d->icmp_rtt_us);
	else
		shirudo_json_kv_null(e, "rtt_us");
	shirudo_json_obj_close(e);	/* icmp */
	shirudo_json_obj_open_key(e, "ssh");
	shirudo_json_kv_bool(e, "ok", d->reachable);
	shirudo_json_kv_bool(e, "status_parsed", d->parsed);
	shirudo_json_obj_close(e);	/* ssh */
	shirudo_json_obj_close(e);	/* reachability */
	shirudo_json_obj_open_key(e, "labels");
	nl = shirudo_labels_count(d->r->labels);
	for (i = 0; i < nl; i++) {
		const char *k, *v;

		shirudo_labels_at(d->r->labels, i, &k, &v);
		shirudo_json_kv_string(e, k, v);
	}
	shirudo_json_obj_close(e);

	if (d->reachable && d->parsed) {
		struct cond conds[4];
		size_t nc = compute_conditions(d, conds, 4);

		shirudo_json_kv_string(e, "role", role_str(d));
		shirudo_json_arr_open(e, "conditions");
		for (i = 0; i < nc; i++) {
			shirudo_json_obj_open(e);
			shirudo_json_kv_string(e, "type", conds[i].type);
			shirudo_json_kv_string(e, "status", conds[i].status);
			shirudo_json_kv_string(e, "detail", conds[i].detail);
			shirudo_json_obj_close(e);
		}
		shirudo_json_arr_close(e);

		/*
		 * Full parsed status report from the target. The top-level
		 * "status" key (above) holds the aggregate verdict; this
		 * "report" object holds the raw fields the verdict derives
		 * from -- conditions, version-id, keyring/tpm details, etc.
		 */
		shirudo_json_obj_open_key(e, "report");
		shirudo_json_kv_string(e, "version_id", d->version_id);
		shirudo_json_kv_bool(e, "is_target", d->is_target);
		shirudo_json_kv_bool(e, "is_operator", d->is_operator);
		shirudo_json_kv_bool(e, "lsm_attached", d->lsm_attached);
		shirudo_json_kv_bool(e, "keyring_present", d->keyring_present);
		if (d->ks_seen)
			shirudo_json_kv_int(e, "keyring_serial",
					    d->keyring_serial);
		else
			shirudo_json_kv_null(e, "keyring_serial");
		if (d->ksp_seen)
			shirudo_json_kv_int(e, "keyring_serial_pinned",
					    d->keyring_serial_pinned);
		else
			shirudo_json_kv_null(e, "keyring_serial_pinned");
		if (d->ksm_seen)
			shirudo_json_kv_bool(e, "keyring_serial_matches",
					     d->keyring_serial_matches);
		else
			shirudo_json_kv_null(e, "keyring_serial_matches");
		shirudo_json_kv_bool(e, "cert_present", d->cert_present);
		shirudo_json_kv_bool(e, "signing_key_present",
				     d->signing_key_present);
		shirudo_json_arr_open(e, "upatches_loaded");
		for (i = 0; i < d->n_up; i++) {
			const struct ev_row *ev =
				last_load_event_for(d, d->upatches[i]);

			shirudo_json_obj_open(e);
			shirudo_json_kv_string(e, "name", d->upatches[i]);
			if (ev) {
				shirudo_json_kv_string(e, "payload_sha256",
						       ev->up_payload);
				shirudo_json_kv_string(e, "applied_ts",
						       ev->ts);
			} else {
				shirudo_json_kv_null(e, "payload_sha256");
				shirudo_json_kv_null(e, "applied_ts");
			}
			shirudo_json_obj_close(e);
		}
		shirudo_json_arr_close(e);
		shirudo_sysinfo_emit_json(e, &d->sys);
		shirudo_json_obj_open_key(e, "tpm");
		shirudo_json_kv_string(e, "nv_index", d->nv_index);
		if (d->chain_seen)
			shirudo_json_kv_string(e, "chain", d->chain);
		else
			shirudo_json_kv_null(e, "chain");
		if (d->cm_seen)
			shirudo_json_kv_bool(e, "chain_matches_eventlog",
					     d->chain_matches);
		else
			shirudo_json_kv_null(e, "chain_matches_eventlog");
		shirudo_json_obj_open_key(e, "eventlog");
		shirudo_json_kv_bool(e, "present", d->ev_present);
		shirudo_json_kv_int(e, "entries", d->ev_entries);
		shirudo_json_kv_int(e, "bytes", d->ev_bytes);
		shirudo_json_arr_open(e, "events");
		for (i = 0; i < d->n_ev; i++) {
			const struct ev_row *ev = &d->events[i];

			shirudo_json_obj_open(e);
			shirudo_json_kv_string(e, "ts", ev->ts);
			shirudo_json_kv_string(e, "type", ev->type);
			shirudo_json_kv_string(e, "digest", ev->digest);
			if (ev->set_digest[0])
				shirudo_json_kv_string(e, "set_digest",
						       ev->set_digest);
			if (ev->up_name[0]) {
				shirudo_json_obj_open_key(e, "upatch");
				shirudo_json_kv_string(e, "name", ev->up_name);
				shirudo_json_kv_string(e, "payload_sha256",
						       ev->up_payload);
				shirudo_json_obj_close(e);
			}
			shirudo_json_obj_close(e);
		}
		shirudo_json_arr_close(e);
		shirudo_json_obj_close(e);	/* eventlog */
		shirudo_json_obj_close(e);	/* tpm */
		shirudo_json_obj_close(e);	/* status */
	}
	shirudo_json_obj_close(e);		/* node */
}

static int cmd_nodes_show(int argc, const char **argv)
{
	struct shirudo_remote *remotes = NULL;
	struct node_detail *nodes = NULL;
	const char *names[256];
	size_t n_remotes = 0, nnames = 0, i, j;
	bool json = false;
	int ret = 0;

	/* argv[0]="nodes", argv[1]="show"; options/names follow. */
	for (i = 2; i < (size_t)argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--json") == 0) {
			json = true;
		} else if (shirudo_is_help(a)) {
			shirudo_print_help(&nodes_help);
			return 0;
		} else if (a[0] == '-') {
			fprintf(stderr, "nodes show: unknown option '%s'\n", a);
			return 2;
		} else if (nnames < ARRAY_SIZE(names)) {
			names[nnames++] = a;
		} else {
			fprintf(stderr, "nodes show: too many names\n");
			return 2;
		}
	}
	if (nnames == 0) {
		fprintf(stderr, "usage: shirudo nodes show [--json] <name>...\n");
		return 2;
	}

	shirudo_remotes_load_all(&remotes, &n_remotes);
	if (n_remotes == 0) {
		pr_err("nodes show: no remotes registered (see remotes.d)");
		return 1;
	}

	{
		struct shirudo_config cfg;

		shirudo_config_load(&cfg);
		nodes = xcalloc(nnames, sizeof(*nodes));
		if (!nodes) {
			shirudo_remotes_free(remotes, n_remotes);
			return 1;
		}
		for (j = 0; j < nnames; j++) {
			const struct shirudo_remote *r = NULL;

			for (i = 0; i < n_remotes; i++)
				if (strcmp(remotes[i].name,
					   names[j]) == 0) {
					r = &remotes[i];
					break;
				}
			if (!r) {
				pr_err("nodes show: '%s' is not a "
				       "registered remote", names[j]);
				ret = 1;
				continue;	/* skipped: r stays NULL */
			}
			fetch_node(r, &cfg, &nodes[j]);
		}
	}

	if (json) {
		struct shirudo_json_emit e;
		size_t cap = 65536;
		char *buf;

		for (j = 0; j < nnames; j++)
			if (nodes[j].r)
				cap += 8192 + 3 * (size_t)nodes[j].ev_bytes;
		if (cap > SHIRUDO_JSON_MAX_BYTES)
			cap = SHIRUDO_JSON_MAX_BYTES;
		buf = xmalloc(cap);
		if (!buf) {
			ret = 1;
			goto done;
		}
		e = (struct shirudo_json_emit){ .buf = buf, .cap = cap };
		shirudo_json_obj_open(&e);
		shirudo_json_kv_int(&e, "schema", 1);
		shirudo_json_arr_open(&e, "nodes");
		for (j = 0; j < nnames; j++)
			if (nodes[j].r)
				emit_node_json(&e, &nodes[j]);
		shirudo_json_arr_close(&e);
		shirudo_json_obj_close(&e);
		if (e.err) {
			pr_err("nodes show: json encode failed: %s",
			       strerror(-e.err));
			ret = 1;
		} else {
			printf("%s\n", buf);
		}
		xfree(buf, cap);
	} else {
		for (j = 0; j < nnames; j++)
			if (nodes[j].r)
				print_describe(&nodes[j]);
	}

done:
	for (j = 0; j < nnames; j++)
		node_detail_free(&nodes[j]);
	xfree(nodes, nnames * sizeof(*nodes));
	shirudo_remotes_free(remotes, n_remotes);
	return ret;
}

int cmd_nodes(int argc, const char **argv)
{
	if (argc >= 2 && shirudo_is_help(argv[1])) {
		shirudo_print_help(&nodes_help);
		return 0;
	}
	/*
	 * Resolve a non-flag argv[1] against the sub-sub list. `show`
	 * branches off; `list` is just the drift-table form (skip the
	 * verb). An unrecognised non-flag argv[1] errors out with a
	 * "Did you mean: show / list" diagnostic -- there's no longer a
	 * `nodes <name>` positional form (use `nodes show <name>` for a
	 * per-node deep dive, --filter/--selector for the table).
	 */
	if (argc >= 2 && argv[1][0] != '-') {
		const char *canonical = shirudo_resolve_subcommand(
			"shirudo nodes", argv[1], nodes_subcmds,
			ARRAY_SIZE(nodes_subcmds));

		if (!canonical)
			return 2;
		if (strcmp(canonical, "show") == 0)
			return cmd_nodes_show(argc, argv);
		/* canonical == "list" */
		argc--;
		argv++;
	}

	const char *filter = NULL, *selexpr = NULL;
	struct shirudo_remote *remotes = NULL;
	struct shirudo_selector *sel = NULL;
	struct node_detail *nodes = NULL;
	size_t n_remotes = 0, n = 0, i;
	bool json = false;
	int ret = 0;

	for (i = 1; i < (size_t)argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--json") == 0)
			json = true;
		else if (strncmp(a, "--filter=", 9) == 0)
			filter = a + 9;
		else if (strncmp(a, "--selector=", 11) == 0)
			selexpr = a + 11;
		else if (shirudo_is_help(a)) {
			shirudo_print_help(&nodes_help);
			return 0;
		} else {
			/*
			 * Bare positional names are no longer accepted for
			 * the drift table -- use `shirudo nodes show <name>`
			 * for a per-node view, or --filter / --selector to
			 * narrow the table.
			 */
			fprintf(stderr, "nodes: unexpected argument '%s' "
				"(use `shirudo nodes show <name>` or "
				"--filter/--selector)\n", a);
			return 2;
		}
	}

	struct shirudo_config cfg;

	shirudo_config_load(&cfg);

	if (selexpr) {
		sel = shirudo_selector_parse(selexpr);
		if (!sel) {
			pr_err("nodes: invalid --selector expression");
			return 2;
		}
	}

	shirudo_remotes_load_all(&remotes, &n_remotes);
	if (n_remotes == 0) {
		pr_err("nodes: no remotes registered (see remotes.d)");
		shirudo_selector_free(sel);
		return 1;
	}

	nodes = xcalloc(n_remotes, sizeof(*nodes));
	if (!nodes) {
		shirudo_remotes_free(remotes, n_remotes);
		shirudo_selector_free(sel);
		return 1;
	}

	/*
	 * Select. --filter and --selector intersect when both are given;
	 * with neither, the table covers every registered remote.
	 */
	for (i = 0; i < n_remotes; i++) {
		if (filter && fnmatch(filter, remotes[i].name, 0) != 0)
			continue;
		if (sel && !shirudo_selector_match(sel, remotes[i].labels))
			continue;
		fetch_node(&remotes[i], &cfg, &nodes[n]);
		n++;
	}

	if (n == 0) {
		pr_err("nodes: --filter/--selector matched zero "
		       "registered remotes");
		ret = 1;
		goto out;
	}

	if (json) {
		/*
		 * Size by total events + slack so even a fleet with long
		 * eventlogs fits without reallocs. Heap-allocated because a
		 * static 64 KiB buffer would be undersized for a hundred
		 * nodes with non-trivial event histories.
		 */
		size_t cap = 65536;
		struct shirudo_json_emit e;
		char *buf;

		for (i = 0; i < n; i++)
			cap += 4096 + 3 * (size_t)nodes[i].ev_bytes;
		if (cap > SHIRUDO_JSON_MAX_BYTES)
			cap = SHIRUDO_JSON_MAX_BYTES;
		buf = xmalloc(cap);
		if (!buf) {
			ret = 1;
			goto out;
		}
		e = (struct shirudo_json_emit){ .buf = buf, .cap = cap };
		shirudo_json_obj_open(&e);
		shirudo_json_kv_int(&e, "schema", 1);
		shirudo_json_arr_open(&e, "nodes");
		for (i = 0; i < n; i++) {
			struct node_detail *s = &nodes[i];
			const struct ev_row *last = last_upatch_event(s);

			shirudo_json_obj_open(&e);
			shirudo_json_kv_string(&e, "name", s->r->name);
			shirudo_json_kv_bool(&e, "reachable", s->reachable);
			shirudo_json_obj_open_key(&e, "icmp");
			shirudo_json_kv_bool(&e, "ok",
				s->icmp_status == SHIRUDO_ICMP_OK);
			if (s->icmp_status == SHIRUDO_ICMP_OK)
				shirudo_json_kv_int(&e, "rtt_us",
					(int64_t)s->icmp_rtt_us);
			else
				shirudo_json_kv_null(&e, "rtt_us");
			shirudo_json_obj_close(&e);
			shirudo_json_kv_string(&e, "status", status_str(s));
			if (s->reachable && s->parsed) {
				shirudo_json_kv_int(&e, "uptime_seconds",
					(int64_t)s->sys.uptime_sec);
				shirudo_json_kv_bool(&e, "lsm_attached",
					s->lsm_attached);
				shirudo_json_kv_string(&e, "version_id",
					s->version_id);
				if (s->chain_seen)
					shirudo_json_kv_string(&e, "chain",
						s->chain);
				else
					shirudo_json_kv_null(&e, "chain");
				if (s->cm_seen)
					shirudo_json_kv_bool(&e,
						"chain_matches_eventlog",
						s->chain_matches);
				else
					shirudo_json_kv_null(&e,
						"chain_matches_eventlog");
				shirudo_json_obj_open_key(&e, "upatches");
				shirudo_json_kv_int(&e, "count",
					(int64_t)s->n_up);
				if (last) {
					shirudo_json_obj_open_key(&e, "last");
					shirudo_json_kv_string(&e, "verb",
						strcmp(last->type,
						       "upatch_unload") == 0
						? "unload" : "load");
					shirudo_json_kv_string(&e, "name",
						last->up_name);
					shirudo_json_kv_string(&e, "ts",
						last->ts);
					shirudo_json_obj_close(&e);
				} else {
					shirudo_json_kv_null(&e, "last");
				}
				shirudo_json_obj_close(&e);
			}
			shirudo_json_obj_close(&e);
		}
		shirudo_json_arr_close(&e);
		shirudo_json_obj_close(&e);
		if (e.err) {
			pr_err("nodes: json encode failed: %s",
			       strerror(-e.err));
			ret = 1;
		} else {
			printf("%s\n", buf);
		}
		xfree(buf, cap);
	} else {
		printf("%-20s %-9s %-4s %-13s %-7s %s\n",
		       "NODE", "PING", "SSH", "STATUS", "UPTIME", "UPATCHES (LAST)");
		for (i = 0; i < n; i++) {
			struct node_detail *s = &nodes[i];
			char pb[16], up[64], ut[16];

			if (s->reachable && s->parsed) {
				shirudo_format_duration(
					(long)s->sys.uptime_sec,
					ut, sizeof(ut));
				upatches_summary(s, up, sizeof(up));
			} else {
				snprintf(ut, sizeof(ut), "-");
				snprintf(up, sizeof(up), "-");
			}
			printf("%-20s %-9s %-4s %-13s %-7s %s\n",
			       s->r->name,
			       ping_str(s->icmp_status, s->icmp_rtt_us,
					pb, sizeof(pb)),
			       s->reachable ? "yes" : "no",
			       status_str(s),
			       ut, up);
		}
	}

out:
	for (i = 0; i < (size_t)n_remotes; i++)
		node_detail_free(&nodes[i]);
	xfree(nodes, (size_t)n_remotes * sizeof(*nodes));
	shirudo_remotes_free(remotes, n_remotes);
	shirudo_selector_free(sel);
	return ret;
}
