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

#include "builtin.h"
#include "util/help.h"
#include "util/json.h"
#include "util/log.h"
#include "util/macros.h"
#include "util/similar.h"
#include "util/malloc.h"
#include "util/remotes.h"
#include "util/selector.h"
#include "util/ssh.h"
#include "util/sysinfo.h"

#define NODE_CMD	"shirudo status --json --include-tpm"
#define SHOW_CMD \
	"shirudo status --json --include-tpm --include-system --include-eventlog"

struct node_state {
	const char	*name;
	bool		reachable;
	char		version_id[80];
	int		lsm_attached;
	char		chain[80];	/* "" if absent/null */
	int		chain_seen;
	int		matches;	/* -1 unknown, 0/1 */
};

static void query_node(const struct shirudo_remote *r, struct node_state *st)
{
	struct shirudo_ssh_session *sess;
	char *out = NULL;
	size_t len = 0;
	int rc;

	st->name = r->name;
	st->matches = -1;

	sess = shirudo_ssh_connect(r->user, r->host, r->port);
	if (!sess)
		return;
	rc = shirudo_ssh_exec(sess, NODE_CMD, &out, &len);
	shirudo_ssh_close(sess);
	if (rc < 0 || !out) {
		xfree(out, len);
		return;
	}

	{
		struct shirudo_json_field tpm[] = {
			{ "chain", SHIRUDO_JSON_T_STRING, st->chain,
			  sizeof(st->chain), 0, NULL, 0 },
			{ "chain_matches_eventlog", SHIRUDO_JSON_T_BOOL,
			  &st->matches, 0, 0, NULL, 0 },
		};
		struct shirudo_json_field top[] = {
			{ "version_id", SHIRUDO_JSON_T_STRING, st->version_id,
			  sizeof(st->version_id), 0, NULL, 0 },
			{ "lsm_attached", SHIRUDO_JSON_T_BOOL, &st->lsm_attached,
			  0, 0, NULL, 0 },
			{ "tpm", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, tpm, 2 },
		};

		if (shirudo_json_parse(out, len, top, ARRAY_SIZE(top)) == 0) {
			st->reachable = true;
			st->chain_seen = tpm[0].seen;
			if (!tpm[1].seen)
				st->matches = -1;
		} else {
			pr_warn("nodes: %s: unparseable status JSON", r->name);
		}
	}
	xfree(out, len);
}

static const char *short_chain(const struct node_state *s, char *buf, size_t n)
{
	if (!s->reachable)
		return "-";
	if (!s->chain_seen)
		return "no-tpm";
	snprintf(buf, n, "%.16s..", s->chain);
	return buf;
}

static const char *match_str(const struct node_state *s)
{
	if (!s->reachable || s->matches < 0)
		return "?";
	return s->matches ? "ok" : "MISMATCH";
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
	.usage      = "shirudo nodes [show] [<name>...] [--json] [--filter=<glob>] [--selector=<expr>]",
	.summary    = "Operator-side fleet observability over registered "
		      "remotes. Bare\n`shirudo nodes` prints the drift table; "
		      "`shirudo nodes show <name>` runs a\nper-node deep dive.",
	.sections   = nodes_help_sections,
	.n_sections = ARRAY_SIZE(nodes_help_sections),
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

static void fetch_node(const struct shirudo_remote *r, struct node_detail *d)
{
	struct shirudo_ssh_session *sess;
	char *out = NULL;
	size_t len = 0;
	int rc;

	d->r = r;
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

/* Payload of the most recent load of <name>, or NULL if not in the log. */
static const char *loaded_payload(const struct node_detail *d, const char *name)
{
	size_t i = d->n_ev;

	while (i--) {
		if (strcmp(d->events[i].type, "upatch_load") == 0 &&
		    strcmp(d->events[i].up_name, name) == 0)
			return d->events[i].up_payload;
	}
	return NULL;
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
	if (d->reachable && d->parsed) {
		printf("Role:              %s\n", role_str(d));
		printf("Reachable:         yes\n");
		printf("Version-ID:        %s\n", d->version_id);
	} else {
		printf("Role:              target (registered)\n");
		printf("Reachable:         %s\n",
		       d->reachable ? "yes (status JSON unparseable)"
				    : "NO");
		if (d->unreach)
			printf("Reason:            %s\n", d->unreach);
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
		printf("  %-30s %s\n", "NAME", "PAYLOAD-SHA256");
		for (i = 0; i < d->n_up; i++) {
			const char *p = loaded_payload(d, d->upatches[i]);

			printf("  %-30s %.16s%s\n", d->upatches[i],
			       p ? p : "-", p ? ".." : "");
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
	if (!d->reachable || !d->parsed)
		shirudo_json_kv_string(e, "error",
				       d->unreach ? d->unreach
						  : "status JSON unparseable");
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

		shirudo_json_obj_open_key(e, "status");
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
		for (i = 0; i < d->n_up; i++)
			shirudo_json_str(e, d->upatches[i]);
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

	nodes = xcalloc(nnames, sizeof(*nodes));
	if (!nodes) {
		shirudo_remotes_free(remotes, n_remotes);
		return 1;
	}

	for (j = 0; j < nnames; j++) {
		const struct shirudo_remote *r = NULL;

		for (i = 0; i < n_remotes; i++)
			if (strcmp(remotes[i].name, names[j]) == 0) {
				r = &remotes[i];
				break;
			}
		if (!r) {
			pr_err("nodes show: '%s' is not a registered remote",
			       names[j]);
			ret = 1;
			continue;	/* nodes[j].r stays NULL -> skipped */
		}
		fetch_node(r, &nodes[j]);
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
	 * `nodes` is mixed: argv[1] may be a sub-subcommand ("show"/"list")
	 * OR a positional remote name. Only treat it as a subcommand when
	 * it tolerantly resolves to one of the declared sub-subs; otherwise
	 * fall through to the drift-table parser so `shirudo nodes <name>`
	 * keeps working. Doesn't print a diagnostic because the fallthrough
	 * still needs to succeed for the registered-name case.
	 */
	if (argc >= 2 && argv[1][0] != '-') {
		const char *names[] = { "list", "show" };
		size_t m[ARRAY_SIZE(names)];
		size_t n = shirudo_resolve(argv[1], names,
					   ARRAY_SIZE(names), m,
					   ARRAY_SIZE(m));

		if (n == 1 && strcmp(names[m[0]], "show") == 0)
			return cmd_nodes_show(argc, argv);
		if (n == 1 && strcmp(names[m[0]], "list") == 0) {
			/* `nodes list ...` is just the drift-table form;
			 * skip the verb so the existing parser sees the
			 * options/names that follow. */
			argc--;
			argv++;
		}
	}

	const char *filter = NULL, *selexpr = NULL;
	struct shirudo_remote *remotes = NULL;
	struct shirudo_selector *sel = NULL;
	struct node_state *nodes = NULL;
	const char *names[256];
	size_t n_remotes = 0, n = 0, nnames = 0, i, j;
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
		} else if (a[0] == '-') {
			fprintf(stderr, "nodes: unknown option '%s'\n", a);
			return 2;
		} else if (nnames < ARRAY_SIZE(names)) {
			names[nnames++] = a;	/* positional remote name */
		} else {
			fprintf(stderr, "nodes: too many names\n");
			return 2;
		}
	}

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

	/* Positional names must be registered (exact match), like rollout. */
	for (j = 0; j < nnames; j++) {
		bool found = false;

		for (i = 0; i < n_remotes; i++)
			if (strcmp(remotes[i].name, names[j]) == 0) {
				found = true;
				break;
			}
		if (!found) {
			pr_err("nodes: '%s' is not a registered remote", names[j]);
			shirudo_remotes_free(remotes, n_remotes);
			shirudo_selector_free(sel);
			return 1;
		}
	}

	nodes = xcalloc(n_remotes, sizeof(*nodes));
	if (!nodes) {
		shirudo_remotes_free(remotes, n_remotes);
		shirudo_selector_free(sel);
		return 1;
	}

	/*
	 * Select, then query each match sequentially. Names, --filter and
	 * --selector all intersect (PLAN.md "Subcommands" / nodes).
	 */
	for (i = 0; i < n_remotes; i++) {
		if (nnames) {
			bool named = false;

			for (j = 0; j < nnames; j++)
				if (strcmp(remotes[i].name, names[j]) == 0) {
					named = true;
					break;
				}
			if (!named)
				continue;
		}
		if (filter && fnmatch(filter, remotes[i].name, 0) != 0)
			continue;
		if (sel && !shirudo_selector_match(sel, remotes[i].labels))
			continue;
		query_node(&remotes[i], &nodes[n]);
		n++;
	}

	if (n == 0) {
		pr_err("nodes: name/filter/selector matched zero "
		       "registered remotes");
		ret = 1;
		goto out;
	}

	if (json) {
		char buf[64 * 1024];
		struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };

		shirudo_json_obj_open(&e);
		shirudo_json_kv_int(&e, "schema", 1);
		shirudo_json_arr_open(&e, "nodes");
		for (i = 0; i < n; i++) {
			struct node_state *s = &nodes[i];

			shirudo_json_obj_open(&e);
			shirudo_json_kv_string(&e, "name", s->name);
			shirudo_json_kv_bool(&e, "reachable", s->reachable);
			if (s->reachable) {
				shirudo_json_kv_bool(&e, "lsm_attached",
						     s->lsm_attached);
				shirudo_json_kv_string(&e, "version_id",
						       s->version_id);
				if (s->chain_seen)
					shirudo_json_kv_string(&e, "chain",
							       s->chain);
				else
					shirudo_json_kv_null(&e, "chain");
				if (s->matches < 0)
					shirudo_json_kv_null(&e,
						"chain_matches_eventlog");
				else
					shirudo_json_kv_bool(&e,
						"chain_matches_eventlog",
						s->matches);
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
	} else {
		printf("%-20s %-9s %-8s %-18s %-10s %s\n",
		       "NODE", "REACHABLE", "LSM", "CHAIN", "VERSION",
		       "CHAIN/LOG");
		for (i = 0; i < n; i++) {
			struct node_state *s = &nodes[i];
			char cb[24];

			printf("%-20s %-9s %-8s %-18s %-10.8s %s\n",
			       s->name,
			       s->reachable ? "yes" : "NO",
			       !s->reachable ? "-" :
				 s->lsm_attached ? "attached" : "DETACHED",
			       short_chain(s, cb, sizeof(cb)),
			       s->reachable ? s->version_id : "-",
			       match_str(s));
		}
	}

out:
	xfree(nodes, (size_t)n_remotes * sizeof(*nodes));
	shirudo_remotes_free(remotes, n_remotes);
	shirudo_selector_free(sel);
	return ret;
}
