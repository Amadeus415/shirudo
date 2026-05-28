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
#include "util/conditions.h"
#include "util/config.h"
#include "util/help.h"
#include "util/format.h"
#include "util/icmp.h"
#include "util/json.h"
#include "util/kmodules.h"
#include "util/log.h"
#include "util/macros.h"
#include "util/similar.h"
#include "util/malloc.h"
#include "util/remotes.h"
#include "util/selector.h"
#include "util/ssh.h"
#include "util/sysinfo.h"
#include "util/timefmt.h"
#include "util/upatch.h"
#include "util/upatch_table.h"

#define SHOW_CMD \
	"shirudo status --json --include-tpm --include-system " \
	"--include-eventlog --include-kernellog --include-modules"

/*
 * Compact ICMP column for the drift table: best-RTT in ms when OK,
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
	case SHIRUDO_ICMP_DISABLED:
		return "off";
	case SHIRUDO_ICMP_ERROR:
	default:
		return "err";
	}
}

/* ---- shirudo nodes show <name>: per-node describe ----------------- */

static const struct shirudo_help_item nodes_subcmds[] = {
	{ "list", "drift table across registered remotes (default if omitted)" },
	{ "show", "per-node deep dive: show [--json] [--show-full] <name>..." },
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
		      "       shirudo nodes show [--json] [--show-full] <name>...",
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

static const struct shirudo_help_item nodes_show_options[] = {
	{ "--json",      "machine-readable JSON output" },
	{ "--show-full", "expand the loaded-modules dependency tree" },
};

static const struct shirudo_help_section nodes_show_sections[] = {
	{ "options:", nodes_show_options, ARRAY_SIZE(nodes_show_options) },
};

static const struct shirudo_help nodes_show_help = {
	.usage      = "shirudo nodes show [--json] [--show-full] <name>...\n"
		      "       shirudo nodes show [--json] <name> upatches\n"
		      "       shirudo nodes show [--json] [--show-full] "
		      "<name> upatches <upatch-name>",
	.summary    = "Per-node deep dive: SSH into each named remote, fetch "
		      "its\n`shirudo status --json` in one round-trip, and "
		      "render it as Conditions /\nSystem Info / upatches "
		      "loaded / TPM Measurement / Eventlog / Assets /\nKernel "
		      "log / Loaded modules. <name> is the operator-local "
		      "registry\nname, not the host/IP.\n\n"
		      "A trailing `upatches` switches the view to just the "
		      "NAME / LOCATION /\nMAPS / AGE table for the loaded "
		      "upatches on one node. Adding a\n<upatch-name> proxies "
		      "`shirudo upatch get` on the target -- the loaded\n"
		      "upatch's source (kernel BTF line_info) plus every "
		      "pinned map's BTF\ntype and contents.",
	.sections   = nodes_show_sections,
	.n_sections = ARRAY_SIZE(nodes_show_sections),
	.footer     =
"Examples:\n"
"  shirudo nodes show prod-edge-01\n"
"  shirudo nodes show --show-full prod-edge-01 prod-edge-02\n"
"  shirudo nodes show --json staging-db-1 | jq '.nodes[0].status'\n"
"  shirudo nodes show prod-edge-01 upatches\n"
"  shirudo nodes show --json prod-edge-01 upatches | jq '.upatches'\n"
"  shirudo nodes show prod-edge-01 upatches cve-2026-31431\n"
"  shirudo nodes show --json prod-edge-01 upatches cve-2026-31431 | jq",
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
 * One loaded upatch as the target shipped it. Status emits
 * upatches_loaded as an array of these objects (name + attach hook +
 * number of pinned maps + pin-dir ctime); the operator parses straight
 * into this row. `loaded_at` is the bpffs pin directory's ctime in ISO
 * UTC -- always set on a successful load, never null even when the
 * eventlog is suppressed (boot-restore one-event-per-boot semantics).
 */
struct up_row {
	char	name[128];
	char	location[160];
	int64_t	n_maps;
	int64_t	age_sec;
	char	loaded_at[32];
	char	payload_sha256[65];
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

	struct up_row	up_scratch;
	struct up_row	*upatches;
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

	/* Mirrors shirudo status's `assets` sub-object. */
	struct {
		char	root[80];
		int	cert, signing_key, keyring_serial;
		int	eventlog, bpffs_mounted;
		int64_t	eventlog_bytes;
		int64_t	upatches, incoming;
		int	upatches_seen, incoming_seen;
	} ats;

	/* Mirrors shirudo status's `kernel_log` array. */
	struct kmsg_row {
		char	ts[32];
		char	msg[256];
	}			kmsg_scratch;
	struct kmsg_row		*kmsg;
	size_t			n_kmsg, cap_kmsg;

	/* Mirrors shirudo status's `modules` array. */
	struct kmod_row {
		char		name[64];
		int64_t		size;
		int64_t		refcount;
		char		loaded_at[32];	/* ISO UTC, empty if absent */
		int64_t		since_boot_sec;	/* 0 if null in JSON */
		int		since_boot_seen;
		uint16_t	deps_off;
		uint16_t	n_deps;
	}			kmod_scratch;
	struct kmod_row		*kmods;
	size_t			n_kmod, cap_kmod;
	char			kdep_scratch[64];
	char			(*kdep_names)[64];
	size_t			n_kdep, cap_kdep;
	char			boot_at[32];	/* top-level ISO UTC */

	/*
	 * Compact view of shirudo status's `upatch_maps[]` -- one row per
	 * pinned map; entry details (values) are fetched on demand via
	 * `shirudo upatch map` over SSH, this just carries summary info.
	 */
	struct umap_row {
		char		upatch[64];
		char		name[24];
		char		type[24];
		int64_t		max_entries;
		int64_t		n_entries;
		int64_t		n_cpus;
		int		truncated;
		char		skipped[80];
		char		first_sum[48];	/* entries[0].sum for percpu */
	}			umap_scratch_inner;
	struct umap_row		*umaps;
	size_t			n_umap, cap_umap;
	char			umap_current[64];	/* outer scratch */
	char			umap_sum_scratch[48];	/* nested entries */
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
	d->upatches[d->n_up++] = d->up_scratch;
	d->up_scratch = (struct up_row){};
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

static int kmsg_on_elem(void *ctx)
{
	struct node_detail *d = ctx;

	if (d->n_kmsg == d->cap_kmsg) {
		size_t nc = d->cap_kmsg ? d->cap_kmsg * 2 : 16;
		void *p = xreallocarray(d->kmsg, d->cap_kmsg, nc,
					sizeof(d->kmsg[0]));

		if (!p)
			return -ENOMEM;
		d->kmsg = p;
		d->cap_kmsg = nc;
	}
	d->kmsg[d->n_kmsg++] = d->kmsg_scratch;
	d->kmsg_scratch = (struct kmsg_row){};
	return 0;
}

static int kdep_on_elem(void *ctx)
{
	struct node_detail *d = ctx;

	if (d->n_kdep == d->cap_kdep) {
		size_t nc = d->cap_kdep ? d->cap_kdep * 2 : 64;
		void *p = xreallocarray(d->kdep_names, d->cap_kdep, nc,
					sizeof(d->kdep_names[0]));

		if (!p)
			return -ENOMEM;
		d->kdep_names = p;
		d->cap_kdep = nc;
	}
	snprintf(d->kdep_names[d->n_kdep], sizeof(d->kdep_names[0]),
		 "%s", d->kdep_scratch);
	d->n_kdep++;
	d->kmod_scratch.n_deps++;
	d->kdep_scratch[0] = '\0';
	return 0;
}

static int kmod_on_elem(void *ctx)
{
	struct node_detail *d = ctx;

	if (d->n_kmod == d->cap_kmod) {
		size_t nc = d->cap_kmod ? d->cap_kmod * 2 : 32;
		void *p = xreallocarray(d->kmods, d->cap_kmod, nc,
					sizeof(d->kmods[0]));

		if (!p)
			return -ENOMEM;
		d->kmods = p;
		d->cap_kmod = nc;
	}
	/*
	 * JSON `since_boot_sec` is nullable; the parser leaves the dst
	 * untouched on null. Use INT64_MIN as a sentinel so we can tell
	 * "JSON had an int" from "JSON had null / field absent" without
	 * relying on per-element schema seen-flag access.
	 */
	d->kmod_scratch.since_boot_seen =
		(d->kmod_scratch.since_boot_sec != INT64_MIN);
	d->kmods[d->n_kmod++] = d->kmod_scratch;
	d->kmod_scratch = (struct kmod_row){
		.deps_off       = (uint16_t)d->n_kdep,
		.since_boot_sec = INT64_MIN,
	};
	return 0;
}

/*
 * The nested entries[] inside each map carries a "sum" string (for
 * percpu types). We capture only the first entry's sum, since the
 * inline nodes-show render shows at most one sum per map; full detail
 * goes through `shirudo upatch map <upatch> <map>`.
 */
static int umap_on_entry_elem(void *ctx)
{
	struct node_detail *d = ctx;

	if (d->umap_sum_scratch[0] && !d->umap_scratch_inner.first_sum[0]) {
		snprintf(d->umap_scratch_inner.first_sum,
			 sizeof(d->umap_scratch_inner.first_sum), "%s",
			 d->umap_sum_scratch);
	}
	d->umap_sum_scratch[0] = '\0';
	return 0;
}

static int umap_on_inner_elem(void *ctx)
{
	struct node_detail *d = ctx;
	struct umap_row *r;

	if (d->n_umap == d->cap_umap) {
		size_t nc = d->cap_umap ? d->cap_umap * 2 : 16;
		void *p = xreallocarray(d->umaps, d->cap_umap, nc,
					sizeof(d->umaps[0]));

		if (!p)
			return -ENOMEM;
		d->umaps = p;
		d->cap_umap = nc;
	}
	snprintf(d->umap_scratch_inner.upatch,
		 sizeof(d->umap_scratch_inner.upatch), "%s",
		 d->umap_current);
	r = &d->umaps[d->n_umap++];
	*r = d->umap_scratch_inner;
	d->umap_scratch_inner = (struct umap_row){};
	return 0;
}

static int umap_on_outer_elem(void *ctx)
{
	struct node_detail *d = ctx;

	d->umap_current[0] = '\0';
	return 0;
}

static void node_detail_free(struct node_detail *d)
{
	xfree(d->upatches, d->cap_up * sizeof(d->upatches[0]));
	xfree(d->events, d->cap_ev * sizeof(d->events[0]));
	xfree(d->kmsg, d->cap_kmsg * sizeof(d->kmsg[0]));
	xfree(d->kmods, d->cap_kmod * sizeof(d->kmods[0]));
	xfree(d->kdep_names, d->cap_kdep * sizeof(d->kdep_names[0]));
	xfree(d->umaps, d->cap_umap * sizeof(d->umaps[0]));
}

/* Parse one `shirudo status --json ...` document into *d. 0 / -errno. */
static int parse_node_detail(const char *out, size_t len,
			     struct node_detail *d)
{
	struct shirudo_json_array up_sink = { up_on_elem, d };
	struct shirudo_json_field up_elem[] = {
		{ "name", SHIRUDO_JSON_T_STRING, d->up_scratch.name,
		  sizeof(d->up_scratch.name), 0, NULL, 0 },
		{ "location", SHIRUDO_JSON_T_STRING, d->up_scratch.location,
		  sizeof(d->up_scratch.location), 0, NULL, 0 },
		{ "n_maps", SHIRUDO_JSON_T_INT, &d->up_scratch.n_maps,
		  0, 0, NULL, 0 },
		{ "loaded_at", SHIRUDO_JSON_T_STRING, d->up_scratch.loaded_at,
		  sizeof(d->up_scratch.loaded_at), 0, NULL, 0 },
		{ "age_sec", SHIRUDO_JSON_T_INT, &d->up_scratch.age_sec,
		  0, 0, NULL, 0 },
		{ "payload_sha256", SHIRUDO_JSON_T_STRING,
		  d->up_scratch.payload_sha256,
		  sizeof(d->up_scratch.payload_sha256), 0, NULL, 0 },
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
	struct shirudo_json_array kmsg_sink = { kmsg_on_elem, d };
	struct shirudo_json_field kmsg_elem[] = {
		{ "ts", SHIRUDO_JSON_T_STRING, d->kmsg_scratch.ts,
		  sizeof(d->kmsg_scratch.ts), 0, NULL, 0 },
		{ "msg", SHIRUDO_JSON_T_STRING, d->kmsg_scratch.msg,
		  sizeof(d->kmsg_scratch.msg), 0, NULL, 0 },
	};
	struct shirudo_json_array kdep_sink = { kdep_on_elem, d };
	struct shirudo_json_field kdep_elem[] = {
		{ "", SHIRUDO_JSON_T_STRING, d->kdep_scratch,
		  sizeof(d->kdep_scratch), 0, NULL, 0 },
	};
	struct shirudo_json_array umap_entries_sink = { umap_on_entry_elem, d };
	struct shirudo_json_field umap_entries_elem[] = {
		{ "sum", SHIRUDO_JSON_T_STRING, d->umap_sum_scratch,
		  sizeof(d->umap_sum_scratch), 0, NULL, 0 },
	};
	struct shirudo_json_array umap_inner_sink = { umap_on_inner_elem, d };
	struct shirudo_json_field umap_inner_elem[] = {
		{ "name", SHIRUDO_JSON_T_STRING, d->umap_scratch_inner.name,
		  sizeof(d->umap_scratch_inner.name), 0, NULL, 0 },
		{ "type", SHIRUDO_JSON_T_STRING, d->umap_scratch_inner.type,
		  sizeof(d->umap_scratch_inner.type), 0, NULL, 0 },
		{ "max_entries", SHIRUDO_JSON_T_INT,
		  &d->umap_scratch_inner.max_entries, 0, 0, NULL, 0 },
		{ "n_entries", SHIRUDO_JSON_T_INT,
		  &d->umap_scratch_inner.n_entries, 0, 0, NULL, 0 },
		{ "n_cpus", SHIRUDO_JSON_T_INT,
		  &d->umap_scratch_inner.n_cpus, 0, 0, NULL, 0 },
		{ "truncated", SHIRUDO_JSON_T_BOOL,
		  &d->umap_scratch_inner.truncated, 0, 0, NULL, 0 },
		{ "skipped", SHIRUDO_JSON_T_STRING,
		  d->umap_scratch_inner.skipped,
		  sizeof(d->umap_scratch_inner.skipped), 0, NULL, 0 },
		{ "entries", SHIRUDO_JSON_T_ARRAY, &umap_entries_sink, 0, 0,
		  umap_entries_elem, ARRAY_SIZE(umap_entries_elem) },
	};
	struct shirudo_json_array umap_outer_sink = { umap_on_outer_elem, d };
	struct shirudo_json_field umap_outer_elem[] = {
		{ "upatch", SHIRUDO_JSON_T_STRING, d->umap_current,
		  sizeof(d->umap_current), 0, NULL, 0 },
		{ "maps", SHIRUDO_JSON_T_ARRAY, &umap_inner_sink, 0, 0,
		  umap_inner_elem, ARRAY_SIZE(umap_inner_elem) },
	};
	struct shirudo_json_array kmod_sink = { kmod_on_elem, d };
	struct shirudo_json_field kmod_elem[] = {
		{ "name", SHIRUDO_JSON_T_STRING, d->kmod_scratch.name,
		  sizeof(d->kmod_scratch.name), 0, NULL, 0 },
		{ "size", SHIRUDO_JSON_T_INT, &d->kmod_scratch.size,
		  0, 0, NULL, 0 },
		{ "refcount", SHIRUDO_JSON_T_INT, &d->kmod_scratch.refcount,
		  0, 0, NULL, 0 },
		{ "loaded_at", SHIRUDO_JSON_T_STRING, d->kmod_scratch.loaded_at,
		  sizeof(d->kmod_scratch.loaded_at), 0, NULL, 0 },
		{ "since_boot_sec", SHIRUDO_JSON_T_INT,
		  &d->kmod_scratch.since_boot_sec, 0, 0, NULL, 0 },
		{ "deps", SHIRUDO_JSON_T_ARRAY, &kdep_sink, 0, 0,
		  kdep_elem, 1 },
	};
	struct shirudo_json_field assets_sub[] = {
		{ "root", SHIRUDO_JSON_T_STRING, d->ats.root,
		  sizeof(d->ats.root), 0, NULL, 0 },
		{ "cert", SHIRUDO_JSON_T_BOOL, &d->ats.cert, 0, 0, NULL, 0 },
		{ "signing_key", SHIRUDO_JSON_T_BOOL, &d->ats.signing_key,
		  0, 0, NULL, 0 },
		{ "keyring_serial", SHIRUDO_JSON_T_BOOL, &d->ats.keyring_serial,
		  0, 0, NULL, 0 },
		{ "eventlog", SHIRUDO_JSON_T_BOOL, &d->ats.eventlog,
		  0, 0, NULL, 0 },
		{ "eventlog_bytes", SHIRUDO_JSON_T_INT, &d->ats.eventlog_bytes,
		  0, 0, NULL, 0 },
		{ "upatches", SHIRUDO_JSON_T_INT, &d->ats.upatches,
		  0, 0, NULL, 0 },
		{ "incoming", SHIRUDO_JSON_T_INT, &d->ats.incoming,
		  0, 0, NULL, 0 },
		{ "bpffs_mounted", SHIRUDO_JSON_T_BOOL, &d->ats.bpffs_mounted,
		  0, 0, NULL, 0 },
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
		{ "mem_avail_kb", SHIRUDO_JSON_T_INT, &d->sys.mem_avail_kb,
		  0, 0, NULL, 0 },
		{ "disk_total_kb", SHIRUDO_JSON_T_INT, &d->sys.disk_total_kb,
		  0, 0, NULL, 0 },
		{ "disk_used_kb", SHIRUDO_JSON_T_INT, &d->sys.disk_used_kb,
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
		  up_elem, ARRAY_SIZE(up_elem) },
		{ "system", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, sys_sub,
		  ARRAY_SIZE(sys_sub) },
		{ "assets", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, assets_sub,
		  ARRAY_SIZE(assets_sub) },
		{ "tpm", SHIRUDO_JSON_T_OBJECT, NULL, 0, 0, tpm_sub, 4 },
		{ "kernel_log", SHIRUDO_JSON_T_ARRAY, &kmsg_sink, 0, 0,
		  kmsg_elem, ARRAY_SIZE(kmsg_elem) },
		{ "modules", SHIRUDO_JSON_T_ARRAY, &kmod_sink, 0, 0,
		  kmod_elem, ARRAY_SIZE(kmod_elem) },
		{ "boot_at", SHIRUDO_JSON_T_STRING, d->boot_at,
		  sizeof(d->boot_at), 0, NULL, 0 },
		{ "upatch_maps", SHIRUDO_JSON_T_ARRAY, &umap_outer_sink,
		  0, 0, umap_outer_elem, ARRAY_SIZE(umap_outer_elem) },
	};

	d->kmod_scratch.since_boot_sec = INT64_MIN;
	/*
	 * Sentinels for nullable integer sys fields. Zero is legitimate
	 * (e.g. 0 KiB of MemAvailable on an oom box), so the schema
	 * parser's "leave untouched on null" semantics need a negative
	 * default to distinguish "not reported" from "reported as 0".
	 */
	d->sys.mem_avail_kb = -1;
	d->sys.disk_total_kb = -1;
	d->sys.disk_used_kb = -1;
	int rc;

	rc = shirudo_json_parse(out, len, top, ARRAY_SIZE(top));
	if (rc)
		return rc;
	d->ks_seen = top[5].seen;
	d->ksp_seen = top[6].seen;
	d->ksm_seen = top[7].seen;
	d->chain_seen = tpm_sub[1].seen;
	d->cm_seen = tpm_sub[2].seen;
	d->ats.upatches_seen = assets_sub[6].seen;
	d->ats.incoming_seen = assets_sub[7].seen;
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

/*
 * Adapt the per-node detail into the flat input shirudo_conditions()
 * expects. The two sit on the same security-relevant fields so the
 * fetched (SSH) view and the local `shirudo status` view share one
 * verdict / Conditions code path.
 */
static void node_detail_to_cond_input(const struct node_detail *d,
				      struct shirudo_conditions_input *in)
{
	*in = (struct shirudo_conditions_input){
		.reachable		= d->reachable,
		.parsed			= d->parsed,
		.unreach		= d->unreach,
		.lsm_attached		= d->lsm_attached,
		.keyring_present	= d->keyring_present,
		.keyring_serial		= d->keyring_serial,
		.keyring_serial_pinned	= d->keyring_serial_pinned,
		.keyring_serial_matches	= d->keyring_serial_matches,
		.ks_seen		= d->ks_seen,
		.ksp_seen		= d->ksp_seen,
		.ksm_seen		= d->ksm_seen,
		.chain_seen		= d->chain_seen,
		.chain_matches		= d->chain_matches,
		.cm_seen		= d->cm_seen,
		.nv_index		= d->nv_index,
	};
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

static const struct ev_row *last_init_event(const struct node_detail *d)
{
	size_t i = d->n_ev;

	while (i--) {
		const struct ev_row *e = &d->events[i];

		if (strcmp(e->type, "init") == 0)
			return e;
	}
	return NULL;
}

/*
 * Thin wrappers so existing call sites stay terse. `node_detail`
 * carries a registry pointer; we use that to short-circuit "?" for
 * a skipped slot, then delegate to the shared verdict logic.
 */
static const char *nd_status(const struct node_detail *d)
{
	struct shirudo_conditions_input in;

	if (!d->r)
		return "?";
	node_detail_to_cond_input(d, &in);
	return shirudo_status_verdict(&in);
}

static void nd_status_reason(const struct node_detail *d, char *buf, size_t cap)
{
	struct shirudo_conditions_input in;

	if (!d->r) {
		buf[0] = '\0';
		return;
	}
	node_detail_to_cond_input(d, &in);
	shirudo_status_reason(&in, buf, cap);
}

/*
 * Fleet-table UPATCHES cell: live-loaded count, plus the verb / name /
 * age of the most recent upatch_load or upatch_unload event. The verb
 * matters -- "2 (unload:old-x, 3d)" means "2 currently loaded, last
 * change was unloading old-x 3 days ago," which reads differently from
 * "2 (load:cve-..., 3d)". After a reboot the chain extension is
 * suppressed per-upatch (one `init` event for the whole boot-restored
 * set), so when no upatch_load/unload event is present but upatches
 * are loaded, fall back to "N (init:<first>, <init-age>)".
 */
static void upatches_summary(const struct node_detail *d, char *buf, size_t cap)
{
	const struct ev_row *last = last_upatch_event(d);
	const struct ev_row *src = last;
	const char *verb, *name;
	char age[16] = "?";
	char nm[20];

	if (!src && d->n_up > 0)
		src = last_init_event(d);
	if (!src) {
		snprintf(buf, cap, "%zu", d->n_up);
		return;
	}
	if (last) {
		verb = strcmp(last->type, "upatch_unload") == 0 ? "unload" : "load";
		name = last->up_name;
	} else {
		verb = "init";
		name = d->upatches[0].name;
	}
	{
		struct tm tm = {};

		if (strptime(src->ts, "%Y-%m-%dT%H:%M:%SZ", &tm))
			shirudo_format_duration(
				(long)(time(NULL) - timegm(&tm)),
				age, sizeof(age));
	}
	if (strlen(name) > 14)
		snprintf(nm, sizeof(nm), "%.14s..", name);
	else
		snprintf(nm, sizeof(nm), "%s", name);
	snprintf(buf, cap, "%zu (%s:%s, %s)", d->n_up, verb, nm, age);
}

/* Linear-search a module by name. Returns index or -1. */
static int kmod_lookup(const struct node_detail *d, const char *name)
{
	size_t i;

	for (i = 0; i < d->n_kmod; i++)
		if (strcmp(d->kmods[i].name, name) == 0)
			return (int)i;
	return -1;
}

/*
 * Recursively print one module + its dep subtree. <prefix> carries the
 * inherited indent for nested levels; <is_last> picks `└── ` vs `├── `;
 * <seen> dedups subtrees already expanded above (shared deps print
 * once and re-appear as `<name> (shared)` thereafter).
 */
static void print_kmod_subtree(const struct node_detail *d, int idx,
			       const char *prefix, int is_last,
			       uint8_t *seen)
{
	const struct kmod_row *m;
	const char *branch = is_last ? "└── " : "├── ";
	char size_s[16];
	char child_prefix[256];
	int already = (seen[idx >> 3] >> (idx & 7)) & 1;
	uint16_t k;

	m = &d->kmods[idx];
	shirudo_human_size((uint64_t)m->size, size_s, sizeof(size_s));

	if (already) {
		printf("%s%s%s (shared)\n", prefix, branch, m->name);
		return;
	}
	seen[idx >> 3] |= (uint8_t)(1U << (idx & 7));

	printf("%s%s%s (%s, refs=%lld)\n", prefix, branch, m->name,
	       size_s, (long long)m->refcount);

	snprintf(child_prefix, sizeof(child_prefix), "%s%s", prefix,
		 is_last ? "    " : "│   ");

	for (k = 0; k < m->n_deps; k++) {
		const char *dep_name = d->kdep_names[m->deps_off + k];
		int dep_idx = kmod_lookup(d, dep_name);
		int last_child = (k == m->n_deps - 1);

		if (dep_idx < 0) {
			/* Dep name not in module list -- print a stub. */
			printf("%s%s%s (stale)\n", child_prefix,
			       last_child ? "└── " : "├── ", dep_name);
			continue;
		}
		print_kmod_subtree(d, dep_idx, child_prefix, last_child,
				   seen);
	}
}

/* Roots = modules whose name isn't in anyone else's dep list. */
static void print_remote_kmod_tree(const struct node_detail *d)
{
	size_t bm_bytes = (d->n_kmod + 7) / 8;
	uint8_t *used = xcalloc(bm_bytes, 1);
	uint8_t *seen = xcalloc(bm_bytes, 1);
	size_t i, n_roots = 0;
	size_t *roots;

	roots = xmalloc(d->n_kmod * sizeof(*roots));
	if (!used || !seen || !roots) {
		xfree(used, bm_bytes);
		xfree(seen, bm_bytes);
		xfree(roots, d->n_kmod * sizeof(*roots));
		printf("  (out of memory)\n");
		return;
	}
	for (i = 0; i < d->n_kmod; i++) {
		const struct kmod_row *m = &d->kmods[i];
		uint16_t k;

		for (k = 0; k < m->n_deps; k++) {
			int dep_idx = kmod_lookup(d,
						  d->kdep_names[m->deps_off
								+ k]);
			if (dep_idx >= 0)
				used[dep_idx >> 3] |=
					(uint8_t)(1U << (dep_idx & 7));
		}
	}
	for (i = 0; i < d->n_kmod; i++)
		if (((used[i >> 3] >> (i & 7)) & 1) == 0)
			roots[n_roots++] = i;
	for (i = 0; i < n_roots; i++)
		print_kmod_subtree(d, (int)roots[i], "  ",
				   i == n_roots - 1, seen);

	xfree(used, bm_bytes);
	xfree(seen, bm_bytes);
	xfree(roots, d->n_kmod * sizeof(*roots));
}

/*
 * qsort comparator over kmod indices, sorting descending by recency
 * (largest since_boot_sec first). Numeric comparison on the integer the
 * target already shipped -- avoids leaning on ISO-8601's lex-sortability
 * property. Modules with no since_boot_sec (e.g. a race where stat()
 * lost to rmmod on the target) sink to the bottom; alphabetical name
 * breaks ties (sec-resolution mtime ties happen routinely when the
 * kernel batch-registers many kobjects in one kernfs tick).
 */
struct kmod_recent_idx {
	const struct node_detail	*d;
	size_t				idx;
};

static int kmod_recent_cmp(const void *a, const void *b)
{
	const struct kmod_recent_idx *x = a, *y = b;
	const struct kmod_row *mx = &x->d->kmods[x->idx];
	const struct kmod_row *my = &y->d->kmods[y->idx];

	if (!mx->since_boot_seen && my->since_boot_seen)
		return 1;
	if (mx->since_boot_seen && !my->since_boot_seen)
		return -1;
	if (mx->since_boot_seen && my->since_boot_seen) {
		if (mx->since_boot_sec != my->since_boot_sec)
			return mx->since_boot_sec < my->since_boot_sec
				? 1 : -1;
	}
	return strcmp(mx->name, my->name);
}

/*
 * Recent-N list in reverse-chronological order: newest at top, oldest
 * at bottom. Each row is
 *   [<loaded_at>]  <name> (<size>, refs=N, <age> since boot)
 * Computed on the operator side from the target-shipped loaded_at +
 * since_boot_sec; failures stay as `?` rather than crowd the table.
 */
static void print_remote_kmod_recent(const struct node_detail *d, size_t last_n)
{
	struct kmod_recent_idx *all;
	size_t take, i;

	if (d->n_kmod == 0) {
		printf("  (no modules loaded)\n");
		return;
	}
	all = xmalloc(d->n_kmod * sizeof(*all));
	if (!all) {
		printf("  (out of memory)\n");
		return;
	}
	for (i = 0; i < d->n_kmod; i++) {
		all[i].d = d;
		all[i].idx = i;
	}
	qsort(all, d->n_kmod, sizeof(*all), kmod_recent_cmp);
	take = d->n_kmod < last_n ? d->n_kmod : last_n;
	/* qsort already put the freshest first -- print in that order. */
	for (i = 0; i < take; i++) {
		const struct kmod_row *m = &d->kmods[all[i].idx];
		char size_s[16], age[24];

		shirudo_human_size((uint64_t)m->size, size_s, sizeof(size_s));
		if (m->since_boot_seen && m->since_boot_sec >= 0)
			shirudo_format_duration((long)m->since_boot_sec,
						age, sizeof(age));
		else
			snprintf(age, sizeof(age), "?");
		printf("  [%s]  %s (%s, refs=%lld, %s since boot)\n",
		       m->loaded_at[0] ? m->loaded_at : "?", m->name,
		       size_s, (long long)m->refcount, age);
	}
	xfree(all, d->n_kmod * sizeof(*all));
}

/* Describe-style report for one node. */
static void print_describe(const struct node_detail *d, bool show_full)
{
	const struct shirudo_remote *r = d->r;
	struct shirudo_condition conds[4];
	char endpoint[320];
	size_t nl, nc, i;

	shirudo_remote_endpoint(r, endpoint, sizeof(endpoint));

	printf("Name:              %s\n", r->name);
	printf("Endpoint:          %s\n", endpoint);
	{
		char reason[160];
		const char *s = nd_status(d);

		nd_status_reason(d, reason, sizeof(reason));
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
	case SHIRUDO_ICMP_DISABLED:
		printf("  %-14s off  (disabled in shirudo.conf: "
		       "nodes.icmp_probes = 0)\n", "ICMP:");
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

	{
		struct shirudo_conditions_input in;

		node_detail_to_cond_input(d, &in);
		nc = shirudo_conditions(&in, conds, ARRAY_SIZE(conds));
	}
	printf("\n");
	shirudo_conditions_print(conds, nc);

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
	if (d->sys.mem_total_kb > 0) {
		char tot[16], used[16];

		shirudo_human_size((uint64_t)d->sys.mem_total_kb * 1024,
				   tot, sizeof(tot));
		if (d->sys.mem_avail_kb >= 0 &&
		    d->sys.mem_avail_kb <= d->sys.mem_total_kb) {
			shirudo_human_size(
				(uint64_t)(d->sys.mem_total_kb -
					   d->sys.mem_avail_kb) * 1024,
				used, sizeof(used));
			printf("  %-16s %s/%s\n", "Memory:", used, tot);
		} else {
			printf("  %-16s %s\n", "Memory:", tot);
		}
	}
	if (d->sys.disk_total_kb > 0 && d->sys.disk_used_kb >= 0) {
		char tot[16], used[16];

		shirudo_human_size((uint64_t)d->sys.disk_total_kb * 1024,
				   tot, sizeof(tot));
		shirudo_human_size((uint64_t)d->sys.disk_used_kb * 1024,
				   used, sizeof(used));
		printf("  %-16s %s/%s\n", "Disk:", used, tot);
	}
	if (d->sys.uptime_sec >= 0)
		printf("  %-16s %ldd %ldh %ldm\n", "Uptime:",
		       d->sys.uptime_sec / 86400,
		       (d->sys.uptime_sec % 86400) / 3600,
		       (d->sys.uptime_sec % 3600) / 60);
	if (d->sys.machine_id[0])
		printf("  %-16s %s\n", "Machine ID:", d->sys.machine_id);
	if (d->sys.boot_id[0])
		printf("  %-16s %s\n", "Boot ID:", d->sys.boot_id);

	{
		/*
		 * Same NAME / LOCATION / MAPS / AGE shape as `shirudo status`
		 * and `shirudo nodes show <name> upatches`. The age basis is the
		 * pin ctime captured by the target; on the operator side the
		 * recompute is from the same timestamp so the columns agree.
		 * For deeper detail (source + map contents) use
		 * `shirudo nodes show <name> upatches <upatch-name>`.
		 */
		struct shirudo_upatch_table_row *rows;
		size_t k;

		rows = xcalloc(d->n_up ? d->n_up : 1, sizeof(*rows));
		if (rows) {
			for (k = 0; k < d->n_up; k++) {
				const struct up_row *u = &d->upatches[k];

				snprintf(rows[k].name, sizeof(rows[k].name),
					 "%.*s", (int)(sizeof(rows[k].name) - 1),
					 u->name);
				snprintf(rows[k].location,
					 sizeof(rows[k].location), "%.*s",
					 (int)(sizeof(rows[k].location) - 1),
					 u->location);
				snprintf(rows[k].loaded_at,
					 sizeof(rows[k].loaded_at), "%s",
					 u->loaded_at);
				snprintf(rows[k].payload_sha256,
					 sizeof(rows[k].payload_sha256), "%s",
					 u->payload_sha256);
				rows[k].n_maps = (uint32_t)u->n_maps;
				rows[k].age_sec = u->age_sec > 0 ? u->age_sec :
					shirudo_upatch_age_sec(u->loaded_at);
			}
			shirudo_upatch_table_print(rows, d->n_up);
			xfree(rows, (d->n_up ? d->n_up : 1) * sizeof(*rows));
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

	printf("\nAssets (%s):\n",
	       d->ats.root[0] ? d->ats.root : "/var/lib/shirudo");
	printf("  %-22s %s\n", "keys/cert.der",
	       d->ats.cert ? "present" : "absent");
	printf("  %-22s %s\n", "keys/signing_key.pem",
	       d->ats.signing_key ? "present" : "absent");
	printf("  %-22s %s\n", "keyring.serial",
	       d->ats.keyring_serial ? "present" : "absent");
	if (d->ats.eventlog)
		printf("  %-22s present (%lld bytes)\n", "eventlog",
		       (long long)d->ats.eventlog_bytes);
	else
		printf("  %-22s absent\n", "eventlog");
	if (!d->ats.upatches_seen)
		printf("  %-22s absent\n", "upatches/");
	else
		printf("  %-22s %lld .upatch\n", "upatches/",
		       (long long)d->ats.upatches);
	if (!d->ats.incoming_seen)
		printf("  %-22s absent\n", "incoming/");
	else if (d->ats.incoming == 0)
		printf("  %-22s empty\n", "incoming/");
	else
		printf("  %-22s %lld staged\n", "incoming/",
		       (long long)d->ats.incoming);
	printf("  %-22s %s\n", "bpffs/",
	       d->ats.bpffs_mounted ? "mounted" : "not mounted");

	if (d->n_kmsg) {
		printf("\nKernel log (last %zu lines, newest first):\n",
		       d->n_kmsg);
		for (i = d->n_kmsg; i-- > 0;)
			printf("  [%s]  %s\n", d->kmsg[i].ts, d->kmsg[i].msg);
	}

	if (d->n_kmod) {
		size_t last = 10;
		size_t shown = d->n_kmod < last ? d->n_kmod : last;

		printf("\nLoaded modules (total %zu, last %zu loads, "
		       "newest first):\n", d->n_kmod, shown);
		print_remote_kmod_recent(d, last);
		if (!show_full)
			printf("  (Use --show-full to show all loaded "
			       "modules in a dependency tree)\n");
		else {
			printf("\nDependency tree:\n");
			print_remote_kmod_tree(d);
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
	shirudo_json_kv_string(e, "status", nd_status(d));
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
	shirudo_json_kv_bool(e, "disabled",
			     d->icmp_status == SHIRUDO_ICMP_DISABLED);
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
		struct shirudo_conditions_input cin;
		struct shirudo_condition conds[4];
		size_t nc;

		node_detail_to_cond_input(d, &cin);
		nc = shirudo_conditions(&cin, conds, ARRAY_SIZE(conds));

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
		{
			struct shirudo_upatch_table_row *rows;
			size_t k;

			rows = xcalloc(d->n_up ? d->n_up : 1, sizeof(*rows));
			if (rows) {
				for (k = 0; k < d->n_up; k++) {
					const struct up_row *u = &d->upatches[k];

					snprintf(rows[k].name,
						 sizeof(rows[k].name), "%.*s",
						 (int)(sizeof(rows[k].name) - 1),
						 u->name);
					snprintf(rows[k].location,
						 sizeof(rows[k].location),
						 "%.*s",
						 (int)(sizeof(rows[k].location)
						       - 1),
						 u->location);
					snprintf(rows[k].loaded_at,
						 sizeof(rows[k].loaded_at), "%s",
						 u->loaded_at);
					snprintf(rows[k].payload_sha256,
						 sizeof(rows[k].payload_sha256),
						 "%s", u->payload_sha256);
					rows[k].n_maps = (uint32_t)u->n_maps;
					rows[k].age_sec = u->age_sec > 0 ?
						u->age_sec :
						shirudo_upatch_age_sec(
							u->loaded_at);
				}
				shirudo_upatch_table_emit_json(e, rows, d->n_up);
				xfree(rows, (d->n_up ? d->n_up : 1) *
					    sizeof(*rows));
			}
		}
		shirudo_sysinfo_emit_json(e, &d->sys);
		shirudo_json_obj_open_key(e, "assets");
		shirudo_json_kv_string(e, "root",
				       d->ats.root[0] ? d->ats.root
						      : "/var/lib/shirudo");
		shirudo_json_kv_bool(e, "cert", d->ats.cert);
		shirudo_json_kv_bool(e, "signing_key", d->ats.signing_key);
		shirudo_json_kv_bool(e, "keyring_serial",
				     d->ats.keyring_serial);
		shirudo_json_kv_bool(e, "eventlog", d->ats.eventlog);
		shirudo_json_kv_int(e, "eventlog_bytes",
				    d->ats.eventlog_bytes);
		if (d->ats.upatches_seen)
			shirudo_json_kv_int(e, "upatches", d->ats.upatches);
		else
			shirudo_json_kv_null(e, "upatches");
		if (d->ats.incoming_seen)
			shirudo_json_kv_int(e, "incoming", d->ats.incoming);
		else
			shirudo_json_kv_null(e, "incoming");
		shirudo_json_kv_bool(e, "bpffs_mounted",
				     d->ats.bpffs_mounted);
		shirudo_json_obj_close(e);	/* assets */
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
		shirudo_json_arr_open(e, "kernel_log");
		for (i = 0; i < d->n_kmsg; i++) {
			shirudo_json_obj_open(e);
			shirudo_json_kv_string(e, "ts", d->kmsg[i].ts);
			shirudo_json_kv_string(e, "msg", d->kmsg[i].msg);
			shirudo_json_obj_close(e);
		}
		shirudo_json_arr_close(e);
		if (d->boot_at[0])
			shirudo_json_kv_string(e, "boot_at", d->boot_at);
		shirudo_json_arr_open(e, "modules");
		for (i = 0; i < d->n_kmod; i++) {
			const struct kmod_row *m = &d->kmods[i];
			uint16_t k;

			shirudo_json_obj_open(e);
			shirudo_json_kv_string(e, "name", m->name);
			shirudo_json_kv_int(e, "size", m->size);
			shirudo_json_kv_int(e, "refcount", m->refcount);
			if (m->loaded_at[0])
				shirudo_json_kv_string(e, "loaded_at",
						       m->loaded_at);
			if (m->since_boot_seen)
				shirudo_json_kv_int(e, "since_boot_sec",
						    m->since_boot_sec);
			else
				shirudo_json_kv_null(e, "since_boot_sec");
			shirudo_json_arr_open(e, "deps");
			for (k = 0; k < m->n_deps; k++)
				shirudo_json_str(e,
					d->kdep_names[m->deps_off + k]);
			shirudo_json_arr_close(e);
			shirudo_json_obj_close(e);
		}
		shirudo_json_arr_close(e);
		/*
		 * Pass through the parsed upatch_maps[] verbatim so operator
		 * tooling sees the same structure regardless of whether it's
		 * reading shirudo nodes show --json or shirudo status --json
		 * on the target. Grouped by upatch.
		 */
		if (d->n_umap) {
			char prev[64] = "";
			size_t k;
			int in_obj = 0;

			shirudo_json_arr_open(e, "upatch_maps");
			for (k = 0; k < d->n_umap; k++) {
				const struct umap_row *m = &d->umaps[k];

				if (strcmp(prev, m->upatch) != 0) {
					if (in_obj) {
						shirudo_json_arr_close(e);
						shirudo_json_obj_close(e);
					}
					shirudo_json_obj_open(e);
					shirudo_json_kv_string(e, "upatch",
							       m->upatch);
					shirudo_json_arr_open(e, "maps");
					snprintf(prev, sizeof(prev), "%s",
						 m->upatch);
					in_obj = 1;
				}
				shirudo_json_obj_open(e);
				shirudo_json_kv_string(e, "name", m->name);
				shirudo_json_kv_string(e, "type", m->type);
				shirudo_json_kv_int(e, "max_entries",
						    m->max_entries);
				shirudo_json_kv_int(e, "n_entries",
						    m->n_entries);
				if (m->n_cpus > 1)
					shirudo_json_kv_int(e, "n_cpus",
							    m->n_cpus);
				shirudo_json_kv_bool(e, "truncated",
						     m->truncated);
				if (m->skipped[0])
					shirudo_json_kv_string(e, "skipped",
							       m->skipped);
				if (m->first_sum[0])
					shirudo_json_kv_string(e, "first_sum",
							       m->first_sum);
				shirudo_json_obj_close(e);
			}
			if (in_obj) {
				shirudo_json_arr_close(e);
				shirudo_json_obj_close(e);
			}
			shirudo_json_arr_close(e);
		}
		shirudo_json_obj_close(e);	/* status */
	}
	shirudo_json_obj_close(e);		/* node */
}

/*
 * NAME / LOCATION / MAPS / AGE table for `shirudo nodes show <name>
 * upatches`. AGE is "time since last upatch_load event for <name>" --
 * the same eventlog projection the upatches loaded section in the
 * full describe uses, so the columns agree across both views.
 */
static void print_upatches_table(const struct node_detail *d)
{
	size_t i;

	if (!d->reachable || !d->parsed) {
		printf("(%s)\n", d->unreach ? d->unreach : "unreachable");
		return;
	}
	if (d->n_up == 0) {
		printf("(no upatches loaded)\n");
		return;
	}
	printf("%-24s  %-28s  %5s  %s\n", "NAME", "LOCATION", "MAPS", "AGE");
	for (i = 0; i < d->n_up; i++) {
		const struct up_row *u = &d->upatches[i];
		const char *ts = NULL;
		char age[16] = "?";

		/*
		 * Prefer the pin dir ctime (always available on a live load,
		 * even after boot-restore where per-upatch eventlog entries
		 * are suppressed). Eventlog is the audit-grade fallback when
		 * we somehow have no ctime to show.
		 */
		if (u->loaded_at[0]) {
			ts = u->loaded_at;
		} else {
			const struct ev_row *ev = last_load_event_for(d,
								      u->name);
			if (ev)
				ts = ev->ts;
		}
		if (ts) {
			struct tm tm = {};

			if (strptime(ts, "%Y-%m-%dT%H:%M:%SZ", &tm))
				shirudo_format_duration(
					(long)(time(NULL) - timegm(&tm)),
					age, sizeof(age));
		}
		printf("%-24s  %-28s  %5lld  %s\n", u->name,
		       u->location[0] ? u->location : "-",
		       (long long)u->n_maps, age);
	}
}

/*
 * --json sibling of the table: a focused object scoped to one node,
 * not the full status report emit_node_json hands back. Same field
 * names as the table columns so jq pipelines compose.
 */
static int emit_upatches_json(const struct node_detail *d)
{
	size_t cap = 8192 + d->n_up * 512;
	struct shirudo_json_emit e;
	int ret = 0;
	char *buf;
	size_t i;

	if (cap > SHIRUDO_JSON_MAX_BYTES)
		cap = SHIRUDO_JSON_MAX_BYTES;
	buf = xmalloc(cap);
	if (!buf)
		return 1;
	e = (struct shirudo_json_emit){ .buf = buf, .cap = cap };
	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_kv_string(&e, "name", d->r->name);
	shirudo_json_kv_bool(&e, "reachable", d->reachable);
	if (!d->reachable || !d->parsed)
		shirudo_json_kv_string(&e, "error",
				       d->unreach ? d->unreach
						  : "status JSON unparseable");
	shirudo_json_arr_open(&e, "upatches");
	for (i = 0; i < d->n_up; i++) {
		const struct up_row *u = &d->upatches[i];
		const struct ev_row *ev = last_load_event_for(d, u->name);

		shirudo_json_obj_open(&e);
		shirudo_json_kv_string(&e, "name", u->name);
		shirudo_json_kv_string(&e, "location", u->location);
		shirudo_json_kv_int(&e, "n_maps", u->n_maps);
		shirudo_json_kv_string(&e, "loaded_at", u->loaded_at);
		if (ev)
			shirudo_json_kv_string(&e, "applied_ts", ev->ts);
		else
			shirudo_json_kv_null(&e, "applied_ts");
		shirudo_json_obj_close(&e);
	}
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);
	if (e.err) {
		pr_err("nodes show upatches: json encode failed: %s",
		       strerror(-e.err));
		ret = 1;
	} else {
		printf("%s\n", buf);
	}
	xfree(buf, cap);
	return ret;
}

static int cmd_nodes_show(int argc, const char **argv)
{
	struct shirudo_remote *remotes = NULL;
	struct node_detail *nodes = NULL;
	const char *names[256];
	const char *deep_upatch = NULL;
	size_t n_remotes = 0, nnames = 0, i, j;
	bool json = false, show_full = false, upatches_mode = false;
	int ret = 0;

	/* argv[0]="nodes", argv[1]="show"; options/names follow. */
	for (i = 2; i < (size_t)argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--json") == 0) {
			json = true;
		} else if (strcmp(a, "--show-full") == 0) {
			show_full = true;
		} else if (shirudo_is_help(a)) {
			shirudo_print_help(&nodes_show_help);
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
	/*
	 * Trailing `upatches [<upatch>]` switches view:
	 *   <name> upatches             -> per-node upatches table
	 *   <name> upatches <upatch>    -> deep-dive (proxy of
	 *                                  `shirudo upatch get <upatch>`
	 *                                  on the target).
	 * Single <name> only -- both are per-node views, not fleet aggregates.
	 */
	if (nnames >= 3 && strcmp(names[nnames - 2], "upatches") == 0) {
		upatches_mode = true;
		deep_upatch = names[nnames - 1];
		nnames -= 2;
	} else if (nnames >= 2 && strcmp(names[nnames - 1], "upatches") == 0) {
		upatches_mode = true;
		nnames--;
	}
	if (upatches_mode && nnames != 1) {
		fprintf(stderr,
			"nodes show: 'upatches' takes exactly one <name>%s\n",
			deep_upatch ? " plus an optional <upatch-name>" : "");
		return 2;
	}
	if (nnames == 0) {
		shirudo_print_help(&nodes_show_help);
		return 2;
	}

	shirudo_remotes_load_all(&remotes, &n_remotes);
	if (n_remotes == 0) {
		pr_err("nodes show: no remotes registered (see remotes.d)");
		return 1;
	}

	/*
	 * Deep-dive: skip the full `shirudo status` fetch entirely and
	 * just proxy `shirudo upatch get <upatch>` on the target. One SSH
	 * exec, no parsing on the operator side -- the target already
	 * renders the bundled view (program info + source + maps + BTF).
	 */
	if (deep_upatch) {
		const struct shirudo_remote *r = NULL;
		struct shirudo_ssh_session *sess;
		char cmd[256];
		char *out = NULL;
		size_t len = 0;
		int rc;

		if (!shirudo_upatch_name_valid(deep_upatch)) {
			pr_err("nodes show: invalid upatch name '%s'",
			       deep_upatch);
			shirudo_remotes_free(remotes, n_remotes);
			return 2;
		}
		for (i = 0; i < n_remotes; i++)
			if (strcmp(remotes[i].name, names[0]) == 0) {
				r = &remotes[i];
				break;
			}
		if (!r) {
			pr_err("nodes show: '%s' is not a registered remote",
			       names[0]);
			shirudo_remotes_free(remotes, n_remotes);
			return 1;
		}
		snprintf(cmd, sizeof(cmd),
			 "shirudo upatch get %s%s%s",
			 deep_upatch,
			 json ? " --json" : "",
			 show_full ? " --show-full" : "");
		sess = shirudo_ssh_connect(r->user, r->host, r->port);
		if (!sess) {
			pr_err("nodes show: ssh connect to '%s' failed",
			       r->name);
			shirudo_remotes_free(remotes, n_remotes);
			return 1;
		}
		rc = shirudo_ssh_exec(sess, cmd, &out, &len);
		shirudo_ssh_close(sess);
		if (rc < 0 || !out) {
			pr_err("nodes show: ssh exec on '%s' failed",
			       r->name);
			xfree(out, len);
			shirudo_remotes_free(remotes, n_remotes);
			return 1;
		}
		if (!json)
			printf("On node: %s (%s)\n\n", r->name, r->host);
		fwrite(out, 1, len, stdout);
		if (len && out[len - 1] != '\n')
			fputc('\n', stdout);
		xfree(out, len);
		shirudo_remotes_free(remotes, n_remotes);
		return 0;
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

	if (upatches_mode) {
		if (!nodes[0].r) {
			ret = 1;	/* unknown-name already diagnosed */
		} else if (json) {
			ret = emit_upatches_json(&nodes[0]);
		} else {
			print_upatches_table(&nodes[0]);
		}
	} else if (json) {
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
				print_describe(&nodes[j], show_full);
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
	if (argc >= 2 && shirudo_is_list_cmds(argv[1])) {
		shirudo_print_subcmd_list(nodes_subcmds,
					  ARRAY_SIZE(nodes_subcmds));
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
			const struct ev_row *init = NULL;

			if (!last && s->n_up > 0)
				init = last_init_event(s);
			shirudo_json_obj_open(&e);
			shirudo_json_kv_string(&e, "name", s->r->name);
			shirudo_json_kv_bool(&e, "reachable", s->reachable);
			shirudo_json_obj_open_key(&e, "icmp");
			shirudo_json_kv_bool(&e, "ok",
				s->icmp_status == SHIRUDO_ICMP_OK);
			shirudo_json_kv_bool(&e, "disabled",
				s->icmp_status == SHIRUDO_ICMP_DISABLED);
			if (s->icmp_status == SHIRUDO_ICMP_OK)
				shirudo_json_kv_int(&e, "rtt_us",
					(int64_t)s->icmp_rtt_us);
			else
				shirudo_json_kv_null(&e, "rtt_us");
			shirudo_json_obj_close(&e);
			shirudo_json_kv_string(&e, "status", nd_status(s));
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
				} else if (init) {
					shirudo_json_obj_open_key(&e, "last");
					shirudo_json_kv_string(&e, "verb", "init");
					shirudo_json_kv_string(&e, "name",
						s->upatches[0].name);
					shirudo_json_kv_string(&e, "ts",
						init->ts);
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
		printf("%-20s %-9s %-6s %-14s %-7s %s\n",
		       "NODE", "ICMP", "SSH", "STATUS", "UPTIME", "UPATCHES (LAST)");
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
			printf("%-20s %-9s %-6s %-14s %-7s %s\n",
			       s->r->name,
			       ping_str(s->icmp_status, s->icmp_rtt_us,
					pb, sizeof(pb)),
			       s->reachable ? "yes" : "no",
			       nd_status(s),
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
