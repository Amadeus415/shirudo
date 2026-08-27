/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Per-upatch resolvers shared by `shirudo status`, `shirudo nodes
 * show`, and `shirudo upatch get`: turn a loaded upatch's bpffs pin
 * into the attach-hook string (lsm/foo, fentry/bar, ...) and the
 * loaded-at timestamp (pin ctime).
 *
 * All operations are read-only bpf() ops + stat(2) on shirudo's
 * private bpffs -- LSM-allowed for the calling exe.
 */

#ifndef SHIRUDO_UTIL_UPATCH_RESOLVE_H
#define SHIRUDO_UTIL_UPATCH_RESOLVE_H

#include <stddef.h>

struct btf;

#define SHIRUDO_UPATCH_LOCATION_MAX	160

/*
 * Open the first pinned link for an upatch. Single-program upatches use
 * "link"; multi-program upatches use "link_0", "link_1", ...
 * Returns a link fd on success, negative errno on failure.
 */
int shirudo_upatch_open_first_link(const char *name);

/*
 * Resolve an upatch name to its SEC()-style attach string in `out`
 * (e.g. "lsm/socket_create", "fentry/tcp_v4_connect"). Returns 0 and
 * empty-string out on success; -errno otherwise. `vbtf` may be NULL
 * (the name resolution then degrades to bare prefix without hook).
 */
int shirudo_upatch_resolve_location(struct btf *vbtf, const char *name,
				    char *out, size_t cap);

/*
 * Stamp the pin directory ctime as an ISO-8601 UTC timestamp; "" on
 * failure or absence. Used as the AGE basis in the upatches table.
 */
void shirudo_upatch_loaded_at(const char *name, char *out, size_t cap);

/*
 * Read the bpffs `security.bpf.shirudo.payload` xattr (32 raw bytes)
 * and lowercase-hex-encode it. `cap` should be >= 65. Empty out on
 * any failure (pin absent, kernel without bpffs-xattr support, etc.).
 */
void shirudo_upatch_payload_sha256(const char *name, char *out, size_t cap);

#endif /* SHIRUDO_UTIL_UPATCH_RESOLVE_H */
