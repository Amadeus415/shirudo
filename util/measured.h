/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The measured set, which rust/src/util/measured.rs implements.
 */

#ifndef SHIRUDO_MEASURED_H
#define SHIRUDO_MEASURED_H

#include <stdbool.h>
#include <stddef.h>

/*
 * The set of upatches the eventlog records as loaded, each with the
 * payload of its load: an init record's set, with every later load
 * added and every unload removed, in order. measured_set_boot() folds
 * this boot's records and is -ENOENT when there are none;
 * measured_set_log() folds every boot's, an empty set when there is no
 * log yet.
 */
struct measured_set;

int measured_set_boot(struct measured_set **out);
int measured_set_log(struct measured_set **out);
bool measured_holds(const struct measured_set *s, const char *name,
		    const char *payload_hex);
void measured_set_free(struct measured_set *s);

struct measured_upatch;
struct upatch;

/* The name and payload an init record lists for the upatch u. */
void measured_upatch_of(struct measured_upatch *e, const struct upatch *u);

/*
 * A member added to the *n of set, which holds at most max: 0, -EINVAL
 * for one upatch_member_valid() refuses, -EEXIST for a name the set
 * holds, for an init event lists each upatch once and sorts by name, or
 * -E2BIG when the set is full.
 */
int measured_set_add(struct measured_upatch *set, size_t *n, size_t max,
		     const char *name, const char *payload_hex);

/*
 * The upatches pinned in the private bpffs, or archived with the seal
 * label, that the set does not hold with the payload their pin or
 * archive records: what a load stopped between its pins and its extend
 * leaves, an unload stopped after its extend, or an archive root
 * brought back after its unload. cb runs for each with its name, and
 * the archive's path, and a non-zero return ends the walk with that
 * value. The number found, or -errno when the pins or archives cannot
 * be read.
 */
int measured_unmeasured_pins(const struct measured_set *s,
			     int (*cb)(const char *name, void *ctx),
			     void *ctx);
int measured_unmeasured_archives(const struct measured_set *s,
				 int (*cb)(const char *name,
					   const char *path, void *ctx),
				 void *ctx);

#endif /* SHIRUDO_MEASURED_H */
