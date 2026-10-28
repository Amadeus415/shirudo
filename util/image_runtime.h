/* SPDX-License-Identifier: BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */

#ifndef SHIRUDO_IMAGE_RUNTIME_H
#define SHIRUDO_IMAGE_RUNTIME_H

#include <shirudo/misc.h>

#include <stdint.h>

struct shirudo_config_update;
struct shirudo_trusted_set;

struct shirudo_config_update *shirudo_image_update_context(void);
int shirudo_image_bootstrap_load(void);
const __u8 *shirudo_image_runtime_root(void);
int shirudo_image_runtime_mount(void);
int shirudo_image_boot_keys(struct shirudo_trusted_set *set);
int shirudo_image_boot_keys_close(void);
int shirudo_image_boot(void);
int shirudo_image_boot_complete(void);
int shirudo_image_enter(const char *command, int argc, const char **argv);
void shirudo_image_leave(void);
int shirudo_image_update(const char *prefix);
int shirudo_image_status(void);

/*
 * The config state status reports: 0 with the selected config active,
 * -EINPROGRESS while an activation is pending, or the integrity error the
 * other commands refuse on; -ENODEV without activation state. root is the
 * selected or pending config's, zero when unknown.
 */
int shirudo_image_config_state(__u8 root[32]);

#endif /* SHIRUDO_IMAGE_RUNTIME_H */
