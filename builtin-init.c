// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Bootstrap the BPF LSM on a target.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <shirudo/upatch.h>

#include "builtin.h"
#include "util/chain.h"
#include "util/config.h"
#include "util/eventlog.h"
#include "util/help.h"
#include "util/json.h"
#include "util/macros.h"
#include "util/keyring.h"
#include "util/kernel_abi.h"
#include "util/loader.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/mode.h"
#include "util/paths.h"
#include "util/preflight.h"
#include "util/seal.h"
#include "util/tpm.h"
#include "util/upatch.h"

static void print_preflight(const struct shirudo_preflight_result *r)
{
	int i;

	printf("pre-flight checks:\n");
	for (i = 0; i < r->n; i++) {
		const struct shirudo_preflight_check *c = &r->checks[i];

		printf("  %-22s %s%s%s\n",
		       c->name,
		       c->ok ? "OK" : "FAIL",
		       c->detail[0] ? ": " : "",
		       c->detail);
	}
	printf("%d/%d passed (%d failed)\n",
	       r->n - r->n_failed, r->n, r->n_failed);
}

static int read_cert_der(unsigned char **out, size_t *out_sz)
{
	unsigned char *buf;
	struct stat st;
	ssize_t n;
	int fd;

	fd = open(SHIRUDO_CERT_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) < 0) {
		int rc = -errno;
		close(fd);
		return rc;
	}
	if (st.st_size <= 0 || st.st_size > 1u * 1024u * 1024u) {
		close(fd);
		return -EINVAL;
	}
	buf = xmalloc((size_t)st.st_size);
	if (!buf) {
		close(fd);
		return -ENOMEM;
	}
	n = read(fd, buf, (size_t)st.st_size);
	close(fd);
	if (n != st.st_size) {
		xfree(buf, (size_t)st.st_size);
		return -EIO;
	}
	*out = buf;
	*out_sz = (size_t)st.st_size;
	return 0;
}

/*
 * Record the keyring serial under the sealed tree so a later upatch
 * load can detect a same-named "shirudo" keyring being swapped in
 * under it (the resolved serial would stop matching). Best-effort:
 * the keyring scoping at load already confines trust to this keyring;
 * the pin only adds swap-detection. Labelled now so seal protects it.
 */
static void pin_keyring_serial(key_serial_t ring)
{
	int rc = shirudo_keyring_pin_serial(ring);

	if (rc) {
		pr_warn("keyring: could not pin serial to %s: %s",
			SHIRUDO_KEYRING_SERIAL_PATH, strerror(-rc));
		return;
	}
	rc = shirudo_seal_label(SHIRUDO_KEYRING_SERIAL_PATH);
	if (rc)
		pr_warn("keyring: could not seal-label %s: %s",
			SHIRUDO_KEYRING_SERIAL_PATH, strerror(-rc));
}

static void keyring_note_asymmetric(key_serial_t serial, const char *type,
				    const char *description, void *ud)
{
	bool *found = ud;

	(void)serial;
	(void)description;
	if (strcmp(type, "asymmetric") == 0)
		*found = true;
}

static int keyring_has_cert(key_serial_t ring)
{
	bool found = false;
	int rc = shirudo_keyring_list(ring, keyring_note_asymmetric, &found);

	if (rc)
		return rc;
	return found ? 1 : 0;
}

static int init_keyring(void)
{
	unsigned char *der = NULL;
	key_serial_t ring, key;
	size_t der_sz = 0;
	int rc;

	/*
	 * Idempotent only when the existing keyring is readable and contains
	 * an asymmetric cert. Older failed init attempts could leave an empty,
	 * unreadable keyring behind; replace that rather than accepting it.
	 */
	ring = shirudo_keyring_find(SHIRUDO_KEYRING_NAME);
	if (ring >= 0) {
		rc = keyring_has_cert(ring);
		if (rc > 0) {
			rc = shirudo_keyring_seal(ring);
			if (rc && rc != -EACCES)
				pr_warn("keyring \"%s\": could not seal (mutable): %s",
					SHIRUDO_KEYRING_NAME, strerror(-rc));
			pr_info("keyring \"%s\" already present (serial=%d), sealed",
				SHIRUDO_KEYRING_NAME, (int)ring);
			pin_keyring_serial(ring);
			return 0;
		}
		pr_warn("keyring \"%s\" serial=%d is %s; recreating",
			SHIRUDO_KEYRING_NAME, (int)ring,
			rc == 0 ? "empty" : strerror(-rc));
		rc = shirudo_keyring_unlink_from_user(ring);
		if (rc) {
			pr_err("unlink stale keyring \"%s\": %s",
			       SHIRUDO_KEYRING_NAME, strerror(-rc));
			return rc;
		}
	} else if (ring != -ENOKEY) {
		pr_err("lookup keyring \"%s\": %s",
		       SHIRUDO_KEYRING_NAME, strerror(-ring));
		return ring;
	}

	rc = read_cert_der(&der, &der_sz);
	if (rc) {
		pr_err("read %s: %s", SHIRUDO_CERT_PATH, strerror(-rc));
		return rc;
	}

	ring = shirudo_keyring_open_or_create(SHIRUDO_KEYRING_NAME);
	if (ring < 0) {
		pr_err("open/create keyring \"%s\": %s",
		       SHIRUDO_KEYRING_NAME, strerror(-ring));
		xfree(der, der_sz);
		return ring;
	}

	key = shirudo_keyring_add_cert(ring, der, der_sz);
	xfree(der, der_sz);
	if (key < 0) {
		pr_err("add cert to keyring: %s", strerror(-key));
		return key;
	}

	/*
	 * Freeze the keyring so no further key can be linked into it this
	 * boot -- a root attacker cannot drop in a second cert to make the
	 * kernel accept BPF they signed. Not fatal if it fails: the LSM
	 * still enforces; the keyring is just left mutable.
	 */
	rc = shirudo_keyring_seal(ring);
	if (rc)
		pr_warn("keyring \"%s\": could not seal (mutable): %s",
			SHIRUDO_KEYRING_NAME, strerror(-rc));

	pr_info("keyring \"%s\" serial=%d%s, cert key serial=%d",
		SHIRUDO_KEYRING_NAME, (int)ring, rc ? "" : " sealed",
		(int)key);
	pin_keyring_serial(ring);
	return 0;
}

static int is_bpffs_mounted(const char *path)
{
	FILE *f = fopen("/proc/self/mounts", "r");
	char line[4096];
	int found = 0;

	if (!f)
		return -errno;
	while (fgets(line, sizeof(line), f)) {
		char src[256], target[256], type[256];

		if (sscanf(line, "%255s %255s %255s",
			   src, target, type) != 3)
			continue;
		if (strcmp(target, path) == 0 && strcmp(type, "bpf") == 0) {
			found = 1;
			break;
		}
	}
	fclose(f);
	return found;
}

static int mkdir_p_mode(const char *path, mode_t mode)
{
	if (mkdir(path, mode) == 0) {
		if (chmod(path, mode) != 0)
			return -errno;
		return 0;
	}
	if (errno == EEXIST)
		return 0;
	return -errno;
}

static int init_bpffs(void)
{
	int rc;

	rc = mkdir_p_mode(SHIRUDO_VAR_LIB, 0700);
	if (rc) {
		pr_err("mkdir %s: %s", SHIRUDO_VAR_LIB, strerror(-rc));
		return rc;
	}
	rc = mkdir_p_mode(SHIRUDO_BPFFS_DIR, 0700);
	if (rc) {
		pr_err("mkdir %s: %s",
		       SHIRUDO_BPFFS_DIR, strerror(-rc));
		return rc;
	}

	rc = is_bpffs_mounted(SHIRUDO_BPFFS_DIR);
	if (rc < 0) {
		pr_err("read /proc/self/mounts: %s", strerror(-rc));
		return rc;
	}
	if (rc) {
		pr_info("bpffs already mounted at %s", SHIRUDO_BPFFS_DIR);
		return 0;
	}

	if (mount("bpf", SHIRUDO_BPFFS_DIR, "bpf",
		  MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=0700") != 0) {
		pr_err("mount bpffs at %s: %s",
		       SHIRUDO_BPFFS_DIR, strerror(errno));
		return -errno;
	}

	pr_info("mounted private bpffs at %s "
		"(mode=0700,nosuid,nodev,noexec)", SHIRUDO_BPFFS_DIR);
	return 0;
}

/*
 * Pack a userspace dev_t (glibc-encoded by stat) into the kernel's
 * internal dev_t encoding so the BPF program's read of
 * inode->i_sb->s_dev compares equal. Kernel uses MKDEV(major, minor)
 * == (major << 20) | minor.
 */
static uint32_t kernel_dev_t(dev_t st_dev)
{
	return ((uint32_t)major(st_dev) << 20) | (minor(st_dev) & 0xfffffu);
}

/* Attach a program and pin its link; *out is NULL on failure. */
static int attach_pin(struct bpf_program *p, const char *pin,
		      struct bpf_link **out)
{
	struct bpf_link *l;
	int err;

	*out = NULL;
	l = bpf_program__attach(p);
	err = libbpf_get_error(l);
	if (err)
		return err;
	if (bpf_link__pin(l, pin) != 0) {
		err = -errno;
		bpf_link__destroy(l);
		return err;
	}
	*out = l;
	return 0;
}

/*
 * Load seal.bpf.o and attach + pin its five filesystem-sealing hooks.
 * Keeps the object open via *obj_out (the caller tears it and the links
 * down together). Must run BEFORE lsm/bpf is attached: seal is loaded
 * unsigned and is not prog_type SYSCALL, so once the bpf() gate is live
 * it would refuse this very load -- the same bootstrap window bpf2 uses.
 */
static int attach_seal(struct bpf_object **obj_out, struct bpf_link **links)
{
	static const struct {
		const char	*prog;
		const char	*pin;
	} hooks[] = {
		{ "shirudo_seal_file_open",        SHIRUDO_SEAL_FILE_OPEN_PIN },
		{ "shirudo_seal_inode_unlink",     SHIRUDO_SEAL_UNLINK_PIN },
		{ "shirudo_seal_inode_rename",     SHIRUDO_SEAL_RENAME_PIN },
		{ "shirudo_seal_inode_setxattr",   SHIRUDO_SEAL_SETXATTR_PIN },
		{ "shirudo_seal_inode_removexattr", SHIRUDO_SEAL_RMXATTR_PIN },
	};
	const struct shirudo_embedded_bpf *blob = shirudo_seal_blob();
	struct bpf_object *obj;
	int err, i;

	*obj_out = NULL;
	if (!blob || !blob->data || !blob->size) {
		pr_err("embedded seal blob missing");
		return -ENOENT;
	}
	obj = bpf_object__open_mem(blob->data, blob->size, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		pr_err("seal: bpf_object__open_mem: %d", err);
		return err;
	}
	err = bpf_object__load(obj);
	if (err) {
		pr_err("seal: bpf_object__load: %d", err);
		bpf_object__close(obj);
		return err;
	}
	for (i = 0; i < (int)ARRAY_SIZE(hooks); i++) {
		struct bpf_program *p =
			bpf_object__find_program_by_name(obj, hooks[i].prog);

		if (!p) {
			pr_err("seal: program %s missing", hooks[i].prog);
			err = -ENOENT;
			break;
		}
		err = attach_pin(p, hooks[i].pin, &links[i]);
		if (err) {
			pr_err("seal: attach %s: %s", hooks[i].prog,
			       strerror(-err));
			break;
		}
	}
	if (err) {
		bpf_object__close(obj);
		return err;
	}
	*obj_out = obj;
	return 0;
}

static int init_lsm(enum shirudo_mode mode, bool native_signing)
{
	/* Must match struct shirudo_sb_id in bpf/bpf2.c byte-for-byte. */
	struct shirudo_sb_id {
		uint32_t	sb_dev;
		uint32_t	exe_dev;
		uint64_t	exe_ino;
		int32_t		keyring_serial;
		uint32_t	mode;
	} id = {};
	/*
	 * The four mount-lifecycle guards over shirudo's bpffs. Table-driven
	 * so the attach loop stays short; each pin is destroyed in the out:
	 * path via mount_links[].
	 */
	static const struct {
		const char	*prog;
		const char	*pin;
	} mount_hooks[] = {
		{ "shirudo_lsm_sb_umount",  SHIRUDO_SB_UMOUNT_LINK_PIN },
		{ "shirudo_lsm_move_mount", SHIRUDO_MOVE_MOUNT_LINK_PIN },
		{ "shirudo_lsm_sb_mount",   SHIRUDO_SB_MOUNT_LINK_PIN },
		{ "shirudo_lsm_sb_remount", SHIRUDO_SB_REMOUNT_LINK_PIN },
	};
	struct bpf_link *mount_links[ARRAY_SIZE(mount_hooks)] = {};
	const struct shirudo_embedded_bpf *blob = native_signing ?
		shirudo_bpf2_blob() : shirudo_bpf2_trusted_root_blob();
	struct bpf_program *p_bpf, *p_unlink, *p_setx, *p_rmx, *p_pload = NULL;
	struct bpf_object *obj = NULL, *seal_obj = NULL;
	struct bpf_link *link_bpf = NULL, *link_unlink = NULL;
	struct bpf_link *link_setx = NULL, *link_rmx = NULL, *link_pload = NULL;
	struct bpf_link *seal_links[5] = {};
	key_serial_t keyring;
	struct bpf_map *m_sb;
	struct stat st;
	uint32_t zero = 0;
	int err, map_fd, i;

	if (access(SHIRUDO_LSM_LINK_PIN, F_OK) == 0) {
		pr_info("bpf2 already attached (%s exists)",
			SHIRUDO_LSM_LINK_PIN);
		return 0;
	}

	if (!blob || !blob->data || !blob->size) {
		pr_err("embedded bpf2 blob missing");
		return -ENOENT;
	}

	obj = bpf_object__open_mem(blob->data, blob->size, NULL);
	err = libbpf_get_error(obj);
	if (err) {
		pr_err("bpf_object__open_mem: %d", err);
		return err;
	}

	err = bpf_object__load(obj);
	if (err) {
		pr_err("bpf_object__load: %d", err);
		goto out;
	}

	if (stat(SHIRUDO_BPFFS_DIR, &st) != 0) {
		err = -errno;
		pr_err("stat %s: %s", SHIRUDO_BPFFS_DIR, strerror(errno));
		goto out;
	}
	id.sb_dev = kernel_dev_t(st.st_dev);

	/*
	 * Record shirudo's own executable identity so the inode_unlink
	 * hook can tell shirudo's `upatch unload` from an attacker's
	 * `rm` of a pin. /proc/self/exe resolves to the running binary.
	 */
	if (stat("/proc/self/exe", &st) != 0) {
		err = -errno;
		pr_err("stat /proc/self/exe: %s", strerror(errno));
		goto out;
	}
	id.exe_dev = kernel_dev_t(st.st_dev);
	id.exe_ino = (uint64_t)st.st_ino;
	id.mode = mode == SHIRUDO_MODE_TRUSTED_ROOT ? 1 : 0;

	/*
	 * The trust anchor lsm/bpf_prog_load enforces: only a load the
	 * kernel verified against exactly this sealed keyring is admitted
	 * from userspace. init_keyring has already linked the cert and
	 * sealed the keyring, so this resolves the same serial the load
	 * path passes as keyring_id.
	 */
	keyring = shirudo_keyring_find(SHIRUDO_KEYRING_NAME);
	if (keyring < 0) {
		err = keyring;
		pr_err("resolve \"%s\" keyring serial: %s",
		       SHIRUDO_KEYRING_NAME, strerror(-err));
		goto out;
	}
	id.keyring_serial = (int32_t)keyring;

	m_sb = bpf_object__find_map_by_name(obj, "shirudo_bpffs_sb");
	if (!m_sb) {
		pr_err("shirudo_bpffs_sb map not in embedded bpf2");
		err = -ENOENT;
		goto out;
	}
	map_fd = bpf_map__fd(m_sb);
	if (bpf_map_update_elem(map_fd, &zero, &id, BPF_ANY) != 0) {
		err = -errno;
		pr_err("populate sb-identity map: %s", strerror(errno));
		goto out;
	}
	if (bpf_map_freeze(map_fd) != 0) {
		err = -errno;
		pr_err("freeze sb-identity map: %s", strerror(errno));
		goto out;
	}

	p_unlink = bpf_object__find_program_by_name(obj,
						    "shirudo_lsm_inode_unlink");
	p_setx = bpf_object__find_program_by_name(obj,
						  "shirudo_lsm_inode_setxattr");
	p_rmx = bpf_object__find_program_by_name(obj,
						 "shirudo_lsm_inode_removexattr");
	if (native_signing)
		p_pload = bpf_object__find_program_by_name(obj,
						   "shirudo_lsm_bpf_prog_load");
	p_bpf = bpf_object__find_program_by_name(obj, "shirudo_lsm_bpf");
	if (!p_unlink || !p_setx || !p_rmx || !p_bpf ||
	    (native_signing && !p_pload)) {
		pr_err("expected programs missing in bpf2 object");
		err = -ENOENT;
		goto out;
	}

	/*
	 * Order: the bpffs guards (inode_unlink/setxattr/removexattr), then
	 * seal's five regular-fs hooks, then the two bpf() gates
	 * (bpf_prog_load admission, then lsm/bpf) LAST. Pinning a link
	 * creates a bpffs inode, gated by neither guard set; seal's unsigned
	 * load and the identity-map freeze must both precede the load gates
	 * going live. lsm/bpf is attached last because its pin is the
	 * canonical "shirudo active" marker checked for idempotency and by
	 * `shirudo status`.
	 */
	err = attach_pin(p_unlink, SHIRUDO_INODE_UNLINK_LINK_PIN, &link_unlink);
	if (err) {
		pr_err("attach lsm/inode_unlink: %s", strerror(-err));
		goto out;
	}
	err = attach_pin(p_setx, SHIRUDO_INODE_SETXATTR_LINK_PIN, &link_setx);
	if (err) {
		pr_err("attach lsm/inode_setxattr: %s", strerror(-err));
		goto out;
	}
	err = attach_pin(p_rmx, SHIRUDO_INODE_RMXATTR_LINK_PIN, &link_rmx);
	if (err) {
		pr_err("attach lsm/inode_removexattr: %s", strerror(-err));
		goto out;
	}

	/*
	 * Mount-lifecycle guards over the bpffs -- attached here with the
	 * other bpffs guards so the mount is immutable before enforcement
	 * goes live. Without these a `umount` of the bpffs would drop every
	 * pin and detach all enforcement (the pins are the links' only
	 * reference, shirudo being agentless).
	 */
	for (i = 0; i < (int)ARRAY_SIZE(mount_hooks); i++) {
		struct bpf_program *p = bpf_object__find_program_by_name(
						obj, mount_hooks[i].prog);

		if (!p) {
			pr_err("program %s missing in bpf2 object",
			       mount_hooks[i].prog);
			err = -ENOENT;
			goto out;
		}
		err = attach_pin(p, mount_hooks[i].pin, &mount_links[i]);
		if (err) {
			pr_err("attach %s: %s", mount_hooks[i].prog,
			       strerror(-err));
			goto out;
		}
	}

	err = attach_seal(&seal_obj, seal_links);
	if (err)
		goto out;

	if (native_signing) {
		err = attach_pin(p_pload, SHIRUDO_LSM_PROG_LOAD_LINK_PIN,
				 &link_pload);
		if (err) {
			pr_err("attach lsm/bpf_prog_load: %s", strerror(-err));
			goto out;
		}
	}

	err = attach_pin(p_bpf, SHIRUDO_LSM_LINK_PIN, &link_bpf);
	if (err) {
		pr_err("attach lsm/bpf: %s", strerror(-err));
		goto out;
	}

	pr_info("bpf2 + seal attached: lsm/bpf gate live (%s), bpffs and "
		"/var/lib/shirudo sealed",
		native_signing ? "kernel signatures" : "trusted root fallback");
	err = 0;
out:
	for (i = 0; i < (int)ARRAY_SIZE(seal_links); i++)
		bpf_link__destroy(seal_links[i]);
	for (i = 0; i < (int)ARRAY_SIZE(mount_links); i++)
		bpf_link__destroy(mount_links[i]);
	bpf_object__close(seal_obj);
	bpf_link__destroy(link_bpf);
	bpf_link__destroy(link_pload);
	bpf_link__destroy(link_rmx);
	bpf_link__destroy(link_setx);
	bpf_link__destroy(link_unlink);
	bpf_object__close(obj);
	return err;
}

#define HEXLEN(n)	((n) * 2 + 1)

/* One member of the restored set, for set_digest and the eventlog. */
struct restore_entry {
	char	name[SHIRUDO_UPATCH_NAME_MAX + 1];
	char	payload_hex[HEXLEN(SHIRUDO_UPATCH_PAYLOAD_HASH_LEN)];
};

static int entry_cmp(const void *a, const void *b)
{
	return strcmp(((const struct restore_entry *)a)->name,
		      ((const struct restore_entry *)b)->name);
}

static int select_upatch(const struct dirent *e)
{
	size_t n = strlen(e->d_name);

	return n > 7 && strcmp(e->d_name + n - 7, ".upatch") == 0;
}

/*
 * Boot-restore: re-apply the installed upatch set after a reboot.
 * Scans /var/lib/shirudo/upatches/ and runs each through the same
 * signed load + attach + pin path as `shirudo upatch load`.
 * All-or-nothing: a single failure stops the sweep and leaves init
 * incomplete (the chain is not extended). On success, returns the
 * loaded set (sorted by upatch name) so the caller can extend the
 * measurement chain by exactly one event over the whole set. The set
 * may be empty (no upatches installed) -- the init event still fires.
 */
static int boot_restore(struct restore_entry **out_set, size_t *out_n)
{
	struct restore_entry *set = NULL;
	struct dirent **names = NULL;
	int n, i, rc = 0;
	size_t cnt = 0;

	*out_set = NULL;
	*out_n = 0;

	n = scandir(SHIRUDO_UPATCHES_DIR, &names, select_upatch, alphasort);
	if (n < 0) {
		if (errno == ENOENT)
			return 0;	/* nothing installed -- empty set */
		pr_err("boot-restore: scandir %s: %s",
		       SHIRUDO_UPATCHES_DIR, strerror(errno));
		return -errno;
	}
	if (n == 0) {
		shirudo_libc_free(names);	/* scandir-owned */
		return 0;
	}

	set = xcalloc((size_t)n, sizeof(*set));
	if (!set) {
		for (i = 0; i < n; i++)
			shirudo_libc_free(names[i]);	/* scandir-owned */
		shirudo_libc_free(names);		/* scandir-owned */
		return -ENOMEM;
	}

	pr_info("boot-restore: re-applying %d upatch%s from %s",
		n, n == 1 ? "" : "es", SHIRUDO_UPATCHES_DIR);

	/* Companion telemetry upatches must create their arena before the Java
	 * selector is restored. Persisted names are not a dependency order. */
	for (int pass = 0; pass < 2; pass++) {
		for (i = 0; i < n; i++) {
			char path[PATH_MAX];
			struct shirudo_upatch u;
			bool is_bpf;

			if (rc)
				continue;
			if (snprintf(path, sizeof(path), "%s/%s", SHIRUDO_UPATCHES_DIR,
				     names[i]->d_name) >= (int)sizeof(path)) {
				pr_err("boot-restore: path too long: %s",
				       names[i]->d_name);
				rc = -ENAMETOOLONG;
				continue;
			}
			if (shirudo_upatch_open(path, &u) != 0) {
				/* The normal apply path emits the detailed parse failure. */
				if (pass == 0)
					continue;
				rc = -EINVAL;
				continue;
			}
			is_bpf = u.hdr.type == SHIRUDO_UPATCH_TYPE_BPF;
			shirudo_upatch_close(&u);
			if ((pass == 0) != is_bpf)
				continue;
			/* Canonical name + payload hash for set_digest / eventlog. */
			if (shirudo_upatch_open(path, &u) == 0) {
				memcpy(set[cnt].name, u.hdr.name,
				       SHIRUDO_UPATCH_NAME_MAX);
				set[cnt].name[SHIRUDO_UPATCH_NAME_MAX] = '\0';
				shirudo_hex_encode(u.hdr.payload_sha256,
					   SHIRUDO_UPATCH_PAYLOAD_HASH_LEN,
					   set[cnt].payload_hex);
				shirudo_upatch_close(&u);
			}
			if (shirudo_upatch_apply(path) != 0) {
				pr_err("boot-restore: failed to apply %s",
				       names[i]->d_name);
				rc = -EINVAL;
				continue;
			}
			cnt++;
		}
	}
	for (i = 0; i < n; i++)
		shirudo_libc_free(names[i]);
	shirudo_libc_free(names);		/* scandir-owned */

	if (rc) {
		xfree(set, (size_t)n * sizeof(*set));
		return rc;
	}

	qsort(set, cnt, sizeof(*set), entry_cmp);
	*out_set = set;
	*out_n = cnt;
	pr_info("boot-restore: %zu upatch%s re-applied", cnt,
		cnt == 1 ? "" : "es");
	return 0;
}

/*
 * Append the single "init" eventlog entry recording this boot's chain
 * extension. The entry's digest is the per-event extension value, so
 * replaying the log reproduces the live NV value.
 */
static int append_init_event(const struct restore_entry *set, size_t n,
			     const uint8_t cert_sha[32],
			     const uint8_t set_digest[32],
			     const uint8_t init_digest[32])
{
	char buf[64 * 1024];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };
	char ts[32], boot_id[64], nv_index[16];
	char cert_hex[HEXLEN(32)], set_hex[HEXLEN(32)], digest_hex[HEXLEN(32)];
	size_t i;

	shirudo_eventlog_timestamp(ts, sizeof(ts));
	shirudo_eventlog_boot_id(boot_id, sizeof(boot_id));
	snprintf(nv_index, sizeof(nv_index), "0x%08X", SHIRUDO_NV_INDEX);
	shirudo_hex_encode(cert_sha, 32, cert_hex);
	shirudo_hex_encode(set_digest, 32, set_hex);
	shirudo_hex_encode(init_digest, 32, digest_hex);

	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 1);
	shirudo_json_kv_string(&e, "ts", ts);
	shirudo_json_kv_string(&e, "nv_index", nv_index);
	shirudo_json_kv_string(&e, "alg", "sha256");
	shirudo_json_kv_string(&e, "digest", digest_hex);
	shirudo_json_kv_string(&e, "type", "init");
	shirudo_json_kv_string(&e, "boot_id", boot_id);
	shirudo_json_kv_string(&e, "cert_sha256", cert_hex);
	shirudo_json_kv_string(&e, "set_digest", set_hex);
	shirudo_json_arr_open(&e, "set");
	for (i = 0; i < n; i++) {
		shirudo_json_obj_open(&e);
		shirudo_json_kv_string(&e, "name", set[i].name);
		shirudo_json_kv_string(&e, "payload_sha256", set[i].payload_hex);
		shirudo_json_obj_close(&e);
	}
	shirudo_json_arr_close(&e);
	shirudo_json_obj_close(&e);

	if (e.err) {
		pr_err("eventlog: init entry encode failed: %s",
		       strerror(-e.err));
		return e.err;
	}
	return shirudo_eventlog_append(buf);
}

/*
 * Extend the TPM2 NV measurement chain by one "init" event covering
 * the restored set, then append the matching eventlog entry. One
 * extension per boot regardless of upatch count (PLAN.md "Boot-restore
 * protocol"). With --no-tpm, or if the TPM/index is unusable, the
 * chain is left unmeasured (degraded mode) and init still completes.
 * An extend that fails after the index exists is a hard error: the LSM
 * is up but the chain is out of sync with reality (category tpm_error).
 */
static int chain_extend_init(const struct restore_entry *set, size_t n,
			     bool allow_no_tpm)
{
	uint8_t cert_sha[32], auth[32], set_digest[32], init_digest[32];
	uint8_t tag_buf[sizeof("shirudo-init") + 64];
	size_t taglen, listing_len = 0, off, i;
	struct shirudo_tpm *tpm = NULL;
	char *listing;
	int rc;

	if (allow_no_tpm) {
		pr_warn("tpm: --no-tpm, measurement chain not extended (degraded)");
		return 0;
	}

	{
		struct shirudo_config cfg;
		bool full;

		shirudo_config_load(&cfg);
		full = shirudo_eventlog_would_exceed(cfg.eventlog_max_bytes);
		explicit_bzero(&cfg, sizeof(cfg));	/* scrub tpm_owner_auth */
		if (full) {
			pr_err("eventlog %s would exceed eventlog.max_bytes=%lu; "
			       "refusing chain extend (eventlog_full)",
			       SHIRUDO_EVENTLOG_PATH, cfg.eventlog_max_bytes);
			return -ENOSPC;
		}
	}

	rc = shirudo_chain_cert_sha256(cert_sha);
	if (rc) {
		pr_err("chain: read %s: %s", SHIRUDO_CERT_PATH, strerror(-rc));
		return rc;
	}
	shirudo_chain_auth_value(cert_sha, auth);

	/* set_digest = SHA256(canonical sorted "<payload_hex> <name>\n" list) */
	for (i = 0; i < n; i++)
		listing_len += strlen(set[i].payload_hex) + 1 +
			       strlen(set[i].name) + 1;
	listing = xmalloc(listing_len + 1);
	if (!listing)
		return -ENOMEM;
	for (i = 0, off = 0; i < n; i++)
		off += (size_t)snprintf(listing + off, listing_len + 1 - off,
					"%s %s\n", set[i].payload_hex,
					set[i].name);
	shirudo_sha256(listing, listing_len, set_digest);
	xfree(listing, listing_len + 1);

	/* init_event = SHA256("shirudo-init\0" || cert_sha256 || set_digest) */
	taglen = sizeof("shirudo-init");
	memcpy(tag_buf, "shirudo-init", taglen);
	memcpy(tag_buf + taglen, cert_sha, 32);
	memcpy(tag_buf + taglen + 32, set_digest, 32);
	shirudo_sha256(tag_buf, taglen + 64, init_digest);

	rc = shirudo_tpm_open(&tpm);
	if (rc) {
		pr_warn("tpm: not usable (%s); measurement disabled (degraded)",
			strerror(-rc));
		return 0;
	}
	{
		struct shirudo_config cfg;

		shirudo_config_load(&cfg);
		rc = shirudo_tpm_nv_define(tpm, SHIRUDO_NV_INDEX, auth,
					   cfg.tpm_owner_auth,
					   cfg.tpm_owner_auth_len);
		explicit_bzero(&cfg, sizeof(cfg));
	}
	if (rc) {
		pr_warn("tpm: NV index 0x%08X cannot be defined; "
			"measurement disabled (degraded)", SHIRUDO_NV_INDEX);
		shirudo_tpm_close(tpm);
		return 0;
	}
	rc = shirudo_tpm_nv_extend(tpm, SHIRUDO_NV_INDEX, auth, init_digest);
	if (rc) {
		pr_err("tpm: NV_Extend failed -- chain NOT advanced while LSM "
		       "active (tpm_error); operator must reconcile");
		shirudo_tpm_close(tpm);
		return rc;
	}
	shirudo_tpm_close(tpm);

	rc = append_init_event(set, n, cert_sha, set_digest, init_digest);
	if (rc) {
		pr_err("eventlog: append failed after extend -- chain/log "
		       "desync; operator must reconcile");
		return rc;
	}

	pr_info("tpm: chain extended (index 0x%08X, %zu upatch%s in set)",
		SHIRUDO_NV_INDEX, n, n == 1 ? "" : "es");
	return 0;
}

static const struct shirudo_help_item init_options[] = {
	{ "--check-only", "run the pre-flight only; never touch kernel state" },
	{ "--no-tpm",     "proceed without TPM (degraded mode)" },
	{ "--trusted-root", "commit userspace signature verification fallback" },
};

static const struct shirudo_help_section init_help_sections[] = {
	{ "options:", init_options,
	  ARRAY_SIZE(init_options) },
};

static const struct shirudo_help init_help = {
	.usage      = "shirudo init [--check-only] [--no-tpm] [--trusted-root]",
	.summary    = "Bootstrap the BPF LSM on this target. Idempotent; safe "
		      "to re-run.\nThe pinned link survives the process exit.",
	.sections   = init_help_sections,
	.n_sections = sizeof(init_help_sections) /
		      sizeof(init_help_sections[0]),
};

static void usage(void)
{
	fprintf(stderr, "usage: %s\n", init_help.usage);
}

int cmd_init(int argc, const char **argv)
{
	struct shirudo_preflight_opts opts = {};
	struct shirudo_preflight_result res;
	struct shirudo_mode_state mode_state = {};
	uint8_t cert_sha256[32];
	enum shirudo_mode mode = SHIRUDO_MODE_UNTRUSTED_ROOT;
	bool mode_committed = false, native_signing = true;
	bool check_only = false;
	int i, rc;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--check-only") == 0) {
			check_only = true;
		} else if (strcmp(a, "--no-tpm") == 0) {
			opts.allow_no_tpm = true;
		} else if (strcmp(a, "--trusted-root") == 0) {
			mode = SHIRUDO_MODE_TRUSTED_ROOT;
		} else if (shirudo_is_help(a)) {
			shirudo_print_help(&init_help);
			return 0;
		} else {
			pr_err("init: unknown option '%s'", a);
			usage();
			return 2;
		}
	}

	rc = shirudo_mode_read(&mode_state);
	if (rc == 0) {
		mode_committed = true;
		if (mode_state.mode == SHIRUDO_MODE_UNTRUSTED_ROOT &&
			mode == SHIRUDO_MODE_TRUSTED_ROOT) {
			pr_err("init: trusted-root cannot downgrade an existing "
			       "untrusted-root commitment");
			return 1;
		}
		mode = mode_state.mode;
	} else if (rc != -ENOENT) {
		pr_err("init: invalid mode state %s: %s", SHIRUDO_MODE_PATH,
		       strerror(-rc));
		return 1;
	}
	rc = shirudo_chain_cert_sha256(cert_sha256);
	if (rc) {
		pr_err("init: read certificate digest: %s", strerror(-rc));
		return 1;
	}
	if (mode_committed &&
	    !shirudo_ct_eq(cert_sha256, mode_state.cert_sha256, 32)) {
		pr_err("init: certificate differs from the committed mode state");
		return 1;
	}
	opts.mode = mode;

	shirudo_preflight_run(&opts, &res);
	print_preflight(&res);

	if (res.n_failed > 0) {
		pr_err("init: pre-flight failed (%d/%d checks)",
		       res.n_failed, res.n);
		return 1;
	}

	if (check_only)
		return 0;

	rc = init_bpffs();
	if (rc)
		return 1;
	if (!mode_committed) {
		rc = shirudo_mode_commit(mode, cert_sha256);
		if (rc) {
			pr_err("init: commit mode state: %s", strerror(-rc));
			return 1;
		}
	}

	rc = init_keyring();
	if (rc)
		return 1;

	if (shirudo_kernel_abi_check(NULL, 0) != 0)
		native_signing = false;

	/*
	 * Label the binary + the /var/lib/shirudo tree (bpffs skipped)
	 * BEFORE init_lsm attaches seal, so the bulk setxattr is not gated
	 * by seal's own inode_setxattr hook.
	 */
	rc = shirudo_seal_label_tree();
	if (rc)
		pr_warn("init: seal label-walk incomplete: %s "
			"(some files may be unsealed)", strerror(-rc));

	rc = init_lsm(mode, native_signing);
	if (rc)
		return 1;

	{
		struct restore_entry *set = NULL;
		size_t n = 0;

		rc = boot_restore(&set, &n);
		if (rc) {
			pr_err("init: incomplete -- LSM active, but boot-restore "
			       "failed; re-run `shirudo init` after fixing the "
			       "upatch");
			xfree(set, n * sizeof(*set));
			return 1;
		}

		rc = chain_extend_init(set, n, opts.allow_no_tpm);
		xfree(set, n * sizeof(*set));
		if (rc) {
			pr_err("init: incomplete -- LSM active and upatches "
			       "loaded, but TPM chain not advanced");
			return 1;
		}
	}

	pr_info("init: complete (LSM active, bpffs sealed against VFS unlink)");
	return 0;
}
