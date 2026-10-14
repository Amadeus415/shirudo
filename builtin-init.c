// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Bootstrap shirudo enforcement on a target.
 */

#include <dirent.h>
#include <endian.h>
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
#include "util/bpm_tree.h"
#include "util/chain.h"
#include "util/config.h"
#include "util/eventlog.h"
#include "util/help.h"
#include "util/json.h"
#include "util/macros.h"
#include "util/identity.h"
#include "util/keyring.h"
#include "util/loader.h"
#include "util/log.h"
#include "util/malloc.h"
#include "util/paths.h"
#include "util/preflight.h"
#include "util/seal.h"
#include "util/tpm.h"
#include "util/upatch.h"
#include "util/upatch_resolve.h"

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

/* Set once init_keyring has chosen the trust anchor for this boot. */
static bool bpf_keyring_mode;

/*
 * The bpf keyring is the trust anchor a signed loader is verified
 * against once it is sealed. Booted with bpf.keyring_unsealed=1 it
 * takes keys until the first seal, which is init's job from the initrd:
 * enrol the certificate and seal. Found sealed, it either holds this
 * certificate (-EEXIST: use it) or was sealed empty by the kernel at
 * boot (-ENOKEY: the user keyring stages the certificate until the
 * target reboots into the production configuration); sealed around
 * someone else's key, it is refused.
 */
static int init_bpf_keyring(key_serial_t ring, const unsigned char *der,
			    size_t der_sz)
{
	key_serial_t key;
	int rc;

	key = shirudo_keyring_bpf_add_cert(der, der_sz);
	if (key >= 0) {
		rc = shirudo_keyring_bpf_seal();
		if (rc) {
			pr_err("bpf keyring: certificate enrolled but the "
			       "keyring could not be sealed: %s",
			       strerror(-rc));
			return rc;
		}
		pr_info("bpf keyring serial=%d: certificate enrolled (key "
			"serial=%d) and sealed", (int)ring, (int)key);
		return 0;
	}
	if (key != -EPERM && key != -EACCES) {
		pr_err("bpf keyring: add cert: %s", strerror(-key));
		if (key == -ENOENT || key == -ENOPKG)
			pr_err("kernel cannot verify this cert's public-key "
			       "algorithm (ML-DSA needs CONFIG_CRYPTO_MLDSA=y "
			       "and CONFIG_CRYPTO_SHA512=y; see "
			       "Documentation/requirements.rst)");
		return key;
	}
	rc = shirudo_keyring_holds_cert(ring, der, der_sz);
	if (rc < 0) {
		pr_err("bpf keyring: compare: %s", strerror(-rc));
		return rc;
	}
	if (rc) {
		pr_info("bpf keyring serial=%d: already enrolled and sealed "
			"this boot", (int)ring);
		return -EEXIST;
	}
	rc = keyring_has_cert(ring);
	if (rc < 0) {
		pr_err("bpf keyring: list: %s", strerror(-rc));
		return rc;
	}
	if (rc == 0)
		return -ENOKEY;
	pr_err("bpf keyring serial=%d is sealed around a certificate that is "
	       "not %s (tampered)", (int)ring, SHIRUDO_CERT_PATH);
	return -EKEYREJECTED;
}

static int init_keyring(void)
{
	struct shirudo_identity id;
	unsigned char *der = NULL;
	key_serial_t ring, key;
	size_t der_sz = 0;
	bool frozen;
	int rc;

	rc = read_cert_der(&der, &der_sz);
	if (rc) {
		pr_err("read %s: %s", SHIRUDO_CERT_PATH, strerror(-rc));
		return rc;
	}
	frozen = shirudo_identity_read(&id) == 0;

	ring = shirudo_keyring_bpf_serial();
	if (ring > 0) {
		rc = init_bpf_keyring(ring, der, der_sz);
		if (rc == 0 || rc == -EEXIST) {
			xfree(der, der_sz);
			if (frozen &&
			    (id.keyring_type != SHIRUDO_SIG_KEYRING_BPF ||
			     id.keyring_serial != ring)) {
				pr_err("bpf keyring serial=%d holds the "
				       "certificate, but the anchor frozen "
				       "this boot is another keyring "
				       "(tampered)", (int)ring);
				return -EKEYREJECTED;
			}
			bpf_keyring_mode = true;
			return 0;
		}
		if (rc != -ENOKEY) {
			xfree(der, der_sz);
			return rc;
		}
		pr_warn("bpf keyring serial=%d is sealed empty; staging the "
			"certificate in the user keyring. Boot with "
			"bpf.keyring_unsealed=1 and run init from the initrd "
			"for the production trust anchor", (int)ring);
	} else {
		pr_warn("kernel has no bpf keyring (%s); staging the "
			"certificate in the user keyring", strerror(-ring));
	}

	/*
	 * Staging. The keyring found by name must be the one whose serial
	 * init froze this boot, if it froze one: a substitute or a missing
	 * keyring cannot be repaired before the next boot, because the
	 * frozen identity is what lsm/bpf_prog_load enforces.
	 */
	ring = shirudo_keyring_find(SHIRUDO_KEYRING_NAME);
	if (frozen && id.keyring_type == SHIRUDO_SIG_KEYRING_USER &&
	    ring != id.keyring_serial) {
		pr_err("keyring \"%s\" is %s; the anchor frozen this boot is "
		       "serial %d, which only a reboot can replace (tampered)",
		       SHIRUDO_KEYRING_NAME, ring < 0 ? "gone" :
		       "not the one init sealed", (int)id.keyring_serial);
		xfree(der, der_sz);
		return -EKEYREJECTED;
	}
	if (ring >= 0) {
		rc = shirudo_keyring_holds_cert(ring, der, der_sz);
		if (rc > 0) {
			xfree(der, der_sz);
			rc = shirudo_keyring_seal(ring);
			if (rc && rc != -EACCES)
				pr_warn("keyring \"%s\": could not seal (mutable): %s",
					SHIRUDO_KEYRING_NAME, strerror(-rc));
			pr_info("keyring \"%s\" already present (serial=%d), sealed",
				SHIRUDO_KEYRING_NAME, (int)ring);
			return 0;
		}
		pr_warn("keyring \"%s\" serial=%d %s; recreating",
			SHIRUDO_KEYRING_NAME, (int)ring,
			rc == 0 ? "does not hold the certificate" :
			strerror(-rc));
		rc = shirudo_keyring_unlink_from_user(ring);
		if (rc) {
			pr_err("unlink stale keyring \"%s\": %s",
			       SHIRUDO_KEYRING_NAME, strerror(-rc));
			xfree(der, der_sz);
			return rc;
		}
	} else if (ring != -ENOKEY) {
		pr_err("lookup keyring \"%s\": %s",
		       SHIRUDO_KEYRING_NAME, strerror(-ring));
		xfree(der, der_sz);
		return ring;
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
		if (key == -ENOENT || key == -ENOPKG)
			pr_err("kernel cannot verify this cert's public-key "
			       "algorithm (ML-DSA needs CONFIG_CRYPTO_MLDSA=y "
			       "and CONFIG_CRYPTO_SHA512=y; see "
			       "Documentation/requirements.rst)");
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
	rc = mkdir_p_mode(SHIRUDO_RUN_DIR, 0700);
	if (rc) {
		pr_err("mkdir %s: %s", SHIRUDO_RUN_DIR, strerror(-rc));
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
 * Load seal.bpf.o and attach + pin its filesystem-sealing and exec hooks.
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
		{ "shirudo_seal_bprm_check_security",
		  SHIRUDO_SEAL_BPRM_CHECK_PIN },
		{ "shirudo_seal_bprm_committed_creds",
		  SHIRUDO_SEAL_BPRM_COMMITTED_PIN },
		{ "shirudo_seal_task_alloc",       SHIRUDO_SEAL_TASK_ALLOC_PIN },
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

static int init_lsm(bool attach_filesystem_seal)
{
	struct shirudo_identity id = {};
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
	const struct shirudo_embedded_bpf *blob = shirudo_bpf2_blob();
	struct bpf_program *p_bpf, *p_unlink, *p_setx, *p_rmx, *p_pload;
	struct bpf_object *obj = NULL, *seal_obj = NULL;
	struct bpf_link *link_bpf = NULL, *link_unlink = NULL;
	struct bpf_link *link_setx = NULL, *link_rmx = NULL, *link_pload = NULL;
	struct bpf_link *seal_links[8] = {};
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
	/* A pin without the links behind it is what a failed attempt leaves. */
	if (unlink(SHIRUDO_IDENTITY_PIN) != 0 && errno != ENOENT) {
		pr_err("unlink stale %s: %s", SHIRUDO_IDENTITY_PIN,
		       strerror(errno));
		return -errno;
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

	/*
	 * The trust anchor lsm/bpf_prog_load enforces: only a load the
	 * kernel verified against exactly this sealed keyring, of exactly
	 * this kind, is admitted from userspace. init_keyring has already
	 * enrolled the cert and sealed the keyring, so this resolves the
	 * serial the kernel records for a load that names it as keyring_id.
	 */
	if (bpf_keyring_mode) {
		keyring = shirudo_keyring_bpf_serial();
		id.keyring_type = SHIRUDO_SIG_KEYRING_BPF;
	} else {
		keyring = shirudo_keyring_find(SHIRUDO_KEYRING_NAME);
		id.keyring_type = SHIRUDO_SIG_KEYRING_USER;
	}
	if (keyring < 0) {
		err = keyring;
		pr_err("resolve the %s keyring serial: %s",
		       bpf_keyring_mode ? "bpf" : "\"shirudo\"",
		       strerror(-err));
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
	/*
	 * Pinned so that every later command reads the anchor init froze
	 * from the kernel rather than from a file: the serial a load names
	 * and status reports is the one lsm/bpf_prog_load enforces.
	 */
	if (bpf_obj_pin(map_fd, SHIRUDO_IDENTITY_PIN) != 0) {
		err = -errno;
		pr_err("pin identity map at %s: %s", SHIRUDO_IDENTITY_PIN,
		       strerror(errno));
		goto out;
	}

	p_unlink = bpf_object__find_program_by_name(obj,
						    "shirudo_lsm_inode_unlink");
	p_setx = bpf_object__find_program_by_name(obj,
						  "shirudo_lsm_inode_setxattr");
	p_rmx = bpf_object__find_program_by_name(obj,
						 "shirudo_lsm_inode_removexattr");
	p_pload = bpf_object__find_program_by_name(obj,
						   "shirudo_lsm_bpf_prog_load");
	p_bpf = bpf_object__find_program_by_name(obj, "shirudo_lsm_bpf");
	if (!p_unlink || !p_setx || !p_rmx || !p_pload || !p_bpf) {
		pr_err("expected programs missing in bpf2 object");
		err = -ENOENT;
		goto out;
	}

	/*
	 * Order: the bpffs guards (inode_unlink/setxattr/removexattr), then
	 * seal's filesystem and exec-identity hooks, then the bpf() gates
	 * (bpf_prog_load admission, then lsm/bpf) LAST. Pinning a link
	 * creates a bpffs inode, gated by neither guard set; seal's unsigned
	 * load and the identity-map freeze must both precede the load gates
	 * going live.
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

	if (attach_filesystem_seal) {
		err = attach_seal(&seal_obj, seal_links);
		if (err)
			goto out;
	}

	err = attach_pin(p_pload, SHIRUDO_LSM_PROG_LOAD_LINK_PIN, &link_pload);
	if (err) {
		pr_err("attach lsm/bpf_prog_load: %s", strerror(-err));
		goto out;
	}

	err = attach_pin(p_bpf, SHIRUDO_LSM_LINK_PIN, &link_bpf);
	if (err) {
		pr_err("attach lsm/bpf: %s", strerror(-err));
		goto out;
	}

	pr_info("bpf2%s attached: lsm/bpf gate live%s",
		attach_filesystem_seal ? " + seal" : "",
		attach_filesystem_seal ? ", bpffs and /var/lib/shirudo sealed" :
		", filesystem seal unavailable on this kernel");
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

static int select_upatch(const struct dirent *e)
{
	size_t n = strlen(e->d_name);

	return n > 7 && strcmp(e->d_name + n - 7, ".upatch") == 0;
}

/*
 * State an older shirudo may have left behind for features this
 * version no longer has: the trusted-root mode record, the Java agent
 * payload with its lock and JAVA_TOOL_OPTIONS selector, and persisted
 * Java-type upatches. None of it can load any more, and a Java upatch
 * would fail every boot-restore, so init removes it before labelling
 * the tree. The selector is removed only when shirudo wrote it.
 */
#define STALE_MODE_PATH		SHIRUDO_VAR_LIB "/mode"
#define STALE_JAVAAGENT_PATH	SHIRUDO_VAR_LIB "/javaagent.jar"
#define STALE_JAVAAGENT_LOCK	SHIRUDO_LOCKS_DIR "/javaagent.lock"
#define STALE_JAVAAGENT_ENV	"/etc/environment.d/shirudo.conf"
#define STALE_JAVAAGENT_ENV_HEAD \
	"JAVA_TOOL_OPTIONS=\"-javaagent:" STALE_JAVAAGENT_PATH
#define STALE_UPATCH_TYPE_JAVA	2u

static void unlink_stale(const char *path)
{
	if (unlink(path) == 0)
		pr_warn("init: removed stale %s", path);
	else if (errno != ENOENT)
		pr_warn("init: cannot remove stale %s: %s", path,
			strerror(errno));
}

static bool is_javaagent_env(void)
{
	static const char head[] = STALE_JAVAAGENT_ENV_HEAD;
	char buf[sizeof(head) - 1];
	ssize_t n;
	int fd;

	fd = open(STALE_JAVAAGENT_ENV, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return false;
	n = read(fd, buf, sizeof(buf));
	close(fd);
	return n == (ssize_t)sizeof(buf) && memcmp(buf, head, sizeof(buf)) == 0;
}

static bool is_java_upatch(const char *path)
{
	unsigned char hdr[SHIRUDO_UPATCH_HEADER_SIZE];
	uint32_t version, type, reserved;
	uint64_t magic;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0)
		return false;
	n = read(fd, hdr, sizeof(hdr));
	close(fd);
	if (n != (ssize_t)sizeof(hdr))
		return false;
	memcpy(&magic, hdr, sizeof(magic));
	memcpy(&version, hdr + 8, sizeof(version));
	memcpy(&type, hdr + SHIRUDO_UPATCH_LEGACY_HEADER_SIZE, sizeof(type));
	memcpy(&reserved, hdr + SHIRUDO_UPATCH_LEGACY_HEADER_SIZE + 4,
	       sizeof(reserved));
	return le64toh(magic) == SHIRUDO_UPATCH_MAGIC &&
	       le32toh(version) == SHIRUDO_UPATCH_VERSION &&
	       le32toh(type) == STALE_UPATCH_TYPE_JAVA && reserved == 0;
}

static void remove_stale_state(void)
{
	struct dirent **names = NULL;
	int n, i;

	unlink_stale(STALE_MODE_PATH);
	unlink_stale(STALE_JAVAAGENT_PATH);
	unlink_stale(STALE_JAVAAGENT_LOCK);
	if (is_javaagent_env())
		unlink_stale(STALE_JAVAAGENT_ENV);

	n = scandir(SHIRUDO_UPATCHES_DIR, &names, select_upatch, alphasort);
	for (i = 0; i < n; i++) {
		char path[PATH_MAX];

		if (snprintf(path, sizeof(path), "%s/%s", SHIRUDO_UPATCHES_DIR,
			     names[i]->d_name) < (int)sizeof(path) &&
		    is_java_upatch(path))
			unlink_stale(path);
		shirudo_libc_free(names[i]);	/* scandir-owned */
	}
	if (n >= 0)
		shirudo_libc_free(names);	/* scandir-owned */
}

/*
 * Boot-restore: re-apply the installed upatch set after a reboot.
 * Scans /var/lib/shirudo/upatches/ and runs each through the same
 * signed load + attach + pin path as `shirudo upatch load`. On a
 * re-run of init an upatch whose link is already pinned this boot is
 * counted and left alone, provided the payload the pin records is the
 * archived one; loading it again would only attach a second link to
 * fail at the pin. All-or-nothing: a single failure stops the sweep
 * and leaves init incomplete (the chain is not extended). On success,
 * returns the loaded set (sorted by upatch name) so the caller can
 * extend the measurement register by exactly one event over the whole
 * set. The set may be empty (no upatches installed) -- the init event
 * still fires.
 */
static int boot_restore(struct shirudo_measured_upatch **out_set, size_t *out_n)
{
	struct shirudo_measured_upatch *set = NULL;
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

	for (i = 0; i < n; i++) {
		char pinned_hex[2 * SHIRUDO_UPATCH_PAYLOAD_HASH_LEN + 1];
		char path[PATH_MAX];
		struct shirudo_upatch u;
		int fd;

		if (rc)
			goto next;
		if (snprintf(path, sizeof(path), "%s/%s", SHIRUDO_UPATCHES_DIR,
			     names[i]->d_name) >= (int)sizeof(path)) {
			pr_err("boot-restore: path too long: %s",
			       names[i]->d_name);
			rc = -ENAMETOOLONG;
			goto next;
		}
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
		fd = shirudo_upatch_open_first_link(set[cnt].name);
		if (fd >= 0) {
			close(fd);
			shirudo_upatch_payload_sha256(set[cnt].name, pinned_hex,
						      sizeof(pinned_hex));
			if (strcmp(pinned_hex, set[cnt].payload_hex) != 0) {
				pr_err("boot-restore: %s is loaded with a "
				       "payload other than the archived one "
				       "(tampered)", set[cnt].name);
				rc = -EINVAL;
				goto next;
			}
			pr_info("boot-restore: %s already loaded",
				set[cnt].name);
			cnt++;
			goto next;
		}
		if (shirudo_upatch_apply(path) != 0) {
			pr_err("boot-restore: failed to apply %s",
			       names[i]->d_name);
			rc = -EINVAL;
			goto next;
		}
		cnt++;
next:
		shirudo_libc_free(names[i]);	/* scandir-owned */
	}
	shirudo_libc_free(names);		/* scandir-owned */

	if (rc) {
		xfree(set, (size_t)n * sizeof(*set));
		return rc;
	}

	*out_set = set;
	*out_n = cnt;
	pr_info("boot-restore: %zu upatch%s re-applied", cnt,
		cnt == 1 ? "" : "es");
	return 0;
}

/*
 * Append the single "init" eventlog entry recording this boot's
 * register: the event digest, the set it covers, and the binding
 * (anchoring PCR value, index name, anchor record) a verifier needs
 * to recompute the register's public area.
 */
static int append_init_event(const struct shirudo_measured_upatch *set,
			     size_t n,
			     const uint8_t cert_sha[32],
			     const uint8_t set_digest[32],
			     const uint8_t tree_root[32],
			     const uint8_t init_digest[32],
			     const struct shirudo_chain_init_info *info)
{
	char buf[64 * 1024];
	struct shirudo_json_emit e = { .buf = buf, .cap = sizeof(buf) };
	char cert_hex[HEXLEN(32)], set_hex[HEXLEN(32)], digest_hex[HEXLEN(32)];
	char pcr_hex[HEXLEN(32)], anchor_hex[HEXLEN(32)], chain_hex[HEXLEN(32)];
	char phase_hex[HEXLEN(32)];
	char name_hex[HEXLEN(SHIRUDO_TPM_NAME_LEN)], tree_hex[HEXLEN(32)];
	char ts[32], boot_id[64], nv_index[16];
	size_t i;

	shirudo_eventlog_timestamp(ts, sizeof(ts));
	shirudo_eventlog_boot_id(boot_id, sizeof(boot_id));
	snprintf(nv_index, sizeof(nv_index), "0x%08X", SHIRUDO_NV_INDEX);
	shirudo_hex_encode(cert_sha, 32, cert_hex);
	shirudo_hex_encode(set_digest, 32, set_hex);
	shirudo_hex_encode(tree_root, 32, tree_hex);
	shirudo_hex_encode(init_digest, 32, digest_hex);
	shirudo_hex_encode(info->pcr_before, 32, pcr_hex);
	shirudo_hex_encode(info->phase_before, 32, phase_hex);
	shirudo_hex_encode(info->name, SHIRUDO_TPM_NAME_LEN, name_hex);
	shirudo_hex_encode(info->anchor_digest, 32, anchor_hex);
	shirudo_hex_encode(info->value, 32, chain_hex);

	shirudo_json_obj_open(&e);
	shirudo_json_kv_int(&e, "schema", 2);
	shirudo_json_kv_string(&e, "ts", ts);
	shirudo_json_kv_string(&e, "nv_index", nv_index);
	shirudo_json_kv_string(&e, "alg", "sha256");
	shirudo_json_kv_string(&e, "digest", digest_hex);
	shirudo_json_kv_string(&e, "type", "init");
	shirudo_json_kv_string(&e, "boot_id", boot_id);
	shirudo_json_kv_int(&e, "tpm_reset_count", info->reset_count);
	shirudo_json_kv_string(&e, "cert_sha256", cert_hex);
	shirudo_json_kv_string(&e, "set_digest", set_hex);
	shirudo_json_kv_string(&e, "tree_root", tree_hex);
	shirudo_json_arr_open(&e, "set");
	for (i = 0; i < n; i++) {
		shirudo_json_obj_open(&e);
		shirudo_json_kv_string(&e, "name", set[i].name);
		shirudo_json_kv_string(&e, "payload_sha256", set[i].payload_hex);
		shirudo_json_obj_close(&e);
	}
	shirudo_json_arr_close(&e);
	shirudo_json_kv_int(&e, "pcr", SHIRUDO_CHAIN_PCR);
	shirudo_json_kv_string(&e, "pcr_before", pcr_hex);
	shirudo_json_kv_int(&e, "phase_pcr", SHIRUDO_CHAIN_PHASE_PCR);
	shirudo_json_kv_string(&e, "phase_before", phase_hex);
	shirudo_json_kv_string(&e, "bound_in", info->initrd ? "initrd" : "root");
	shirudo_json_kv_string(&e, "nv_name", name_hex);
	shirudo_json_kv_string(&e, "anchor", info->anchor);
	shirudo_json_kv_string(&e, "anchor_digest", anchor_hex);
	shirudo_json_kv_string(&e, "chain", chain_hex);
	shirudo_json_obj_close(&e);

	if (e.err) {
		pr_err("eventlog: init entry encode failed: %s",
		       strerror(-e.err));
		return e.err;
	}
	return shirudo_eventlog_append(buf);
}

/* The upatch tree's projection root at boot, zeros when no tree is kept. */
static void tree_root_at_boot(uint8_t out[32])
{
	struct shirudo_tree_state s = {};

	memset(out, 0, 32);
	if (shirudo_tree_state_read(&s) == 0 &&
	    shirudo_hex_decode(s.projection_root, out, 32) != 0)
		memset(out, 0, 32);
}

/*
 * Bind this boot's register and extend it by one "init" event covering
 * the restored set, then append the matching eventlog entry. One
 * extension per boot regardless of upatch count (architecture.rst,
 * boot restore); a re-run of init finds the register written and on
 * record and leaves it alone. The register is mandatory: a TPM that
 * cannot be opened or an index that cannot be bound is a hard error
 * (category tpm_error), never an unmeasured init, because an
 * unmeasured target is indistinguishable from a tampered one.
 */
static int chain_extend_init(struct shirudo_measured_upatch *set, size_t n)
{
	uint8_t cert_sha[32], set_digest[32], tree_root[32], init_digest[32];
	struct shirudo_chain_init_info info;
	int rc;

	{
		struct shirudo_config cfg;
		unsigned long max_bytes;
		bool full;

		shirudo_config_load(&cfg);
		max_bytes = cfg.eventlog_max_bytes;
		full = shirudo_eventlog_would_exceed(max_bytes);
		explicit_bzero(&cfg, sizeof(cfg));	/* scrub tpm_owner_auth */
		if (full) {
			pr_err("eventlog %s would exceed eventlog.max_bytes=%lu; "
			       "refusing chain extend (eventlog_full)",
			       shirudo_eventlog_path(), max_bytes);
			return -ENOSPC;
		}
	}

	rc = shirudo_chain_cert_sha256(cert_sha);
	if (rc) {
		pr_err("chain: read %s: %s", SHIRUDO_CERT_PATH, strerror(-rc));
		return rc;
	}

	/*
	 * init_event = SHA256("shirudo-init\0" || cert_sha256 || set_digest
	 *                     || tree_root), the formula the operator's
	 * predictor shares (util/attest.c).
	 */
	tree_root_at_boot(tree_root);
	shirudo_chain_init_event(cert_sha, set, n, tree_root, set_digest,
				  init_digest);

	rc = shirudo_chain_init(init_digest, &info);
	if (rc == -ENODEV) {
		pr_err("tpm: not usable; shirudo requires a TPM 2.0 "
		       "(tpm_error)");
		return rc;
	}
	if (rc == -EEXIST) {
		pr_err("tpm: the register this boot recorded is gone or "
		       "replaced; refusing to bind another before the next "
		       "TPM reset (tampered)");
		return rc;
	}
	if (rc == -EACCES) {
		pr_err("tpm: register 0x%08X cannot be bound (tpm_error); on "
		       "a TPM with owner auth set, supply it via "
		       "tpm.owner_auth in /etc/shirudo/shirudo.conf or "
		       "SHIRUDO_TPM_OWNER_AUTH", SHIRUDO_NV_INDEX);
		return rc;
	}
	if (rc) {
		pr_err("tpm: register extend failed -- chain NOT advanced "
		       "while LSM active (tpm_error); operator must "
		       "reconcile");
		return rc;
	}
	if (info.reused) {
		pr_info("tpm: register already bound this boot; chain "
			"unchanged (index 0x%08X)", SHIRUDO_NV_INDEX);
		return 0;
	}

	rc = append_init_event(set, n, cert_sha, set_digest, tree_root,
			       init_digest, &info);
	if (rc) {
		pr_err("eventlog: append failed after extend -- chain/log "
		       "desync; operator must reconcile");
		return rc;
	}

	pr_info("tpm: register bound in the %s and extended (index 0x%08X, "
		"PCR %u anchored, %zu upatch%s in set)",
		info.initrd ? "initrd" : "root file system", SHIRUDO_NV_INDEX,
		SHIRUDO_CHAIN_PCR, n, n == 1 ? "" : "es");
	if (!info.initrd)
		pr_warn("tpm: init ran after the initrd; the register's binding "
			"can be told from an initrd one by PCR %u",
			SHIRUDO_CHAIN_PHASE_PCR);
	return 0;
}

static const struct shirudo_help_item init_options[] = {
	{ "--check-only", "run the pre-flight only; never touch kernel state" },
	{ "--no-seal",    "skip filesystem sealing when target LSM hooks are not sleepable" },
};

static const struct shirudo_help_section init_help_sections[] = {
	{ "options:", init_options,
	  ARRAY_SIZE(init_options) },
};

static const struct shirudo_help init_help = {
	.usage      = "shirudo init [--check-only] [--no-seal]",
	.summary    = "Bootstrap enforcement on this target. Idempotent; safe "
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
	struct shirudo_preflight_result res;
	bool check_only = false, no_seal = false;
	int i, rc;

	for (i = 1; i < argc; i++) {
		const char *a = argv[i];

		if (strcmp(a, "--check-only") == 0) {
			check_only = true;
		} else if (strcmp(a, "--no-seal") == 0) {
			no_seal = true;
		} else if (shirudo_is_help(a)) {
			shirudo_print_help(&init_help);
			return 0;
		} else {
			pr_err("init: unknown option '%s'", a);
			usage();
			return 2;
		}
	}

	shirudo_preflight_run(&res);
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
	remove_stale_state();

	rc = init_keyring();
	if (rc)
		return 1;

	/*
	 * Label the binary + the /var/lib/shirudo tree
	 * BEFORE init_lsm attaches seal, so the bulk setxattr is not gated
	 * by seal's own inode_setxattr hook.
	 */
	rc = shirudo_seal_label_tree();
	if (rc)
		pr_warn("init: seal label-walk incomplete: %s "
			"(some files may be unsealed)", strerror(-rc));

	rc = init_lsm(!no_seal);
	if (rc)
		return 1;

	{
		struct shirudo_measured_upatch *set = NULL;
		size_t n = 0;

		rc = boot_restore(&set, &n);
		if (rc) {
			pr_err("init: incomplete -- LSM active, but boot-restore "
			       "failed; re-run `shirudo init` after fixing the "
			       "upatch");
			xfree(set, n * sizeof(*set));
			return 1;
		}

		rc = chain_extend_init(set, n);
		xfree(set, n * sizeof(*set));
		if (rc) {
			pr_err("init: incomplete -- LSM active and upatches "
			       "loaded, but TPM register not advanced");
			return 1;
		}
	}

	pr_info("init: complete (LSM active%s)",
		no_seal ? ", filesystem seal skipped" :
		", bpffs sealed against VFS unlink");
	return 0;
}
