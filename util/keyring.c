// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Raw add_key(2)/keyctl(2) wrappers; no libkeyutils dependency.
 */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <linux/keyctl.h>

#include "keyring.h"
#include "io.h"
#include "malloc.h"
#include "paths.h"

#ifndef KEY_SPEC_USER_KEYRING
#define KEY_SPEC_USER_KEYRING	(-4)
#endif

/* keyring permission bits (avoid a libkeyutils dependency). */
#define KEY_POS_VIEW	0x01000000
#define KEY_POS_READ	0x02000000
#define KEY_POS_WRITE	0x04000000
#define KEY_POS_SEARCH	0x08000000
#define KEY_POS_LINK	0x10000000
#define KEY_POS_SETATTR	0x20000000
#define KEY_USR_VIEW	0x00010000
#define KEY_USR_READ	0x00020000
#define KEY_USR_WRITE	0x00040000
#define KEY_USR_SEARCH	0x00080000
#define KEY_USR_SETATTR	0x00200000

#ifndef KEY_SPEC_SESSION_KEYRING
#define KEY_SPEC_SESSION_KEYRING (-3)
#endif

static long sys_add_key(const char *type, const char *desc,
			const void *payload, size_t plen, key_serial_t ring)
{
	return syscall(__NR_add_key, type, desc, payload, plen, ring);
}

static long sys_keyctl(int cmd, long a, long b, long c, long d)
{
	return syscall(__NR_keyctl, cmd, a, b, c, d);
}

key_serial_t shirudo_keyring_find(const char *name)
{
	long ret = sys_keyctl(KEYCTL_SEARCH, KEY_SPEC_USER_KEYRING,
			      (long)"keyring", (long)name, 0);
	if (ret < 0)
		return (key_serial_t)-errno;
	return (key_serial_t)ret;
}

static int shirudo_keyring_make_mutable(key_serial_t keyring)
{
	/*
	 * A named keyring linked only from @u is not necessarily possessed by
	 * a systemd service process. Give root enough owner permission to
	 * populate it; init drops write/setattr again when sealing succeeds.
	 */
	long perm = KEY_POS_VIEW | KEY_POS_READ | KEY_POS_WRITE |
		    KEY_POS_SEARCH | KEY_POS_LINK | KEY_POS_SETATTR |
		    KEY_USR_VIEW | KEY_USR_READ | KEY_USR_WRITE |
		    KEY_USR_SEARCH | KEY_USR_SETATTR;

	if (sys_keyctl(KEYCTL_SETPERM, keyring, perm, 0, 0) < 0)
		return -errno;
	return 0;
}

key_serial_t shirudo_keyring_open_or_create(const char *name)
{
	key_serial_t s = shirudo_keyring_find(name);
	long ret;
	int rc;

	if (s != -ENOKEY)
		return s;	/* success, or some other error */

	ret = sys_add_key("keyring", name, NULL, 0,
			  KEY_SPEC_SESSION_KEYRING);
	if (ret < 0)
		return (key_serial_t)-errno;

	rc = shirudo_keyring_make_mutable((key_serial_t)ret);
	if (rc)
		return (key_serial_t)rc;

	if (sys_keyctl(KEYCTL_LINK, ret, KEY_SPEC_USER_KEYRING, 0, 0) < 0)
		return (key_serial_t)-errno;

	return (key_serial_t)ret;
}

int shirudo_keyring_unlink_from_user(key_serial_t keyring)
{
	if (sys_keyctl(KEYCTL_UNLINK, keyring, KEY_SPEC_USER_KEYRING, 0, 0) < 0)
		return -errno;
	return 0;
}

key_serial_t shirudo_keyring_add_cert(key_serial_t keyring,
				      const void *cert, size_t cert_len)
{
	long ret = sys_add_key("asymmetric", NULL, cert, cert_len, keyring);

	if (ret < 0)
		return (key_serial_t)-errno;
	return (key_serial_t)ret;
}

int shirudo_keyring_seal(key_serial_t keyring)
{
	/*
	 * Possessor + user keep view/read/search (so any root process can
	 * still search the cert at load); nobody keeps write/link/setattr.
	 * Once SETATTR is gone the perms are locked for the boot.
	 */
	long perm = KEY_POS_VIEW | KEY_POS_READ | KEY_POS_SEARCH |
		    KEY_USR_VIEW | KEY_USR_READ | KEY_USR_SEARCH;

	if (sys_keyctl(KEYCTL_SETPERM, keyring, perm, 0, 0) < 0)
		return -errno;
	return 0;
}

int shirudo_keyring_pin_serial(key_serial_t serial)
{
	char buf[16];
	int fd, len, rc = 0;

	len = snprintf(buf, sizeof(buf), "%d\n", (int)serial);
	if (len < 0 || (size_t)len >= sizeof(buf))
		return -EINVAL;

	fd = open(SHIRUDO_KEYRING_SERIAL_PATH,
		  O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	rc = shirudo_write_all(fd, buf, (size_t)len);
	if (close(fd) < 0 && !rc)
		rc = -errno;
	return rc;
}

key_serial_t shirudo_keyring_read_pinned_serial(void)
{
	char buf[32], *end;
	ssize_t n;
	long val;
	int fd;

	fd = open(SHIRUDO_KEYRING_SERIAL_PATH, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return (key_serial_t)-errno;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0)
		return (key_serial_t)-errno;

	buf[n] = '\0';
	errno = 0;
	val = strtol(buf, &end, 10);
	if (end == buf || (errno && val == 0))
		return (key_serial_t)-EINVAL;
	if (val < 1 || val > INT32_MAX)
		return (key_serial_t)-EINVAL;
	return (key_serial_t)val;
}

static int describe_key(key_serial_t serial,
			char *out, size_t out_sz)
{
	long ret = sys_keyctl(KEYCTL_DESCRIBE, serial, (long)out,
			      (long)out_sz, 0);
	if (ret < 0)
		return -errno;
	if ((size_t)ret > out_sz)
		return -ERANGE;
	return 0;
}

/* "type;uid;gid;perm;description" -> &type, &description */
static void split_describe(char *desc, const char **type,
			   const char **description)
{
	char *p = desc;
	int i;

	*type = desc;
	for (i = 0; i < 4; i++) {
		p = strchr(p, ';');
		if (!p) {
			*description = "";
			return;
		}
		if (i == 0)
			*p = '\0';
		p++;
	}
	*description = p;
}

int shirudo_keyring_list(key_serial_t keyring,
			 shirudo_keyring_cb cb, void *ud)
{
	key_serial_t *serials = NULL;
	size_t cap = 64 * sizeof(*serials);
	long ret;
	size_t n, i;

	serials = xmalloc(cap);
	if (!serials)
		return -ENOMEM;

	ret = sys_keyctl(KEYCTL_READ, keyring, (long)serials, (long)cap, 0);
	if (ret < 0) {
		xfree(serials, cap);
		return -errno;
	}
	if ((size_t)ret > cap) {
		void *bigger = xreallocarray(serials, cap, (size_t)ret, 1);

		if (!bigger) {
			xfree(serials, cap);
			return -ENOMEM;
		}
		serials = bigger;
		cap = (size_t)ret;
		ret = sys_keyctl(KEYCTL_READ, keyring, (long)serials,
				 (long)cap, 0);
		if (ret < 0) {
			xfree(serials, cap);
			return -errno;
		}
		/*
		 * The keyring can grow again between the two reads;
		 * KEYCTL_READ then returns the full size while filling only
		 * cap bytes. Clamp to what the buffer actually holds so the
		 * loop below never reads past the allocation.
		 */
		if ((size_t)ret > cap)
			ret = (long)cap;
	}

	n = (size_t)ret / sizeof(*serials);
	for (i = 0; i < n; i++) {
		char desc[512];
		const char *type, *description;

		if (describe_key(serials[i], desc, sizeof(desc)) != 0)
			continue;
		split_describe(desc, &type, &description);
		cb(serials[i], type, description, ud);
	}
	xfree(serials, cap);
	return 0;
}
