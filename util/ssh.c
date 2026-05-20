// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libssh wrappers: session + strict host-key verification + publickey
 * auth (ssh-agent and the operator's default keys) + exec channels.
 * shirudo never fork+execs ssh/scp/sftp; everything goes through
 * libssh linked into the binary.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <libssh/libssh.h>
#include <libssh/sftp.h>

#include "log.h"
#include "malloc.h"
#include "ssh.h"

#define SHIRUDO_SSH_CONNECT_TIMEOUT_S	8L

struct shirudo_ssh_session {
	ssh_session	s;
};

struct shirudo_ssh_session *shirudo_ssh_connect(const char *user,
						const char *host, int port)
{
	long timeout = SHIRUDO_SSH_CONNECT_TIMEOUT_S;
	struct shirudo_ssh_session *h;
	int verbosity = SSH_LOG_NONE;
	int rc;

	h = calloc(1, sizeof(*h));
	if (!h)
		return NULL;
	h->s = ssh_new();
	if (!h->s) {
		free(h);
		return NULL;
	}

	ssh_options_set(h->s, SSH_OPTIONS_HOST, host);
	ssh_options_set(h->s, SSH_OPTIONS_USER, user);
	ssh_options_set(h->s, SSH_OPTIONS_PORT, &port);
	ssh_options_set(h->s, SSH_OPTIONS_TIMEOUT, &timeout);
	ssh_options_set(h->s, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

	if (ssh_connect(h->s) != SSH_OK) {
		pr_err("ssh: connect %s@%s:%d: %s", user, host, port,
		       ssh_get_error(h->s));
		shirudo_ssh_close(h);
		return NULL;
	}

	/*
	 * Strict host-key verification: only an already-known, unchanged
	 * key proceeds. No trust-on-first-use -- an unknown or changed
	 * key fails loudly (the operator must add it to known_hosts out
	 * of band).
	 */
	rc = ssh_session_is_known_server(h->s);
	if (rc != SSH_KNOWN_HOSTS_OK) {
		const char *why =
			rc == SSH_KNOWN_HOSTS_CHANGED ? "host key CHANGED" :
			rc == SSH_KNOWN_HOSTS_UNKNOWN ? "host key unknown" :
			rc == SSH_KNOWN_HOSTS_NOT_FOUND ? "no known_hosts" :
			"host-key check failed";
		pr_err("ssh: %s@%s:%d: %s -- refusing (add to known_hosts)",
		       user, host, port, why);
		shirudo_ssh_close(h);
		return NULL;
	}

	if (ssh_userauth_publickey_auto(h->s, NULL, NULL) != SSH_AUTH_SUCCESS) {
		pr_err("ssh: %s@%s:%d: publickey auth failed: %s",
		       user, host, port, ssh_get_error(h->s));
		shirudo_ssh_close(h);
		return NULL;
	}
	return h;
}

void shirudo_ssh_close(struct shirudo_ssh_session *h)
{
	if (!h)
		return;
	if (h->s) {
		if (ssh_is_connected(h->s))
			ssh_disconnect(h->s);
		ssh_free(h->s);
	}
	free(h);
}

/* Upload local -> remote via SFTP, creating the parent dir if needed. */
int shirudo_ssh_sftp_push(struct shirudo_ssh_session *h,
			  const char *local, const char *remote)
{
	char *slash, dir[1024], chunk[65536];
	sftp_session sftp;
	sftp_file rf;
	size_t got;
	int rc = 0;
	FILE *lf;

	sftp = sftp_new(h->s);
	if (!sftp)
		return -EIO;
	if (sftp_init(sftp) != SSH_OK) {
		sftp_free(sftp);
		return -EIO;
	}

	/* Best-effort mkdir of the parent directory. */
	slash = strrchr(remote, '/');
	if (slash && (size_t)(slash - remote) < sizeof(dir)) {
		memcpy(dir, remote, slash - remote);
		dir[slash - remote] = '\0';
		if (dir[0])
			sftp_mkdir(sftp, dir, 0700);	/* ignore EEXIST */
	}

	lf = fopen(local, "rb");
	if (!lf) {
		rc = -errno;
		sftp_free(sftp);
		return rc;
	}
	rf = sftp_open(sftp, remote, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (!rf) {
		fclose(lf);
		sftp_free(sftp);
		return -EIO;
	}

	while ((got = fread(chunk, 1, sizeof(chunk), lf)) > 0) {
		if (sftp_write(rf, chunk, got) != (ssize_t)got) {
			rc = -EIO;
			break;
		}
	}
	if (!rc && ferror(lf))
		rc = -EIO;

	sftp_close(rf);
	fclose(lf);
	sftp_free(sftp);
	return rc;
}

/*
 * Run cmd, capturing stdout into a freshly-allocated NUL-terminated
 * buffer. Returns the remote exit status (>= 0) on success, or a
 * negative -errno on a local/transport failure.
 */
int shirudo_ssh_exec(struct shirudo_ssh_session *h, const char *cmd,
		     char **stdout_out, size_t *stdout_len)
{
	size_t len = 0, cap = 0;
	int rc, exit_status;
	char *buf = NULL;
	ssh_channel ch;

	*stdout_out = NULL;
	*stdout_len = 0;

	ch = ssh_channel_new(h->s);
	if (!ch)
		return -ENOMEM;
	if (ssh_channel_open_session(ch) != SSH_OK) {
		ssh_channel_free(ch);
		return -EIO;
	}
	if (ssh_channel_request_exec(ch, cmd) != SSH_OK) {
		ssh_channel_close(ch);
		ssh_channel_free(ch);
		return -EIO;
	}

	for (;;) {
		char chunk[4096];

		rc = ssh_channel_read(ch, chunk, sizeof(chunk), 0);
		if (rc < 0) {
			xfree(buf, cap);
			ssh_channel_close(ch);
			ssh_channel_free(ch);
			return -EIO;
		}
		if (rc == 0)
			break;		/* EOF */
		if (len + (size_t)rc + 1 > cap) {
			size_t ncap = cap ? cap * 2 : 8192;
			char *nb;

			while (ncap < len + (size_t)rc + 1)
				ncap *= 2;
			nb = xreallocarray(buf, cap, ncap, 1);
			if (!nb) {
				xfree(buf, cap);
				ssh_channel_close(ch);
				ssh_channel_free(ch);
				return -ENOMEM;
			}
			buf = nb;
			cap = ncap;
		}
		memcpy(buf + len, chunk, (size_t)rc);
		len += (size_t)rc;
	}

	exit_status = ssh_channel_get_exit_status(ch);
	ssh_channel_send_eof(ch);
	ssh_channel_close(ch);
	ssh_channel_free(ch);

	if (!buf) {
		buf = xmalloc(1);
		if (!buf)
			return -ENOMEM;
	}
	buf[len] = '\0';
	*stdout_out = buf;
	*stdout_len = len;
	return exit_status < 0 ? 0 : exit_status;
}
