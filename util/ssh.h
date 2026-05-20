/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libssh wrappers (session+authn, SFTP, exec channels).
 */

#ifndef SHIRUDO_SSH_H
#define SHIRUDO_SSH_H

#include <stddef.h>

struct shirudo_ssh_session;

struct shirudo_ssh_session *shirudo_ssh_connect(const char *user,
						const char *host, int port);
void shirudo_ssh_close(struct shirudo_ssh_session *s);

int shirudo_ssh_sftp_push(struct shirudo_ssh_session *s,
			  const char *local, const char *remote);
int shirudo_ssh_exec(struct shirudo_ssh_session *s, const char *cmd,
		     char **stdout_out, size_t *stdout_len);

#endif /* SHIRUDO_SSH_H */
