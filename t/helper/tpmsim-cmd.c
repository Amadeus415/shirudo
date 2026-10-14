// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * libtpms-backed TPM 2.0 for the tss2 "cmd" TCTI: commands on stdin,
 * responses on stdout, state kept under the directory in argv[1].
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libtpms/tpm_error.h>
#include <libtpms/tpm_library.h>

#define SIM_CMD_MAX	(64u * 1024u)

/* TPM2_Startup(TPM_SU_CLEAR): sent when no volatile state was restored. */
static const unsigned char startup_clear[] = {
	0x80, 0x01, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
};

static int read_full(int fd, void *buf, size_t n)
{
	unsigned char *p = buf;
	size_t off = 0;

	while (off < n) {
		ssize_t got = read(fd, p + off, n - off);

		if (got < 0 && errno == EINTR)
			continue;
		if (got <= 0)
			return -1;
		off += (size_t)got;
	}
	return 0;
}

static int write_full(int fd, const void *buf, size_t n)
{
	const unsigned char *p = buf;
	size_t off = 0;

	while (off < n) {
		ssize_t put = write(fd, p + off, n - off);

		if (put < 0 && errno == EINTR)
			continue;
		if (put <= 0)
			return -1;
		off += (size_t)put;
	}
	return 0;
}

static int load_blob(const char *path, unsigned char **out, uint32_t *len)
{
	unsigned char *buf;
	struct stat st;
	int fd;

	*out = NULL;
	*len = 0;
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (fstat(fd, &st) != 0 || st.st_size <= 0 ||
	    st.st_size > 16 * 1024 * 1024) {
		close(fd);
		return -1;
	}
	buf = malloc((size_t)st.st_size);
	if (!buf || read_full(fd, buf, (size_t)st.st_size) != 0) {
		free(buf);
		close(fd);
		return -1;
	}
	close(fd);
	*out = buf;
	*len = (uint32_t)st.st_size;
	return 0;
}

static int store_blob(const char *path, const unsigned char *buf,
		      uint32_t len)
{
	char tmp[4096 + 8];
	int fd, rc;

	snprintf(tmp, sizeof(tmp), "%s.tmp", path);
	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	rc = write_full(fd, buf, len);
	if (close(fd) != 0)
		rc = -1;
	if (rc == 0)
		rc = rename(tmp, path);
	return rc;
}

static int process(unsigned char **resp, uint32_t *resp_size,
		   uint32_t *resp_cap, const unsigned char *cmd, uint32_t len)
{
	TPM_RESULT r = TPMLIB_Process(resp, resp_size, resp_cap,
				      (unsigned char *)cmd, len);

	return r == TPM_SUCCESS ? 0 : -1;
}

static int save_state(const char *dir)
{
	static const struct {
		enum TPMLIB_StateType	type;
		const char		*name;
	} blobs[] = {
		{ TPMLIB_STATE_PERMANENT, "permanent" },
		{ TPMLIB_STATE_VOLATILE,  "volatile" },
	};
	char path[4096];
	size_t i;
	int rc = 0;

	for (i = 0; i < sizeof(blobs) / sizeof(blobs[0]); i++) {
		unsigned char *blob = NULL;
		uint32_t blob_len = 0;

		if (TPMLIB_GetState(blobs[i].type, &blob, &blob_len) !=
		    TPM_SUCCESS || !blob) {
			rc = -1;
			continue;
		}
		snprintf(path, sizeof(path), "%s/%s", dir, blobs[i].name);
		if (store_blob(path, blob, blob_len) != 0)
			rc = -1;
		free(blob);
	}
	return rc;
}

int main(int argc, char **argv)
{
	unsigned char *resp = NULL, *permanent = NULL, *vol = NULL;
	uint32_t resp_size = 0, resp_cap = 0, permanent_len, vol_len;
	char path[4096];
	int rc = 0;

	if (argc != 2) {
		fprintf(stderr, "usage: tpmsim-cmd <state-dir>\n");
		return 2;
	}
	if ((mkdir(argv[1], 0700) != 0 && errno != EEXIST) ||
	    chdir(argv[1]) != 0) {
		perror("tpmsim-cmd: state directory");
		return 1;
	}
	setenv("TPM_PATH", ".", 1);
	if (TPMLIB_ChooseTPMVersion(TPMLIB_TPM_VERSION_2) != TPM_SUCCESS) {
		fprintf(stderr, "tpmsim-cmd: TPM 2.0 unsupported by libtpms\n");
		return 1;
	}
	snprintf(path, sizeof(path), "permanent");
	if (load_blob(path, &permanent, &permanent_len) == 0 &&
	    TPMLIB_SetState(TPMLIB_STATE_PERMANENT, permanent,
			    permanent_len) != TPM_SUCCESS) {
		fprintf(stderr, "tpmsim-cmd: permanent state rejected\n");
		return 1;
	}
	snprintf(path, sizeof(path), "volatile");
	if (permanent && load_blob(path, &vol, &vol_len) == 0 &&
	    TPMLIB_SetState(TPMLIB_STATE_VOLATILE, vol, vol_len) !=
	    TPM_SUCCESS) {
		fprintf(stderr, "tpmsim-cmd: volatile state rejected\n");
		return 1;
	}
	if (TPMLIB_MainInit() != TPM_SUCCESS) {
		fprintf(stderr, "tpmsim-cmd: TPMLIB_MainInit failed\n");
		return 1;
	}
	/* No volatile state means a power cycle: PCRs and STCLEAR reset. */
	if (!vol && process(&resp, &resp_size, &resp_cap, startup_clear,
			    sizeof(startup_clear)) != 0) {
		fprintf(stderr, "tpmsim-cmd: TPM2_Startup failed\n");
		return 1;
	}

	for (;;) {
		unsigned char cmd[SIM_CMD_MAX];
		uint32_t len;

		if (read_full(STDIN_FILENO, cmd, 10) != 0)
			break;
		len = ((uint32_t)cmd[2] << 24) | ((uint32_t)cmd[3] << 16) |
		      ((uint32_t)cmd[4] << 8) | cmd[5];
		if (len < 10 || len > sizeof(cmd) ||
		    (len > 10 && read_full(STDIN_FILENO, cmd + 10,
					   len - 10) != 0)) {
			rc = 1;
			break;
		}
		if (process(&resp, &resp_size, &resp_cap, cmd, len) != 0 ||
		    write_full(STDOUT_FILENO, resp, resp_size) != 0) {
			rc = 1;
			break;
		}
	}
	if (save_state(".") != 0) {
		fprintf(stderr, "tpmsim-cmd: saving TPM state failed\n");
		rc = 1;
	}
	TPMLIB_Terminate();
	free(resp);
	free(permanent);
	free(vol);
	return rc;
}
