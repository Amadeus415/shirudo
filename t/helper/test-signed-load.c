// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Attempts the signed-loader load of a .upatch through the new
 * load-time fold path -- exactly the sequence builtin-upatch.c uses --
 * but against a caller-chosen keyring: the cert at argv[2] is added to
 * the process session keyring and that keyring's serial is passed as
 * attr.keyring_id. Prints "loaded" on success or "errno=<n>" on
 * failure (the errno the kernel returned from BPF_PROG_LOAD).
 *
 * Used by t1112 to show that a loader carrying a perfectly valid
 * signature -- one the kernel verifies (BPF_SIG_VERIFIED) -- is still
 * denied with EACCES by shirudo's lsm/bpf_prog_load admission hook when
 * the verifying keyring is not the sealed "shirudo" keyring. That is a
 * distinct outcome from t1105's ENOKEY (cert absent from the keyring):
 * here the signature passes and the hook is what refuses. No libbpf;
 * raw bpf() syscalls only.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <linux/bpf.h>
#include <linux/keyctl.h>
#include <openssl/evp.h>

#include "shirudo/upatch.h"

static long sys_bpf(int cmd, union bpf_attr *a)
{
	return syscall(__NR_bpf, cmd, a, sizeof(*a));
}

static uint32_t rd_le32(const void *p)
{
	uint32_t v;

	memcpy(&v, p, sizeof(v));
	return v;
}

int main(int argc, char **argv)
{
	const struct shirudo_upatch_header *h;
	uint8_t insns_sha[32];
	unsigned char *m, cert[8192];
	unsigned int shalen = 32;
	const void *insns, *sig, *data;
	int ufd, cfd, cn, map_fd, prog_fd, key = 0;
	long serial;
	union bpf_attr a;
	struct stat st;
	int fda[1];

	if (argc < 3) {
		fprintf(stderr, "usage: %s <upatch> <cert.der>\n", argv[0]);
		return 2;
	}

	ufd = open(argv[1], O_RDONLY);
	if (ufd < 0 || fstat(ufd, &st) != 0) {
		fprintf(stderr, "open %s: %s\n", argv[1], strerror(errno));
		return 2;
	}
	m = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, ufd, 0);
	if (m == MAP_FAILED) {
		fprintf(stderr, "mmap: %s\n", strerror(errno));
		return 2;
	}
	h = (const struct shirudo_upatch_header *)m;
	insns = m + rd_le32(&h->loader_insns_off);
	sig   = m + rd_le32(&h->signature_off);
	data  = m + rd_le32(&h->data_off);

	cfd = open(argv[2], O_RDONLY);
	if (cfd < 0) {
		fprintf(stderr, "open %s: %s\n", argv[2], strerror(errno));
		return 2;
	}
	cn = read(cfd, cert, sizeof(cert));
	close(cfd);
	if (cn <= 0) {
		fprintf(stderr, "read cert: short\n");
		return 2;
	}

	if (syscall(__NR_add_key, "asymmetric", "", cert, (size_t)cn,
		    KEY_SPEC_SESSION_KEYRING) < 0) {
		fprintf(stderr, "add_key cert: %s\n", strerror(errno));
		return 2;
	}
	/* keyring_id is the containing keyring's serial, not the key's. */
	serial = syscall(__NR_keyctl, KEYCTL_GET_KEYRING_ID,
			 KEY_SPEC_SESSION_KEYRING, 1);
	if (serial < 0) {
		fprintf(stderr, "get session keyring: %s\n", strerror(errno));
		return 2;
	}

	/* excl_prog_hash = SHA-256(insns): the map -> loader digest bind. */
	EVP_Digest(insns, rd_le32(&h->loader_insns_len), insns_sha, &shalen,
		   EVP_sha256(), NULL);

	memset(&a, 0, sizeof(a));
	a.map_type = BPF_MAP_TYPE_ARRAY;
	a.key_size = 4;
	a.value_size = rd_le32(&h->data_len);
	a.max_entries = 1;
	a.excl_prog_hash = (uint64_t)(uintptr_t)insns_sha;
	a.excl_prog_hash_size = sizeof(insns_sha);
	memcpy(a.map_name, "__loader.map", 12);
	map_fd = sys_bpf(BPF_MAP_CREATE, &a);
	if (map_fd < 0) {
		fprintf(stderr, "MAP_CREATE: %s\n", strerror(errno));
		return 2;
	}

	memset(&a, 0, sizeof(a));
	a.map_fd = map_fd;
	a.key = (uint64_t)(uintptr_t)&key;
	a.value = (uint64_t)(uintptr_t)data;
	if (sys_bpf(BPF_MAP_UPDATE_ELEM, &a) < 0) {
		fprintf(stderr, "UPDATE: %s\n", strerror(errno));
		return 2;
	}
	memset(&a, 0, sizeof(a));
	a.map_fd = map_fd;
	if (sys_bpf(BPF_MAP_FREEZE, &a) < 0) {
		fprintf(stderr, "FREEZE: %s\n", strerror(errno));
		return 2;
	}

	fda[0] = map_fd;
	memset(&a, 0, sizeof(a));
	a.prog_type = BPF_PROG_TYPE_SYSCALL;
	a.insn_cnt = rd_le32(&h->loader_insns_len) / sizeof(struct bpf_insn);
	a.insns = (uint64_t)(uintptr_t)insns;
	a.license = (uint64_t)(uintptr_t)"Dual BSD/GPL";
	a.prog_flags = BPF_F_SLEEPABLE;
	a.signature = (uint64_t)(uintptr_t)sig;
	a.signature_size = rd_le32(&h->signature_len);
	a.keyring_id = (int32_t)serial;
	a.fd_array = (uint64_t)(uintptr_t)fda;
	a.fd_array_cnt = 1;
	memcpy(a.prog_name, "sigtest", 7);
	prog_fd = sys_bpf(BPF_PROG_LOAD, &a);
	if (prog_fd >= 0) {
		printf("loaded\n");
		close(prog_fd);
		return 0;
	}
	printf("errno=%d\n", errno);
	return 0;
}
