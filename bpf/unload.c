// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0)
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Signed UNLOAD-directive template. shirudo-build --unload patches
 * shirudo_unload_params via libbpf bpf_map__set_initial_value() on
 * the synthetic .rodata map, then runs gen_loader + CMS sign on
 * this object. Loading this signed program is the unload
 * authorization gate (the kernel verifies its CMS signature against
 * the keyring); the body returns 0 because the actual work runs in
 * userspace today -- shirudo VFS-unlinks the pin to detach, and does
 * the payload_mismatch compare against the bpf2-protected
 * security.bpf.shirudo.payload pin xattr. The signature-covered
 * expected_sha256 in .rodata is the value a future in-kernel
 * detach + compare would use once bpf_sys_bpf gains the
 * BPF_LINK_DETACH / BPF_OBJ_GET ops; until then
 * it documents intent and pins the value into the signature.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#define SHIRUDO_UPATCH_NAME_MAX	256
#define SHIRUDO_SHA256_LEN	32

struct shirudo_unload_params {
	char	name[SHIRUDO_UPATCH_NAME_MAX];
	__u8	expected_sha256[SHIRUDO_SHA256_LEN];
};

volatile const struct shirudo_unload_params shirudo_unload_params = {
	.name		 = "<unpatched>",
	.expected_sha256 = {},
};

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("syscall")
int shirudo_unload(void *ctx)
{
	/*
	 * TODO: look up /run/shirudo/bpffs/upatches/<name>/link
	 * via bpf_sys_bpf(BPF_OBJ_GET), cross-check the loaded upatch's
	 * payload_sha256 against the signature-covered
	 * shirudo_unload_params.expected_sha256, then BPF_LINK_DETACH +
	 * BPF_OBJ_UNPIN from kernel context. Blocked on bpf_sys_bpf()
	 * gaining those ops; until then the detach and
	 * payload compare run in userspace.
	 */
	(void)ctx;
	return 0;
}
