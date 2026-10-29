// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef PHP_BAILOUT_TARGET
#define PHP_BAILOUT_TARGET "/tmp/shirudo-php2shell-php"
#endif

struct bailout_stats {
	__u64 hits;
	__u64 signal_errors;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bailout_stats);
} stats SEC(".maps");

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":_zend_bailout")
int php_bailout(struct pt_regs *ctx)
{
	struct bailout_stats *value;
	__u32 key = 0;
	long err;

	value = bpf_map_lookup_elem(&stats, &key);
	if (value)
		__sync_fetch_and_add(&value->hits, 1);
	err = bpf_send_signal(9);
	if (err && value)
		__sync_fetch_and_add(&value->signal_errors, 1);
	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
