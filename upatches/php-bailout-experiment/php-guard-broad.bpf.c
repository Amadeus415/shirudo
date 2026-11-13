// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

#ifndef PHP_BAILOUT_TARGET
#define PHP_BAILOUT_TARGET "/tmp/shirudo-php2shell-php"
#endif

#include "php-exec.h"

struct guard_stats {
	__u64 oom;
	__u64 bailout;
	__u64 zend_error;
	__u64 php_error;
	__u64 multipart;
	__u64 signal_errors;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct guard_stats);
} stats SEC(".maps");

enum guard_reason {
	GUARD_OOM,
	GUARD_BAILOUT,
	GUARD_ZEND_ERROR,
	GUARD_PHP_ERROR,
	GUARD_MULTIPART,
};

static __always_inline void stop_worker(enum guard_reason reason)
{
	struct guard_stats *value;
	__u32 key = 0;
	long err;

	value = bpf_map_lookup_elem(&stats, &key);
	if (value) {
		switch (reason) {
		case GUARD_OOM:
			__sync_fetch_and_add(&value->oom, 1);
			break;
		case GUARD_BAILOUT:
			__sync_fetch_and_add(&value->bailout, 1);
			break;
		case GUARD_ZEND_ERROR:
			__sync_fetch_and_add(&value->zend_error, 1);
			break;
		case GUARD_PHP_ERROR:
			__sync_fetch_and_add(&value->php_error, 1);
			break;
		case GUARD_MULTIPART:
			__sync_fetch_and_add(&value->multipart, 1);
			break;
		}
	}
	err = bpf_send_signal(9);
	if (err && value)
		__sync_fetch_and_add(&value->signal_errors, 1);
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":zend_mm_safe_error")
int broad_oom(struct pt_regs *ctx)
{
	stop_worker(GUARD_OOM);
	return 0;
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":_zend_bailout")
int broad_bailout(struct pt_regs *ctx)
{
	stop_worker(GUARD_BAILOUT);
	return 0;
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":zend_error_zstr_at")
int broad_zend_error(struct pt_regs *ctx)
{
	stop_worker(GUARD_ZEND_ERROR);
	return 0;
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":php_error_cb")
int broad_php_error(struct pt_regs *ctx)
{
	stop_worker(GUARD_PHP_ERROR);
	return 0;
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":rfc1867_post_handler")
int broad_multipart(struct pt_regs *ctx)
{
	stop_worker(GUARD_MULTIPART);
	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
