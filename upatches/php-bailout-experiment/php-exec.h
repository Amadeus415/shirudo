/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/* Copyright (c) 2026 Authors of shirudo */
#ifndef SHIRUDO_PHP_EXEC_H
#define SHIRUDO_PHP_EXEC_H

#include <bpf/bpf_tracing.h>

#define PHP_EXEC_EPERM 1
#define PHP_EXEC_ENOMEM 12

struct php_exec_stats {
	__u64 marked;
	__u64 denied;
	__u64 inherited;
	__u64 mark_errors;
	__u64 fork_errors;
	__u64 signal_errors;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct php_exec_stats);
} exec_stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u8);
} php_workers SEC(".maps");

static __always_inline struct php_exec_stats *php_exec_stats_get(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&exec_stats, &key);
}

/* Keep the worker marked between requests, including request shutdown. */
SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":php_request_startup")
int php_exec_mark(struct pt_regs *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct php_exec_stats *value = php_exec_stats_get();
	__u8 *marked;
	long err;

	marked = bpf_task_storage_get(&php_workers, task, NULL,
				      BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (marked) {
		if (!*marked && value)
			__sync_fetch_and_add(&value->marked, 1);
		*marked = 1;
		return 0;
	}
	if (value)
		__sync_fetch_and_add(&value->mark_errors, 1);
	err = bpf_send_signal(9);
	if (err && value)
		__sync_fetch_and_add(&value->signal_errors, 1);
	return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(php_exec_inherit, struct task_struct *child,
	     unsigned long clone_flags, int ret)
{
	struct task_struct *parent = bpf_get_current_task_btf();
	struct php_exec_stats *value;
	__u8 *marked;

	if (ret)
		return ret;
	marked = bpf_task_storage_get(&php_workers, parent, NULL, 0);
	if (!marked || !*marked)
		return 0;
	value = php_exec_stats_get();
	marked = bpf_task_storage_get(&php_workers, child, NULL,
				      BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!marked) {
		if (value)
			__sync_fetch_and_add(&value->fork_errors, 1);
		return -PHP_EXEC_ENOMEM;
	}
	*marked = 1;
	if (value)
		__sync_fetch_and_add(&value->inherited, 1);
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(php_exec_deny, struct linux_binprm *bprm, int ret)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct php_exec_stats *value;
	__u8 *marked;

	if (ret)
		return ret;
	marked = bpf_task_storage_get(&php_workers, task, NULL, 0);
	if (!marked || !*marked)
		return 0;
	value = php_exec_stats_get();
	if (value)
		__sync_fetch_and_add(&value->denied, 1);
	return -PHP_EXEC_EPERM;
}

#endif
