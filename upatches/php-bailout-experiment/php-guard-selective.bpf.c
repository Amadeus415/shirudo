// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2026 Authors of shirudo */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#ifndef PHP_BAILOUT_TARGET
#define PHP_BAILOUT_TARGET "/tmp/shirudo-php2shell-php"
#endif

#include "php-exec.h"

/* E_FATAL_ERRORS from the PHP 8.4 and 8.5 zend_errors.h headers. */
#define PHP_FATAL_ERRORS (1 | 4 | 16 | 64 | 256 | 4096)

struct guard_stats {
	__u64 oom;
	__u64 bailout;
	__u64 fatal;
	__u64 early_diagnostic;
	__u64 early_session;
	__u64 allowed_diagnostic;
	__u64 phase_errors;
	__u64 signal_errors;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct guard_stats);
} stats SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, __u8);
} application_tasks SEC(".maps");

enum guard_reason {
	GUARD_OOM,
	GUARD_BAILOUT,
	GUARD_FATAL,
	GUARD_EARLY_DIAGNOSTIC,
	GUARD_EARLY_SESSION,
};

static __always_inline struct guard_stats *guard_stats_get(void)
{
	__u32 key = 0;

	return bpf_map_lookup_elem(&stats, &key);
}

static __always_inline void stop_worker(enum guard_reason reason)
{
	struct guard_stats *value = guard_stats_get();
	long err;

	if (value) {
		switch (reason) {
		case GUARD_OOM:
			__sync_fetch_and_add(&value->oom, 1);
			break;
		case GUARD_BAILOUT:
			__sync_fetch_and_add(&value->bailout, 1);
			break;
		case GUARD_FATAL:
			__sync_fetch_and_add(&value->fatal, 1);
			break;
		case GUARD_EARLY_DIAGNOSTIC:
			__sync_fetch_and_add(&value->early_diagnostic, 1);
			break;
		case GUARD_EARLY_SESSION:
			__sync_fetch_and_add(&value->early_session, 1);
			break;
		}
	}
	err = bpf_send_signal(9);
	if (err && value)
		__sync_fetch_and_add(&value->signal_errors, 1);
}

static __always_inline bool in_application(void)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u8 *state;

	state = bpf_task_storage_get(&application_tasks, task, 0, 0);
	return state && *state;
}

static __always_inline void clear_application(void)
{
	struct task_struct *task = bpf_get_current_task_btf();
	__u8 *state;

	state = bpf_task_storage_get(&application_tasks, task, 0, 0);
	if (state)
		*state = 0;
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":php_request_startup")
int selective_request_startup(struct pt_regs *ctx)
{
	clear_application();
	return 0;
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":php_execute_script")
int selective_script_start(struct pt_regs *ctx)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct guard_stats *value;
	__u8 *state;

	state = bpf_task_storage_get(&application_tasks, task, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (state) {
		*state = 1;
	} else {
		value = guard_stats_get();
		if (value)
			__sync_fetch_and_add(&value->phase_errors, 1);
	}
	return 0;
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":php_request_shutdown")
int selective_request_shutdown(struct pt_regs *ctx)
{
	clear_application();
	return 0;
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":zend_mm_safe_error")
int selective_oom(struct pt_regs *ctx)
{
	stop_worker(GUARD_OOM);
	return 0;
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":_zend_bailout")
int selective_bailout(struct pt_regs *ctx)
{
	stop_worker(GUARD_BAILOUT);
	return 0;
}

static __always_inline void check_diagnostic(struct pt_regs *ctx)
{
	struct guard_stats *value;
	int type = (int)PT_REGS_PARM1(ctx);

	if (type & PHP_FATAL_ERRORS) {
		stop_worker(GUARD_FATAL);
	} else if (!in_application()) {
		stop_worker(GUARD_EARLY_DIAGNOSTIC);
	} else {
		value = guard_stats_get();
		if (value)
			__sync_fetch_and_add(&value->allowed_diagnostic, 1);
	}
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":zend_error_zstr_at")
int selective_zend_error(struct pt_regs *ctx)
{
	check_diagnostic(ctx);
	return 0;
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":php_error_cb")
int selective_php_error(struct pt_regs *ctx)
{
	check_diagnostic(ctx);
	return 0;
}

SEC("uprobe.multi/" PHP_BAILOUT_TARGET ":php_session_initialize")
int selective_early_session(struct pt_regs *ctx)
{
	if (!in_application())
		stop_worker(GUARD_EARLY_SESSION);
	return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
