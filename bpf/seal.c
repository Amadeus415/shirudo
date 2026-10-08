// SPDX-License-Identifier: (BSD-2-Clause OR GPL-2.0)
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * Filesystem-sealing LSM: xattr-based identity, never paths.
 *
 * Every file/directory under /var/lib/shirudo/ (except the private
 * bpffs mount, which bpf/bpf2.c guards) is labelled with the inode
 * xattr security.bpf.shirudo whose value is the installed shirudo's
 * SHIRUDO_VERSION_ID; the shirudo binary carries the same label. The
 * filesystem hooks read the target's label and, if present, require the
 * calling task's executable to carry an equal label -- so only shirudo
 * may write, unlink, rename, or relabel its own on-disk state. The exec
 * hooks cache whether the successfully executed file carries a Shirudo
 * label in task storage for later access-control decisions. An
 * unlabelled filesystem target is not ours and is allowed through
 * untouched. No bpf_d_path(), no path strings: the label rides the
 * inode, immune to bind-mount / namespace / TOCTOU games. Reads are not
 * gated; only write-mode opens and the mutating inode ops are.
 *
 * The filesystem and exec xattr hooks are sleepable (lsm.s/) because
 * reading an xattr can sleep. The xattr-reading kfuncs write into a
 * bpf_dynptr over map memory
 * (the verifier rejects stack), so the two scratch buffers live in
 * per-task storage: a task is in only one of these syscalls at a time,
 * and its storage survives CPU migration across the sleeping read -- so
 * no cross-invocation races, unlike a shared global buffer.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef EACCES
#define EACCES		13
#endif
#ifndef FMODE_WRITE
#define FMODE_WRITE	0x2
#endif

char _license[] SEC("license") = "Dual BSD/GPL";

#define SHIRUDO_XATTR	"security.bpf.shirudo"
/* SHIRUDO_VERSION_ID is a SHA-256 hex string -- always 64 bytes. */
#define LABEL_LEN	64

struct seal_scratch {
	char	target[LABEL_LEN];
	char	exe[LABEL_LEN];
	__u8	exec_candidate_valid;
	__u8	exec_candidate_labelled;
	__u8	exe_is_shirudo;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct seal_scratch);
} seal_scratch_map SEC(".maps");

extern struct file *bpf_get_task_exe_file(struct task_struct *task) __ksym;
extern void bpf_put_file(struct file *file) __ksym;
extern int bpf_get_dentry_xattr(struct dentry *dentry, const char *name__str,
				struct bpf_dynptr *value_p) __ksym;
extern int bpf_get_file_xattr(struct file *file, const char *name__str,
			      struct bpf_dynptr *value_p) __ksym;

/*
 * With the target's label already read into s->target (tlen bytes),
 * decide the verdict. tlen != LABEL_LEN means the target is not one of
 * shirudo's labelled inodes -- allow. Otherwise the calling task's
 * exe_file must carry an equal label. 0 = allow, -EACCES = deny.
 */
static __always_inline int seal_verdict(struct task_struct *task,
					struct seal_scratch *s, int tlen)
{
	struct bpf_dynptr edp;
	struct file *exe;
	int elen, i, diff = 0;

	if (tlen != LABEL_LEN)
		return 0;		/* not labelled (absent / wrong size) */

	exe = bpf_get_task_exe_file(task);
	if (!exe)
		return -EACCES;		/* no exe (kernel thread): not shirudo */
	bpf_dynptr_from_mem(s->exe, LABEL_LEN, 0, &edp);
	elen = bpf_get_file_xattr(exe, SHIRUDO_XATTR, &edp);
	bpf_put_file(exe);

	if (elen != LABEL_LEN)
		return -EACCES;		/* caller's exe is not shirudo */
	for (i = 0; i < LABEL_LEN; i++)
		diff |= s->target[i] ^ s->exe[i];
	return diff ? -EACCES : 0;
}

static __always_inline struct seal_scratch *seal_scratch_get(
						struct task_struct *task)
{
	return bpf_task_storage_get(&seal_scratch_map, task, NULL,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}

/*
 * Stage the candidate executable's seal label during exec. A later LSM
 * hook may still reject the exec, so the persistent task marker is only
 * updated by bprm_committed_creds after a successful exec. This is because
 * the task struct storage would be reused on the error case for some
 * other task.
 */
SEC("lsm.s/bprm_check_security")
int BPF_PROG(shirudo_seal_bprm_check_security,
	     struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct seal_scratch *s = seal_scratch_get(task);
	struct file *file = bprm->file;
	struct bpf_dynptr dp;
	int len = -1;

	if (!s)
		return 0;
	if (file) {
		bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &dp);
		len = bpf_get_file_xattr(file, SHIRUDO_XATTR, &dp);
	}
	s->exec_candidate_labelled = len == LABEL_LEN;
	s->exec_candidate_valid = 1;
	return 0;
}

SEC("lsm.s/bprm_committed_creds")
void BPF_PROG(shirudo_seal_bprm_committed_creds,
	      const struct linux_binprm *bprm)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct seal_scratch *s =
		bpf_task_storage_get(&seal_scratch_map, task, NULL, 0);

	(void)bprm;
	if (!s || !s->exec_candidate_valid)
		return;
	if (!s->exec_candidate_labelled) {
		/* Scratch is transient; unlabelled tasks need no persistent entry. */
		bpf_task_storage_delete(&seal_scratch_map, task);
		return;
	}
	s->exe_is_shirudo = 1;
	s->exec_candidate_valid = 0;
	s->exec_candidate_labelled = 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(shirudo_seal_task_alloc, struct task_struct *child,
	     __u64 clone_flags)
{
	struct task_struct *parent = bpf_get_current_task_btf();
	struct seal_scratch *parent_s;
	struct seal_scratch *child_s;

	(void)clone_flags;
	parent_s = bpf_task_storage_get(&seal_scratch_map, parent, NULL, 0);
	if (!parent_s || !parent_s->exe_is_shirudo)
		return 0;
	child_s = seal_scratch_get(child);
	if (child_s)
		child_s->exe_is_shirudo = 1;
	return 0;
}

/* Do not create task-bound perf events for a committed Shirudo task. */
SEC("lsm/perf_event_alloc")
int BPF_PROG(shirudo_seal_perf_event_alloc,
	     struct perf_event *event, int ret)
{
	struct task_struct *target;
	struct seal_scratch *s;

	if (ret)
		return ret;

	target = event->hw.target;
	if (!target)
		return 0; /* CPU-wide events have no task target to inspect. */

	s = bpf_task_storage_get(&seal_scratch_map, target, NULL, 0);
	if (s && s->exe_is_shirudo)
		return -EACCES;

	return 0;
}

/* Do not allow ptrace access to tasks whose committed executable is Shirudo. */
SEC("lsm.s/ptrace_access_check")
int BPF_PROG(shirudo_seal_ptrace_access_check,
	     struct task_struct *child, unsigned int mode, int ret)
{
	struct seal_scratch *s;

	(void)mode;
	if (ret)
		return ret;

	s = bpf_task_storage_get(&seal_scratch_map, child, NULL, 0);
	if (s && s->exe_is_shirudo)
		return -EACCES;

	return 0;
}

SEC("lsm.s/file_open")
int BPF_PROG(shirudo_seal_file_open, struct file *file)
{
	struct task_struct *task;
	struct seal_scratch *s;
	struct bpf_dynptr tdp;

	if (!(BPF_CORE_READ(file, f_mode) & FMODE_WRITE))
		return 0;		/* reads are fine */
	task = bpf_get_current_task_btf();
	s = seal_scratch_get(task);
	if (!s)
		return 0;		/* no scratch: fail open (see header) */
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	return seal_verdict(task, s,
			    bpf_get_file_xattr(file, SHIRUDO_XATTR, &tdp));
}

static __always_inline int seal_dentry(struct dentry *dentry)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct seal_scratch *s = seal_scratch_get(task);
	struct bpf_dynptr tdp;

	if (!s)
		return 0;
	bpf_dynptr_from_mem(s->target, LABEL_LEN, 0, &tdp);
	return seal_verdict(task, s,
			    bpf_get_dentry_xattr(dentry, SHIRUDO_XATTR, &tdp));
}

SEC("lsm.s/inode_unlink")
int BPF_PROG(shirudo_seal_inode_unlink, struct inode *dir,
	     struct dentry *dentry)
{
	return seal_dentry(dentry);
}

/* Protect the source of a rename -- moving a labelled inode out. */
SEC("lsm.s/inode_rename")
int BPF_PROG(shirudo_seal_inode_rename, struct inode *old_dir,
	     struct dentry *old_dentry, struct inode *new_dir,
	     struct dentry *new_dentry)
{
	return seal_dentry(old_dentry);
}

SEC("lsm.s/inode_setxattr")
int BPF_PROG(shirudo_seal_inode_setxattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name, const void *value,
	     __u64 size, int flags)
{
	return seal_dentry(dentry);
}

SEC("lsm.s/inode_removexattr")
int BPF_PROG(shirudo_seal_inode_removexattr, struct mnt_idmap *idmap,
	     struct dentry *dentry, const char *name)
{
	return seal_dentry(dentry);
}
