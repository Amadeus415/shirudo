/* SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause) */
#ifndef SHIRUDO_BEES_EXEC_UID_COMMON_H
#define SHIRUDO_BEES_EXEC_UID_COMMON_H

#include <bpf/bpf_core_read.h>

struct sock_common___ipv6 {
	__u32 skc_v6_daddr[4];
} __attribute__((preserve_access_index));

struct linux_obs_sockaddr_in6 {
	__u16 sin6_family;
	__be16 sin6_port;
	__be32 sin6_flowinfo;
	__u32 sin6_addr[4];
	__u32 sin6_scope_id;
};

struct linux_obs_ipv6hdr {
	__be32 version_flow;
	__be16 payload_len;
	__u8 nexthdr;
	__u8 hop_limit;
	__u32 saddr[4];
	__u32 daddr[4];
};

static __always_inline bool obs_ipv6_enabled(void)
{
	return bpf_core_field_exists(struct sock_common___ipv6,
				     skc_v6_daddr);
}

struct exec_uid {
	__u64 ino;
	__u32 dev;
	__u32 _pad;
};

struct task_exec_meta {
	__u8 present;
	__u8 _pad[7];
	struct exec_uid uid;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_exec_meta);
} obs_i_task SEC(".maps");

static __always_inline int exec_uid_from_file(struct file *file,
					      struct exec_uid *uid)
{
	struct inode *inode;

	if (!file)
		return -1;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode || !BPF_CORE_READ(inode, i_sb))
		return -1;

	uid->ino = BPF_CORE_READ(inode, i_ino);
	uid->dev = BPF_CORE_READ(inode, i_sb, s_dev);
	uid->_pad = 0;
	if (!uid->ino)
		return -1;

	return 0;
}

static __always_inline void task_exec_set(struct task_struct *task,
					  const struct exec_uid *uid)
{
	struct task_exec_meta *meta;

	meta = bpf_task_storage_get(&obs_i_task, task, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!meta)
		return;

	meta->present = 1;
	meta->_pad[0] = 0;
	meta->_pad[1] = 0;
	meta->_pad[2] = 0;
	meta->_pad[3] = 0;
	meta->_pad[4] = 0;
	meta->_pad[5] = 0;
	meta->_pad[6] = 0;
	meta->uid = *uid;
}

static __always_inline void task_exec_delete(struct task_struct *task)
{
	bpf_task_storage_delete(&obs_i_task, task);
}

static __always_inline bool task_exec_current_uid(struct task_struct *task,
						  struct exec_uid *uid)
{
	struct task_exec_meta *meta;

	if (!task)
		return false;

	meta = bpf_task_storage_get(&obs_i_task, task, 0, 0);
	if (!meta || !meta->present)
		return false;

	*uid = meta->uid;
	return true;
}

static __always_inline bool task_exec_parent_uid(struct task_struct *task,
						 struct exec_uid *uid)
{
	struct task_struct *parent;

	if (!task)
		return false;

	parent = task->real_parent;
	if (!parent || parent == task)
		return false;

	return task_exec_current_uid(parent, uid);
}

static __always_inline bool exec_uid_equal_arena(
	const struct exec_uid __arena *a, const struct exec_uid *b)
{
	return a->ino == b->ino && a->dev == b->dev;
}

static __always_inline __u64 exec_uid_hash_mix(__u64 h,
					       const struct exec_uid *uid)
{
	h ^= uid->ino + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	h ^= uid->dev + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
	h ^= h >> 33;
	h *= 0xff51afd7ed558ccdULL;
	h ^= h >> 33;
	return h;
}

#endif /* SHIRUDO_BEES_EXEC_UID_COMMON_H */
