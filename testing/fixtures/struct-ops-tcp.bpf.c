// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} inits SEC(".maps");

char _license[] SEC("license") = "Dual BSD/GPL";

SEC("struct_ops/shirudo_test_cc_init")
void BPF_PROG(shirudo_test_cc_init, struct sock *sk)
{
	__u32 key = 0;
	__u64 *value = bpf_map_lookup_elem(&inits, &key);

	if (value)
		__sync_fetch_and_add(value, 1);
}

SEC("struct_ops/shirudo_test_cc_ssthresh")
__u32 BPF_PROG(shirudo_test_cc_ssthresh, struct sock *sk)
{
	return tcp_reno_ssthresh(sk);
}

SEC("struct_ops/shirudo_test_cc_cong_avoid")
void BPF_PROG(shirudo_test_cc_cong_avoid, struct sock *sk, __u32 ack,
	      __u32 acked)
{
	tcp_reno_cong_avoid(sk, ack, acked);
}

SEC("struct_ops/shirudo_test_cc_undo_cwnd")
__u32 BPF_PROG(shirudo_test_cc_undo_cwnd, struct sock *sk)
{
	return tcp_reno_undo_cwnd(sk);
}

SEC(".struct_ops.link")
struct tcp_congestion_ops shirudo_test_cc = {
	.init		= (void *)shirudo_test_cc_init,
	.ssthresh	= (void *)shirudo_test_cc_ssthresh,
	.cong_avoid	= (void *)shirudo_test_cc_cong_avoid,
	.undo_cwnd	= (void *)shirudo_test_cc_undo_cwnd,
	.name		= "shirudo_test_cc",
};
