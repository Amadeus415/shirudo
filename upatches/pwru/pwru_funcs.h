/* SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause */
/*
 * Copyright (c) 2026 Authors of shirudo
 *
 * The functions the upatch probes, included where PWRU_FUNC and PWRU_TP
 * are defined. PWRU_FUNC(function, its sk_buff, its drop reason) is an
 * fentry program on the function, PWRU_TP(name, tracepoint, ...) a
 * tp_btf program on the tracepoint, which records the name. SKB(n) is
 * argument n, from 0, REASON(n) argument n as a drop reason. Each must
 * be a function or tracepoint of the target's vmlinux BTF, or the load
 * fails.
 *
 * Every packet passes one function of each layer it crosses, in each
 * direction; a drop between two of them shows as the reason the
 * kfree_skb tracepoint gives.
 */

/*
 * On the way in, from every driver, the backlog and GRO alike. The
 * compiler may clone __netif_receive_skb_core() as a .constprop
 * function, which fentry cannot attach to by the function's name.
 */
PWRU_TP(__netif_receive_skb_core, netif_receive_skb, SKB(0), NO_REASON)
PWRU_FUNC(ip_rcv_core, SKB(0), NO_REASON)
PWRU_FUNC(ip6_rcv_core, SKB(0), NO_REASON)
PWRU_FUNC(ip_forward, SKB(0), NO_REASON)
PWRU_FUNC(ip6_forward, SKB(0), NO_REASON)
PWRU_FUNC(ip_protocol_deliver_rcu, SKB(1), NO_REASON)
/*
 * ip6_protocol_deliver_rcu() has no BTF in a kernel clang builds, so IPv6
 * takes the packet one call before it, where the LOCAL_IN hook passes it on.
 */
PWRU_FUNC(ip6_input_finish, SKB(2), NO_REASON)

/* On the way out, sent from the host and forwarded alike. */
PWRU_FUNC(ip_output, SKB(2), NO_REASON)
PWRU_FUNC(ip6_output, SKB(2), NO_REASON)
PWRU_FUNC(__dev_queue_xmit, SKB(0), NO_REASON)
PWRU_FUNC(dev_hard_start_xmit, SKB(0), NO_REASON)

/* Every netfilter hook a rule is registered on, in both directions. */
PWRU_FUNC(nf_hook_slow, SKB(0), NO_REASON)

/*
 * Where it is dropped, and where it is freed once used: the tracepoints
 * fire once the last reference is gone. sk_skb_reason_drop() and
 * consume_skb() see references that may not be the last, and
 * kfree_skb_list_reason(), napi_consume_skb() and net_tx_action() free
 * without calling either. What a TCP or UDP reader took goes to
 * skb_attempt_defer_free(), which fires neither tracepoint when it runs
 * on the CPU that allocated the sk_buff.
 */
PWRU_TP(kfree_skb, kfree_skb, SKB(0), REASON(2))
PWRU_TP(consume_skb, consume_skb, SKB(0), NO_REASON)
