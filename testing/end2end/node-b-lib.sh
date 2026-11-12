#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# testing/end2end/node-b-lib.sh -- reach node B, the second target that
# end2end/host.sh boots beside the suite's VM, as root over SSH. A test in
# node A sources it as it is; host.sh sets NODE_B_DIR and NODE_B_HOST first.

# What host.sh records of node B: port, the host port of its SSH server,
# key, the key of its root, and ready once it is prepared, else failed.
: "${NODE_B_DIR:=/mnt/shirudo-src/build/test-vm/end2end/node-b}"
# Where node B's SSH port is forwarded: QEMU's address for the host, as
# node A sees it.
: "${NODE_B_HOST:=10.0.2.2}"

# Wait up to $1 seconds, 600 by default, for node B to be prepared. Fails
# at once when it did not boot.
node_b_wait() {
	node_b_tries=0
	until [ -e "$NODE_B_DIR/ready" ]; do
		[ ! -e "$NODE_B_DIR/failed" ] || return 1
		node_b_tries=$((node_b_tries + 1))
		[ "$node_b_tries" -le "${1:-600}" ] || return 1
		sleep 1
	done
}

# Run the command line $* in node B's root shell, with this standard input
# and output. The words are joined and parsed again there, as by ssh.
node_b() {
	ssh -F /dev/null -i "$NODE_B_DIR/key" -o IdentitiesOnly=yes \
		-o BatchMode=yes -o ConnectTimeout=10 -o LogLevel=ERROR \
		-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
		-p "$(cat "$NODE_B_DIR/port")" "root@$NODE_B_HOST" "$@"
}
