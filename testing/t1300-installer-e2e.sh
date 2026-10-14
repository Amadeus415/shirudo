#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t1300 -- the installer, end to end: boot a stock Ubuntu cloud image in
# QEMU with a vTPM, install the bpf-next kernel packages, reboot into
# that kernel, run tools/gen-initrd/install.sh the way a user would with
# a local target package and the operator's certificate, reboot again
# and check that shirudo came up in the production configuration, bound
# from the initrd. Driven from the host (`make test-installer`); it
# needs KVM, qemu, swtpm, cloud-localds, the full kernel packages
# (`make bpf-next`), a target package (`make bindeb-pkg
# PKG_ROLES=target`) and a bundle certificate (`make test-vm-bundle`).
#
#   TEST_INSTALLER_KERNEL_DEBS   directory with linux-image-*.deb
#   TEST_INSTALLER_PACKAGE       the shirudo-target .deb to install
#   TEST_INSTALLER_CERT          the certificate to install (cert.der)
#   TEST_INSTALLER_ROOTFS        the cloud image (default: the test VM's)
#   TEST_INSTALLER_WORK_DIR      scratch and logs (default: build/test-installer)
#   TEST_INSTALLER_CPUS/MEMORY   guest size (default: 4 and 4G)

ORIG_PWD=$PWD
cd "$(dirname "$0")" || exit 1
. ./test-lib.sh
REPO_ROOT=$(cd .. && pwd)

# Inputs come as paths relative to where the caller stood.
abs() {
	case "$1" in
	""|/*) printf '%s\n' "$1" ;;
	*) printf '%s/%s\n' "$ORIG_PWD" "$1" ;;
	esac
}

ROOTFS_NAME=ubuntu-26.04-server-cloudimg-amd64.img
ROOTFS_URL=${TEST_VM_ROOTFS_URL:-https://cloud-images.ubuntu.com/releases/server/26.04/release/$ROOTFS_NAME}
KERNEL_DEBS=$(abs "${TEST_INSTALLER_KERNEL_DEBS:-$REPO_ROOT/artifacts/bpf-next-kernel-debs}")
PACKAGE=$(abs "${TEST_INSTALLER_PACKAGE:-$(ls -t "$REPO_ROOT"/shirudo-target_*.deb 2>/dev/null | head -1)}")
CERT=$(abs "${TEST_INSTALLER_CERT:-$(ls "$REPO_ROOT"/build/test-vm*/host-bundle/fixtures/cert.der 2>/dev/null | head -1)}")
WORK=$(abs "${TEST_INSTALLER_WORK_DIR:-$REPO_ROOT/build/test-installer}")
CPUS=${TEST_INSTALLER_CPUS:-4}
MEMORY=${TEST_INSTALLER_MEMORY:-4G}
ROOTFS=$(abs "${TEST_INSTALLER_ROOTFS:-$(ls "$REPO_ROOT"/build/test-vm*/cache/rootfs/$ROOTFS_NAME 2>/dev/null | head -1)}")

for tool in qemu-system-x86_64 qemu-img swtpm cloud-localds ssh ssh-keygen ss; do
	command -v "$tool" >/dev/null 2>&1 || test_skip_all "$tool not found"
done
[ -r /dev/kvm ] && [ -w /dev/kvm ] || test_skip_all "/dev/kvm is not usable"
image_deb=
for f in "$KERNEL_DEBS"/linux-image-[0-9]*.deb; do
	case "$f" in *-dbg*) continue ;; esac
	[ -e "$f" ] && { image_deb=$f; break; }
done
[ -n "$image_deb" ] || test_skip_all "no linux-image package in $KERNEL_DEBS (make bpf-next)"
[ -s "$PACKAGE" ] || test_skip_all "no shirudo-target package (make bindeb-pkg PKG_ROLES=target)"
[ -s "$CERT" ] || test_skip_all "no certificate to install (TEST_INSTALLER_CERT)"
KREL=$(basename "$image_deb" | sed -n 's/^linux-image-\([^_]*\)_.*/\1/p')
[ -n "$KREL" ] || test_skip_all "cannot tell the kernel release from $image_deb"

mkdir -p "$WORK"
if [ ! -s "$ROOTFS" ]; then
	ROOTFS=$WORK/$ROOTFS_NAME
	if [ ! -s "$ROOTFS" ]; then
		echo "# downloading $ROOTFS_URL" >&2
		curl -fsSL -o "$ROOTFS.tmp" "$ROOTFS_URL" &&
		curl -fsSL -o "$WORK/SHA256SUMS" "${ROOTFS_URL%/*}/SHA256SUMS" &&
		(cd "$WORK" && grep " \*$ROOTFS_NAME\$" SHA256SUMS |
			sed "s|\\*$ROOTFS_NAME|$ROOTFS_NAME.tmp|" | sha256sum -c --quiet -) &&
		mv "$ROOTFS.tmp" "$ROOTFS" || test_skip_all "cannot fetch the cloud image"
	fi
fi

RUN=$WORK/run.$$
mkdir -p "$RUN/tpm"
SSH_KEY=$RUN/id_ed25519
ssh-keygen -q -t ed25519 -N '' -f "$SSH_KEY" >/dev/null
SSH_PORT=
for p in $(seq 22100 22199); do
	ss -ltn 2>/dev/null | grep -q ":$p " || { SSH_PORT=$p; break; }
done
[ -n "$SSH_PORT" ] || test_skip_all "no free ssh port"
SSH_OPTS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
	  -o ConnectTimeout=5 -o LogLevel=ERROR -o BatchMode=yes
	  -i "$SSH_KEY" -p "$SSH_PORT")
QEMU_PID=
SWTPM_PID=

# -n: a caller may drive this test with a script on stdin.
vm_ssh() {
	ssh -n "${SSH_OPTS[@]}" root@127.0.0.1 "$@"
}

vm_scp() {
	scp -q "${SSH_OPTS[@]/-p/-P}" "$@"
}

vm_wait_ssh() {
	local _
	for _ in $(seq 1 120); do
		vm_ssh true 2>/dev/null && return 0
		sleep 5
	done
	return 1
}

vm_wait_down() {
	local _
	for _ in $(seq 1 60); do
		kill -0 "$QEMU_PID" 2>/dev/null || return 0
		sleep 2
	done
	return 1
}

vm_start() {
	local tag=$1

	swtpm socket --tpmstate "dir=$RUN/tpm" --tpm2 --daemon \
		--ctrl "type=unixio,path=$RUN/tpm/sock" \
		--pid "file=$RUN/tpm/pid" --log "file=$RUN/tpm/log,level=5" || return 1
	SWTPM_PID=$(cat "$RUN/tpm/pid")
	qemu-system-x86_64 -enable-kvm -cpu host -machine q35 -smp "$CPUS" -m "$MEMORY" \
		-drive "file=$RUN/disk.qcow2,if=virtio,format=qcow2" \
		-drive "file=$RUN/seed.img,if=virtio,format=raw,readonly=on" \
		-netdev "user,id=net0,hostfwd=tcp:127.0.0.1:$SSH_PORT-:22" \
		-device virtio-net-pci,netdev=net0 \
		-chardev "socket,id=chrtpm,path=$RUN/tpm/sock" \
		-tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0 \
		-display none -serial "file:$RUN/console-$tag.log" \
		-pidfile "$RUN/qemu.pid" -daemonize || return 1
	QEMU_PID=$(cat "$RUN/qemu.pid")
	vm_wait_ssh
}

# A reboot keeps QEMU and the TPM state: the vTPM resets with the guest.
vm_reboot() {
	vm_ssh reboot >/dev/null 2>&1 || true
	sleep 15
	vm_wait_ssh
}

vm_stop() {
	[ -n "$QEMU_PID" ] && kill -0 "$QEMU_PID" 2>/dev/null && {
		vm_ssh poweroff >/dev/null 2>&1 || true
		vm_wait_down || kill "$QEMU_PID" 2>/dev/null || true
	}
	[ -n "$SWTPM_PID" ] && kill "$SWTPM_PID" 2>/dev/null
	QEMU_PID=
	SWTPM_PID=
}

cleanup() {
	vm_stop
	[ "${KEEP_RUN:-0}" = 1 ] || rm -rf "$RUN/disk.qcow2" "$RUN/seed.img" "$RUN/tpm"
}
trap cleanup EXIT

qemu-img create -q -f qcow2 -F qcow2 -b "$ROOTFS" "$RUN/disk.qcow2" 20G ||
	test_skip_all "cannot create the disk overlay"
cat >"$RUN/user-data" <<EOF
#cloud-config
disable_root: false
ssh_pwauth: false
users:
  - name: root
    ssh_authorized_keys:
      - $(cat "$SSH_KEY.pub")
growpart:
  mode: auto
  devices: ['/']
EOF
printf 'instance-id: shirudo-installer-%s\nlocal-hostname: shirudo-installer\n' "$$" >"$RUN/meta-data"
cloud-localds "$RUN/seed.img" "$RUN/user-data" "$RUN/meta-data" >/dev/null 2>&1 ||
	test_skip_all "cloud-localds failed"

test_expect_success 'the stock cloud image boots and answers over ssh' '
	vm_start boot1
'

test_expect_success 'the bpf-next kernel packages install and grub lists the kernel' '
	vm_scp "$KERNEL_DEBS"/linux-image-[0-9]*.deb root@127.0.0.1:/root/ &&
	vm_ssh "DEBIAN_FRONTEND=noninteractive dpkg -i /root/linux-image-*.deb >/root/kernel-install.log 2>&1 || { tail -20 /root/kernel-install.log; exit 1; }" &&
	vm_ssh "grep -q \"$KREL\" /boot/grub/grub.cfg"
'

test_expect_success 'the guest reboots into the bpf-next kernel' '
	vm_reboot &&
	[ "$(vm_ssh uname -r)" = "$KREL" ] &&
	vm_ssh test -c /dev/tpmrm0
'

test_expect_success 'the installer installs the package, the certificate, the command line and the initrd' '
	vm_scp "$PACKAGE" root@127.0.0.1:/root/shirudo-target.deb &&
	vm_scp "$CERT" root@127.0.0.1:/root/cert.der &&
	vm_scp "$REPO_ROOT/tools/gen-initrd/install.sh" root@127.0.0.1:/root/install.sh &&
	vm_ssh "bash /root/install.sh --package /root/shirudo-target.deb --cert /root/cert.der --switch-to-dracut >/root/install.log 2>&1 || { tail -30 /root/install.log; exit 1; }" &&
	vm_ssh "grep -q bpf.keyring_unsealed=1 /boot/grub/grub.cfg" &&
	vm_ssh "shirudo-gen-initrd --check /boot/initrd.img-$KREL >/dev/null" &&
	vm_ssh "systemctl is-enabled shirudo.service >/dev/null"
'

test_expect_success 'the guest reboots into the production configuration' '
	vm_reboot &&
	vm_ssh "grep -q -w bpf.keyring_unsealed=1 /proc/cmdline" &&
	vm_ssh "shirudo status --json" >"$RUN/status.json" &&
	python3 - "$RUN/status.json" <<"PY"
import json, sys
d = json.load(open(sys.argv[1], encoding="utf-8"))
assert d["mode"] == "production", d["mode"]
assert d["tpm"]["bound_in"] == "initrd", d["tpm"]
assert d["keyring_mode"] == "bpf", d["keyring_mode"]
PY
'

test_expect_success 'the initrd unit completed init and the root adopted its record' '
	vm_ssh "journalctl -b -u shirudo-initrd.service --no-pager | grep -q \"init: complete\"" &&
	vm_ssh "systemctl is-active shirudo.service >/dev/null" &&
	vm_ssh "test ! -e /run/shirudo/eventlog.pending" &&
	vm_ssh "grep -q \"\\\"bound_in\\\":\\\"initrd\\\"\" /var/lib/shirudo/eventlog"
'

test_expect_success 'the initrd target test passes on the installed system' '
	vm_ssh "mkdir -p /root/testing" &&
	vm_scp test-lib.sh integration-lib.sh t1122-initrd.sh root@127.0.0.1:/root/testing/ &&
	vm_ssh "cd /root/testing && SHIRUDO_BIN=/usr/bin/shirudo sh ./t1122-initrd.sh" >"$RUN/t1122.log" 2>&1 &&
	! grep -q "^not ok" "$RUN/t1122.log" &&
	grep -q "^ok 1" "$RUN/t1122.log"
'

test_done
