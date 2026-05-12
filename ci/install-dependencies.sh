#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Install build- and runtime-time dependencies for shirudo.
#
# Library set (per PLAN.md "Minimal vetted library dependencies"):
#   libcrypto (OpenSSL), libssh >= 0.10, libtss2-esys + libtss2-tcti-device,
#   libbpf, libelf, zlib. Plus clang/LLVM for BPF compilation and
#   bpftool as a build-time tool for vmlinux.h generation.

. "$(dirname "$0")/lib.sh"

case "$distro" in
debian)
	export DEBIAN_FRONTEND=noninteractive
	run sudo apt-get update -qq
	run sudo apt-get install -y --no-install-recommends \
		build-essential clang lld llvm \
		libssl-dev libssh-dev libtss2-dev libelf-dev zlib1g-dev \
		libbpf-dev linux-libc-dev pkg-config make git \
		swtpm tpm2-tools \
		shellcheck clang-format sparse
	;;
fedora)
	run sudo dnf install -y \
		gcc clang lld llvm openssl-devel libssh-devel \
		tpm2-tss-devel elfutils-libelf-devel zlib-devel \
		libbpf-devel kernel-headers pkgconf-pkg-config make git \
		swtpm tpm2-tools \
		ShellCheck clang-tools-extra sparse
	;;
arch)
	run sudo pacman -Sy --noconfirm \
		base-devel clang lld llvm openssl libssh tpm2-tss \
		libelf zlib libbpf linux-api-headers pkgconf make git \
		swtpm tpm2-tools \
		shellcheck sparse
	;;
alpine)
	run sudo apk add --no-cache \
		build-base clang lld llvm openssl-dev libssh-dev \
		tpm2-tss-dev elfutils-dev zlib-dev libbpf-dev \
		linux-headers pkgconf make git \
		swtpm tpm2-tools \
		shellcheck sparse
	;;
*)
	die "unsupported distro: $distro (extend ci/install-dependencies.sh)"
	;;
esac

# Sanity check: report the versions we got, for debugging CI runs.
run clang --version
run pkg-config --modversion libssh openssl libtss2-esys libelf || true
run swtpm --version || true
