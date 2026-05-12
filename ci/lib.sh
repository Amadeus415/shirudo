# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Shared helpers for ci/*.sh. Sourced by every CI entry point.
#
# Required environment:
#     $jobname  - identifies the CI job (e.g. linux-x86_64-clang).
#                 Set by the provider's YAML; consumed here to pick
#                 distro detection and dependency sets.

set -eu

# Distro detection - simple, no library deps. Sets $distro to one of
# {debian, fedora, arch, alpine, unknown}.
detect_distro() {
	if [ -r /etc/os-release ]; then
		. /etc/os-release
		case "$ID" in
		debian|ubuntu) distro=debian ;;
		fedora|rhel|centos) distro=fedora ;;
		arch) distro=arch ;;
		alpine) distro=alpine ;;
		*) distro=unknown ;;
		esac
	else
		distro=unknown
	fi
}

# Echo to stderr with a [ci] prefix so output is greppable.
log() {
	printf '[ci] %s\n' "$*" >&2
}

# Fail with a message and non-zero exit.
die() {
	log "FATAL: $*"
	exit 1
}

# Run a command, echoing it first.
run() {
	log "+ $*"
	"$@"
}

detect_distro
: "${jobname:=local}"
log "jobname=$jobname distro=$distro"
