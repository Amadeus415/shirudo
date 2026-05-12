#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Static checks that don't depend on a working build:
#   - clang-format on every C/H file (kernel coding style, see
#     .clang-format in repo root once that lands)
#   - shellcheck on every shell script
#   - sparse semantic checks on the userspace tree, if available
#   - SPDX header presence check on every C/H/Makefile/shell file

. "$(dirname "$0")/lib.sh"

failed=0

check_spdx() {
	# Every C/H/Makefile/.sh file must have an SPDX-License-Identifier
	# line within the first 5 lines. Exceptions: vendored files under
	# util/sign.c carry their upstream SPDX tag (still SPDX-compliant).
	log "SPDX header check"
	while IFS= read -r f; do
		case "$f" in
		# Skip auto-generated files and vendored trees.
		util/version_id.c|third_party/*|*/vmlinux.h) continue ;;
		esac
		if ! head -n 5 "$f" | grep -q SPDX-License-Identifier; then
			log "missing SPDX header: $f"
			failed=1
		fi
	done <<-EOF
		$(git ls-files '*.c' '*.h' '*.sh' 'Makefile*' 'ci/*.sh' 't/*.sh' \
			2>/dev/null || find . -type f \( \
				-name '*.c' -o -name '*.h' -o -name '*.sh' \
				-o -name 'Makefile*' \
			\) -not -path './third_party/*' -not -path './.git/*')
	EOF
}

run_clang_format() {
	command -v clang-format >/dev/null 2>&1 || {
		log "clang-format not present; skipping"
		return 0
	}
	log "clang-format --dry-run -Werror"
	clang-format --dry-run -Werror \
		$(git ls-files '*.c' '*.h' 2>/dev/null \
			| grep -Ev '^(third_party|util/version_id\.c)') \
		|| failed=1
}

run_shellcheck() {
	command -v shellcheck >/dev/null 2>&1 || {
		log "shellcheck not present; skipping"
		return 0
	}
	log "shellcheck"
	shellcheck $(git ls-files '*.sh' 2>/dev/null \
		| grep -v '^third_party/') \
		|| failed=1
}

run_sparse() {
	command -v sparse >/dev/null 2>&1 || {
		log "sparse not present; skipping"
		return 0
	}
	log "sparse (informational; not gating)"
	# Sparse warnings are informational in CI; do not flip $failed.
	make C=1 -k 2>&1 | tee /tmp/sparse.log || true
}

check_spdx
run_clang_format
run_shellcheck
run_sparse

exit "$failed"
