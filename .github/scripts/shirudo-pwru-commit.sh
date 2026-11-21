#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/shirudo-pwru-commit.sh -- print, as a step output, the
# shirudo-pwru commit testing/vm/build-bundle.sh pins. shirudo-pwru is
# private: the workflow checks it out with a token of its own into the
# cache where build-bundle.sh then finds it.
#
#   .github/scripts/shirudo-pwru-commit.sh >>"$GITHUB_OUTPUT"

set -eu

cd "$(git rev-parse --show-toplevel)"

commit=$(sed -n 's/^SHIRUDO_PWRU_COMMIT=\([0-9a-f]\{40\}\)$/\1/p' \
	testing/vm/build-bundle.sh)
if [ -z "$commit" ]; then
	echo "shirudo-pwru-commit: no SHIRUDO_PWRU_COMMIT in testing/vm/build-bundle.sh" >&2
	exit 1
fi
printf 'commit=%s\n' "$commit"
