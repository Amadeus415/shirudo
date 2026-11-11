#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# .github/scripts/check-docs.sh -- check Documentation/ against the tree:
# every option a console example passes to shirudo exists in a parser,
# every failure category the code emits, every tamper counter and every
# proof has its entry in the reference, and every hook, counter, test,
# proof and unit a page names exists.
#
#   .github/scripts/check-docs.sh
#
# Runs from anywhere inside the checkout.

set -eu

cd "$(git rev-parse --show-toplevel)"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Loops on the right of a pipe run in subshells, so findings go to a file.
report() {
	printf '%s: %s\n' "$1" "$2" >>"$work/errors"
	if [ -n "${GITHUB_ACTIONS:-}" ]; then
		printf '::error file=%s::%s\n' "$1" "$2"
	fi
	printf '%s: %s\n' "$1" "$2" >&2
}

find Documentation -name '*.rst' -not -path 'Documentation/output*' \
	-not -path 'Documentation/contribute/code/coding-style.rst' | sort >"$work/pages"

# The options of the command lines in console blocks, by page.
while IFS= read -r page; do
	grep -E '^[[:space:]]+(operator\$|target#|\$|#) shirudo( |$)' "$page" |
		grep -oE -- '--[a-z0-9][a-z0-9-]*' | sort -u |
		sed "s|^|$page |"
done <"$work/pages" >"$work/options"

cat shirudo.c builtin-*.c rust/src/builtin/*.rs tools/shirudo-build/*.c \
	tools/gen-image/* tools/gen-initrd/* >"$work/parsers"
while read -r page option; do
	grep -qF -- "\"$option" "$work/parsers" ||
		grep -qE -- "(^|[^a-z0-9-])$option([^a-z0-9-]|\$)" \
			tools/gen-image/* tools/gen-initrd/* ||
		report "$page" "no parser accepts $option"
done <"$work/options"

# Every failure category the code emits has an entry.
categories=Documentation/reference/failure-categories.rst
{
	grep -ohE 'rep_fail\([^,]+, "[a-z_]+", "[a-z_]+"' builtin-*.c util/*.c |
		sed -E 's/.*"([a-z_]+)"$/\1/'
	grep -ohE '(cat|category) = "[a-z_]+"' builtin-*.c util/*.c |
		sed -E 's/.*"([a-z_]+)"$/\1/'
	sed -n '/^static const char \*cat_from_load_errno/,/^}/p' builtin-upatch.c |
		grep -oE 'return "[a-z_]+"' | sed -E 's/.*"([a-z_]+)"$/\1/'
} | sort -u >"$work/categories"
while IFS= read -r category; do
	grep -qF "\`\`$category\`\`" "$categories" ||
		report "$categories" "no entry for the emitted category $category"
done <"$work/categories"

# Every tamper counter has an entry, and a page names no other.
counters=Documentation/security/tamper-counters.rst
grep -oE '= \{ "[A-Za-z]+",' util/tamper.c | sed -E 's/.*"([A-Za-z]+)".*/\1/' |
	sort -u >"$work/counters"
while IFS= read -r counter; do
	grep -qF "\`\`$counter\`\`" "$counters" ||
		report "$counters" "no entry for the counter $counter"
done <"$work/counters"

# The hooks, counters and tests a threat fact box names exist.
grep -ohE 'SEC\("lsm(\.s)?/[a-z_]+"\)' bpf/*.c bpf/lib/*.h |
	sed -E 's/SEC\("lsm(\.s)?\/([a-z_]+)"\)/\2/' | sort -u >"$work/hooks"
while IFS= read -r page; do
	grep -E '^:(Enforced at|Counters|Tests):' "$page" >"$work/facts" || continue
	grep '^:Enforced at:' "$work/facts" | grep -oE '``(lsm/)?[a-z_]+``' |
		tr -d '`' | sed 's|^lsm/||' | sort -u | while IFS= read -r hook; do
		grep -qx "$hook" "$work/hooks" ||
			report "$page" "no BPF program attaches to $hook"
	done
	grep '^:Counters:' "$work/facts" | grep -oE '``[A-Za-z]+``' |
		tr -d '`' | sort -u | while IFS= read -r counter; do
		grep -qx "$counter" "$work/counters" ||
			report "$page" "no tamper counter is named $counter"
	done
done <"$work/pages"

# Every test id a page names exists under testing/.
find testing -name 't[0-9][0-9][0-9][0-9]-*' | sed -E 's|.*/(t[0-9]{4}).*|\1|' |
	sort -u >"$work/tests"
while IFS= read -r page; do
	grep -oE '``t[0-9]{4}[a-z0-9-]*``' "$page" | tr -d '`' | cut -c1-5 |
		sort -u | while IFS= read -r test; do
		grep -qx "$test" "$work/tests" ||
			report "$page" "no test is numbered $test"
	done
done <"$work/pages"

# Every proof has a row on the coverage page, and a fact box names only
# proofs that exist.
coverage=Documentation/contribute/testing/proof-coverage.rst
grep -v '^[[:space:]]*\(#\|$\)' testing/proofs/cbmc/proofs.list |
	awk '{ print $1 }' >"$work/proofs"
for model in testing/proofs/lean4/Shirudo/*.lean; do
	model=${model##*/}
	printf 'Shirudo.%s\n' "${model%.lean}"
done >>"$work/proofs"
while IFS= read -r proof; do
	grep -qF "* - \`\`$proof\`\`" "$coverage" ||
		report "$coverage" "no row for the proof $proof"
done <"$work/proofs"
while IFS= read -r page; do
	grep '^:Proofs:' "$page" | grep -oE '``[A-Za-z0-9.-]+``' | tr -d '`' |
		sort -u | while IFS= read -r proof; do
		grep -qx "$proof" "$work/proofs" ||
			report "$page" "no proof is named $proof"
	done
done <"$work/pages"

# Every unit a page names exists under systemd/.
while IFS= read -r page; do
	grep -oE 'shirudo(-[a-z0-9]+)*\.(service|timer)' "$page" | sort -u |
		while IFS= read -r unit; do
		[ -e "systemd/$unit" ] || [ -e "systemd/$unit.in" ] ||
			report "$page" "no unit is named $unit"
	done
done <"$work/pages"

printf 'docs: %s pages checked\n' "$(wc -l <"$work/pages")"
[ ! -s "$work/errors" ]
