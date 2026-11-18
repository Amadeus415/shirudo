#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0008 -- .github/scripts/check-docs.sh: the whole of each field of a
# threat's fact box, a hook by its section, the programs and counters no
# threat names, and the source files a proof reads or the coverage page
# lists as read by none, on a throwaway repository, and the tree itself.

cd "$(dirname "$0")/.."
. ./test-lib.sh
command -v git >/dev/null 2>&1 || test_skip_all "git not installed"
ROOT=$(cd .. && pwd)
S=$ROOT/.github/scripts/check-docs.sh
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
R=$W/repo
TM=Documentation/security/threat-model.rst
COV=Documentation/contribute/testing/proof-coverage.rst

# A file with the given lines, each argument one line.
put() {
	f=$R/$1
	shift
	mkdir -p "$(dirname "$f")"
	printf '%s\n' "$@" >"$f"
}

# A tree the check passes: one fact box whose fields continue on a second
# line, two harnesses, one of which reads its file through a header.
good() {
	rm -rf "$R" && mkdir -p "$R" && git init -q "$R" &&
	put shirudo.c 'int main(void) { return 0; }' &&
	put builtin-upatch.c 'int upatch;' &&
	put tools/shirudo-build/build.c 'int build;' &&
	put tools/gen-image/gen '#!/bin/sh' &&
	put tools/gen-initrd/gen '#!/bin/sh' &&
	put util/tamper.c 'static const struct point points[] = {' \
		'	[0] = { "Good", 1 },' '};' &&
	put util/integrity.c 'static const struct point points[] = {' \
		'	[0] = { "Kept", 1 },' '};' &&
	put util/read.c 'int read_one;' &&
	put util/chained.c 'int chained;' &&
	put util/unread.c 'int unread;' &&
	put bpf/guard.c 'SEC("lsm/file_open")' 'SEC("lsm.s/inode_setattr")' &&
	put bpf/lib/guard.h 'struct guard;' &&
	put testing/functional/build/t1001-one.sh '#!/bin/sh' &&
	put testing/proofs/cbmc/proofs.list 'first --unwind 1' 'second --unwind 1' &&
	put testing/proofs/cbmc/first.c '#include "proof.h"' \
		'#include "../../../util/read.c"' &&
	put testing/proofs/cbmc/model.h '#include "../../../util/chained.c"' &&
	put testing/proofs/cbmc/second.c '#include "proof.h"' '#include "model.h"' &&
	put testing/proofs/lean4/Shirudo/Model.lean 'theorem model : True := trivial' &&
	put Documentation/security/tamper-counters.rst '``Good``' &&
	put Documentation/security/integrity-counters.rst '``Kept``' &&
	put "$TM" ':Enforced at: ``lsm/file_open``,' \
		'   ``lsm.s/inode_setattr``' \
		':Counters: none for a first attempt,' \
		'   ``Good``, ``Kept``' \
		':Tests: ``t1001``' \
		':Proofs: ``first``,' \
		'   ``second``' &&
	put "$COV" '   * - ``first``' '   * - ``second``' \
		'   * - ``Shirudo.Model``' '' \
		'Files without a proof' '---------------------' '' \
		'   * - :src:`shirudo.c`, :src:`builtin-upatch.c`,' \
		'       :src:`tools/shirudo-build/build.c`,' \
		'       :src:`util/integrity.c`, :src:`util/tamper.c`,' \
		'       :src:`util/unread.c`' '' \
		'Not covered yet' '---------------'
}

check() {
	(cd "$R" && git add -A && sh "$S") >"$W/out" 2>"$W/err"
}

# The check fails and says so.
refuses() {
	! check && grep -qF "$1" "$W/err"
}

test_expect_success 'a tree whose fields continue on a second line passes' '
	good && check
'

test_expect_success 'a hook on a continuation line is checked, by its section' '
	good && sed -i "s|lsm.s/inode_setattr|lsm.s/inode_setattrx|" "$R/$TM" &&
	refuses "no BPF program has the section lsm.s/inode_setattrx" &&
	good && sed -i "s|lsm.s/inode_setattr|lsm/inode_setattr|" "$R/$TM" &&
	refuses "no BPF program has the section lsm/inode_setattr"
'

test_expect_success 'a counter and a proof on a continuation line are checked' '
	good && sed -i "s|\`\`Good\`\`|\`\`Goodx\`\`|" "$R/$TM" &&
	refuses "no counter is named Goodx" &&
	good && sed -i "s|\`\`second\`\`|\`\`secondx\`\`|" "$R/$TM" &&
	refuses "no proof is named secondx"
'

test_expect_success 'an integrity counter needs its entry and a fact box' '
	good && put Documentation/security/integrity-counters.rst "none" &&
	refuses "no entry for the counter Kept" &&
	good && sed -i "s|, \`\`Kept\`\`||" "$R/$TM" &&
	refuses "no threat names the counter Kept"
'

test_expect_success 'every program and every counter stands in a fact box' '
	good && put bpf/guard.c "SEC(\"lsm/file_open\")" \
		"SEC(\"lsm.s/inode_setattr\")" "SEC(\"lsm/task_kill\")" &&
	refuses "no threat names the program lsm/task_kill" &&
	good && put util/tamper.c "static const struct point points[] = {" \
		"	[0] = { \"Good\", 1 }," "	[1] = { \"Other\", 1 }," "};" &&
	put Documentation/security/tamper-counters.rst "\`\`Good\`\`" "\`\`Other\`\`" &&
	refuses "no threat names the counter Other"
'

test_expect_success 'a source file is read by a proof or listed as read by none' '
	good && put util/new.c "int new_file;" &&
	refuses "no proof reads util/new.c and no line says why" &&
	good && put testing/proofs/cbmc/second.c "#include \"proof.h\"" &&
	refuses "no proof reads util/chained.c and no line says why"
'

test_expect_success 'the list names only source files no proof reads' '
	good && sed -i "s|:src:\`util/unread.c\`|:src:\`util/unread.c\`, :src:\`util/read.c\`|" "$R/$COV" &&
	refuses "a proof reads util/read.c, which the page lists as read by none" &&
	good && sed -i "s|:src:\`util/unread.c\`|:src:\`util/gone.c\`|" "$R/$COV" &&
	refuses "no source file is named util/gone.c" &&
	grep -qF "no proof reads util/unread.c and no line says why" "$W/err"
'

test_expect_success 'the tree itself passes' '
	(cd "$ROOT" && sh "$S") >"$W/out" 2>"$W/err"
'

test_done
