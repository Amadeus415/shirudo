#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# t0002 -- util/selector label-expression grammar and evaluation:
# equality, inequality, existence/non-existence, && / || with
# precedence, parentheses, and rejection of malformed expressions.
# Wrong evaluation here means rolling out to the wrong fleet subset.

cd "$(dirname "$0")"
. ./test-lib.sh

H=helper/test-selector

# One registered remote: type=production, location=us-east-1, role=db.
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/shirudo/remotes.d"
cat > "$WORK/shirudo/remotes.d/n.conf" <<'EOF'
host = 10.0.0.1
label.type = production
label.location = us-east-1
label.role = db
EOF
export XDG_CONFIG_HOME="$WORK"

test_expect_success 'equality matches / mismatches' '
	[ "$(./$H "type=production")" = "match" ] &&
	[ "$(./$H "type=staging")" = "nomatch" ]
'

test_expect_success 'inequality' '
	[ "$(./$H "type!=staging")" = "match" ] &&
	[ "$(./$H "type!=production")" = "nomatch" ]
'

test_expect_success 'existence and non-existence' '
	[ "$(./$H "location")" = "match" ] &&
	[ "$(./$H "nosuch")" = "nomatch" ] &&
	[ "$(./$H "!nosuch")" = "match" ] &&
	[ "$(./$H "!location")" = "nomatch" ]
'

test_expect_success "&& requires both terms" '
	[ "$(./$H "type=production && location=us-east-1")" = "match" ] &&
	[ "$(./$H "type=production && location=eu-west-1")" = "nomatch" ]
'

test_expect_success "|| requires either term" '
	[ "$(./$H "type=staging || role=db")" = "match" ] &&
	[ "$(./$H "type=staging || role=cache")" = "nomatch" ]
'

test_expect_success "&& binds tighter than ||" '
	[ "$(./$H "type=staging && role=cache || location=us-east-1")" = "match" ] &&
	[ "$(./$H "type=production && role=cache || location=eu-west-1")" = "nomatch" ]
'

test_expect_success "parentheses override precedence" '
	[ "$(./$H "(type=staging || role=db) && location=us-east-1")" = "match" ] &&
	[ "$(./$H "(type=staging || role=cache) && location=us-east-1")" = "nomatch" ]
'

test_expect_success "malformed expressions are rejected" '
	[ "$(./$H "&&")" = "parse-error" ] &&
	[ "$(./$H "type=production &&")" = "parse-error" ] &&
	[ "$(./$H "(type=production")" = "parse-error" ]
'

test_done
