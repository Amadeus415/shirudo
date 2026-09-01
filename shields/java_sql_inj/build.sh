#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ROOT/../.." && pwd)"
OUTPUT_DIR="${JAVA_SQL_INJ_OUTPUT_DIR:-$REPO_ROOT/build/java_sql_inj}"
KEYS_DIR="${JAVA_SQL_INJ_KEYS_DIR:-}"
PACKAGE_VERSION="${JAVA_SQL_INJ_PACKAGE_VERSION:-0.1.0}"
SHIRUDO="${SHIRUDO_BIN:-$REPO_ROOT/shirudo}"
BPM_BIN="${BPM_BIN:-$OUTPUT_DIR/bpm}"
JAVA_SQL_INJ_GOCACHE="${JAVA_SQL_INJ_GOCACHE:-${TMPDIR:-/tmp}/shirudo-java-sql-inj-gocache}"

log()
{
	printf '[java-sql-inj] %s\n' "$*" >&2
}

die()
{
	log "error: $*"
	exit 1
}

command -v mvn >/dev/null 2>&1 || die "mvn is required"
command -v go >/dev/null 2>&1 || die "go is required to build the BPM helper"
[[ -x "$SHIRUDO" ]] || die "shirudo binary is not executable: $SHIRUDO"

TEMP_KEYS=""
TEMP_ROOT=""
cleanup()
{
	[[ -z "$TEMP_KEYS" ]] || rm -rf -- "$TEMP_KEYS"
	[[ -z "$TEMP_ROOT" ]] || rm -rf -- "$TEMP_ROOT"
}
trap cleanup EXIT

if [[ -z "$KEYS_DIR" ]]; then
	TEMP_KEYS="$(mktemp -d)"
	KEYS_DIR="$TEMP_KEYS"
	"$SHIRUDO" genkey --keys-dir "$KEYS_DIR" >/dev/null
elif [[ ! -s "$KEYS_DIR/cert.der" ]]; then
	mkdir -p "$KEYS_DIR"
	"$SHIRUDO" genkey --keys-dir "$KEYS_DIR" >/dev/null
fi
[[ -s "$KEYS_DIR/cert.der" ]] || die "BPM certificate is missing: $KEYS_DIR/cert.der"

mkdir -p "$OUTPUT_DIR"
log "building shaded agent and H2 application"
mvn -q -f "$ROOT/pom.xml" -DskipTests package

AGENT_JAR="$ROOT/agent/target/shirudo-sqli-agent-1.0-SNAPSHOT.jar"
APP_JAR="$ROOT/app/target/shirudo-sqli-app-1.0-SNAPSHOT.jar"
[[ -s "$AGENT_JAR" ]] || die "agent JAR was not built: $AGENT_JAR"
[[ -s "$APP_JAR" ]] || die "application JAR was not built: $APP_JAR"

install -m 0644 "$AGENT_JAR" "$OUTPUT_DIR/agent.jar"
install -m 0644 "$APP_JAR" "$OUTPUT_DIR/vulnerable-app.jar"
install -m 0755 "$ROOT/sql_inj_vuln" "$OUTPUT_DIR/sql_inj_vuln"

TEMP_ROOT="$(mktemp -d)"
PACKAGE_CONTEXT="$TEMP_ROOT/java_sql_inj"
mkdir -p "$PACKAGE_CONTEXT/agent/target" "$PACKAGE_CONTEXT/app/target" \
	"$PACKAGE_CONTEXT/bpf/include/bpf" "$PACKAGE_CONTEXT/bpf/lib"
install -m 0644 "$ROOT/Beefile" "$PACKAGE_CONTEXT/Beefile"
install -m 0644 "$ROOT/README.md" "$PACKAGE_CONTEXT/README.md"
install -m 0644 "$ROOT/javaagent_metrics.bpf.c" \
	"$PACKAGE_CONTEXT/javaagent_metrics.bpf.c"
install -m 0644 "$REPO_ROOT/bpf/vmlinux.h" "$PACKAGE_CONTEXT/vmlinux.h"
for header in "$REPO_ROOT"/bpf/include/bpf/*.h; do
	install -m 0644 "$header" "$PACKAGE_CONTEXT/bpf/include/bpf/"
done
install -m 0644 "$REPO_ROOT"/bpf/lib/shirudo_*.h \
	"$PACKAGE_CONTEXT/bpf/lib/"
install -d "$PACKAGE_CONTEXT/decoders"
install -m 0644 "$ROOT/decoders/javaagent.lua" \
	"$PACKAGE_CONTEXT/decoders/javaagent.lua"
install -m 0755 "$ROOT/sql_inj_vuln" "$PACKAGE_CONTEXT/sql_inj_vuln"
install -m 0644 "$AGENT_JAR" \
	"$PACKAGE_CONTEXT/agent/target/shirudo-sqli-agent-1.0-SNAPSHOT.jar"
install -m 0644 "$APP_JAR" \
	"$PACKAGE_CONTEXT/app/target/shirudo-sqli-app-1.0-SNAPSHOT.jar"

log "building BPM helper from current source"
(
	cd "$REPO_ROOT/bpm"
	GOCACHE="$JAVA_SQL_INJ_GOCACHE" go build -o "$BPM_BIN" .
)

log "building BPM package"
(
	cd "$OUTPUT_DIR"
	PATH="$(dirname "$SHIRUDO"):$REPO_ROOT/tools/shirudo-build:$PATH" \
		"$BPM_BIN" build "$PACKAGE_CONTEXT" \
			--version "$PACKAGE_VERSION" --keys-dir "$KEYS_DIR" >/dev/null
)

install -m 0644 "$PACKAGE_CONTEXT/java-sql-inj.upatch" \
	"$OUTPUT_DIR/java-sql-inj.upatch"
install -m 0644 "$PACKAGE_CONTEXT/java-sql-inj.unload.upatch" \
	"$OUTPUT_DIR/java-sql-inj.unload.upatch"
install -m 0644 "$PACKAGE_CONTEXT/javaagent-metrics.upatch" \
	"$OUTPUT_DIR/javaagent-metrics.upatch"
install -m 0644 "$PACKAGE_CONTEXT/javaagent-metrics.unload.upatch" \
	"$OUTPUT_DIR/javaagent-metrics.unload.upatch"

PACKAGE_PATH="$OUTPUT_DIR/java-sql-injection-$PACKAGE_VERSION.bee"
[[ -s "$PACKAGE_PATH" ]] || die "BPM package was not built: $PACKAGE_PATH"

log "ready: $OUTPUT_DIR"
