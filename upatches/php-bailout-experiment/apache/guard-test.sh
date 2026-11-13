#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
set -euo pipefail

php_version=${PHP_DEMO_VERSION:-8.4.26}
case "$php_version" in
    8.4.26) fixtures=/mnt/shirudo-bundle/fixtures/php2shell ;;
    8.5.11) fixtures=/mnt/shirudo-bundle/fixtures/php2shell-8.5.11 ;;
    *) printf 'unsupported PHP demo version: %s\n' "$php_version" >&2; exit 2 ;;
esac
demo=/mnt/shirudo-src/upatches/php-bailout-experiment/apache
runtime=/usr/local/bin/shirudo-runtime
loaded=
server_pid=
response_status=
response_body=

cleanup()
{
    if [ -n "$loaded" ]; then
        "$runtime" upatch unload \
            "$fixtures/$loaded.unload.upatch" --report=- || true
    fi
    if [ -r /run/apache2/apache2.pid ]; then
        local pid
        pid=$(cat /run/apache2/apache2.pid)
        if [ "$(cat "/proc/$pid/comm" 2>/dev/null)" = apache2 ]; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    fi
    if [ -n "$server_pid" ]; then
        wait "$server_pid" || true
    fi
}

request()
{
    local phase=$1 kind=$2 output

    output=$(mktemp)
    case "$kind" in
        form)
            response_status=$(curl --max-time 8 -sS -F note=hello \
                -o "$output" -w '%{http_code}' \
                http://127.0.0.1:18080/healthy.php 2>/dev/null || true)
            ;;
        progress)
            response_status=$(curl --max-time 8 -sS -b PHPSESSID=demo \
                -F PHP_SESSION_UPLOAD_PROGRESS=demo -F file=@/etc/hosts \
                -o "$output" -w '%{http_code}' \
                http://127.0.0.1:18080/healthy.php 2>/dev/null || true)
            ;;
        exec-direct|exec-shell)
            response_status=$(curl --max-time 8 -sS -o "$output" \
                -w '%{http_code}' \
                "http://127.0.0.1:18080/exec.php?method=${kind#exec-}" \
                2>/dev/null || true)
            ;;
        *)
            response_status=$(curl --max-time 8 -sS -o "$output" \
                -w '%{http_code}' \
                "http://127.0.0.1:18080/$kind.php" 2>/dev/null || true)
            ;;
    esac
    response_body=$(cat "$output")
    printf '%s %s status=%s body=' "$phase" "$kind" "$response_status"
    tr '\n' '|' <"$output"
    printf '\n'
    rm -f "$output"
}

expect_ok()
{
    [ "$response_status" = 200 ] &&
        printf '%s\n' "$response_body" | grep -q HEALTHY
}

expect_closed()
{
    if [ "$response_status" != 000 ] ||
        printf '%s\n' "$response_body" | grep -q SHUTDOWN_REACHED; then
        echo 'expected a closed connection without a shutdown marker' >&2
        return 1
    fi
    sleep 1
}

replace_worker()
{
    local old_pid new_pid attempt

    request before-restart healthy
    expect_ok
    old_pid=$(printf '%s\n' "$response_body" | sed -n 's/^PID=//p')
    [ -n "$old_pid" ]
    kill -USR1 "$(cat /run/apache2/apache2.pid)"
    for attempt in $(seq 1 20); do
        sleep 1
        request after-restart healthy
        new_pid=$(printf '%s\n' "$response_body" | sed -n 's/^PID=//p')
        if expect_ok && [ -n "$new_pid" ] && [ "$new_pid" != "$old_pid" ]; then
            printf 'worker replaced: %s -> %s\n' "$old_pid" "$new_pid"
            return 0
        fi
    done
    echo 'Apache did not replace its worker' >&2
    return 1
}

expect_exec_allowed()
{
    [ "$response_status" = 200 ] &&
        printf '%s\n' "$response_body" | grep -q 'status=0 output=PROGRAM_STARTED' &&
        printf '%s\n' "$response_body" | grep -q PHP_STILL_RUNNING
}

expect_exec_denied()
{
    [ "$response_status" = 200 ] &&
        ! printf '%s\n' "$response_body" | grep -q PROGRAM_STARTED &&
        printf '%s\n' "$response_body" | grep -q PHP_STILL_RUNNING
}

exec_stats()
{
    "$runtime" upatch get "$1" --json | python3 -c '
import json
import re
import sys
maps = json.load(sys.stdin)["upatch"]["maps"]
stats = next(item for item in maps if item["name"] == "exec_stats")
value = stats["entries"][0]["value"]
fields = {name: int(number, 0) for name, number in
          re.findall(r"(\w+)=([0-9]+)", value)}
assert fields["denied"] == int(sys.argv[1]), value
assert fields["marked"] >= 1, value
assert fields["inherited"] >= int(sys.argv[2]), value
for field in ("mark_errors", "fork_errors", "signal_errors"):
    assert fields[field] == 0, value
print("exec_stats " + value)
' "$2" "$3"
}

check_exec_fixture()
{
    local target

    target=$(cat "$fixtures/exec.path")
    mkdir -p "$(dirname "$target")"
    install -m 0755 "$fixtures/php-exec-target" "$target"
    "$target" baseline
    "$runtime" upatch load "$fixtures/php-exec-fixture.upatch" --report=-
    loaded=php-exec-fixture
    "$target" guarded
    exec_stats "$loaded" 6 3
    "$runtime" upatch unload "$fixtures/$loaded.unload.upatch" --report=-
    loaded=
    "$target" baseline
}

stats()
{
    "$runtime" upatch get "$1" --json | python3 -c '
import json
import re
import sys
maps = json.load(sys.stdin)["upatch"]["maps"]
stats = next(item for item in maps if item["name"] == "stats")
value = stats["entries"][0]["value"]
fields = {name: int(number, 0) for name, number in
          re.findall(r"(\w+)=([0-9]+)", value)}
assert fields["signal_errors"] == 0, value
if len(sys.argv) > 1 and sys.argv[1] == "selective":
    assert fields["oom"] >= 1, value
    assert fields["fatal"] >= 1, value
    assert fields["early_diagnostic"] >= 1, value
    assert fields["early_session"] >= 1, value
    assert fields["allowed_diagnostic"] >= 1, value
    assert fields["phase_errors"] == 0, value
else:
    assert fields["oom"] >= 1, value
    assert fields["zend_error"] >= 1, value
    assert fields["multipart"] >= 2, value
print(value)
' "$2"
}

bash "$demo/setup-vm.sh"
trap cleanup EXIT
check_exec_fixture
# Apache signals its process group during shutdown.
setsid --wait apachectl -DFOREGROUND >/tmp/php2shell-guard-apache.log 2>&1 &
server_pid=$!
for attempt in $(seq 1 20); do
    if curl -fsS --max-time 2 \
        http://127.0.0.1:18080/healthy.php >/dev/null 2>&1; then
        break
    fi
    sleep 1
done
request baseline healthy
expect_ok
request baseline ordinary-warning
expect_ok
request baseline form
expect_ok
request baseline progress
expect_ok
request baseline exec-direct
expect_exec_allowed
request baseline exec-shell
expect_exec_allowed

"$runtime" upatch load "$fixtures/php-guard-broad.upatch" --report=-
loaded=php-guard-broad
replace_worker
request broad healthy
expect_ok
request broad exec-direct
expect_closed
request broad exec-shell
expect_closed
exec_stats "$loaded" 2 2
request broad ordinary-warning
expect_closed
request broad form
expect_closed
request broad progress
expect_closed
request broad fatal
expect_closed
request broad oom
expect_closed
request broad shutdown-warning
expect_closed
stats php-guard-broad broad
"$runtime" upatch unload "$fixtures/$loaded.unload.upatch" --report=-
loaded=

"$runtime" upatch load "$fixtures/php-guard-selective.upatch" --report=-
loaded=php-guard-selective
replace_worker
request selective healthy
expect_ok
request selective exec-direct
expect_exec_denied
request selective exec-shell
expect_exec_denied
exec_stats "$loaded" 2 2
request selective ordinary-warning
expect_ok
request selective form
expect_ok
request selective progress
expect_closed
request selective fatal
expect_closed
request selective oom
expect_closed
request selective shutdown-warning
expect_closed
request selective healthy
expect_ok
stats php-guard-selective selective
"$runtime" upatch unload "$fixtures/$loaded.unload.upatch" --report=-
loaded=
request restored ordinary-warning
expect_ok
request restored form
expect_ok
request restored exec-direct
expect_exec_allowed
request restored exec-shell
expect_exec_allowed
printf 'APACHE_PHP_GUARD_PASS\n'
