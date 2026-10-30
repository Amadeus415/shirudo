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
    [ "$response_status" = 000 ] &&
        ! printf '%s\n' "$response_body" | grep -q SHUTDOWN_REACHED
    sleep 1
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
apachectl -DFOREGROUND >/tmp/php2shell-guard-apache.log 2>&1 &
trap cleanup EXIT
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

"$runtime" upatch load "$fixtures/php-guard-broad.upatch" --report=-
loaded=php-guard-broad
kill -USR1 "$(cat /run/apache2/apache2.pid)"
sleep 1
request broad healthy
expect_ok
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
kill -USR1 "$(cat /run/apache2/apache2.pid)"
sleep 1
request selective healthy
expect_ok
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
printf 'APACHE_PHP_GUARD_PASS\n'
