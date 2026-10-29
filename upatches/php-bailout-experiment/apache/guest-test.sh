#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
set -euo pipefail

fixtures=/mnt/shirudo-bundle/fixtures/php2shell
demo=/mnt/shirudo-src/upatches/php-bailout-experiment/apache
target=$(cat "$fixtures/apache.path")
root=/opt/shirudo/php2shell/www
runtime=/usr/local/bin/shirudo-runtime
loaded=0
apache_pid=0
response_status=
response_body=

cleanup()
{
    if (( loaded )); then
        "$runtime" upatch unload \
            "$fixtures/php-bailout-apache.unload.upatch" --report=- || true
    fi
    apachectl stop >/dev/null 2>&1 || true
    if (( apache_pid )); then
        kill "$apache_pid" 2>/dev/null || true
        wait "$apache_pid" 2>/dev/null || true
    fi
}

request()
{
    local phase=$1 name=$2 output
    output=$(mktemp)
    response_status=$(curl --max-time 8 -sS -o "$output" -w '%{http_code}' \
        "http://127.0.0.1:18080/$name.php" 2>/dev/null || true)
    response_body=$(cat "$output")
    printf '%s %s status=%s body=' "$phase" "$name" "$response_status"
    tr '\n' '|' <"$output"
    printf '\n'
    rm -f "$output"
}

expect_healthy()
{
    [ "$response_status" = 200 ] &&
        printf '%s\n' "$response_body" | grep -qx HEALTHY
}

expect_shutdown()
{
    [ "$response_status" = 200 ] &&
        printf '%s\n' "$response_body" | grep -qx SHUTDOWN_REACHED
}

expect_killed()
{
    [ "$response_status" = 000 ] &&
        ! printf '%s\n' "$response_body" | grep -q SHUTDOWN_REACHED
}

if ! command -v apachectl >/dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    if ! { apt-get update -qq && apt-get install -y -qq apache2; } \
        >/tmp/php2shell-apt.log 2>&1; then
        tail -60 /tmp/php2shell-apt.log >&2
        exit 1
    fi
fi
(cd "$fixtures" && sha256sum -c APACHE-SHA256SUMS)
mkdir -p "$(dirname "$target")" "$root"
install -m 0755 "$fixtures/libphp-8.4.26.so" "$target"
install -m 0644 "$demo"/www/*.php "$root/"
systemctl stop apache2 >/dev/null 2>&1 || true
a2dismod -f mpm_event >/dev/null
a2enmod mpm_prefork >/dev/null
install -m 0644 "$demo/ports.conf" /etc/apache2/ports.conf
install -m 0644 "$demo/mpm_prefork.conf" \
    /etc/apache2/mods-available/mpm_prefork.conf
install -m 0644 "$demo/site.conf" \
    /etc/apache2/sites-available/000-default.conf
sed "s|@MODULE@|$target|" "$demo/php2shell.conf.in" \
    >/etc/apache2/conf-enabled/php2shell.conf
apachectl -t
apachectl -DFOREGROUND >/tmp/php2shell-apache.stdout 2>&1 &
apache_pid=$!
trap cleanup EXIT
for attempt in $(seq 1 20); do
    if curl -fsS --max-time 2 \
        http://127.0.0.1:18080/healthy.php >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

printf 'kernel=%s\nmodule=%s\n' "$(uname -r)" "$target"
request baseline healthy
expect_healthy
baseline_pid=$(printf '%s\n' "$response_body" |
    sed -n 's/^PID=\([0-9][0-9]*\)$/\1/p')
[ -n "$baseline_pid" ]
request baseline fatal
expect_shutdown
request baseline oom
expect_shutdown
request baseline healthy
expect_healthy

"$runtime" upatch load "$fixtures/php-bailout-apache.upatch" --report=-
loaded=1
request guarded healthy
expect_healthy
request guarded fatal
expect_killed
sleep 1
request guarded oom
expect_killed
sleep 1
request guarded healthy
expect_healthy
new_pid=$(printf '%s\n' "$response_body" |
    sed -n 's/^PID=\([0-9][0-9]*\)$/\1/p')
[ -n "$new_pid" ] && [ "$new_pid" != "$baseline_pid" ]
"$runtime" upatch get php-bailout-apache --json |
    python3 -c '
import json
import re
import sys
upatch = json.load(sys.stdin)["upatch"]
stats = next(item for item in upatch["maps"] if item["name"] == "stats")
value = stats["entries"][0]["value"]
match = re.fullmatch(r"\{ hits=([^,]+), signal_errors=([^ }]+) \}", value)
assert match and int(match[1], 0) == 2 and int(match[2], 0) == 0, value
print(value)
'
"$runtime" upatch unload "$fixtures/php-bailout-apache.unload.upatch" --report=-
loaded=0
request restored fatal
expect_shutdown
request restored oom
expect_shutdown
request restored healthy
expect_healthy
printf 'APACHE_PHP_BAILOUT_DEMO_PASS\n'
