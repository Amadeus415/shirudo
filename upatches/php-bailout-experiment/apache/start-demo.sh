#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
set -euo pipefail

demo=/mnt/shirudo-src/upatches/php-bailout-experiment/apache
pidfile=/run/php2shell-apache-demo.pid
if [ -s "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    echo 'Apache demo is already running on 127.0.0.1:18080'
    exit 0
fi
bash "$demo/setup-vm.sh"
nohup apachectl -DFOREGROUND </dev/null \
    >/var/log/apache2/php2shell-demo.log 2>&1 &
pid=$!
printf '%s\n' "$pid" >"$pidfile"
for attempt in $(seq 1 20); do
    if curl -fsS --max-time 2 http://127.0.0.1:18080/index.php \
        2>/dev/null | grep -q 'Apache is serving PHP'; then
        echo 'Apache demo ready on 127.0.0.1:18080'
        exit 0
    fi
    sleep 1
done
kill "$pid" 2>/dev/null || true
rm -f "$pidfile"
tail -30 /var/log/apache2/php2shell-demo.log >&2
exit 1
