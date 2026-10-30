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
target=$(cat "$fixtures/apache.path")
root=/opt/shirudo/php2shell/www

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
install -m 0755 "$fixtures/libphp-$php_version.so" "$target"
install -m 0644 "$demo"/www/*.php "$root/"
if [ "$php_version" = 8.5.11 ]; then
    mkdir -p "$root/early"
    install -m 0644 "$demo/www/healthy.php" "$root/early/healthy.php"
fi
systemctl stop apache2 >/dev/null 2>&1 || true
a2dismod -f mpm_event >/dev/null
a2enmod mpm_prefork >/dev/null
install -m 0644 "$demo/ports.conf" /etc/apache2/ports.conf
install -m 0644 "$demo/mpm_prefork.conf" \
    /etc/apache2/mods-available/mpm_prefork.conf
site="$demo/site.conf"
if [ "$php_version" = 8.5.11 ]; then
    site="$demo/site-8.5.conf"
fi
install -m 0644 "$site" /etc/apache2/sites-available/000-default.conf
sed "s|@MODULE@|$target|" "$demo/php2shell.conf.in" \
    >/etc/apache2/conf-enabled/php2shell.conf
apachectl -t
