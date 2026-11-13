#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
set -euo pipefail

repo=$(cd "$(dirname "$0")/../../.." && pwd)
apache="$repo/upatches/php-bailout-experiment/apache"
php_version=${PHP_DEMO_VERSION:-8.4.26}
case "$php_version" in
    8.4.26)
        archive_sha256=32a2de53862ad44ed4a5005244ce4f1b50c271e74dced215449a4443b40569f1
        work="$repo/build/php2shell/apache-demo"
        fixture_name=php2shell
        ;;
    8.5.11)
        archive_sha256=d9be75c08e8c316f4c8f4194d8fbe1750a15f6a6d9d4e3fe72082abeeb800360
        work="$repo/build/php2shell/apache-demo-8.5.11"
        fixture_name=php2shell-8.5.11
        ;;
    *)
        printf 'unsupported PHP demo version: %s\n' "$php_version" >&2
        exit 2
        ;;
esac
archive="$repo/build/php2shell/php-$php_version.tar.xz"
target="$work/php-$php_version/.libs/libphp.so"

[ "$#" -eq 1 ] || {
    printf 'usage: %s <test-vm-host-bundle>\n' "$0" >&2
    exit 2
}
bundle=$(realpath "$1")
keys="$bundle.operator/keys"
fixtures="$bundle/fixtures/$fixture_name"
builder="$repo/tools/shirudo-build/shirudo-build"
mkdir -p "$work" "$fixtures"

[ "$(uname -m)" = x86_64 ] || {
    echo 'this demo supports x86-64 only' >&2
    exit 1
}
[ -r "$keys/signing_key.pem" ] && [ -x "$builder" ] || {
    echo 'build the Shirudo VM bundle first' >&2
    exit 1
}
cmp -s "$keys/cert.der" "$bundle/fixtures/cert.der" || {
    echo 'the VM key does not match the bundle certificate' >&2
    exit 1
}
if [ ! -s "$archive" ]; then
    curl -fL --retry 3 "https://www.php.net/distributions/php-$php_version.tar.xz" \
        -o "$archive.tmp"
    mv "$archive.tmp" "$archive"
fi
printf '%s  %s\n' "$archive_sha256" "$archive" | sha256sum -c --status

docker build -q -t shirudo-php2shell-apache-demo:local \
    -f "$apache/Dockerfile" "$apache" >"$work/docker-build.log" 2>&1 || {
        tail -60 "$work/docker-build.log" >&2
        exit 1
    }
docker run --rm --network none --user "$(id -u):$(id -g)" \
    -e HOME=/tmp -e PHP_DEMO_VERSION="$php_version" \
    -v "$work:/work/apache-demo" -v "$archive:/php-src.tar.xz:ro" \
    shirudo-php2shell-apache-demo:local bash -lc '
        set -euo pipefail
        if [ ! -d /work/apache-demo/php-$PHP_DEMO_VERSION ]; then
            tar -xJf /php-src.tar.xz -C /work/apache-demo
        fi
        cd /work/apache-demo/php-$PHP_DEMO_VERSION
        if [ ! -f config.status ]; then
            CFLAGS="-O2 -g" LDFLAGS="-Wl,--build-id=sha1" \
                ./configure --disable-all --with-apxs2=/usr/bin/apxs2 \
                --disable-cli --disable-cgi --disable-phpdbg \
                --disable-opcache --enable-session --without-pear \
                --without-valgrind > /work/apache-demo/php-configure.log 2>&1
        fi
        make -j"$(nproc)" > /work/apache-demo/php-build.log 2>&1
    ' >"$work/container-build.log" 2>&1 || {
        tail -60 "$work/container-build.log" "$work/php-configure.log" \
            "$work/php-build.log" 2>/dev/null >&2 || true
        exit 1
    }
[ -r "$target" ] || {
    echo 'libphp.so was not built' >&2
    exit 1
}

build_upatch()
{
    local name=$1 source=$2 probe_target=${3:-$target} object load unload digest

    object="$work/$name.bpf.o"
    load="$work/$name.upatch"
    unload="$work/$name.unload.upatch"
    clang -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Wextra -Werror \
        -Wno-missing-declarations -Wno-unused-parameter \
        -I"$repo/vendor/linux" -I"$repo/vendor/libbpf" \
        "-DPHP_BAILOUT_TARGET=\"$probe_target\"" \
        -c "$source" -o "$object"
    "$builder" "$object" --name "$name" -o "$load" --keys-dir "$keys"
    digest=$("$repo/shirudo" upatch info "$load" --json |
        python3 -c 'import json, sys; print(json.load(sys.stdin)["payload_sha256"])')
    "$builder" --unload "$name" -o "$unload" \
        --payload-sha256 "$digest" --keys-dir "$keys"
    install -m 0644 "$load" "$unload" "$fixtures/"
}

exec_target="$work/php-exec-target"
cc -O2 -g -Wall -Wextra -Werror -pthread -Wl,--build-id=sha1 \
    "$repo/testing/fixtures/php-exec-target.c" -o "$exec_target"
build_upatch php-exec-fixture "$repo/testing/fixtures/php-exec.bpf.c" \
    "$exec_target"
install -m 0755 "$exec_target" "$fixtures/php-exec-target"
printf '%s\n' "$exec_target" >"$fixtures/exec.path"

build_upatch php-bailout-apache \
    "$repo/upatches/php-bailout-experiment/php-bailout.bpf.c"
for symbol in zend_mm_safe_error _zend_bailout zend_error_zstr_at \
    php_error_cb rfc1867_post_handler php_execute_script \
    php_request_startup php_request_shutdown php_session_initialize; do
    nm "$target" | awk -v name="$symbol" '$3 == name { found = 1 } END { exit !found }' || {
        printf 'required PHP symbol missing: %s\n' "$symbol" >&2
        exit 1
    }
done
build_upatch php-guard-broad \
    "$repo/upatches/php-bailout-experiment/php-guard-broad.bpf.c"
build_upatch php-guard-selective \
    "$repo/upatches/php-bailout-experiment/php-guard-selective.bpf.c"
"$repo/testing/helper/test-upatch-prog-metadata" \
    "$work/php-bailout-apache.upatch" uprobe-multi "$target" _zend_bailout 1
install -m 0644 "$target" "$fixtures/libphp-$php_version.so"
printf '%s\n' "$target" >"$fixtures/apache.path"
(
    cd "$fixtures"
    sha256sum "libphp-$php_version.so" php-bailout-apache.upatch \
        php-bailout-apache.unload.upatch \
        php-guard-broad.upatch php-guard-broad.unload.upatch \
        php-guard-selective.upatch php-guard-selective.unload.upatch \
        php-exec-fixture.upatch php-exec-fixture.unload.upatch \
        php-exec-target exec.path apache.path >APACHE-SHA256SUMS
)
printf 'Apache demo ready in %s\n' "$fixtures"
