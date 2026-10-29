#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
set -euo pipefail

repo=$(cd "$(dirname "$0")/../../.." && pwd)
apache="$repo/upatches/php-bailout-experiment/apache"
work="$repo/build/php2shell/apache-demo"
archive="$repo/build/php2shell/php-8.4.26.tar.xz"
target="$work/php-8.4.26/.libs/libphp.so"
archive_sha256=32a2de53862ad44ed4a5005244ce4f1b50c271e74dced215449a4443b40569f1

[ "$#" -eq 1 ] || {
    printf 'usage: %s <test-vm-host-bundle>\n' "$0" >&2
    exit 2
}
bundle=$(realpath "$1")
keys="$bundle.operator/keys"
fixtures="$bundle/fixtures/php2shell"
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
    curl -fL --retry 3 https://www.php.net/distributions/php-8.4.26.tar.xz \
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
    -e HOME=/tmp -v "$work:/work/apache-demo" -v "$archive:/php-src.tar.xz:ro" \
    shirudo-php2shell-apache-demo:local bash -lc '
        set -euo pipefail
        if [ ! -d /work/apache-demo/php-8.4.26 ]; then
            tar -xJf /php-src.tar.xz -C /work/apache-demo
        fi
        cd /work/apache-demo/php-8.4.26
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

object="$work/php-bailout-apache.bpf.o"
load="$work/php-bailout-apache.upatch"
unload="$work/php-bailout-apache.unload.upatch"
clang -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Wextra -Werror \
    -Wno-missing-declarations -Wno-unused-parameter \
    -I"$repo/vendor/linux" -I"$repo/vendor/libbpf" \
    "-DPHP_BAILOUT_TARGET=\"$target\"" \
    -c "$repo/upatches/php-bailout-experiment/php-bailout.bpf.c" -o "$object"
"$builder" "$object" --name php-bailout-apache -o "$load" --keys-dir "$keys"
digest=$("$repo/shirudo" upatch info "$load" --json |
    python3 -c 'import json, sys; print(json.load(sys.stdin)["payload_sha256"])')
"$builder" --unload php-bailout-apache -o "$unload" \
    --payload-sha256 "$digest" --keys-dir "$keys"
"$repo/testing/helper/test-upatch-prog-metadata" "$load" \
    uprobe-multi "$target" _zend_bailout 1
install -m 0644 "$load" "$unload" "$fixtures/"
install -m 0644 "$target" "$fixtures/libphp-8.4.26.so"
printf '%s\n' "$target" >"$fixtures/apache.path"
(
    cd "$fixtures"
    sha256sum libphp-8.4.26.so php-bailout-apache.upatch \
        php-bailout-apache.unload.upatch apache.path >APACHE-SHA256SUMS
)
printf 'Apache demo ready in %s\n' "$fixtures"
