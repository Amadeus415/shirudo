#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
[ "$#" -eq 1 ] || {
	printf 'usage: %s <test-vm-host-bundle>\n' "$0" >&2
	exit 2
}
bundle=$(realpath "$1")
keys="$bundle.operator/keys"
work="$repo/build/php2shell"
php_dir="$work/php-8.4.26"
php="$php_dir/sapi/cli/php"
fixture="$work/bailout-target"
fixtures="$bundle/fixtures/php2shell"
builder="$repo/tools/shirudo-build/shirudo-build"
source="$repo/upatches/php-bailout-experiment/php-bailout.bpf.c"
archive="$work/php-8.4.26.tar.xz"
archive_sha256=32a2de53862ad44ed4a5005244ce4f1b50c271e74dced215449a4443b40569f1

die()
{
	printf 'php bailout VM setup: %s\n' "$*" >&2
	exit 1
}

build_php()
{
	if [ ! -s "$archive" ]; then
		curl -fL --retry 3 \
			https://www.php.net/distributions/php-8.4.26.tar.xz \
			-o "$archive.tmp"
		mv "$archive.tmp" "$archive"
	fi
	printf '%s  %s\n' "$archive_sha256" "$archive" |
		sha256sum -c --status || die "PHP source checksum does not match"
	if [ ! -d "$php_dir" ]; then
		tar -xJf "$archive" -C "$work"
	fi
	if [ ! -f "$php_dir/config.status" ]; then
		(
			cd "$php_dir"
			CFLAGS='-O2 -g' LDFLAGS='-Wl,--build-id=sha1' \
				./configure --disable-all --enable-cli --disable-cgi \
				--disable-phpdbg --disable-opcache --without-pear \
				--without-valgrind >"$work/php-configure.log" 2>&1
		) || {
			tail -80 "$work/php-configure.log" >&2
			die "PHP configure failed"
		}
	fi
	make -j"$(nproc)" -C "$php_dir" >"$work/php-build.log" 2>&1 || {
		tail -80 "$work/php-build.log" >&2
		die "PHP build failed"
	}
	[ -x "$php" ] || die "PHP CLI binary was not built"
}

build_upatch()
{
	local name=$1 target=$2
	local object="$work/$name.bpf.o"
	local load="$work/$name.upatch"
	local unload="$work/$name.unload.upatch"
	local digest

	clang -target bpf -D__TARGET_ARCH_x86 -O2 -g -Wall -Wextra -Werror \
		-Wno-missing-declarations -Wno-unused-parameter \
		-I"$repo/vendor/linux" -I"$repo/vendor/libbpf" \
		"-DPHP_BAILOUT_TARGET=\"$target\"" \
		-c "$source" -o "$object"
	"$builder" "$object" --name "$name" -o "$load" --keys-dir "$keys"
	digest=$("$repo/shirudo" upatch info "$load" --json |
		python3 -c 'import json, sys; print(json.load(sys.stdin)["payload_sha256"])')
	"$builder" --unload "$name" -o "$unload" \
		--payload-sha256 "$digest" --keys-dir "$keys"
	"$repo/testing/helper/test-upatch-prog-metadata" "$load" \
		uprobe-multi "$target" _zend_bailout 1
	install -m 0644 "$load" "$fixtures/"
	install -m 0644 "$unload" "$fixtures/"
}

[ "$(uname -m)" = x86_64 ] || die "this experiment currently supports x86-64 only"
[ -r "$keys/signing_key.pem" ] || die "VM signing key missing; rebuild the host bundle"
cmp -s "$keys/cert.der" "$bundle/fixtures/cert.der" ||
	die "VM signing key does not match the bundle certificate"
[ -x "$builder" ] || die "build Shirudo and the VM bundle first"
[ -x "$repo/testing/helper/test-upatch-prog-metadata" ] ||
	die "build the VM test helpers first"
mkdir -p "$work" "$fixtures"

build_php
cc -O0 -g -Wl,--build-id=sha1 \
	-o "$fixture" "$repo/testing/fixtures/php2shell-bailout-target.c"
build_upatch php-bailout-fixture "$fixture"
build_upatch php-bailout-cli "$php"
install -m 0755 "$fixture" "$fixtures/bailout-target"
install -m 0755 "$php" "$fixtures/php"
printf '%s\n' "$fixture" >"$fixtures/fixture.path"
printf '%s\n' "$php" >"$fixtures/php.path"
(
	cd "$fixtures"
	sha256sum -- bailout-target php *.upatch *.path >SHA256SUMS
)
printf 'signed PHP bailout fixtures in %s\n' "$fixtures"
