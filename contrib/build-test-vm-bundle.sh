#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Build the host-side payload imported by contrib/test-vm.sh. The bundle is
# shared by all VMs, while TPM state and the test workspace remain per-VM.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUNDLE_DIR="${TEST_VM_HOST_BUNDLE:-${REPO_ROOT}/build/test-vm/host-bundle}"
WORK_DIR="${TEST_VM_WORK_DIR:-${REPO_ROOT}/build/test-vm}"
RUNTIME_CACHE_DIR="${TEST_VM_RUNTIME_CACHE_DIR:-${WORK_DIR}/cache/runtime}"
BPF_DEPS_DIR="${TEST_VM_BPF_DEPS_DIR:-${REPO_ROOT}/artifacts/bpf-next-kernel-debs/shirudo-bpf-deps}"
LIBGUESTFS_KERNEL_CACHE="${WORK_DIR}/cache/libguestfs/ubuntu"
UBUNTU_CODENAME="${TEST_VM_UBUNTU_CODENAME:-resolute}"
PACKAGE_FILE="$REPO_ROOT/contrib/test-vm-runtime-packages"
DEFAULT_ROOTFS_URL="https://cloud-images.ubuntu.com/releases/server/26.04/release/ubuntu-26.04-server-cloudimg-amd64.img"
ROOTFS_URL="${TEST_VM_ROOTFS_URL:-$DEFAULT_ROOTFS_URL}"
ROOTFS_SHA256="${TEST_VM_ROOTFS_SHA256:-}"
ROOTFS_NAME="ubuntu-26.04-server-cloudimg-amd64.img"
ROOTFS_CACHE="${WORK_DIR}/cache/rootfs/${ROOTFS_NAME}"
LOCK_FILE="${BUNDLE_DIR}.lock"
STAMP_FILE="${TEST_VM_BUNDLE_STAMP:-${BUNDLE_DIR}/.stamp}"
STAMP_INPUTS="${TEST_VM_BUNDLE_INPUTS:-}"
PACKAGE_CERT="${TEST_VM_PACKAGE_CERT:-}"
RUNTIME_PREP_VERSION=4
RUNTIME_DISK_SIZE="${TEST_VM_RUNTIME_DISK_SIZE:-8G}"

log()
{
	printf '[test-vm-bundle] %s\n' "$*" >&2
}

die()
{
	log "error: $*"
	exit 1
}

validate_package_cert()
{
	[[ -z "$PACKAGE_CERT" ]] && return 0
	[[ -f "$PACKAGE_CERT" && -r "$PACKAGE_CERT" && -s "$PACKAGE_CERT" ]] ||
		die "TEST_VM_PACKAGE_CERT is not a readable, non-empty regular file: $PACKAGE_CERT"
}

require_command()
{
	local command_name="$1" package_name="$2"
	command -v "$command_name" >/dev/null 2>&1 ||
		die "missing host command: $command_name (install with: sudo apt-get install -y $package_name)"
}

check_libguestfs_host()
{
	local kernel="" candidate
	if [[ -n "${SUPERMIN_KERNEL:-}" ]]; then
		[[ -r "$SUPERMIN_KERNEL" ]] ||
			die "SUPERMIN_KERNEL is not readable: $SUPERMIN_KERNEL"
	else
		for candidate in /boot/vmlinuz* /lib/modules/*/vmlinuz; do
			if [[ -r "$candidate" ]]; then
				kernel="$candidate"
				break
			fi
		done
		if [[ -z "$kernel" ]]; then
			prepare_ubuntu_libguestfs_kernel
			log "libguestfs host check: using cached Ubuntu $UBUNTU_CODENAME kernel"
		fi
	fi
	if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
		log "libguestfs host check: /dev/kvm unavailable; appliance will use slower TCG"
	else
		log "libguestfs host check: KVM available"
	fi
}

prepare_ubuntu_libguestfs_kernel()
{
	local cache_dir index metadata package version kernel_version filename deb tmp
	local module_package module_filename kernel_info module_info module_root
	cache_dir="$LIBGUESTFS_KERNEL_CACHE/$UBUNTU_CODENAME"
	index="$cache_dir/Packages.gz"
	metadata="$cache_dir/kernel.info"
	mkdir -p "$cache_dir"
	if [[ ! -s "$metadata" || "$(awk -F '\t' '{print NF; exit}' "$metadata")" != 5 ]]; then
		curl -fsSL --retry 3 \
			--output "${index}.tmp" \
			"https://archive.ubuntu.com/ubuntu/dists/${UBUNTU_CODENAME}-updates/main/binary-amd64/Packages.gz" \
			|| die "could not download Ubuntu $UBUNTU_CODENAME kernel package index"
		mv -- "${index}.tmp" "$index"
		kernel_info="$(awk -v RS='' -v FS='\n' '
			{
				package=arch=version=filename=""
				for (i = 1; i <= NF; i++) {
					if ($i ~ /^Package: /) package=substr($i, 10)
					if ($i ~ /^Architecture: /) arch=substr($i, 15)
					if ($i ~ /^Version: /) version=substr($i, 10)
					if ($i ~ /^Filename: /) filename=substr($i, 11)
				}
				if (package ~ /^linux-image-[0-9].*-generic$/ &&
				    arch == "amd64" && version != "" && filename != "")
					print version "\t" package "\t" filename
			}
		' <(gzip -dc "$index") | sort -V | tail -1)"
		[[ -n "$kernel_info" ]] ||
			die "Ubuntu $UBUNTU_CODENAME has no amd64 generic kernel package"
		IFS=$'\t' read -r version package filename <<<"$kernel_info"
		kernel_version="${package#linux-image-}"
		module_info="$(awk -v want="linux-modules-$kernel_version" -v RS='' -v FS='\n' '
			{
				package=arch=version=filename=""
				for (i = 1; i <= NF; i++) {
					if ($i ~ /^Package: /) package=substr($i, 10)
					if ($i ~ /^Architecture: /) arch=substr($i, 15)
					if ($i ~ /^Version: /) version=substr($i, 10)
					if ($i ~ /^Filename: /) filename=substr($i, 11)
				}
				if (package == want && arch == "amd64" && version != "" && filename != "")
					print package "\t" filename
			}
		' <(gzip -dc "$index") | sort -V | tail -1)"
		[[ -n "$module_info" ]] ||
			die "Ubuntu $UBUNTU_CODENAME has no matching $kernel_version modules package"
		IFS=$'\t' read -r module_package module_filename <<<"$module_info"
		printf '%s\t%s\t%s\t%s\t%s\n' "$version" "$package" "$filename" \
			"$module_package" "$module_filename" >"${metadata}.tmp"
		mv -- "${metadata}.tmp" "$metadata"
	fi
	IFS=$'\t' read -r version package filename module_package module_filename <"$metadata"
	[[ -n "$version" && -n "$package" && -n "$filename" &&
	   -n "$module_package" && -n "$module_filename" ]] ||
		die "invalid cached Ubuntu kernel metadata: $metadata"
	kernel_version="${package#linux-image-}"
	deb="$cache_dir/$package.deb"
	if [[ ! -s "$deb" ]]; then
		curl -fsSL --retry 3 --output "${deb}.tmp" \
			"https://archive.ubuntu.com/ubuntu/$filename" ||
			die "could not download Ubuntu kernel package $package"
		mv -- "${deb}.tmp" "$deb"
	fi
	local module_deb="$cache_dir/$module_package.deb"
	if [[ ! -s "$module_deb" ]]; then
		curl -fsSL --retry 3 --output "${module_deb}.tmp" \
			"https://archive.ubuntu.com/ubuntu/$module_filename" ||
			die "could not download Ubuntu kernel modules package $module_package"
		mv -- "${module_deb}.tmp" "$module_deb"
	fi
	version="${version%% *}"
	tmp="$cache_dir/.root.tmp.$$"
	rm -rf -- "$tmp"
	mkdir -p "$tmp"
	dpkg-deb -x "$deb" "$tmp"
	dpkg-deb -x "$module_deb" "$tmp"
	module_root="$tmp/lib/modules"
	[[ -d "$module_root/$kernel_version" ]] || module_root="$tmp/usr/lib/modules"
	if [[ ! -r "$module_root/$kernel_version/modules.dep" ]]; then
		if [[ "$module_root" == "$tmp/usr/lib/modules" ]]; then
			mkdir -p "$tmp/lib"
			ln -s ../usr/lib/modules "$tmp/lib/modules"
			module_root="$tmp/lib/modules"
		fi
		depmod -b "$tmp" "$kernel_version"
	fi
	[[ -r "$tmp/boot/vmlinuz-$kernel_version" &&
	   -r "$module_root/$kernel_version/modules.dep" ]] ||
		die "Ubuntu kernel package $package lacks a usable kernel/module tree"
	if [[ ! -r "$cache_dir/boot/vmlinuz-$kernel_version" ||
	      ! -r "$cache_dir/lib/modules/$kernel_version/modules.dep" ]]; then
		mkdir -p "$cache_dir/boot" "$cache_dir/lib"
		[[ -L "$cache_dir/lib/modules" ]] && rm -f -- "$cache_dir/lib/modules"
		mkdir -p "$cache_dir/lib/modules"
		cp -a "$tmp/boot/." "$cache_dir/boot/"
		cp -a "$module_root/." "$cache_dir/lib/modules/"
	fi
	[[ -r "$cache_dir/boot/vmlinuz-$kernel_version" &&
	   -r "$cache_dir/lib/modules/$kernel_version/modules.dep" ]] ||
		die "Ubuntu kernel package lacks a usable kernel/module tree"
	rm -rf -- "$tmp"
	export SUPERMIN_KERNEL="$cache_dir/boot/vmlinuz-$kernel_version"
	export SUPERMIN_MODULES="$cache_dir/lib/modules/$kernel_version"
	export SUPERMIN_KERNEL_VERSION="$kernel_version"
	return 0
}

for dependency in \
	"flock:util-linux" "curl:curl" "sha256sum:coreutils" "awk:gawk" \
	"qemu-img:qemu-utils" "virt-customize:libguestfs-tools" \
	"dpkg-deb:dpkg" "openssl:openssl" \
	"gzip:gzip" "depmod:kmod"; do
	IFS=: read -r command_name package_name <<<"$dependency"
	require_command "$command_name" "$package_name"
done
check_libguestfs_host

resolve_rootfs()
{
	local sums expected actual tmp
	mkdir -p "$(dirname "$ROOTFS_CACHE")"
	if [[ -n "$ROOTFS_SHA256" ]]; then
		expected="${ROOTFS_SHA256,,}"
	elif [[ "$ROOTFS_URL" != "$DEFAULT_ROOTFS_URL" ]]; then
		die "a custom TEST_VM_ROOTFS_URL requires TEST_VM_ROOTFS_SHA256"
	else
		sums="${ROOTFS_CACHE}.SHA256SUMS"
		curl -fsSL --retry 3 --output "$sums" \
			https://cloud-images.ubuntu.com/releases/server/26.04/release/SHA256SUMS
		expected="$(awk -v name="*$ROOTFS_NAME" '$2 == name {print $1; exit}' "$sums")"
		rm -f -- "$sums"
	fi
	[[ "$expected" =~ ^[0-9a-fA-F]{64}$ ]] ||
		die "could not determine a valid SHA-256 for $ROOTFS_NAME"
	if [[ -s "$ROOTFS_CACHE" ]]; then
		actual="$(sha256sum "$ROOTFS_CACHE" | awk '{print $1}')"
		[[ "$actual" == "$expected" ]] || rm -f -- "$ROOTFS_CACHE"
	fi
	if [[ ! -s "$ROOTFS_CACHE" ]]; then
		tmp="${ROOTFS_CACHE}.tmp.$$"
		log "downloading Ubuntu runtime rootfs: $ROOTFS_URL"
		curl -fL --retry 3 --output "$tmp" "$ROOTFS_URL"
		actual="$(sha256sum "$tmp" | awk '{print $1}')"
		[[ "$actual" == "$expected" ]] || {
			rm -f -- "$tmp"
			die "downloaded rootfs SHA-256 mismatch"
		}
		mv -- "$tmp" "$ROOTFS_CACHE"
	fi
	ROOTFS_DIGEST="$expected"
}

prepare_runtime_image()
{
	local package_digest disk_size_key
	package_digest="$(sha256sum "$PACKAGE_FILE" | awk '{print $1}')"
	disk_size_key="${RUNTIME_DISK_SIZE//[^A-Za-z0-9]/_}"
	RUNTIME_KEY="rootfs-${ROOTFS_DIGEST}-packages-${package_digest}-disk-${disk_size_key}-v${RUNTIME_PREP_VERSION}"
	RUNTIME_IMAGE="$RUNTIME_CACHE_DIR/$RUNTIME_KEY.qcow2"
	if [[ ! -s "$RUNTIME_IMAGE" ]]; then
		"$REPO_ROOT/contrib/prepare-test-vm-runtime.sh" \
			--rootfs "$ROOTFS_CACHE" \
			--cache-dir "$RUNTIME_CACHE_DIR" \
			--package-file "$PACKAGE_FILE" \
			--runtime-key "$RUNTIME_KEY" \
			--runtime-disk-size "$RUNTIME_DISK_SIZE" \
			--key-output "$RUNTIME_CACHE_DIR/.${RUNTIME_KEY}.key"
	fi
}

bundle_is_current()
{
	local input

	[[ -f "$STAMP_FILE" && -n "$STAMP_INPUTS" ]] || return 1
	[[ -x "$BUNDLE_DIR/root/usr/local/bin/shirudo" ]] || return 1
	[[ -s "$BUNDLE_DIR/runtime-image-key" ]] || return 1
	[[ "$(<"$BUNDLE_DIR/runtime-image-key")" == "$RUNTIME_KEY" ]] || return 1
	[[ -s "$RUNTIME_IMAGE" ]] || return 1
	for input in $STAMP_INPUTS; do
		[[ -e "$input" ]] || return 1
		[[ "$input" -nt "$STAMP_FILE" ]] && return 1
	done
	return 0
}

command -v flock >/dev/null 2>&1 ||
	die "flock is required; install it with: sudo apt-get install -y util-linux"

validate_package_cert

make_mbedtls_test_cert()
{
	local keys_dir="$1"

	# The OpenSSL-generated certificate from `shirudo genkey` contains an
	# empty authorityKeyIdentifier extension.  mbedTLS rejects that extension
	# while parsing the target's cert.der, so use a minimal equivalent test
	# certificate for target-side CMS verification.
	openssl req -new -x509 -key "$keys_dir/signing_key.pem" \
		-outform DER -out "$keys_dir/cert.der" -days 3650 \
		-subj /CN=shirudo \
		-addext 'basicConstraints=critical,CA:FALSE' \
		-addext 'keyUsage=digitalSignature' \
		-addext 'subjectKeyIdentifier=hash'
}

mkdir -p "$(dirname "$BUNDLE_DIR")"
exec 9>"$LOCK_FILE"
flock 9

resolve_rootfs
prepare_runtime_image

if bundle_is_current; then
	log "reusing current host bundle: $BUNDLE_DIR"
	exit 0
fi

BPF_MAKE_ARGS=()
if [[ -f "$BPF_DEPS_DIR/bpftool" &&
	  -f "$BPF_DEPS_DIR/bpf/libbpf.a" &&
	  -f "$BPF_DEPS_DIR/vmlinux.h" ]]; then
	log "using bpf-next kernel dependency artifacts"
	BPF_MAKE_ARGS=(USE_BPF_NEXT_DEPS=1)
else
	log "bpf-next kernel dependency artifacts unavailable; using vendored tools"
fi

log "building host Shirudo payload and test helpers"
make -C "$REPO_ROOT" "${BPF_MAKE_ARGS[@]}" all shirudo-build test-helpers

TMP_DIR="$(mktemp -d "${BUNDLE_DIR}.tmp.XXXXXX")"
FIXTURE_WORK="$(mktemp -d "${BUNDLE_DIR}.fixtures.XXXXXX")"
cleanup()
{
	rm -rf -- "$TMP_DIR" "$FIXTURE_WORK"
}
trap cleanup EXIT

make -C "$REPO_ROOT" "${BPF_MAKE_ARGS[@]}" \
	DESTDIR="$TMP_DIR/root" install-target

install -d "$TMP_DIR/test-helpers/t/helper"
while IFS= read -r helper; do
	install -m 0755 "$REPO_ROOT/$helper" "$TMP_DIR/test-helpers/$helper"
done <<'EOF'
t/helper/test-json-parser
t/helper/test-chain
t/helper/test-config
t/helper/test-bpf-load
t/helper/test-dns-prog-run
t/helper/test-kernel-abi
t/helper/test-otel-map
t/helper/test-upatch-map-types
t/helper/test-upatch-prog-metadata
t/helper/test-upatch-decode
t/helper/test-upatch-serializer-pages
t/helper/test-signed-load
t/helper/test-exec-churn
t/helper/otel-mock.py
t/helper/test-oci-registry.py
EOF

build_fixture()
{
	local source="$1"
	local name="$2"
	local keys_dir="$3"

	(
		cd "$REPO_ROOT"
		"$REPO_ROOT/tools/shirudo-build/shirudo-build" \
			"$REPO_ROOT/test-vm/fixtures/$source" \
			-o "$TMP_DIR/fixtures/$name.upatch" \
			--name "$name" --vmlinux "$REPO_ROOT/bpf/vmlinux.h" \
			--key "$keys_dir/signing_key.pem" \
			--cert "$keys_dir/cert.der"
	)
}

build_tree_test_registry()
{
	local registry_dir="$TMP_DIR/fixtures/tree-oci"
	local tree_payload="$FIXTURE_WORK/tree-payload.json"
	local tree_signature="$FIXTURE_WORK/tree-payload.sig"
	local tree_initial_payload="$FIXTURE_WORK/tree-payload-initial.json"
	local tree_initial_signature="$FIXTURE_WORK/tree-payload-initial.sig"
	local tree_updated_payload="$FIXTURE_WORK/tree-payload-updated.json"
	local tree_updated_signature="$FIXTURE_WORK/tree-payload-updated.sig"
	local tree_restored_payload="$FIXTURE_WORK/tree-payload-delete-restored.json"
	local tree_restored_signature="$FIXTURE_WORK/tree-payload-delete-restored.sig"

	python3 - "$registry_dir" \
		"$TMP_DIR/fixtures/shirudo-test-tree-match.upatch" \
		"$TMP_DIR/fixtures/shirudo-test-tree-skip.upatch" \
		"$TMP_DIR/fixtures/shirudo-test-tree-match.unload.upatch" \
		"$tree_payload" "$tree_initial_payload" "$tree_updated_payload" \
		"$tree_restored_payload" <<'PY'
import hashlib
import json
import pathlib
import sys

registry, match_path, skip_path, match_unload_path, tree_payload, \
    initial_payload, updated_payload, restored_payload = \
    map(pathlib.Path, sys.argv[1:])
tree_endpoint = "oci://127.0.0.1:5443/shirudo/upatch-tree"


def digest(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


def write(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


def artifact(repository, path, title):
    body = path.read_bytes()
    layer_digest = digest(body)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [{
            "mediaType": "application/vnd.shirudo.upatch.v1",
            "digest": layer_digest,
            "size": len(body),
            "annotations": {"org.opencontainers.image.title": title},
        }],
    }
    manifest_body = json.dumps(manifest, separators=(",", ":")).encode()
    manifest_digest = digest(manifest_body)
    repo_root = registry.joinpath(*repository.split("/"))
    write(repo_root / "manifests" / manifest_digest, manifest_body)
    write(repo_root / "blobs" / layer_digest, body)
    return {
        "repository": "oci://127.0.0.1:5443/" + repository,
        "manifest_digest": manifest_digest,
        "layer_digest": layer_digest,
        "payload_sha256": digest(body),
    }


match_artifact = artifact("shirudo/tree-match", match_path,
                         "shirudo-test-tree-match.upatch")
skip_artifact = artifact("shirudo/tree-skip", skip_path,
                        "shirudo-test-tree-skip.upatch")
match_unload_artifact = artifact("shirudo/tree-match-unload",
                                 match_unload_path,
                                 "shirudo-test-tree-match.unload.upatch")


def operation(seq, name, selector, artifact_info, op="add"):
    unsigned = {
        "seq": seq,
        "op": op,
        "id": name,
        "selector": selector,
        "artifact": artifact_info,
    }
    operation_digest = digest(json.dumps(unsigned, separators=(",", ":"))
                              .encode())
    return dict(unsigned, operation_digest=operation_digest)


publication = {
    "schema": 2,
    "tree_id": "shirudo-test-tree",
    "generation": 1,
    "base": {"seq": 0},
    "operations": [
        operation(1, "shirudo-test-tree-match",
                  {"architecture": ["x86_64"],
                   "labels": {"env": ["tree-test"]}}, match_artifact),
        operation(2, "shirudo-test-tree-skip",
                  {"architecture": ["x86_64"],
                   "labels": {"env": ["not-this-node"]}}, skip_artifact),
    ],
    "head": {"seq": 2},
}
tree_payload.write_bytes(json.dumps(publication, separators=(",", ":"))
                         .encode())

initial = {
    "schema": 2,
    "tree_id": "shirudo-test-tree-sequential",
    "generation": 1,
    "base": {"seq": 0},
    "operations": [
        operation(1, "shirudo-test-tree-match",
                  {"architecture": ["x86_64"],
                   "labels": {"env": ["tree-test"]}}, match_artifact),
    ],
    "head": {"seq": 1},
}
initial_payload.write_bytes(json.dumps(initial, separators=(",", ":"))
                              .encode())

updated = {
    "schema": 2,
    "tree_id": "shirudo-test-tree-sequential",
    "generation": 2,
    "base": {"seq": 0},
    "operations": [
        initial["operations"][0],
        operation(2, "shirudo-test-tree-skip",
                  {"architecture": ["x86_64"],
                   "labels": {"env": ["tree-test"]}}, skip_artifact),
    ],
    "head": {"seq": 2},
}
updated_payload.write_bytes(json.dumps(updated, separators=(",", ":"))
                              .encode())

delete_initial = {
    "schema": 2,
    "tree_id": "shirudo-test-tree-delete",
    "generation": 1,
    "base": {"seq": 0},
    "operations": [
        operation(1, "shirudo-test-tree-match",
                  {"architecture": ["x86_64"],
                   "labels": {"env": ["tree-test"]}}, match_artifact),
    ],
    "head": {"seq": 1},
}
delete_initial_payload = initial_payload.with_name("tree-payload-delete-initial.json")
delete_initial_payload.write_bytes(
    json.dumps(delete_initial, separators=(",", ":")).encode())

delete_updated = {
    "schema": 2,
    "tree_id": "shirudo-test-tree-delete",
    "generation": 2,
    "base": {"seq": 0},
    "operations": [
        delete_initial["operations"][0],
        operation(2, "shirudo-test-tree-match",
                  {"architecture": ["x86_64"],
                   "labels": {"env": ["tree-test"]}},
                  match_unload_artifact, op="delete"),
    ],
    "head": {"seq": 2},
}
delete_updated_payload = updated_payload.with_name("tree-payload-delete-updated.json")
delete_updated_payload.write_bytes(
    json.dumps(delete_updated, separators=(",", ":")).encode())

delete_restored = {
    "schema": 2,
    "tree_id": "shirudo-test-tree-delete",
    "generation": 3,
    "base": {"seq": 0},
    "operations": [
        delete_initial["operations"][0],
        delete_updated["operations"][1],
        operation(3, "shirudo-test-tree-match",
                  {"architecture": ["x86_64"],
                   "labels": {"env": ["tree-test"]}}, match_artifact),
    ],
    "head": {"seq": 3},
}
restored_payload.write_bytes(
    json.dumps(delete_restored, separators=(",", ":")).encode())
PY

	for tree_variant in stable initial updated delete-initial delete-updated delete-restored; do
		case "$tree_variant" in
		stable)
			payload="$tree_payload"
			signature="$tree_signature"
			;;
		initial)
			payload="$tree_initial_payload"
			signature="$tree_initial_signature"
			;;
		updated)
			payload="$tree_updated_payload"
			signature="$tree_updated_signature"
			;;
		delete-initial)
			payload="${tree_initial_payload%/*}/tree-payload-delete-initial.json"
			signature="${tree_initial_signature%/*}/tree-payload-delete-initial.sig"
			;;
		delete-updated)
			payload="${tree_updated_payload%/*}/tree-payload-delete-updated.json"
			signature="${tree_updated_signature%/*}/tree-payload-delete-updated.sig"
			;;
		delete-restored)
			payload="$tree_restored_payload"
			signature="$tree_restored_signature"
			;;
		esac
		openssl cms -sign -binary -in "$payload" \
			-signer "$FIXTURE_WORK/trusted/cert.der" \
			-inkey "$FIXTURE_WORK/trusted/signing_key.pem" \
			-outform DER -out "$signature" -nosmimecap \
			-nocerts -noattr -keyid
	done

	python3 - "$registry_dir" \
		"$tree_payload" "$tree_signature" \
		"$tree_initial_payload" "$tree_initial_signature" \
		"$tree_updated_payload" "$tree_updated_signature" \
		"${tree_initial_payload%/*}/tree-payload-delete-initial.json" \
		"${tree_initial_signature%/*}/tree-payload-delete-initial.sig" \
		"${tree_updated_payload%/*}/tree-payload-delete-updated.json" \
		"${tree_updated_signature%/*}/tree-payload-delete-updated.sig" \
		"$tree_restored_payload" "$tree_restored_signature" <<'PY'
import hashlib
import json
import pathlib
import sys

registry, stable_payload, stable_signature, initial_payload, \
    initial_signature, updated_payload, updated_signature, \
    delete_initial_payload, delete_initial_signature, \
    delete_updated_payload, delete_updated_signature, \
    delete_restored_payload, delete_restored_signature = \
    map(pathlib.Path, sys.argv[1:])


def digest(body):
    return "sha256:" + hashlib.sha256(body).hexdigest()


def write(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(body)


def write_manifest(repo, reference, payload_path, signature_path):
    payload = payload_path.read_bytes()
    signature = signature_path.read_bytes()
    payload_digest = digest(payload)
    signature_digest = digest(signature)
    write(repo / "blobs" / payload_digest, payload)
    write(repo / "blobs" / signature_digest, signature)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "layers": [
            {"mediaType": "application/vnd.shirudo.upatch.tree.v2+json",
             "digest": payload_digest, "size": len(payload)},
            {"mediaType": "application/vnd.shirudo.upatch.tree.signature.v2",
             "digest": signature_digest, "size": len(signature)},
        ],
    }
    write(repo / "manifests" / reference,
          json.dumps(manifest, separators=(",", ":")).encode())


write_manifest(registry / "shirudo" / "upatch-tree", "stable",
               stable_payload, stable_signature)
sequential_repo = registry / "shirudo" / "upatch-tree-sequential"
write_manifest(sequential_repo, "stable", initial_payload, initial_signature)
write_manifest(sequential_repo, "updated", updated_payload, updated_signature)
delete_repo = registry / "shirudo" / "upatch-tree-delete"
write_manifest(delete_repo, "stable", delete_initial_payload,
               delete_initial_signature)
write_manifest(delete_repo, "updated", delete_updated_payload,
               delete_updated_signature)
write_manifest(delete_repo, "restored", delete_restored_payload,
               delete_restored_signature)
PY
}

build_obs_fixture()
{
	local keys_dir="$1"
	local source_dir="$FIXTURE_WORK/linux_obs"
	local empty_source_dir="$FIXTURE_WORK/linux_obs_empty"
	local benchmark_dir="$TMP_DIR/fixtures/benchmark"

	# Keep the production blocklist out of the integration fixture. The
	# fixture is deliberately built from a reserved address so TCP and UDP
	# denial can be tested without external network state.
	mkdir -p "$source_dir/decoders"
	for source in \
		linux-observability.bpf.c exec_uid_arena.bpf.c exec_uid_common.h \
		tcp_connect_arena.bpf.c udp_arena.bpf.c dns_arena.bpf.c \
		ipv4_shields_arena.bpf.c gen_ipv4_shields.py; do
		cp "$REPO_ROOT/shields/linux_obs/$source" "$source_dir/$source"
	done
	cp "$REPO_ROOT/shields/linux_obs/decoders/"*.lua "$source_dir/decoders/"
	cat >"$source_dir/ipv4.list" <<'EOF'
127.0.0.2/32
203.0.113.10/32
EOF
	python3 "$source_dir/gen_ipv4_shields.py" \
		"$source_dir/ipv4.list" "$source_dir/ipv4_shields_generated.h"

	(
		cd "$REPO_ROOT"
		"$REPO_ROOT/tools/shirudo-build/shirudo-build" \
			"$source_dir/linux-observability.bpf.c" \
			-o "$TMP_DIR/fixtures/linux-observability.upatch" \
			--name linux-observability --vmlinux "$REPO_ROOT/bpf/vmlinux.h" \
		--key "$keys_dir/signing_key.pem" \
		--cert "$keys_dir/cert.der"
	)

	mkdir -p "$empty_source_dir/decoders" "$benchmark_dir/empty" \
		"$benchmark_dir/firewall"
	cp -a "$source_dir/." "$empty_source_dir/"
	cat >"$empty_source_dir/ipv4.list" <<'EOF'
# Empty IPv4 firewall list: benchmark the IPv4 observability path only.
EOF
	python3 "$empty_source_dir/gen_ipv4_shields.py" \
		"$empty_source_dir/ipv4.list" \
		"$empty_source_dir/ipv4_shields_generated.h"
	cp "$TMP_DIR/fixtures/linux-observability.upatch" \
		"$benchmark_dir/firewall/linux-observability.upatch"
	(
		cd "$REPO_ROOT"
		"$REPO_ROOT/tools/shirudo-build/shirudo-build" \
			"$empty_source_dir/linux-observability.bpf.c" \
			-o "$benchmark_dir/empty/linux-observability.upatch" \
			--name linux-observability --vmlinux "$REPO_ROOT/bpf/vmlinux.h" \
			--key "$keys_dir/signing_key.pem" \
			--cert "$keys_dir/cert.der"
	)
}

build_java_sql_inj_fixture()
{
	local keys_dir="$1"
	local output_dir="$FIXTURE_WORK/java_sql_inj"

	mkdir -p "$output_dir"
	JAVA_SQL_INJ_OUTPUT_DIR="$output_dir" \
	JAVA_SQL_INJ_KEYS_DIR="$keys_dir" \
	SHIRUDO_BIN="$REPO_ROOT/shirudo" \
		"$REPO_ROOT/shields/java_sql_inj/build.sh"
}

log "building target-test fixtures on the operator host"
mkdir -p "$TMP_DIR/fixtures/decoders" "$FIXTURE_WORK/trusted" \
	"$FIXTURE_WORK/foreign" "$FIXTURE_WORK/own"
"$REPO_ROOT/shirudo" genkey --keys-dir "$FIXTURE_WORK/trusted" >/dev/null
"$REPO_ROOT/shirudo" genkey --keys-dir "$FIXTURE_WORK/foreign" >/dev/null
"$REPO_ROOT/shirudo" genkey --keys-dir "$FIXTURE_WORK/own" >/dev/null
make_mbedtls_test_cert "$FIXTURE_WORK/trusted"

"${CC:-cc}" -O0 -g -Wl,--build-id=sha1 \
	-o /tmp/shirudo-test-uprobe-target \
	"$REPO_ROOT/test-vm/fixtures/uprobe-target.c"

build_fixture basic.bpf.c shirudo-test-basic "$FIXTURE_WORK/trusted"
build_fixture basic.bpf.c shirudo-test-lifecycle "$FIXTURE_WORK/trusted"
build_fixture basic.bpf.c shirudo-test-tree-match "$FIXTURE_WORK/trusted"
build_fixture basic.bpf.c shirudo-test-tree-skip "$FIXTURE_WORK/trusted"
build_fixture marker.bpf.c shirudo-test-marker "$FIXTURE_WORK/trusted"
build_fixture map-export.bpf.c shirudo-test-map-export "$FIXTURE_WORK/trusted"
build_fixture otel-backend.bpf.c shirudo-test-otel-backend "$FIXTURE_WORK/trusted"
build_fixture serialized-metric.bpf.c shirudo-test-serialized-metric "$FIXTURE_WORK/trusted"
build_fixture uprobe-multi.bpf.c shirudo-test-uprobe-multi "$FIXTURE_WORK/trusted"
build_fixture basic.bpf.c shirudo-test-foreign "$FIXTURE_WORK/foreign"
build_fixture basic.bpf.c shirudo-test-own-keyring "$FIXTURE_WORK/own"
build_obs_fixture "$FIXTURE_WORK/trusted"
build_java_sql_inj_fixture "$FIXTURE_WORK/trusted"

basic_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-basic.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
marker_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-marker.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
map_export_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-map-export.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
lifecycle_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-lifecycle.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
tree_match_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-tree-match.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
tree_skip_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-tree-skip.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
uprobe_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-uprobe-multi.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
otel_backend_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-otel-backend.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
serialized_metric_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/shirudo-test-serialized-metric.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
observability_payload="$($REPO_ROOT/shirudo upatch info \
	"$TMP_DIR/fixtures/linux-observability.upatch" --json |
	python3 -c 'import json,sys; print(json.load(sys.stdin)["payload_sha256"])')"
"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
	shirudo-test-basic --payload-sha256 "$basic_payload" \
	-o "$TMP_DIR/fixtures/shirudo-test-basic.unload.upatch" \
	--key "$FIXTURE_WORK/trusted/signing_key.pem" \
	--cert "$FIXTURE_WORK/trusted/cert.der"
"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
	shirudo-test-basic --payload-sha256 "$(printf 'aa%.0s' {1..32})" \
	-o "$TMP_DIR/fixtures/shirudo-test-basic-mismatch.unload.upatch" \
	--key "$FIXTURE_WORK/trusted/signing_key.pem" \
	--cert "$FIXTURE_WORK/trusted/cert.der"
"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
	shirudo-test-marker --payload-sha256 "$marker_payload" \
	-o "$TMP_DIR/fixtures/shirudo-test-marker.unload.upatch" \
	--key "$FIXTURE_WORK/trusted/signing_key.pem" \
	--cert "$FIXTURE_WORK/trusted/cert.der"
"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
	shirudo-test-lifecycle --payload-sha256 "$lifecycle_payload" \
	-o "$TMP_DIR/fixtures/shirudo-test-lifecycle.unload.upatch" \
	--key "$FIXTURE_WORK/trusted/signing_key.pem" \
	--cert "$FIXTURE_WORK/trusted/cert.der"
"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
	shirudo-test-tree-match --payload-sha256 "$tree_match_payload" \
	-o "$TMP_DIR/fixtures/shirudo-test-tree-match.unload.upatch" \
	--key "$FIXTURE_WORK/trusted/signing_key.pem" \
	--cert "$FIXTURE_WORK/trusted/cert.der"
"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
	shirudo-test-tree-skip --payload-sha256 "$tree_skip_payload" \
	-o "$TMP_DIR/fixtures/shirudo-test-tree-skip.unload.upatch" \
	--key "$FIXTURE_WORK/trusted/signing_key.pem" \
	--cert "$FIXTURE_WORK/trusted/cert.der"
build_tree_test_registry
"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
	shirudo-test-map-export --payload-sha256 "$map_export_payload" \
	-o "$TMP_DIR/fixtures/shirudo-test-map-export.unload.upatch" \
	--key "$FIXTURE_WORK/trusted/signing_key.pem" \
	--cert "$FIXTURE_WORK/trusted/cert.der"
"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
	shirudo-test-otel-backend --payload-sha256 "$otel_backend_payload" \
	-o "$TMP_DIR/fixtures/shirudo-test-otel-backend.unload.upatch" \
	--key "$FIXTURE_WORK/trusted/signing_key.pem" \
	--cert "$FIXTURE_WORK/trusted/cert.der"
"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
	shirudo-test-serialized-metric --payload-sha256 "$serialized_metric_payload" \
	-o "$TMP_DIR/fixtures/shirudo-test-serialized-metric.unload.upatch" \
	--key "$FIXTURE_WORK/trusted/signing_key.pem" \
	--cert "$FIXTURE_WORK/trusted/cert.der"
"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
	linux-observability --payload-sha256 "$observability_payload" \
	-o "$TMP_DIR/fixtures/linux-observability.unload.upatch" \
	--key "$FIXTURE_WORK/trusted/signing_key.pem" \
	--cert "$FIXTURE_WORK/trusted/cert.der"
"$REPO_ROOT/tools/shirudo-build/shirudo-build" --unload \
	shirudo-test-uprobe-multi --payload-sha256 "$uprobe_payload" \
	-o "$TMP_DIR/fixtures/shirudo-test-uprobe-multi.unload.upatch" \
	--key "$FIXTURE_WORK/trusted/signing_key.pem" \
	--cert "$FIXTURE_WORK/trusted/cert.der"

mv /tmp/shirudo-test-uprobe-target \
	"$TMP_DIR/fixtures/shirudo-test-uprobe-target"

cp "$FIXTURE_WORK/trusted/cert.der" "$TMP_DIR/fixtures/cert.der"
cp "$FIXTURE_WORK/own/cert.der" "$TMP_DIR/fixtures/own.der"
install -d "$TMP_DIR/java_sql_inj"
install -m 0644 "$FIXTURE_WORK/java_sql_inj/vulnerable-app.jar" \
	"$TMP_DIR/java_sql_inj/vulnerable-app.jar"
install -m 0755 "$FIXTURE_WORK/java_sql_inj/sql_inj_vuln" \
	"$TMP_DIR/java_sql_inj/sql_inj_vuln"
install -m 0644 "$FIXTURE_WORK/java_sql_inj/java-sql-injection-0.1.0.bee" \
	"$TMP_DIR/java_sql_inj/java-sql-injection-0.1.0.bee"
install -m 0644 "$FIXTURE_WORK/java_sql_inj/java-sql-inj.upatch" \
	"$TMP_DIR/fixtures/java-sql-inj.upatch"
install -m 0644 "$FIXTURE_WORK/java_sql_inj/java-sql-inj.unload.upatch" \
	"$TMP_DIR/fixtures/java-sql-inj.unload.upatch"
install -m 0644 "$FIXTURE_WORK/java_sql_inj/javaagent-metrics.upatch" \
	"$TMP_DIR/fixtures/javaagent-metrics.upatch"
install -m 0644 "$FIXTURE_WORK/java_sql_inj/javaagent-metrics.unload.upatch" \
	"$TMP_DIR/fixtures/javaagent-metrics.unload.upatch"
if [[ -n "$PACKAGE_CERT" ]]; then
	install -m 0644 "$PACKAGE_CERT" "$TMP_DIR/fixtures/package-cert.der"
else
	install -m 0644 "$FIXTURE_WORK/trusted/cert.der" \
		"$TMP_DIR/fixtures/package-cert.der"
fi
(
	cd "$TMP_DIR/fixtures"
	sha256sum -- *.upatch benchmark/*/*.upatch cert.der own.der package-cert.der > manifest
)

printf 'shirudo-test-vm-bundle-v1\n' >"$TMP_DIR/format"
if [[ ${#BPF_MAKE_ARGS[@]} -eq 1 ]]; then
	printf 'bpf-next-deps\n' >"$TMP_DIR/dependency-mode"
else
	printf 'vendored-tools\n' >"$TMP_DIR/dependency-mode"
fi
printf 'shirudo-test-vm-bundle-stamp-v1\n' >"$TMP_DIR/.stamp"
printf '%s\n' "$RUNTIME_KEY" >"$TMP_DIR/runtime-image-key"

rm -rf -- "$BUNDLE_DIR"
mv -- "$TMP_DIR" "$BUNDLE_DIR"
touch "$STAMP_FILE"
trap - EXIT
log "ready: $BUNDLE_DIR"
