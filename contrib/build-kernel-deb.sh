#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive

KERNEL_LOCALVERSION="-bpf-next"
KERNEL_PATCHES="${KERNEL_PATCHES:-}"
WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:-/tmp}/bpf-next-kernel-build}"
SOURCE_DIR="${WORK_DIR}/linux"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_SOURCE_DIR="${KERNEL_SOURCE_DIR:-${REPO_ROOT}/third_party/bpf-next}"
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/artifacts/bpf-next-kernel-debs}"
BUNDLE_PATH="${BUNDLE_PATH:-${OUTPUT_DIR}.tar.gz}"

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  bc \
  bison \
  build-essential \
  ca-certificates \
  cpio \
  debhelper \
  dpkg-dev \
  dwarves \
  fakeroot \
  flex \
  git \
  kmod \
  libdw-dev \
  libelf-dev \
  libncurses-dev \
  libssl-dev \
  openssl \
  pahole \
  python3 \
  rsync \
  xz-utils \
  zstd

rm -rf "$WORK_DIR" "$OUTPUT_DIR" "$BUNDLE_PATH" "${BUNDLE_PATH}.sha256sum"
mkdir -p "$WORK_DIR" "$OUTPUT_DIR"

if [[ ! -d "$KERNEL_SOURCE_DIR" ]]; then
  echo "kernel source directory not found: ${KERNEL_SOURCE_DIR}" >&2
  exit 1
fi
if ! git -C "$KERNEL_SOURCE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "kernel source directory is not a git checkout: ${KERNEL_SOURCE_DIR}" >&2
  exit 1
fi

submodule_commit="$(git -C "$KERNEL_SOURCE_DIR" rev-parse HEAD)"
git clone --no-checkout "$KERNEL_SOURCE_DIR" "$SOURCE_DIR"
cd "$SOURCE_DIR"
git checkout --detach "$submodule_commit"

upstream_commit="$(git rev-parse HEAD)"
applied_patches=()

apply_kernel_patch() {
  local patch_path="$1"
  local patch_subject

  if [[ "$patch_path" != /* ]]; then
    patch_path="${REPO_ROOT}/${patch_path}"
  fi
  if [[ ! -f "$patch_path" ]]; then
    echo "kernel patch not found: ${patch_path}" >&2
    exit 1
  fi

  echo "Applying kernel patch: ${patch_path}"
  if git apply --reverse --check "$patch_path" >/dev/null 2>&1; then
    echo "Kernel patch already applied: ${patch_path}"
    applied_patches+=("$patch_path")
    return
  fi

  git config user.name "shirudo workflow"
  git config user.email "shirudo@localhost"
  if ! git apply --index "$patch_path"; then
    echo "failed to apply kernel patch: ${patch_path}" >&2
    exit 1
  fi
  patch_subject="$(
    sed -n \
      -e 's/^Subject: \[PATCH[^]]*\] //p' \
      -e 's/^Subject: //p' \
      "$patch_path" | head -n 1
  )"
  if [[ -z "$patch_subject" ]]; then
    patch_subject="Apply $(basename "$patch_path")"
  fi
  git commit -m "$patch_subject"
  applied_patches+=("$patch_path")
}

expand_kernel_patches() {
  local patch_entry="$1"
  local patch_path="$patch_entry"

  if [[ "$patch_path" != /* ]]; then
    patch_path="${REPO_ROOT}/${patch_path}"
  fi

  if [[ -d "$patch_path" ]]; then
    find "$patch_path" -maxdepth 1 -type f -name '*.patch' | sort
  else
    printf '%s\n' "$patch_path"
  fi
}

for patch_entry in $KERNEL_PATCHES; do
  while IFS= read -r patch_path; do
    [[ -n "$patch_path" ]] || continue
    apply_kernel_patch "$patch_path"
  done < <(expand_kernel_patches "$patch_entry")
done

kernel_commit="$(git rev-parse HEAD)"
if [[ -f "/boot/config-$(uname -r)" ]]; then
  cp "/boot/config-$(uname -r)" .config
elif [[ -r /proc/config.gz ]]; then
  zcat /proc/config.gz > .config
else
  make defconfig
fi

scripts/config --set-str LOCALVERSION "$KERNEL_LOCALVERSION"
scripts/config --enable BPF
scripts/config --enable BPF_SYSCALL
scripts/config --enable BPF_JIT
scripts/config --enable BPF_LSM
scripts/config --enable DEBUG_INFO
scripts/config --enable DEBUG_INFO_BTF
scripts/config --enable KEYS
scripts/config --enable ASYMMETRIC_KEY_TYPE
scripts/config --enable X509_CERTIFICATE_PARSER
scripts/config --enable PKCS7_MESSAGE_PARSER
scripts/config --enable SYSTEM_DATA_VERIFICATION
scripts/config --enable TCG_TPM
scripts/config --enable PCI
scripts/config --enable PCI_MSI
scripts/config --enable NETDEVICES
scripts/config --enable ETHERNET
scripts/config --enable NET_VENDOR_AMAZON
scripts/config --module ENA_ETHERNET
scripts/config --enable NVME_CORE
scripts/config --enable BLK_DEV_NVME
scripts/config --enable NVME_MULTIPATH
scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
scripts/config --set-str SYSTEM_REVOCATION_KEYS ""

make olddefconfig

require_config() {
  local symbol="$1"
  local expected_pattern="$2"

  if ! grep -Eq "^${symbol}=${expected_pattern}$" .config; then
    echo "required kernel config ${symbol} does not match ${expected_pattern}" >&2
    grep -E "^${symbol}=|^# ${symbol} is not set" .config >&2 || true
    exit 1
  fi
}

require_config CONFIG_BPF_LSM y
require_config CONFIG_DEBUG_INFO_BTF y
require_config CONFIG_PCI y
require_config CONFIG_PCI_MSI y
require_config CONFIG_NETDEVICES y
require_config CONFIG_ETHERNET y
require_config CONFIG_NET_VENDOR_AMAZON y
require_config CONFIG_ENA_ETHERNET '[ym]'
require_config CONFIG_NVME_CORE '[ym]'
require_config CONFIG_BLK_DEV_NVME '[ym]'
require_config CONFIG_DEVTMPFS y
require_config CONFIG_EXT4_FS '[ym]'

kernel_release="$(make -s kernelrelease)"
package_version="1+$(date -u +%Y%m%d%H%M%S)+g${kernel_commit:0:12}"
make -j "$(nproc)" bindeb-pkg KDEB_PKGVERSION="$package_version"

find "$WORK_DIR" -maxdepth 1 -type f -name '*.deb' ! -name '*-dbg*.deb' -exec cp {} "$OUTPUT_DIR/" \;

if ! find "$OUTPUT_DIR" -type f -name 'linux-image-[0-9]*.deb' ! -name '*-dbg*' | grep -q .; then
  echo "kernel image deb was not produced" >&2
  exit 1
fi

cat > "${OUTPUT_DIR}/bpf-next-kernel-build" <<EOF
source_dir=${KERNEL_SOURCE_DIR}
upstream_commit=${upstream_commit}
commit=${kernel_commit}
patches_requested=${KERNEL_PATCHES}
patches_applied=${applied_patches[*]}
kernel_release=${kernel_release}
package_version=${package_version}
built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

(
  cd "$OUTPUT_DIR"
  sha256sum *.deb bpf-next-kernel-build > SHA256SUMS
)

mkdir -p "$(dirname "$BUNDLE_PATH")"
tar -C "$OUTPUT_DIR" -czf "$BUNDLE_PATH" .
(
  cd "$(dirname "$BUNDLE_PATH")"
  sha256sum "$(basename "$BUNDLE_PATH")" > "$(basename "$BUNDLE_PATH").sha256sum"
)

echo "Built kernel deb bundle: ${BUNDLE_PATH}"
