#!/usr/bin/env bash
set -euo pipefail

KERNEL_LOCALVERSION="-bpf-next"
KERNEL_PATCHES="${KERNEL_PATCHES:-}"
KERNEL_CONFIG="${KERNEL_CONFIG:-}"
WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:-/tmp}/bpf-next-kernel-build}"
SOURCE_DIR="${WORK_DIR}/linux"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_SOURCE_DIR="${KERNEL_SOURCE_DIR:-${REPO_ROOT}/third_party/bpf-next}"
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/artifacts/bpf-next-kernel-debs}"
BUNDLE_PATH="${BUNDLE_PATH:-${OUTPUT_DIR}.tar.gz}"
VMLINUX_PATH="${OUTPUT_DIR}/bzImage"
VMLINUX_BTF_PATH="${OUTPUT_DIR}/vmlinux.btf"
BPF_DEPS_DIR="${OUTPUT_DIR}/shirudo-bpf-deps"
BPF_DEPS_LIBBPF_DIR="${BPF_DEPS_DIR}/bpf"

BUILD_DEPENDENCIES=(
  bc
  bison
  build-essential
  ca-certificates
  cpio
  debhelper
  dpkg-dev
  dwarves
  fakeroot
  flex
  git
  kmod
  libdw-dev
  libelf-dev
  libncurses-dev
  libssl-dev
  openssl
  pahole
  python3
  rsync
  xz-utils
  zstd
)

print_dependency_install_command() {
  printf '  sudo apt-get install -y --no-install-recommends'
  printf ' %q' "$@"
  printf '\n'
}

check_build_dependencies() {
  local package
  local package_status
  local -a missing_packages=()

  if ! command -v dpkg-query >/dev/null 2>&1; then
    echo "cannot check kernel build dependencies: dpkg-query is not installed" >&2
    echo "make bpf-next currently supports Debian and Ubuntu build hosts" >&2
    echo "Install the required packages with:" >&2
    print_dependency_install_command "${BUILD_DEPENDENCIES[@]}" >&2
    exit 1
  fi

  for package in "${BUILD_DEPENDENCIES[@]}"; do
    package_status="$(dpkg-query -W -f='${Status}' "$package" 2>/dev/null || true)"
    if [[ "$package_status" != "install ok installed" ]]; then
      missing_packages+=("$package")
    fi
  done

  if (( ${#missing_packages[@]} != 0 )); then
    echo "missing kernel build dependencies: ${missing_packages[*]}" >&2
    echo "Install them with:" >&2
    print_dependency_install_command "${missing_packages[@]}" >&2
    exit 1
  fi
}

check_build_dependencies

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
if [[ -n "$(git -C "$KERNEL_SOURCE_DIR" status --porcelain)" ]]; then
  echo "kernel source checkout is dirty: ${KERNEL_SOURCE_DIR}" >&2
  echo "commit or stash its changes before running make bpf-next" >&2
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
if [[ -n "$KERNEL_CONFIG" ]]; then
  if [[ "$KERNEL_CONFIG" != /* ]]; then
    KERNEL_CONFIG="${REPO_ROOT}/${KERNEL_CONFIG}"
  fi
  if [[ ! -f "$KERNEL_CONFIG" ]]; then
    echo "kernel config not found: ${KERNEL_CONFIG}" >&2
    exit 1
  fi
  cp "$KERNEL_CONFIG" .config
  config_source="$KERNEL_CONFIG"
else
  make x86_64_defconfig
  config_source="x86_64_defconfig"
fi

scripts/config --set-str LOCALVERSION "$KERNEL_LOCALVERSION"
scripts/config --enable BPF
scripts/config --enable BPF_SYSCALL
scripts/config --enable BPF_JIT
scripts/config --enable BPF_LSM
scripts/config --enable FUNCTION_TRACER
scripts/config --disable DEBUG_INFO_NONE
scripts/config --enable DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT
scripts/config --enable DEBUG_INFO
scripts/config --enable DEBUG_INFO_BTF
scripts/config --enable KEYS
scripts/config --enable ASYMMETRIC_KEY_TYPE
scripts/config --enable X509_CERTIFICATE_PARSER
scripts/config --enable PKCS7_MESSAGE_PARSER
scripts/config --enable SYSTEM_DATA_VERIFICATION
scripts/config --enable TCG_TPM
scripts/config --enable TCG_TIS_CORE
scripts/config --enable TCG_TIS
scripts/config --enable UPROBES
scripts/config --enable SECURITY
scripts/config --enable SECURITYFS
scripts/config --enable DEVTMPFS
scripts/config --enable DEVTMPFS_MOUNT
scripts/config --enable VIRTIO
scripts/config --enable VIRTIO_PCI
scripts/config --enable VIRTIO_BLK
scripts/config --enable VIRTIO_NET
scripts/config --enable NET_9P
scripts/config --enable NET_9P_VIRTIO
scripts/config --enable 9P_FS
scripts/config --enable OVERLAY_FS
scripts/config --enable EXT4_FS
scripts/config --enable EFI_PARTITION
scripts/config --enable ISO9660_FS
scripts/config --enable SERIAL_8250
scripts/config --enable SERIAL_8250_CONSOLE
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
require_config CONFIG_FUNCTION_TRACER y
require_config CONFIG_DYNAMIC_FTRACE y
require_config CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS y
require_config CONFIG_DEBUG_INFO_BTF y
require_config CONFIG_TCG_TPM y
require_config CONFIG_TCG_TIS_CORE y
require_config CONFIG_TCG_TIS y
require_config CONFIG_UPROBES y
require_config CONFIG_SECURITYFS y
require_config CONFIG_PCI y
require_config CONFIG_PCI_MSI y
require_config CONFIG_NETDEVICES y
require_config CONFIG_ETHERNET y
require_config CONFIG_NET_VENDOR_AMAZON y
require_config CONFIG_ENA_ETHERNET '[ym]'
require_config CONFIG_NVME_CORE '[ym]'
require_config CONFIG_BLK_DEV_NVME '[ym]'
require_config CONFIG_DEVTMPFS y
require_config CONFIG_DEVTMPFS_MOUNT y
require_config CONFIG_VIRTIO y
require_config CONFIG_VIRTIO_PCI y
require_config CONFIG_VIRTIO_BLK y
require_config CONFIG_VIRTIO_NET y
require_config CONFIG_NET_9P y
require_config CONFIG_NET_9P_VIRTIO y
require_config CONFIG_9P_FS y
require_config CONFIG_OVERLAY_FS y
require_config CONFIG_EXT4_FS y
require_config CONFIG_EFI_PARTITION y
require_config CONFIG_ISO9660_FS y
require_config CONFIG_SERIAL_8250 y
require_config CONFIG_SERIAL_8250_CONSOLE y

kernel_release="$(make -s kernelrelease)"
package_version="1+$(date -u +%Y%m%d%H%M%S)+g${kernel_commit:0:12}"
make -j "$(nproc)" bindeb-pkg KDEB_PKGVERSION="$package_version"

find "$WORK_DIR" -maxdepth 1 -type f -name '*.deb' ! -name '*-dbg*.deb' -exec cp {} "$OUTPUT_DIR/" \;

if ! find "$OUTPUT_DIR" -type f -name 'linux-image-[0-9]*.deb' ! -name '*-dbg*' | grep -q .; then
  echo "kernel image deb was not produced" >&2
  exit 1
fi

if [[ ! -s "arch/x86/boot/bzImage" ]]; then
  echo "kernel bzImage was not produced" >&2
  exit 1
fi
cp arch/x86/boot/bzImage "$VMLINUX_PATH"
cp .config "${OUTPUT_DIR}/kernel.config"

# Keep the exact detached BTF used by this kernel build.  It lets Shirudo
# generate bpf/vmlinux.h against the artifact kernel before that kernel is
# booted, rather than accidentally using the build host's /sys BTF.
if [[ ! -s vmlinux ]]; then
  echo "kernel vmlinux was not produced" >&2
  exit 1
fi
if ! objcopy --dump-section .BTF="$VMLINUX_BTF_PATH" vmlinux; then
  echo "failed to extract .BTF from kernel vmlinux" >&2
  exit 1
fi
if [[ ! -s "$VMLINUX_BTF_PATH" ]]; then
  echo "kernel vmlinux has no usable .BTF section" >&2
  exit 1
fi

# Build the userspace BPF tools against the exact bpf-next checkout used for
# the kernel. The VM runner consumes these artifacts instead of rebuilding
# libbpf and bpftool for every fresh guest.
echo "Building Shirudo BPF dependency artifacts"
make -C "$SOURCE_DIR/tools/lib/bpf" CC="${CC:-cc}"
make -C "$SOURCE_DIR/tools/bpf/bpftool" CC="${CC:-cc}"
mkdir -p "$BPF_DEPS_LIBBPF_DIR"
cp "$SOURCE_DIR/tools/lib/bpf/libbpf.a" "$BPF_DEPS_LIBBPF_DIR/"
cp "$SOURCE_DIR/tools/lib/bpf"/*.h "$BPF_DEPS_LIBBPF_DIR/"
cp "$SOURCE_DIR/tools/bpf/bpftool/bpftool" "$BPF_DEPS_DIR/"
"$BPF_DEPS_DIR/bpftool" btf dump file "$VMLINUX_BTF_PATH" format c \
  >"$BPF_DEPS_DIR/vmlinux.h"
cat >"$BPF_DEPS_DIR/build" <<EOF
source_dir=${KERNEL_SOURCE_DIR}
kernel_commit=${kernel_commit}
libbpf_source=${kernel_commit}:tools/lib/bpf
bpftool_source=${kernel_commit}:tools/bpf/bpftool
built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

cat > "${OUTPUT_DIR}/bpf-next-kernel-build" <<EOF
source_dir=${KERNEL_SOURCE_DIR}
upstream_commit=${upstream_commit}
commit=${kernel_commit}
patches_requested=${KERNEL_PATCHES}
patches_applied=${applied_patches[*]}
config_source=${config_source}
kernel_release=${kernel_release}
package_version=${package_version}
built_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF

(
  cd "$OUTPUT_DIR"
  sha256sum bzImage > bzImage.sha256sum
  sha256sum vmlinux.btf > vmlinux.btf.sha256sum
  find . -type f ! -name SHA256SUMS -print0 | sort -z |
    xargs -0 sha256sum > SHA256SUMS
)

mkdir -p "$(dirname "$BUNDLE_PATH")"
tar -C "$OUTPUT_DIR" -czf "$BUNDLE_PATH" .
(
  cd "$(dirname "$BUNDLE_PATH")"
  sha256sum "$(basename "$BUNDLE_PATH")" > "$(basename "$BUNDLE_PATH").sha256sum"
)

echo "Built kernel bzImage: ${VMLINUX_PATH}"
echo "Built kernel BTF: ${VMLINUX_BTF_PATH}"
echo "Built Shirudo BPF dependency artifacts: ${BPF_DEPS_DIR}"
echo "Built kernel deb bundle: ${BUNDLE_PATH}"
