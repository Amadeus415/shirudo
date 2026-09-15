#!/usr/bin/env bash
set -euo pipefail

KERNEL_TAG="${KERNEL_TAG:-bpf-next}"
KERNEL_COMMIT="${KERNEL_COMMIT:-}"
KERNEL_REPOSITORY="${KERNEL_REPOSITORY:-https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git}"
KERNEL_PATCHES="${KERNEL_PATCHES:-}"
KERNEL_CONFIG="${KERNEL_CONFIG:-}"
KERNEL_PROFILE="${KERNEL_PROFILE:-full}"
KERNEL_BUILD_JOBS="${KERNEL_BUILD_JOBS:-$(nproc)}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL_SOURCE_DIR_INPUT="${KERNEL_SOURCE_DIR:-}"
if [[ "$KERNEL_TAG" =~ ^[0-9]+\.[0-9]+([.][0-9]+)?$ ]]; then
  KERNEL_TAG="v${KERNEL_TAG}"
fi
if [[ "$KERNEL_TAG" != "bpf-next" &&
      ! "$KERNEL_TAG" =~ ^v[0-9]+\.[0-9]+([.][0-9]+)?$ ]]; then
  echo "KERNEL_TAG must be bpf-next or a Linux release tag such as v6.18" >&2
  exit 1
fi
case "$KERNEL_PROFILE" in
  full|small)
    ;;
  *)
    echo "KERNEL_PROFILE must be full or small" >&2
    exit 1
    ;;
esac
if [[ "$KERNEL_PROFILE" == small && "$KERNEL_TAG" != bpf-next ]]; then
  echo "KERNEL_PROFILE=small is supported only for bpf-next" >&2
  exit 1
fi
if [[ -n "$KERNEL_COMMIT" ]]; then
  if [[ "$KERNEL_TAG" == "bpf-next" ]]; then
    echo "KERNEL_COMMIT is supported only for stable/LTS kernel tags" >&2
    exit 1
  fi
  if [[ ! "$KERNEL_COMMIT" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
    echo "KERNEL_COMMIT must contain 7 to 40 hexadecimal characters" >&2
    exit 1
  fi
  KERNEL_COMMIT="${KERNEL_COMMIT,,}"
fi
KERNEL_ARTIFACT_NAME="bpf-next"
if [[ "$KERNEL_PROFILE" == small ]]; then
  KERNEL_ARTIFACT_NAME="bpf-next-small"
fi
if [[ "$KERNEL_TAG" != "bpf-next" ]]; then
  KERNEL_ARTIFACT_NAME="linux-${KERNEL_TAG}"
fi
if [[ -n "$KERNEL_COMMIT" ]]; then
  KERNEL_ARTIFACT_NAME="${KERNEL_ARTIFACT_NAME}-${KERNEL_COMMIT}"
fi
if [[ -z "${KERNEL_LOCALVERSION:-}" ]]; then
  if [[ "$KERNEL_PROFILE" == small ]]; then
    KERNEL_LOCALVERSION="-bpf-next-small"
  elif [[ "$KERNEL_TAG" == "bpf-next" ]]; then
    KERNEL_LOCALVERSION="-bpf-next"
  else
    KERNEL_LOCALVERSION="-shirudo-${KERNEL_TAG#v}"
  fi
fi
PACKAGE_FORMAT="${PACKAGE_FORMAT:-deb}"
case "$PACKAGE_FORMAT" in
  deb)
    PACKAGE_SUFFIX="debs"
    ;;
  rpm)
    PACKAGE_SUFFIX="rpms"
    ;;
  *)
    echo "unsupported PACKAGE_FORMAT: ${PACKAGE_FORMAT} (expected deb or rpm)" >&2
    exit 1
    ;;
esac
WORK_DIR="${WORK_DIR:-${RUNNER_TEMP:-/tmp}/${KERNEL_ARTIFACT_NAME}-kernel-build}"
SOURCE_DIR="${WORK_DIR}/linux"
if [[ -n "$KERNEL_SOURCE_DIR_INPUT" ]]; then
  KERNEL_SOURCE_DIR="$KERNEL_SOURCE_DIR_INPUT"
elif [[ "$KERNEL_TAG" == "bpf-next" ]]; then
  KERNEL_SOURCE_DIR="${REPO_ROOT}/third_party/bpf-next"
else
  KERNEL_SOURCE_DIR="$SOURCE_DIR"
fi
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/artifacts/${KERNEL_ARTIFACT_NAME}-kernel-${PACKAGE_SUFFIX}}"
BUNDLE_PATH="${BUNDLE_PATH:-${OUTPUT_DIR}.tar.gz}"
KERNEL_OBSERVABILITY_CONFIGS_FILE="${KERNEL_OBSERVABILITY_CONFIGS_FILE:-${REPO_ROOT}/contrib/kernel-observability-configs.txt}"
KERNEL_SMALL_CONFIG="${KERNEL_SMALL_CONFIG:-${REPO_ROOT}/contrib/kernel-small.config}"
VMLINUX_PATH="${OUTPUT_DIR}/bzImage"
VMLINUX_BTF_PATH="${OUTPUT_DIR}/vmlinux.btf"
BPF_DEPS_DIR="${OUTPUT_DIR}/shirudo-bpf-deps"
BPF_DEPS_LIBBPF_DIR="${BPF_DEPS_DIR}/bpf"

if [[ "$PACKAGE_FORMAT" == deb ]]; then
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
    llvm
    openssl
    pahole
    python3
    rsync
    xz-utils
    zstd
  )
else
  BUILD_DEPENDENCIES=(
    bc
    bison
    ca-certificates
    cpio
    dwarves
    elfutils-devel
    elfutils-libelf-devel
    flex
    gcc
    git
    gzip
    hostname
    kmod
    make
    ncurses-devel
    openssl
    openssl-devel
    perl
    python3
    rpm-build
    rsync
    tar
    xz
    zstd
  )
fi

run_as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "installing kernel build dependencies requires root or sudo" >&2
    exit 1
  fi
}

install_build_dependencies() {
  local missing_dependencies=()
  if [[ "$PACKAGE_FORMAT" == deb ]]; then
    if ! command -v apt-get >/dev/null 2>&1; then
      echo "cannot install Debian kernel build dependencies: apt-get is not installed" >&2
      exit 1
    fi
    if command -v dpkg-query >/dev/null 2>&1; then
      for dependency in "${BUILD_DEPENDENCIES[@]}"; do
        if ! dpkg-query -W -f='${Status}\n' "$dependency" 2>/dev/null |
          grep -q 'install ok installed'; then
          missing_dependencies+=("$dependency")
        fi
      done
    else
      missing_dependencies=("${BUILD_DEPENDENCIES[@]}")
    fi
    if [[ ${#missing_dependencies[@]} -eq 0 ]]; then
      echo "All kernel build dependencies are already installed"
      return
    fi
    run_as_root apt-get update
    run_as_root apt-get install -y --no-install-recommends "${missing_dependencies[@]}"
  else
    if ! command -v dnf >/dev/null 2>&1; then
      echo "cannot install RPM kernel build dependencies: dnf is not installed" >&2
      exit 1
    fi
    if command -v rpm >/dev/null 2>&1; then
      for dependency in "${BUILD_DEPENDENCIES[@]}"; do
        rpm -q "$dependency" >/dev/null 2>&1 ||
          missing_dependencies+=("$dependency")
      done
    else
      missing_dependencies=("${BUILD_DEPENDENCIES[@]}")
    fi
    if [[ ${#missing_dependencies[@]} -eq 0 ]]; then
      echo "All kernel build dependencies are already installed"
      return
    fi
    run_as_root dnf install -y "${missing_dependencies[@]}"
  fi
}

install_build_dependencies

rm -rf "$WORK_DIR" "$OUTPUT_DIR" "$BUNDLE_PATH" "${BUNDLE_PATH}.sha256sum"
mkdir -p "$WORK_DIR" "$OUTPUT_DIR"

if [[ "$KERNEL_TAG" != "bpf-next" && -z "$KERNEL_SOURCE_DIR_INPUT" ]]; then
  echo "Fetching third-party Linux kernel ${KERNEL_TAG}"
  if [[ -n "$KERNEL_COMMIT" ]]; then
    git clone --filter=blob:none --no-checkout \
      "$KERNEL_REPOSITORY" "$KERNEL_SOURCE_DIR"
  else
    git clone --depth 1 --branch "$KERNEL_TAG" \
      "$KERNEL_REPOSITORY" "$KERNEL_SOURCE_DIR"
  fi
fi
if [[ ! -d "$KERNEL_SOURCE_DIR" ]]; then
  echo "kernel source directory not found: ${KERNEL_SOURCE_DIR}" >&2
  exit 1
fi
if ! git -C "$KERNEL_SOURCE_DIR" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "kernel source directory is not a git checkout: ${KERNEL_SOURCE_DIR}" >&2
  exit 1
fi
# An exact-commit clone is intentionally created with --no-checkout. Select
# the requested commit before checking cleanliness; otherwise Git reports the
# intentionally absent worktree files as staged deletions.
if [[ -n "$KERNEL_COMMIT" && -z "$KERNEL_SOURCE_DIR_INPUT" ]]; then
  git -C "$KERNEL_SOURCE_DIR" checkout --detach "$KERNEL_COMMIT"
fi
if [[ -n "$(git -C "$KERNEL_SOURCE_DIR" status --porcelain)" ]]; then
  echo "kernel source checkout is dirty: ${KERNEL_SOURCE_DIR}" >&2
  echo "commit or stash its changes before running make kernel" >&2
  exit 1
fi

if [[ "$KERNEL_SOURCE_DIR" == "$SOURCE_DIR" ]]; then
  cd "$SOURCE_DIR"
else
  submodule_commit="$(git -C "$KERNEL_SOURCE_DIR" rev-parse HEAD)"
  git clone --no-checkout "$KERNEL_SOURCE_DIR" "$SOURCE_DIR"
  cd "$SOURCE_DIR"
  if [[ -n "$KERNEL_COMMIT" ]]; then
    git rev-parse --verify "$KERNEL_COMMIT^{commit}" >/dev/null 2>&1 || {
      echo "KERNEL_COMMIT is not available in KERNEL_SOURCE_DIR: ${KERNEL_COMMIT}" >&2
      exit 1
    }
    git checkout --detach "$KERNEL_COMMIT"
  else
    git checkout --detach "$submodule_commit"
  fi
fi

if [[ -n "$KERNEL_COMMIT" ]]; then
  git rev-parse --verify "$KERNEL_COMMIT^{commit}" >/dev/null 2>&1 || {
    echo "kernel commit not found in ${KERNEL_REPOSITORY}: ${KERNEL_COMMIT}" >&2
    exit 1
  }
  git checkout --detach "$KERNEL_COMMIT"
fi

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
if [[ "$KERNEL_PROFILE" == small ]]; then
  small_config="$KERNEL_SMALL_CONFIG"
  if [[ -n "$KERNEL_CONFIG" ]]; then
    small_config="$KERNEL_CONFIG"
  fi
  if [[ "$small_config" != /* ]]; then
    small_config="${REPO_ROOT}/${small_config}"
  fi
  if [[ ! -f "$small_config" ]]; then
    echo "small kernel config fragment not found: ${small_config}" >&2
    exit 1
  fi
  make KCONFIG_ALLCONFIG="$small_config" allnoconfig
  config_source="${small_config} (KCONFIG_ALLCONFIG)"
else
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
fi

scripts/config --set-str LOCALVERSION "$KERNEL_LOCALVERSION"
if [[ "$KERNEL_PROFILE" != small ]]; then
scripts/config --enable BPF
scripts/config --enable BPF_SYSCALL
scripts/config --enable BPF_JIT
scripts/config --enable BPF_LSM
scripts/config --enable CGROUP_BPF
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
scripts/config --enable TCG_CRB
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
scripts/config --enable SQUASHFS
scripts/config --enable SQUASHFS_XZ
scripts/config --enable SQUASHFS_ZSTD
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
# Build additional drivers and filesystems as loadable modules for the VM
# kernel artifact. COMPILE_TEST makes platform-specific drivers such as
# mvpp2 available in an x86_64 compile.
# 9p stays built in because the VM uses it for early boot mounts. The
# upstream optee driver is ARM-only and cannot be selected by this x86_64
# kernel build.
scripts/config --enable COMPILE_TEST
scripts/config --disable WERROR
scripts/config --module BATMAN_ADV
scripts/config --module BCMGENET
scripts/config --module CEPH_FS
scripts/config --module DM_CACHE
scripts/config --enable WAN
scripts/config --module HDLC
scripts/config --module FARSYNC
scripts/config --module HFS_FS
scripts/config --module MVPP2
scripts/config --enable NF_CONNTRACK
scripts/config --module NETFILTER_CONNCOUNT
scripts/config --module NFT_CONNLIMIT
scripts/config --module NETFILTER_NETLINK_OSF
scripts/config --module NFSD
scripts/config --module OPENVSWITCH
scripts/config --module CRYPTO_PCRYPT
scripts/config --module QED
scripts/config --module QEDE
scripts/config --module SCSI_FC_ATTRS
scripts/config --module SCSI_QLA_FC
scripts/config --module RDS
scripts/config --module SND
scripts/config --module SND_PCM
scripts/config --module TUN
scripts/config --module UDF_FS
scripts/config --module FUSE_FS
scripts/config --module VIRTIO_FS
scripts/config --module VETH
scripts/config --module BRIDGE
scripts/config --module VLAN_8021Q
scripts/config --module BTRFS_FS
scripts/config --enable NETFILTER_ADVANCED
# NETFILTER_XTABLES_LEGACY was introduced after the older stable branches
# supported by this workflow.  Those branches include legacy table support
# in NETFILTER_XTABLES itself, so do not ask scripts/config to set a symbol
# that their Kconfig does not define.
netfilter_xtables_legacy_available=0
if grep -RqsE '^[[:space:]]*config NETFILTER_XTABLES_LEGACY([[:space:]]|$)' \
  net include; then
  scripts/config --enable NETFILTER_XTABLES_LEGACY
  netfilter_xtables_legacy_available=1
fi
if grep -RqsE '^[[:space:]]*config IP_NF_IPTABLES_LEGACY([[:space:]]|$)' \
  net include; then
  scripts/config --module IP_NF_IPTABLES_LEGACY
  scripts/config --module IP6_NF_IPTABLES_LEGACY
  if (( ! netfilter_xtables_legacy_available )); then
    # In this intermediate Kconfig model, the table modules select the
    # legacy base symbols. Keep every selector modular so the base symbols
    # cannot be promoted back to y during olddefconfig.
    for legacy_selector in \
      IP_NF_FILTER IP_NF_MANGLE IP_NF_NAT IP_NF_SECURITY \
      IP6_NF_FILTER IP6_NF_MANGLE IP6_NF_NAT IP6_NF_SECURITY; do
      if grep -RqsE "^[[:space:]]*config ${legacy_selector}([[:space:]]|$)" \
        net include; then
        scripts/config --module "$legacy_selector"
      fi
    done
  fi
else
  # Before the legacy selector split, these symbols also selected the
  # legacy iptables implementations.
  scripts/config --module IP_NF_IPTABLES
  scripts/config --module IP6_NF_IPTABLES
fi
scripts/config --module IP_NF_RAW
scripts/config --module IP6_NF_RAW
scripts/config --module NETFILTER_XT_MATCH_LENGTH
scripts/config --module BRIDGE_NETFILTER
scripts/config --module NF_TABLES
scripts/config --module NF_FLOW_TABLE
scripts/config --module NF_FLOW_TABLE_INET
scripts/config --enable NF_FLOW_TABLE_PROCFS
scripts/config --enable NVME_CORE
scripts/config --enable BLK_DEV_NVME
scripts/config --enable NVME_MULTIPATH
scripts/config --set-str SYSTEM_TRUSTED_KEYS ""
scripts/config --set-str SYSTEM_REVOCATION_KEYS ""
fi

# Enable the CVE load-repair Kconfig set when the selected kernel defines it.
# Tristate drivers are requested as modules so the VM can load them on demand;
# existing y/m values are preserved. Kconfig dependency resolution remains the
# kernel's authority, and the post-olddefconfig report records symbols that
# could not be selected on this architecture or branch.
kernel_config_value() {
  local symbol="$1"
  local value

  value="$(awk -F= -v want="${symbol}" '$1 == want { print $2; exit }' .config)"
  if [[ -n "$value" ]]; then
    printf '%s\n' "$value"
  elif grep -q "^# ${symbol} is not set$" .config; then
    printf 'n\n'
  else
    printf 'unknown\n'
  fi
}

declare -A KCONFIG_DEFINITION_CACHE=()

kconfig_definition_file() {
  local symbol="$1"
  if [[ ${KCONFIG_DEFINITION_CACHE[$symbol]+present} ]]; then
    printf '%s\n' "${KCONFIG_DEFINITION_CACHE[$symbol]}"
    return
  fi
  local definition_file
  definition_file="$(grep -Rls --include='Kconfig*' \
    -E "^[[:space:]]*(config|menuconfig)[[:space:]]+${symbol}([[:space:]]|$)" \
    . 2>/dev/null | head -n 1 || true)"
  KCONFIG_DEFINITION_CACHE[$symbol]="$definition_file"
  printf '%s\n' "$definition_file"
}

kconfig_symbol_kind() {
  local symbol="$1"
  local file="$2"
  awk -v want="$symbol" '
    /^[[:space:]]*(config|menuconfig)[[:space:]]+/ {
      active = ($2 == want)
      next
    }
    active && /^[[:space:]]*tristate([[:space:]]|$)/ { print "tristate"; exit }
    active && /^[[:space:]]*bool([[:space:]]|$)/ { print "bool"; exit }
  ' "$file"
}

if [[ "$KERNEL_PROFILE" != small && -f "$KERNEL_OBSERVABILITY_CONFIGS_FILE" ]]; then
  while IFS= read -r requested_symbol; do
    requested_symbol="${requested_symbol%%#*}"
    requested_symbol="${requested_symbol//[[:space:]]/}"
    [[ -n "$requested_symbol" ]] || continue
    symbol="${requested_symbol#CONFIG_}"
    definition_file="$(kconfig_definition_file "$symbol")"
    [[ -n "$definition_file" ]] || continue
    current="$(kernel_config_value "CONFIG_${symbol}")"
    [[ "$current" == y || "$current" == m ]] && continue
    kind="$(kconfig_symbol_kind "$symbol" "$definition_file")"
    if [[ "$kind" == tristate ]]; then
      scripts/config --module "$symbol"
    else
      scripts/config --enable "$symbol"
    fi
  done < "$KERNEL_OBSERVABILITY_CONFIGS_FILE"
elif [[ "$KERNEL_PROFILE" != small ]]; then
  echo "kernel observability Kconfig list not found: ${KERNEL_OBSERVABILITY_CONFIGS_FILE}" >&2
fi

make olddefconfig

KERNEL_OBSERVABILITY_CONFIG_REPORT="${OUTPUT_DIR}/kernel-observability-configs.txt"
{
  printf '# Kernel profile: %s\n' "$KERNEL_PROFILE"
  printf '# Kernel observability Kconfig results for %s\n' "$kernel_commit"
  printf '# symbol\tvalue\tdefinition\n'
  if [[ "$KERNEL_PROFILE" != small && -f "$KERNEL_OBSERVABILITY_CONFIGS_FILE" ]]; then
    while IFS= read -r requested_symbol; do
      requested_symbol="${requested_symbol%%#*}"
      requested_symbol="${requested_symbol//[[:space:]]/}"
      [[ -n "$requested_symbol" ]] || continue
      symbol="${requested_symbol#CONFIG_}"
      definition_file="$(kconfig_definition_file "$symbol")"
      value="$(kernel_config_value "CONFIG_${symbol}")"
      printf '%s\t%s\t%s\n' "$requested_symbol" "$value" "${definition_file:-not-defined}"
    done < "$KERNEL_OBSERVABILITY_CONFIGS_FILE"
  fi
} > "$KERNEL_OBSERVABILITY_CONFIG_REPORT"
enabled_count="$(awk -F '\t' '$2 == "y" || $2 == "m" { count++ } END { print count + 0 }' "$KERNEL_OBSERVABILITY_CONFIG_REPORT")"
unmet_count="$(awk -F '\t' '$2 == "n" || $2 == "unknown" { count++ } END { print count + 0 }' "$KERNEL_OBSERVABILITY_CONFIG_REPORT")"
echo "Kernel observability Kconfig results: enabled=${enabled_count} unmet_or_unknown=${unmet_count}"

require_config() {
  local symbol="$1"
  local expected_pattern="$2"

  if ! grep -Eq "^${symbol}=${expected_pattern}$" .config; then
    echo "required kernel config ${symbol} does not match ${expected_pattern}" >&2
    grep -E "^${symbol}=|^# ${symbol} is not set" .config >&2 || true
    exit 1
  fi
}

require_config_disabled() {
  local symbol="$1"

  if ! grep -Eq "^${symbol}=n$|^# ${symbol} is not set$" .config; then
    echo "required kernel config ${symbol} is not disabled" >&2
    grep -E "^${symbol}=|^# ${symbol} is not set" .config >&2 || true
    exit 1
  fi
}

if [[ "$KERNEL_PROFILE" == small ]]; then
require_config CONFIG_BPF_LSM y
require_config CONFIG_CGROUP_BPF y
require_config CONFIG_FUNCTION_TRACER y
require_config CONFIG_DYNAMIC_FTRACE y
require_config CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS y
require_config CONFIG_DEBUG_INFO_BTF y
require_config CONFIG_TCG_TPM y
require_config CONFIG_TCG_TIS_CORE y
require_config CONFIG_TCG_TIS y
require_config CONFIG_UPROBES y
require_config CONFIG_SECURITY y
require_config CONFIG_SECURITYFS y
require_config CONFIG_PCI y
require_config CONFIG_PCI_MSI y
require_config CONFIG_PCIEPORTBUS y
require_config CONFIG_NETDEVICES y
require_config CONFIG_ETHERNET y
require_config CONFIG_PACKET y
require_config CONFIG_ISO9660_FS y
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
require_config CONFIG_TMPFS y
require_config CONFIG_EFI_PARTITION y
require_config CONFIG_SERIAL_8250 y
require_config CONFIG_SERIAL_8250_CONSOLE y
require_config CONFIG_ACPI y
require_config CONFIG_PNP y
require_config CONFIG_PNPACPI y
require_config CONFIG_CC_OPTIMIZE_FOR_SIZE y
require_config CONFIG_KERNEL_XZ y
require_config_disabled CONFIG_MODULES
else
require_config CONFIG_BPF_LSM y
require_config CONFIG_CGROUP_BPF y
require_config CONFIG_FUNCTION_TRACER y
require_config CONFIG_DYNAMIC_FTRACE y
require_config CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS y
require_config CONFIG_DEBUG_INFO_BTF y
require_config CONFIG_TCG_TPM y
require_config CONFIG_TCG_TIS_CORE y
require_config CONFIG_TCG_TIS y
require_config CONFIG_TCG_CRB y
require_config CONFIG_UPROBES y
require_config CONFIG_SECURITYFS y
require_config CONFIG_PCI y
require_config CONFIG_PCI_MSI y
require_config CONFIG_NETDEVICES y
require_config CONFIG_ETHERNET y
require_config CONFIG_NET_VENDOR_AMAZON y
require_config CONFIG_ENA_ETHERNET '[ym]'
require_config CONFIG_COMPILE_TEST y
require_config CONFIG_BATMAN_ADV m
require_config CONFIG_BCMGENET m
require_config CONFIG_CEPH_FS m
require_config CONFIG_DM_CACHE m
require_config CONFIG_WAN y
require_config CONFIG_HDLC m
require_config CONFIG_FARSYNC m
require_config CONFIG_HFS_FS m
require_config CONFIG_MVPP2 m
require_config CONFIG_NF_CONNTRACK y
if (( netfilter_xtables_legacy_available )); then
  require_config CONFIG_NETFILTER_XTABLES_LEGACY y
fi
if grep -RqsE '^[[:space:]]*config IP_NF_IPTABLES_LEGACY([[:space:]]|$)' \
  net include; then
  require_config CONFIG_IP_NF_IPTABLES_LEGACY m
  require_config CONFIG_IP6_NF_IPTABLES_LEGACY m
else
  require_config CONFIG_IP_NF_IPTABLES m
  require_config CONFIG_IP6_NF_IPTABLES m
fi
require_config CONFIG_IP_NF_RAW m
require_config CONFIG_IP6_NF_RAW m
require_config CONFIG_NETFILTER_XT_MATCH_LENGTH m
require_config CONFIG_NETFILTER_CONNCOUNT m
require_config CONFIG_NFT_CONNLIMIT m
require_config CONFIG_NETFILTER_NETLINK_OSF m
require_config CONFIG_NFSD m
require_config CONFIG_OPENVSWITCH m
require_config CONFIG_CRYPTO_PCRYPT m
require_config CONFIG_QED m
require_config CONFIG_QEDE m
require_config CONFIG_SCSI_FC_ATTRS m
require_config CONFIG_SCSI_QLA_FC m
require_config CONFIG_RDS m
require_config CONFIG_SND m
require_config CONFIG_SND_PCM m
require_config CONFIG_TUN m
require_config CONFIG_UDF_FS m
require_config CONFIG_FUSE_FS m
require_config CONFIG_VIRTIO_FS m
require_config CONFIG_VETH m
require_config CONFIG_BRIDGE m
require_config CONFIG_VLAN_8021Q m
require_config CONFIG_BTRFS_FS m
require_config CONFIG_BRIDGE_NETFILTER m
require_config CONFIG_NF_FLOW_TABLE m
require_config CONFIG_NF_FLOW_TABLE_INET m
require_config CONFIG_NF_FLOW_TABLE_PROCFS y
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
require_config CONFIG_SQUASHFS y
require_config CONFIG_SQUASHFS_XZ y
require_config CONFIG_SQUASHFS_ZSTD y
require_config CONFIG_EXT4_FS y
require_config CONFIG_EFI_PARTITION y
require_config CONFIG_ISO9660_FS y
require_config CONFIG_SERIAL_8250 y
require_config CONFIG_SERIAL_8250_CONSOLE y
fi

# Refresh the generated release after the config edits above.  kernelrelease
# reads include/config/kernel.release, which may still contain the pre-config
# value until its FORCE target has run; the Debian package uses the refreshed
# value when it stages /lib/modules.
make -s include/config/kernel.release
kernel_release="$(<include/config/kernel.release)"
package_version="1+$(date -u +%Y%m%d%H%M%S)+g${kernel_commit:0:12}"
# GCC 15 defaults to GNU C23, while older stable snapshots still use `bool`
# and `false` as identifiers. KCFLAGS covers normal Kbuild CFLAGS, but x86
# EFI and realmode Makefiles replace KBUILD_CFLAGS for their special builds.
# Put GNU11 on the compiler command itself so those paths receive it too.
# Older stable snapshots can also trigger discarded-qualifier warnings in the
# bundled host-side libbpf, so keep that compatibility warning in host tools.
kernel_cc="${CC:-cc} -std=gnu11"
kernel_hostcflags="${HOSTCFLAGS:-} -std=gnu11 -Wno-error=discarded-qualifiers"
kernel_kcflags="${KCFLAGS:-} -Wno-error=unterminated-string-initialization -std=gnu11"
if [[ "$PACKAGE_FORMAT" == deb ]]; then
  make -j "$KERNEL_BUILD_JOBS" bindeb-pkg KDEB_PKGVERSION="$package_version" \
    CC="$kernel_cc" \
    HOSTCFLAGS="$kernel_hostcflags" \
    KCFLAGS="$kernel_kcflags"

  find "$WORK_DIR" -maxdepth 1 -type f -name '*.deb' ! -name '*-dbg*.deb' -exec cp {} "$OUTPUT_DIR/" \;

  if ! find "$OUTPUT_DIR" -type f -name 'linux-image-[0-9]*.deb' ! -name '*-dbg*' | grep -q .; then
    echo "kernel image deb was not produced" >&2
    exit 1
  fi
else
  make -j "$KERNEL_BUILD_JOBS" binrpm-pkg

  find "$SOURCE_DIR/rpmbuild/RPMS" -type f -name '*.rpm' \
    ! -name '*debug*' ! -name '*debuginfo*' -exec cp {} "$OUTPUT_DIR/" \;

  if ! find "$OUTPUT_DIR" -maxdepth 1 -type f -name '*.rpm' | grep -q .; then
    echo "kernel RPM was not produced" >&2
    exit 1
  fi
fi

# The VM boots bzImage directly, so carry the matching module tree alongside
# it. This keeps module loading deterministic for a selected kernel commit.
MODULES_STAGE_DIR="${WORK_DIR}/modules"
rm -rf "$MODULES_STAGE_DIR"
mkdir -p "$MODULES_STAGE_DIR"
IMAGE_DEB="$(find "$OUTPUT_DIR" -maxdepth 1 -type f \
  -name 'linux-image-[0-9]*.deb' ! -name '*-dbg*.deb' -print -quit)"
dpkg-deb -x "$IMAGE_DEB" "$MODULES_STAGE_DIR"
MODULES_SOURCE_DIR=""
for candidate in \
  "$MODULES_STAGE_DIR/lib/modules/$kernel_release" \
  "$MODULES_STAGE_DIR/usr/lib/modules/$kernel_release"; do
  if [[ -d "$candidate" ]]; then
    MODULES_SOURCE_DIR="$candidate"
    break
  fi
done
if [[ -z "$MODULES_SOURCE_DIR" ]]; then
  if [[ "$KERNEL_PROFILE" == small ]]; then
    echo "Small kernel has no loadable modules; continuing without a module tree"
    mkdir -p "$OUTPUT_DIR/lib/modules/$kernel_release"
  else
    echo "kernel image deb has no modules for ${kernel_release}" >&2
    exit 1
  fi
else
  mkdir -p "$OUTPUT_DIR/lib/modules"
  cp -a "$MODULES_SOURCE_DIR" "$OUTPUT_DIR/lib/modules/"
  depmod -b "$OUTPUT_DIR" "$kernel_release"
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

# Build the userspace BPF tools against the exact kernel checkout used for
# the kernel. The VM runner consumes these artifacts instead of rebuilding
# libbpf and bpftool for every fresh guest.
echo "Building Shirudo BPF dependency artifacts"
make -C "$SOURCE_DIR/tools/lib/bpf" CC="${CC:-cc}" \
  EXTRA_CFLAGS="-g -O2 -Wno-error=discarded-qualifiers"
make -C "$SOURCE_DIR/tools/bpf/bpftool" CC="${CC:-cc}" \
  EXTRA_CFLAGS="-g -O2 -Wno-error=discarded-qualifiers"
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

cat > "${OUTPUT_DIR}/${KERNEL_ARTIFACT_NAME}-kernel-build" <<EOF
source_dir=${KERNEL_SOURCE_DIR}
source_repository=${KERNEL_REPOSITORY}
tag=${KERNEL_TAG}
requested_commit=${KERNEL_COMMIT}
upstream_commit=${upstream_commit}
commit=${kernel_commit}
package_format=${PACKAGE_FORMAT}
patches_requested=${KERNEL_PATCHES}
patches_applied=${applied_patches[*]}
profile=${KERNEL_PROFILE}
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

echo "Built ${KERNEL_TAG} kernel bzImage: ${VMLINUX_PATH}"
echo "Built kernel BTF: ${VMLINUX_BTF_PATH}"
echo "Built Shirudo BPF dependency artifacts: ${BPF_DEPS_DIR}"
echo "Built kernel ${PACKAGE_FORMAT} bundle: ${BUNDLE_PATH}"
