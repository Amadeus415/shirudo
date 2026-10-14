# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# shirudo top-level Makefile.
#
# Run `make` from the repo root. Feature probes write config.mk;
# Makefile.shirudo contains the actual build graph.

EXTRAVERSION = -rc0
NAME = Social BPF Coding

export EXTRAVERSION NAME

MAKEFLAGS += -rR --no-print-directory

include Makefile.version

# Output verbosity. `make V=1` shows full command lines.
ifeq ($(V),1)
  Q =
else
  Q = @
endif
export Q V

# Install paths (override at make-invocation time for packagers).
prefix      ?= /usr/local
exec_prefix ?= $(prefix)
bindir      ?= $(exec_prefix)/bin
libexecdir  ?= $(exec_prefix)/libexec
sharedir    ?= $(prefix)/share
libdir      ?= $(exec_prefix)/lib
mandir      ?= $(sharedir)/man
completionsdir ?= $(sharedir)/bash-completion/completions
# Absolute by default (systemd does not scan /usr/local); packagers override.
systemdunitdir ?= /usr/lib/systemd/system
dracutmodulesdir ?= /usr/lib/dracut/modules.d

# Local target dependency build defaults. make target-deps builds a static
# OpenSSL (3.5+), an OpenSSL-backed static libcurl and TPM2-TSS under
# TARGET_DEPS_DIR; these are overridable for a prebuilt dependency prefix.
TARGET_MULTIARCH ?= $(shell dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || gcc -print-multiarch)
TARGET_DEPS_DIR ?= $(CURDIR)/build/target-deps
TARGET_DEPS_OPENSSL_PREFIX ?= $(TARGET_DEPS_DIR)/openssl
TARGET_DEPS_CURL_PREFIX ?= $(TARGET_DEPS_DIR)/curl
SHIRUDO_TARGET_STATIC_LIBDIR ?= $(TARGET_DEPS_DIR)/lib
SHIRUDO_TARGET_PKG_CONFIG_PATH ?= $(TARGET_DEPS_CURL_PREFIX)/lib/pkgconfig:$(TARGET_DEPS_OPENSSL_PREFIX)/lib/pkgconfig:$(SHIRUDO_TARGET_STATIC_LIBDIR)/pkgconfig

export prefix exec_prefix bindir libexecdir sharedir libdir mandir completionsdir \
       systemdunitdir dracutmodulesdir SHIRUDO_TARGET_PKG_CONFIG_PATH \
       SHIRUDO_TARGET_STATIC_LIBDIR
export VM_SSH_COMMAND

.PHONY: all help html-docs target target-deps target-deps-clean shirudo-target target-config shirudo-build bpf-deps test-helpers linux-obs-ipv4-shields bundle test-vm-bundle kernel bpf-next kernel-small vm vm-small test-vm-small-bundle vm-console vm-ssh vm-stop vm-clean test-op test-tgt test-tgt-obs test-tgt-obs-fuzz test-vm test-vm-clean install \
        install-target install-operator bindeb-pkg binrpm-pkg bintar-pkg clean \
        distclean test config

KERNEL_PATCHES ?= $(if $(wildcard kernel/*.patch),kernel/,)
PACKAGE_FORMAT  ?= deb

INSTALLER_TARBALL    ?= shirudo.tar.gz
INSTALLER_STAGE      ?= build/shirudo-installer
INSTALLER_ROOT       := $(INSTALLER_STAGE)/root
INSTALLER_PRIVATE_LIBDIR ?= $(libdir)/shirudo

STATIC_IMAGE_TARBALL ?= shirudo-static.tar.gz
STATIC_IMAGE_STAGE   ?= build/shirudo-static-image
STATIC_IMAGE_ROOT    := $(STATIC_IMAGE_STAGE)/root

# Distribution packaging (make bindeb-pkg, make binrpm-pkg). Distro
# packages live under /usr, not /usr/local, and that prefix is baked into
# the binary (it is how the core `shirudo` finds shirudo-build), so both
# rebuild with this prefix.
PKG_PREFIX      ?= /usr
PKG_RAW_VERSION ?= $(shell $(SHIRUDO_GIT_DESCRIBE) 2>/dev/null || cat VERSION)
# Which roles to package. The target package is static apart from glibc
# and portable across distributions; the operator package links the
# build host's shared libraries and belongs on the distribution it is
# built on, so PKG_ROLES=operator builds just that one there.
PKG_ROLES       ?= target operator
PKG_MAINTAINER  ?= $(shell git config user.name 2>/dev/null || echo shirudo) <$(shell git config user.email 2>/dev/null || echo shirudo@localhost)>

DEB_STAGE      ?= build/deb
DEB_RAW_VERSION ?= $(PKG_RAW_VERSION)
DEB_VERSION    ?= $(shell printf '%s' "$(DEB_RAW_VERSION)" | sed 's/^v//; s/[^A-Za-z0-9.+:~-]/./g; /^[0-9]/!s/^/0~/')
DEB_ARCH       ?= $(shell dpkg --print-architecture 2>/dev/null || echo amd64)
DEB_TARGET_PKG   ?= shirudo-target_$(DEB_VERSION)_$(DEB_ARCH).deb
DEB_OPERATOR_PKG ?= shirudo-operator_$(DEB_VERSION)_$(DEB_ARCH).deb

# An RPM Version may not contain '-', so the describe output is split at
# the first dash: a plain tag is Release 1; commits past the tag
# ("-<n>-g<hash>", "-dirty") become Release 1.<n>.g<hash>, sorting after
# the tag; a pre-release tag suffix ("-rc1") becomes Release 0.rc1,
# sorting before the final 1. A describe without any tag is version
# 0.<hash>.
RPM_STAGE       ?= build/rpm
RPM_RAW_VERSION ?= $(PKG_RAW_VERSION)
RPM_VERSION     ?= $(shell printf '%s\n' "$(RPM_RAW_VERSION)" | sed 's/^v//; s/-.*//; s/[^A-Za-z0-9.+~^]/./g; /^[0-9]/!s/^/0./')
RPM_RELEASE     ?= $(shell printf '%s\n' "$(RPM_RAW_VERSION)" | sed 's/^v//; s/^[^-]*//; s/^-//; s/[^A-Za-z0-9.+~^]/./g' | sed -e 's/^$$/1/;t' -e 's/^[0-9]/1.&/;t' -e 's/^dirty/1.&/;t' -e 's/^/0./')
RPM_ARCH        ?= $(shell rpm --eval '%{_arch}' 2>/dev/null || uname -m)
RPM_TARGET_PKG   ?= shirudo-target-$(RPM_VERSION)-$(RPM_RELEASE).$(RPM_ARCH).rpm
RPM_OPERATOR_PKG ?= shirudo-operator-$(RPM_VERSION)-$(RPM_RELEASE).$(RPM_ARCH).rpm

# The outer make exports bindir/libexecdir/... derived from the default
# prefix, and a sub-make's `?=` will not recompute an already-set (env)
# value -- so we must hand the whole path set to the packaging sub-makes
# as command-line overrides (which beat the environment and propagate).
PKG_PATHS := prefix=$(PKG_PREFIX) exec_prefix=$(PKG_PREFIX) \
             bindir=$(PKG_PREFIX)/bin libexecdir=$(PKG_PREFIX)/libexec \
             sharedir=$(PKG_PREFIX)/share libdir=$(PKG_PREFIX)/lib \
             mandir=$(PKG_PREFIX)/share/man \
             completionsdir=$(PKG_PREFIX)/share/bash-completion/completions \
             systemdunitdir=/usr/lib/systemd/system

all: config
	+$(Q)$(MAKE) -f Makefile.shirudo PROFILE=operator CONFIG_MK=config.mk all

target-deps:
ifeq ($(TARGET_DEPS_PREBUILT),1)
	@printf 'shirudo: using prebuilt target dependencies\n'
else
	+$(Q)$(MAKE) -f Makefile.target-deps \
		TARGET_DEPS_DIR="$(TARGET_DEPS_DIR)" \
		TARGET_STATIC_LIBDIR="$(SHIRUDO_TARGET_STATIC_LIBDIR)" \
		TARGET_OPENSSL_PREFIX="$(TARGET_DEPS_OPENSSL_PREFIX)" \
		TARGET_CURL_PREFIX="$(TARGET_DEPS_CURL_PREFIX)"
endif

target-deps-clean:
	+$(Q)$(MAKE) -f Makefile.target-deps \
		TARGET_DEPS_DIR="$(TARGET_DEPS_DIR)" clean

target: shirudo-target

shirudo-target:
	+$(Q)$(MAKE) target-deps
	+$(Q)$(MAKE) target-config
	+$(Q)$(MAKE) -f Makefile.shirudo PROFILE=target CONFIG_MK=config-target.mk shirudo-target

target-config:
	+$(Q)$(MAKE) -f Makefile.config -B SHIRUDO_PROFILE=target \
		CONFIG_OUT=config-target.mk \
		SHIRUDO_TARGET_PKG_CONFIG_PATH="$(SHIRUDO_TARGET_PKG_CONFIG_PATH)" \
		SHIRUDO_TARGET_STATIC_LIBDIR="$(SHIRUDO_TARGET_STATIC_LIBDIR)" config.mk

define HELP_TEXT

shirudo make targets (run from the repo root):

  Build
    make                   build the shirudo binary (default target)
    make target-deps       build and stage static target dependencies
    make bpf-deps          refresh vendor/libbpf (libbpf, BPF headers, UAPI)
                           from a kernel tree; KERNEL_SRC=/path selects one,
                           the default clones bpf-next (on demand only)
    make target             alias for make shirudo-target
    make shirudo-target    build the target binary with static OpenSSL and
                           a static OpenSSL-backed libcurl and runtime
                           libraries (set SHIRUDO_TARGET_STATIC_LIBDIR when
                           static system archives use a custom directory)
    make ... SHIRUDO_DEBUG=0
                           omit DWARF debug information from C objects
    make ... SANITIZE=address,undefined
                           build the host-side binaries and test helpers
                           with the given sanitizers (combine with test-op)
    make shirudo-build     build the operator-only artifact builder
                           (compile + sign .upatch; ships in the operator
                           package, never to a target)
    make kernel KERNEL_TAG=v6.18 [KERNEL_COMMIT=sha]
                           build a tagged or exact-commit third-party Linux
                           kernel DEB/BTF bundle (KERNEL_CONFIG=path overrides
                           defconfig)
    make bpf-next          build bpf-next kernel packages, BTF, and BPF tools
                           (default: DEBs; set PACKAGE_FORMAT=rpm for RPMs)
    make kernel-small      build the minimal bpf-next kernel used by vm-small
    make vm KERNEL=6.18   boot a VM using a locally built stable kernel;
                           KERNEL_COMMIT selects an exact stable commit
                           supported selections: 7.2, 6.18, 6.12, 6.6, 6.1
    make clean             remove build artifacts
    make distclean         clean and drop the cached config.mk

  Test
    make test-op           build the operator tools, then run only the
                           host/operator-side TAP suite under testing/; safe without
                           root, LSM, or a target kernel
    make html-docs         render Documentation/*.rst with docutils in strict
                           mode into Documentation/output/ (needs rst2html
                           from python3-docutils); CI runs it on every push
    make test              run the full pipeline: bundle, host checks, and
                           target-side VM tests
    make test-tgt          boot a prepared target VM and run the complete
                           target-side suite, including LSM, load/unload,
                           uprobe, and OTEL map-export coverage
    make vm                boot a uniquely named persistent vTPM VM, prepare
                           Shirudo, and return without running the test suite
    make vm-small          boot the minimal persistent vTPM VM (1 CPU, 512 MiB,
                           4 GiB), prepare Shirudo, and report memory usage
    make vm-console        attach to the serial console of a named running VM
    make vm-ssh             open an SSH shell to a named running VM
    make test-tgt          boot a uniquely named vTPM VM with QEMU + swtpm,
                           import the host payload and prebuilt fixtures, run
                           the target integration suite, and retain the
                           stopped state for inspection
    make test-tgt-obs      boot the target VM and run only Linux observability
                           integration coverage
    make test-tgt-obs-fuzz boot the observability VM and additionally run the
                           seeded DNS mutation corpus (defaults: 5000 cases,
                           seed 0x53484952)
    make test-vm            compatibility alias for make test-tgt
    make test-vm-bundle    build/reuse the host-side Shirudo payload used by
                           make vm and make test-tgt, plus target-test fixtures;
                           prepare/reuse the content-keyed guest runtime image;
                           invalidated by source, Makefile, config, script,
                           fixture, and artifact changes
    make bundle             alias for make test-vm-bundle
    make vm-stop [VM_NAME=name]
                           stop one VM, or all VMs without a name; preserve state
    make vm-clean [VM_NAME=name]
                           remove one VM, or all VM state without a name
    make test-vm-clean      compatibility alias for make vm-clean

  Install   (honors DESTDIR and prefix=/bindir=/libexecdir=/systemdunitdir=)
    make install           shirudo binary + bash completion (common)
    make install-target    install + target systemd units for reboot
                           persistence, BPM refresh, periodic map export,
                           and status keepalive
    make install-operator  install + shirudo-build + BPF headers
                           (operator host)

  Package   (each rebuilds; pick by target environment)
    make bindeb-pkg        Two binary .deb's for Debian/Ubuntu targets:
                           shirudo-target_<version>_<arch>.deb (binary +
                           target systemd units) and
                           shirudo-operator_<version>_<arch>.deb (binary +
                           shirudo-build).
                           Rebuilds from clean with prefix=/usr.
    make binrpm-pkg        The same two packages as binary .rpm's for
                           Fedora, RHEL and SUSE targets:
                           shirudo-target-<version>-<release>.<arch>.rpm and
                           shirudo-operator-<version>-<release>.<arch>.rpm.
                           Needs rpmbuild (rpm on Debian/Ubuntu, rpm-build
                           on Fedora). Rebuilds from clean with prefix=/usr.
                           PKG_ROLES=target or =operator builds one of the
                           two (both package targets): the target package is
                           static and portable, the operator package links
                           the host's shared libraries and is built on the
                           distribution it is for.
    make bintar-pkg        Two distro-agnostic target-installer tarballs:
                           both use the target binary with static OpenSSL and
                           OpenSSL-backed libcurl; shirudo-static.tar.gz also
                           bundles the remaining dynamic libraries via rpath.

  Other
    make config            run feature probes, write config.mk
    make help              show this overview

  Variables: prefix (=/usr/local), bindir, libexecdir, systemdunitdir,
             SHIRUDO_TARGET_PKG_CONFIG_PATH (target OpenSSL/libcurl .pc dirs),
             SHIRUDO_TARGET_STATIC_LIBDIR (static runtime archive directory),
             TARGET_DEPS_OPENSSL_PREFIX/CURL_PREFIX (target-deps outputs),
             VM_NAME (optional unique VM name), VM_TENANT (OTEL tenant),
             KERNEL (VM kernel: bpf-next, 7.2, 6.18, 6.12, 6.6, or 6.1),
             KERNEL_TAG (kernel target tag, e.g. v6.18; TAG is an alias),
             KERNEL_COMMIT (optional 7-40 hex stable-kernel commit),
             KERNEL_REPOSITORY (third-party Linux git repository),
             KERNEL_SOURCE_DIR (existing clean Linux checkout),
             KERNEL_CONFIG (optional kernel config),
             VM_SSH_COMMAND (optional one-off command for make vm-ssh),
             TEST_VM_SSH_PORT (optional fixed localhost SSH port),
             TEST_VM_MAP_EXPORT_ENDPOINT (OTLP base URL),
             TEST_VM_MAP_EXPORT_CA (optional PEM CA file),
             TEST_VM_MAP_EXPORT_INSECURE=true (explicit HTTP only),
             TEST_VM_OCI_CA (optional PEM CA file for guest OCI trust),
             TEST_VM_BPM_TREE_CONFIG (optional upatch tree config for interactive
             VM),
             TEST_VM_PACKAGE_CERT (optional public package cert.der),
             TEST_VM_BPM_OCI_REPOSITORY (optional name=oci://endpoint),
             TEST_VM_BPM_OCI_INDEX_CERT (repository index certificate),
             TEST_VM_ROOTFS_URL/SHA256 (custom base image selection),
             TEST_VM_UBUNTU_CODENAME (kernel archive codename; default resolute),
             TEST_VM_BUNDLE_DIR (host VM payload cache),
             TEST_VM_RUNTIME_CACHE_DIR (prepared runtime image cache),
             TEST_VM_CPUS/MEMORY/DISK_SIZE (VM resource overrides),
             TEST_VM_VERBOSE=1 (stream test VM QEMU output; otherwise show TAP progress),
             TEST_VM_SUITE=tree (run only the tree-sync target tests),
             DNS_OBS_FUZZ_SEED / DNS_OBS_FUZZ_CASES (override the optional DNS
             mutation run),
             DESTDIR (staged install), V=1 (echo full command lines).

endef
export HELP_TEXT

help:
	@printf '%s\n' "$$HELP_TEXT"

# Render every document with docutils and fail on anything it reports, so a
# Sphinx-only role, a duplicate link target or a mis-parsed table breaks the
# build rather than the rendered page. coding-style.rst is the kernel's text
# verbatim; its restarted enumerated list is an informational note that is not
# ours to fix, so that one file halts at warnings instead.
RST2HTML ?= rst2html
DOCS_HTML_DIR ?= Documentation/output
DOCS_RST := $(sort $(wildcard Documentation/*.rst))

html-docs:
	$(Q)command -v $(RST2HTML) >/dev/null 2>&1 || { \
	    printf 'shirudo: %s not found; install python3-docutils\n' '$(RST2HTML)' >&2; \
	    exit 1; }
	$(Q)mkdir -p $(DOCS_HTML_DIR)
	$(Q)for f in $(DOCS_RST); do \
	    out=$(DOCS_HTML_DIR)/$$(basename $$f .rst).html; \
	    case $$f in \
	    Documentation/coding-style.rst) halt=--halt=warning ;; \
	    *) halt=--strict ;; \
	    esac; \
	    printf '  HTML    %s\n' "$$out"; \
	    $(RST2HTML) $$halt --no-generator "$$f" > "$$out" || { \
	        rm -f "$$out"; exit 1; }; \
	done

shirudo-build: config
	+$(Q)$(MAKE) -f Makefile.shirudo shirudo-build

linux-obs-ipv4-shields:
	$(Q)python3 upatches/linux_obs/gen_ipv4_shields.py \
		upatches/linux_obs/ipv4.list \
		upatches/linux_obs/ipv4_shields_generated.h

test-helpers: config
	+$(Q)$(MAKE) -f Makefile.shirudo test-helpers

TEST_VM_WORK_DIR ?= build/test-vm
TEST_VM_BUNDLE_DIR ?= $(TEST_VM_WORK_DIR)/host-bundle
TEST_VM_RUNTIME_CACHE_DIR ?= $(TEST_VM_WORK_DIR)/cache/runtime
TEST_VM_CPUS ?= 4
TEST_VM_MEMORY ?= 4G
TEST_VM_DISK_SIZE ?= 30G
TEST_VM_UBUNTU_CODENAME ?= resolute
TEST_VM_VERBOSE ?= 0
DNS_OBS_FUZZ_SEED ?= 0x53484952
DNS_OBS_FUZZ_CASES ?= 5000
TEST_VM_BUNDLE_STAMP := $(TEST_VM_BUNDLE_DIR)/.stamp
TEST_VM_BUNDLE_KERNEL_ARTIFACT_DIR ?= artifacts/bpf-next-kernel-debs
TEST_VM_BUNDLE_SOURCES := $(sort $(wildcard \
	*.c *.h include/*.h util/*.c util/*.h \
	bpf/*.c bpf/lib/*.h \
	vendor/linux/vmlinux.h \
	tools/shirudo-build/*.c tools/shirudo-build/*.h \
	testing/helper/*.c testing/helper/*.py completion/* systemd/*.in \
	systemd/*.timer testing/fixtures/*.c testing/fixtures/*.lua \
	testing/fixtures/decoders/* \
	upatches/linux_obs/*.c upatches/linux_obs/*.h upatches/linux_obs/*.list \
		upatches/linux_obs/*.py upatches/linux_obs/Beefile \
	upatches/linux_obs/decoders/*))
TEST_VM_BUNDLE_ARTIFACTS := $(sort $(wildcard \
	artifacts/bpf-next-kernel-debs \
	artifacts/bpf-next-kernel-debs/*))
TEST_VM_BUNDLE_INPUTS := $(sort \
	Makefile Makefile.config Makefile.shirudo Makefile.version config.mk \
	contrib/build-test-vm-bundle.sh contrib/test-vm-guest.sh \
	contrib/prepare-test-vm-runtime.sh contrib/test-vm-runtime-packages \
	$(TEST_VM_BUNDLE_SOURCES) $(TEST_VM_BUNDLE_ARTIFACTS) \
	$(if $(strip $(TEST_VM_PACKAGE_CERT)),$(TEST_VM_PACKAGE_CERT)))

TEST_VM_SMALL_WORK_DIR ?= build/test-vm-small
TEST_VM_SMALL_BUNDLE_DIR ?= $(TEST_VM_SMALL_WORK_DIR)/host-bundle
TEST_VM_SMALL_RUNTIME_CACHE_DIR ?= $(TEST_VM_SMALL_WORK_DIR)/cache/runtime
TEST_VM_SMALL_RUNTIME_DISK_SIZE ?= 4G
TEST_VM_SMALL_KERNEL_ARTIFACT_DIR ?= artifacts/bpf-next-small-kernel-debs
TEST_VM_SMALL_KERNEL_IMAGE := $(TEST_VM_SMALL_KERNEL_ARTIFACT_DIR)/bzImage
TEST_VM_SMALL_KERNEL_STAMP := $(TEST_VM_SMALL_KERNEL_ARTIFACT_DIR)/bzImage.sha256sum
TEST_VM_SMALL_BUNDLE_STAMP := $(TEST_VM_SMALL_BUNDLE_DIR)/.stamp
TEST_VM_SMALL_BUNDLE_ARTIFACTS := $(sort $(wildcard \
	$(TEST_VM_SMALL_KERNEL_ARTIFACT_DIR) \
	$(TEST_VM_SMALL_KERNEL_ARTIFACT_DIR)/* \
	$(TEST_VM_SMALL_KERNEL_ARTIFACT_DIR)/*))
TEST_VM_BUNDLE_COMMON_INPUTS := $(sort \
	Makefile Makefile.config Makefile.shirudo Makefile.version config.mk \
	contrib/build-test-vm-bundle.sh contrib/test-vm-guest.sh \
	contrib/prepare-test-vm-runtime.sh contrib/test-vm-runtime-packages \
	contrib/kernel-small.config $(TEST_VM_BUNDLE_SOURCES) \
	$(if $(strip $(TEST_VM_PACKAGE_CERT)),$(TEST_VM_PACKAGE_CERT)))
TEST_VM_SMALL_BUNDLE_INPUTS := $(sort \
	$(TEST_VM_BUNDLE_COMMON_INPUTS) $(TEST_VM_SMALL_BUNDLE_ARTIFACTS))

# `make vm` keeps bpf-next as its default, but can select a stable kernel
# built from an upstream Linux tag. The stable list is intentionally explicit
# so a typo cannot silently create a new VM kernel artifact directory.
VM_KERNEL ?= $(if $(strip $(KERNEL)),$(KERNEL),bpf-next)
VM_KERNEL_VERSION := $(patsubst v%,%,$(VM_KERNEL))
VM_KERNEL_STABLE_VERSIONS := 7.2 6.18 6.12 6.6 6.1
KERNEL_COMMIT ?=
KERNEL_COMMIT_SUFFIX := $(if $(strip $(KERNEL_COMMIT)),-$(KERNEL_COMMIT),)
ifeq ($(VM_KERNEL),bpf-next)
ifneq ($(strip $(KERNEL_COMMIT)),)
  $(error KERNEL_COMMIT is supported only for stable/LTS VM kernels)
endif
  VM_KERNEL_TAG := bpf-next
  VM_KERNEL_ARTIFACT_DIR := artifacts/bpf-next-kernel-debs
  VM_KERNEL_IMAGE :=
  VM_KERNEL_STAMP :=
  VM_KERNEL_DEP :=
else ifneq ($(filter $(VM_KERNEL_VERSION),$(VM_KERNEL_STABLE_VERSIONS)),)
  VM_KERNEL_TAG := v$(VM_KERNEL_VERSION)
  VM_KERNEL_ARTIFACT_DIR := artifacts/linux-$(VM_KERNEL_TAG)$(KERNEL_COMMIT_SUFFIX)-kernel-debs
  VM_KERNEL_IMAGE := $(VM_KERNEL_ARTIFACT_DIR)/bzImage
  VM_KERNEL_STAMP := $(VM_KERNEL_ARTIFACT_DIR)/bzImage.sha256sum
  VM_KERNEL_DEP := $(VM_KERNEL_STAMP)
else
  $(error unsupported VM KERNEL '$(VM_KERNEL)'; choose bpf-next, 7.2, 6.18, 6.12, 6.6, or 6.1)
endif

KERNEL_TAG ?= $(if $(strip $(TAG)),$(TAG),bpf-next)
KERNEL_TAG_VERSION := $(patsubst v%,%,$(KERNEL_TAG))
KERNEL_REPOSITORY ?= https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
KERNEL_SOURCE_DIR ?=
KERNEL_CONFIG ?=
KERNEL_BUILD_JOBS ?= $(shell nproc)
KERNEL_OBSERVABILITY_CONFIGS_FILE ?= $(abspath contrib/kernel-observability-configs.txt)
ifeq ($(KERNEL_TAG),bpf-next)
ifneq ($(filter kernel bpf-next,$(MAKECMDGOALS)),)
ifneq ($(strip $(KERNEL_COMMIT)),)
  $(error KERNEL_COMMIT is supported only for stable/LTS kernel tags)
endif
endif
  KERNEL_TAG_NORMALIZED := bpf-next
  KERNEL_BUILD_ARTIFACT_DIR := artifacts/bpf-next-kernel-debs
else
  KERNEL_TAG_NORMALIZED := v$(KERNEL_TAG_VERSION)
  KERNEL_BUILD_ARTIFACT_DIR := artifacts/linux-$(KERNEL_TAG_NORMALIZED)$(KERNEL_COMMIT_SUFFIX)-kernel-debs
endif
KERNEL_BUILD_STAMP := $(KERNEL_BUILD_ARTIFACT_DIR)/bzImage.sha256sum


test-vm-bundle: $(TEST_VM_BUNDLE_STAMP)

$(TEST_VM_BUNDLE_STAMP): $(TEST_VM_BUNDLE_INPUTS)
	$(Q)TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		TEST_VM_WORK_DIR="$(abspath $(TEST_VM_WORK_DIR))" \
		TEST_VM_RUNTIME_CACHE_DIR="$(abspath $(TEST_VM_RUNTIME_CACHE_DIR))" \
		TEST_VM_UBUNTU_CODENAME="$(TEST_VM_UBUNTU_CODENAME)" \
		TEST_VM_ROOTFS_URL="$(TEST_VM_ROOTFS_URL)" \
		TEST_VM_ROOTFS_SHA256="$(TEST_VM_ROOTFS_SHA256)" \
		TEST_VM_PACKAGE_CERT="$(TEST_VM_PACKAGE_CERT)" \
		TEST_VM_BUNDLE_STAMP="$(abspath $(TEST_VM_BUNDLE_STAMP))" \
		TEST_VM_BUNDLE_INPUTS="$(abspath $(TEST_VM_BUNDLE_INPUTS))" \
		contrib/build-test-vm-bundle.sh

kernel-small: $(TEST_VM_SMALL_KERNEL_STAMP)

$(TEST_VM_SMALL_KERNEL_STAMP): contrib/build-kernel-package.sh contrib/kernel-small.config
	$(Q)KERNEL_TAG='bpf-next' \
		KERNEL_PROFILE='small' \
		KERNEL_SMALL_CONFIG='$(abspath contrib/kernel-small.config)' \
		PACKAGE_FORMAT='$(PACKAGE_FORMAT)' \
		KERNEL_PATCHES='$(KERNEL_PATCHES)' \
		KERNEL_BUILD_JOBS='$(KERNEL_BUILD_JOBS)' \
		KERNEL_REPOSITORY='$(KERNEL_REPOSITORY)' \
		KERNEL_SOURCE_DIR='$(KERNEL_SOURCE_DIR)' \
		OUTPUT_DIR="$(abspath $(TEST_VM_SMALL_KERNEL_ARTIFACT_DIR))" \
		contrib/build-kernel-package.sh

test-vm-small-bundle: $(TEST_VM_SMALL_KERNEL_STAMP) $(TEST_VM_SMALL_BUNDLE_STAMP)

$(TEST_VM_SMALL_BUNDLE_STAMP): $(TEST_VM_SMALL_BUNDLE_INPUTS)
	$(Q)TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_SMALL_BUNDLE_DIR))" \
		TEST_VM_WORK_DIR="$(abspath $(TEST_VM_SMALL_WORK_DIR))" \
		TEST_VM_RUNTIME_CACHE_DIR="$(abspath $(TEST_VM_SMALL_RUNTIME_CACHE_DIR))" \
		TEST_VM_RUNTIME_DISK_SIZE="$(TEST_VM_SMALL_RUNTIME_DISK_SIZE)" \
		TEST_VM_UBUNTU_CODENAME="$(TEST_VM_UBUNTU_CODENAME)" \
		TEST_VM_ROOTFS_URL="$(TEST_VM_ROOTFS_URL)" \
		TEST_VM_ROOTFS_SHA256="$(TEST_VM_ROOTFS_SHA256)" \
		TEST_VM_PACKAGE_CERT="$(TEST_VM_PACKAGE_CERT)" \
		TEST_VM_BUNDLE_STAMP="$(abspath $(TEST_VM_SMALL_BUNDLE_STAMP))" \
		TEST_VM_BUNDLE_INPUTS="$(abspath $(TEST_VM_SMALL_BUNDLE_INPUTS))" \
		contrib/build-test-vm-bundle.sh

kernel: $(KERNEL_BUILD_STAMP)

bpf-next:
	$(Q)PACKAGE_FORMAT='$(PACKAGE_FORMAT)' \
		KERNEL_PATCHES='$(KERNEL_PATCHES)' \
		KERNEL_BUILD_JOBS='$(KERNEL_BUILD_JOBS)' \
		KERNEL_OBSERVABILITY_CONFIGS_FILE='$(KERNEL_OBSERVABILITY_CONFIGS_FILE)' \
		contrib/build-kernel-package.sh

$(KERNEL_BUILD_STAMP): contrib/build-kernel-package.sh $(KERNEL_OBSERVABILITY_CONFIGS_FILE)
	$(Q)KERNEL_TAG='$(KERNEL_TAG_NORMALIZED)' \
		KERNEL_COMMIT='$(KERNEL_COMMIT)' \
		KERNEL_PATCHES='$(KERNEL_PATCHES)' \
		KERNEL_REPOSITORY='$(KERNEL_REPOSITORY)' \
		KERNEL_SOURCE_DIR='$(KERNEL_SOURCE_DIR)' \
		KERNEL_CONFIG='$(KERNEL_CONFIG)' \
		PACKAGE_FORMAT='$(PACKAGE_FORMAT)' \
		KERNEL_BUILD_JOBS='$(KERNEL_BUILD_JOBS)' \
		KERNEL_OBSERVABILITY_CONFIGS_FILE='$(KERNEL_OBSERVABILITY_CONFIGS_FILE)' \
		OUTPUT_DIR="$(abspath $(KERNEL_BUILD_ARTIFACT_DIR))" \
		contrib/build-kernel-package.sh

# A VM selection owns its kernel artifact independently of the generic
# KERNEL_TAG selection used by `make kernel`.
ifneq ($(VM_KERNEL_DEP),)
ifneq ($(VM_KERNEL_TAG),$(KERNEL_TAG_NORMALIZED))
$(VM_KERNEL_STAMP):
	+$(Q)$(MAKE) kernel KERNEL_TAG='$(VM_KERNEL_TAG)' KERNEL_COMMIT='$(KERNEL_COMMIT)'
endif
endif

vm: $(VM_KERNEL_DEP) test-vm-bundle
	$(Q)VM_MODE=interactive VM_NAME="$(VM_NAME)" VM_TENANT="$(VM_TENANT)" \
		TEST_VM_KERNEL_PROFILE="full" \
		TEST_VM_KERNEL="$(abspath $(VM_KERNEL_IMAGE))" \
		TEST_VM_KERNEL_ARTIFACT_DIR="$(abspath $(VM_KERNEL_ARTIFACT_DIR))" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" \
		TEST_VM_RUNTIME_CACHE_DIR="$(TEST_VM_RUNTIME_CACHE_DIR)" \
		TEST_VM_CPUS="$(TEST_VM_CPUS)" \
		TEST_VM_MEMORY="$(TEST_VM_MEMORY)" \
		TEST_VM_DISK_SIZE="$(TEST_VM_DISK_SIZE)" \
		TEST_VM_SSH_PORT="$(TEST_VM_SSH_PORT)" \
		TEST_VM_MAP_EXPORT_ENDPOINT="$(TEST_VM_MAP_EXPORT_ENDPOINT)" \
		TEST_VM_MAP_EXPORT_TENANT_ID="$(TEST_VM_MAP_EXPORT_TENANT_ID)" \
		TEST_VM_MAP_EXPORT_INSECURE="$(TEST_VM_MAP_EXPORT_INSECURE)" \
		TEST_VM_MAP_EXPORT_CA="$(TEST_VM_MAP_EXPORT_CA)" \
		TEST_VM_OCI_CA="$(TEST_VM_OCI_CA)" \
		TEST_VM_BPM_TREE_CONFIG="$(TEST_VM_BPM_TREE_CONFIG)" \
		TEST_VM_PACKAGE_CERT="$(TEST_VM_PACKAGE_CERT)" \
		TEST_VM_BPM_OCI_REPOSITORY="$(TEST_VM_BPM_OCI_REPOSITORY)" \
		TEST_VM_BPM_OCI_INDEX_CERT="$(TEST_VM_BPM_OCI_INDEX_CERT)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		contrib/test-vm.sh

vm-small: kernel-small test-vm-small-bundle
	$(Q)VM_MODE=interactive VM_NAME="$(VM_NAME)" VM_TENANT="$(VM_TENANT)" \
		TEST_VM_KERNEL_PROFILE="small" \
		TEST_VM_KERNEL="$(abspath $(TEST_VM_SMALL_KERNEL_IMAGE))" \
		TEST_VM_KERNEL_ARTIFACT_DIR="" \
		TEST_VM_WORK_DIR="$(TEST_VM_SMALL_WORK_DIR)" \
		TEST_VM_RUNTIME_CACHE_DIR="$(TEST_VM_SMALL_RUNTIME_CACHE_DIR)" \
		TEST_VM_CPUS="1" \
		TEST_VM_MEMORY="512M" \
		TEST_VM_DISK_SIZE="4G" \
		TEST_VM_SSH_PORT="$(TEST_VM_SSH_PORT)" \
		TEST_VM_MAP_EXPORT_ENDPOINT="$(TEST_VM_MAP_EXPORT_ENDPOINT)" \
		TEST_VM_MAP_EXPORT_TENANT_ID="$(TEST_VM_MAP_EXPORT_TENANT_ID)" \
		TEST_VM_MAP_EXPORT_INSECURE="$(TEST_VM_MAP_EXPORT_INSECURE)" \
		TEST_VM_MAP_EXPORT_CA="$(TEST_VM_MAP_EXPORT_CA)" \
		TEST_VM_OCI_CA="$(TEST_VM_OCI_CA)" \
		TEST_VM_BPM_TREE_CONFIG="$(TEST_VM_BPM_TREE_CONFIG)" \
		TEST_VM_PACKAGE_CERT="$(TEST_VM_PACKAGE_CERT)" \
		TEST_VM_BPM_OCI_REPOSITORY="$(TEST_VM_BPM_OCI_REPOSITORY)" \
		TEST_VM_BPM_OCI_INDEX_CERT="$(TEST_VM_BPM_OCI_INDEX_CERT)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_SMALL_BUNDLE_DIR))" \
		contrib/test-vm.sh

vm-console:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" contrib/test-vm.sh --console

vm-ssh:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" contrib/test-vm.sh --ssh

test-tgt: $(VM_KERNEL_DEP) test-vm-bundle
	$(Q)VM_MODE=test TEST_VM_SUITE="$(TEST_VM_SUITE)" VM_VERBOSE="$(TEST_VM_VERBOSE)" VM_NAME="$(VM_NAME)" VM_TENANT="$(VM_TENANT)" \
		TEST_VM_KERNEL="$(abspath $(VM_KERNEL_IMAGE))" \
		TEST_VM_KERNEL_ARTIFACT_DIR="$(abspath $(VM_KERNEL_ARTIFACT_DIR))" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" \
		TEST_VM_RUNTIME_CACHE_DIR="$(TEST_VM_RUNTIME_CACHE_DIR)" \
		TEST_VM_MAP_EXPORT_ENDPOINT="$(TEST_VM_MAP_EXPORT_ENDPOINT)" \
		TEST_VM_MAP_EXPORT_TENANT_ID="$(TEST_VM_MAP_EXPORT_TENANT_ID)" \
		TEST_VM_MAP_EXPORT_INSECURE="$(TEST_VM_MAP_EXPORT_INSECURE)" \
		TEST_VM_MAP_EXPORT_CA="$(TEST_VM_MAP_EXPORT_CA)" \
		TEST_VM_OCI_CA="$(TEST_VM_OCI_CA)" \
		TEST_VM_BPM_OCI_REPOSITORY="$(TEST_VM_BPM_OCI_REPOSITORY)" \
		TEST_VM_BPM_OCI_INDEX_CERT="$(TEST_VM_BPM_OCI_INDEX_CERT)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		contrib/test-vm.sh

test-tgt-obs: $(VM_KERNEL_DEP) test-vm-bundle
	$(Q)VM_MODE=test TEST_VM_SUITE=obs TEST_VM_DNS_FUZZ=0 VM_VERBOSE="$(TEST_VM_VERBOSE)" VM_NAME="$(VM_NAME)" VM_TENANT="$(VM_TENANT)" \
		TEST_VM_KERNEL="$(abspath $(VM_KERNEL_IMAGE))" \
		TEST_VM_KERNEL_ARTIFACT_DIR="$(abspath $(VM_KERNEL_ARTIFACT_DIR))" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" \
		TEST_VM_RUNTIME_CACHE_DIR="$(TEST_VM_RUNTIME_CACHE_DIR)" \
		TEST_VM_MAP_EXPORT_ENDPOINT="$(TEST_VM_MAP_EXPORT_ENDPOINT)" \
		TEST_VM_MAP_EXPORT_TENANT_ID="$(TEST_VM_MAP_EXPORT_TENANT_ID)" \
		TEST_VM_MAP_EXPORT_INSECURE="$(TEST_VM_MAP_EXPORT_INSECURE)" \
		TEST_VM_MAP_EXPORT_CA="$(TEST_VM_MAP_EXPORT_CA)" \
		TEST_VM_OCI_CA="$(TEST_VM_OCI_CA)" \
		TEST_VM_BPM_OCI_REPOSITORY="$(TEST_VM_BPM_OCI_REPOSITORY)" \
		TEST_VM_BPM_OCI_INDEX_CERT="$(TEST_VM_BPM_OCI_INDEX_CERT)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		contrib/test-vm.sh

test-tgt-obs-fuzz: $(VM_KERNEL_DEP) test-vm-bundle
	$(Q)VM_MODE=test TEST_VM_SUITE=obs TEST_VM_DNS_FUZZ=1 \
		TEST_VM_DNS_FUZZ_SEED="$(DNS_OBS_FUZZ_SEED)" \
		TEST_VM_DNS_FUZZ_CASES="$(DNS_OBS_FUZZ_CASES)" \
		VM_VERBOSE="$(TEST_VM_VERBOSE)" VM_NAME="$(VM_NAME)" VM_TENANT="$(VM_TENANT)" \
		TEST_VM_KERNEL="$(abspath $(VM_KERNEL_IMAGE))" \
		TEST_VM_KERNEL_ARTIFACT_DIR="$(abspath $(VM_KERNEL_ARTIFACT_DIR))" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" \
		TEST_VM_RUNTIME_CACHE_DIR="$(TEST_VM_RUNTIME_CACHE_DIR)" \
		TEST_VM_MAP_EXPORT_ENDPOINT="$(TEST_VM_MAP_EXPORT_ENDPOINT)" \
		TEST_VM_MAP_EXPORT_TENANT_ID="$(TEST_VM_MAP_EXPORT_TENANT_ID)" \
		TEST_VM_MAP_EXPORT_INSECURE="$(TEST_VM_MAP_EXPORT_INSECURE)" \
		TEST_VM_MAP_EXPORT_CA="$(TEST_VM_MAP_EXPORT_CA)" \
		TEST_VM_OCI_CA="$(TEST_VM_OCI_CA)" \
		TEST_VM_PACKAGE_CERT="$(TEST_VM_PACKAGE_CERT)" \
		TEST_VM_BPM_OCI_REPOSITORY="$(TEST_VM_BPM_OCI_REPOSITORY)" \
		TEST_VM_BPM_OCI_INDEX_CERT="$(TEST_VM_BPM_OCI_INDEX_CERT)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		contrib/test-vm.sh

vm-stop:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" contrib/test-vm.sh --stop

vm-clean:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" contrib/test-vm.sh --clean

test-vm-clean: vm-clean

# Build two target-installer tarballs (kernel-style `bin*-pkg`). Both target
# binaries statically link OpenSSL and OpenSSL-backed libcurl. The static image
# additionally bundles the remaining dynamic libraries into lib/shirudo/ via
# an $ORIGIN-relative rpath for embedded / legacy / minimal targets.
# Each tarball contains a staged install-target tree under root/ plus an
# install.sh wrapper. The two flavors need different target binary builds (the
# bundled one carries an rpath), so the recipe rebuilds the target artifact
# between them.
bintar-pkg: config packaging/tar/install.sh packaging/tar/bundle-libs.sh
	@printf '  STAGE   $(INSTALLER_STAGE)  (system libs)\n'
	$(Q)rm -rf $(INSTALLER_STAGE) $(INSTALLER_TARBALL)
	$(Q)rm -f shirudo shirudo-target
	$(Q)install -d $(INSTALLER_STAGE) $(dir $(INSTALLER_TARBALL))
	+$(Q)$(MAKE) target-deps
	+$(Q)$(MAKE) target-config
	+$(Q)$(MAKE) -f Makefile.shirudo PROFILE=target CONFIG_MK=config-target.mk \
	    LDFLAGS='$(LDFLAGS)' \
	    SHIRUDO_BUNDLE_RPATH=0 \
	    DESTDIR=$(abspath $(INSTALLER_ROOT)) \
	    install-target
	$(Q)install -m 0755 packaging/tar/install.sh $(INSTALLER_STAGE)/install.sh
	$(Q)install -m 0644 LICENSE README.md VERSION $(INSTALLER_STAGE)/
	@printf '  TAR     $(INSTALLER_TARBALL)\n'
	$(Q)tar -C $(dir $(INSTALLER_STAGE)) -czf $(INSTALLER_TARBALL) \
	    $(notdir $(INSTALLER_STAGE))
	@printf '  STAGE   $(STATIC_IMAGE_STAGE)  (bundled libs)\n'
	$(Q)rm -rf $(STATIC_IMAGE_STAGE) $(STATIC_IMAGE_TARBALL)
	$(Q)rm -f shirudo shirudo-target
	$(Q)install -d $(STATIC_IMAGE_STAGE) $(dir $(STATIC_IMAGE_TARBALL))
	+$(Q)$(MAKE) target-deps
	+$(Q)$(MAKE) target-config
	+$(Q)$(MAKE) -f Makefile.shirudo PROFILE=target CONFIG_MK=config-target.mk \
	    LDFLAGS='$(LDFLAGS)' \
	    SHIRUDO_BUNDLE_RPATH=1 \
	    DESTDIR=$(abspath $(STATIC_IMAGE_ROOT)) \
	    install-target
	$(Q)packaging/tar/bundle-libs.sh \
	    "$(abspath $(STATIC_IMAGE_ROOT)$(bindir)/shirudo)" \
	    "$(abspath $(STATIC_IMAGE_ROOT)$(INSTALLER_PRIVATE_LIBDIR))"
	$(Q)install -m 0755 packaging/tar/install.sh \
	    $(STATIC_IMAGE_STAGE)/install.sh
	$(Q)install -m 0644 LICENSE README.md VERSION $(STATIC_IMAGE_STAGE)/
	@printf '  TAR     $(STATIC_IMAGE_TARBALL)\n'
	$(Q)tar -C $(dir $(STATIC_IMAGE_STAGE)) -czf $(STATIC_IMAGE_TARBALL) \
	    $(notdir $(STATIC_IMAGE_STAGE))
	@printf 'shirudo: wrote $(INSTALLER_TARBALL) and $(STATIC_IMAGE_TARBALL)\n'

# Build two .deb packages (kernel-style `make bindeb-pkg`):
#   shirudo-target_<version>_<arch>.deb
#       shirudo + the systemd reboot, map-export, and keepalive units
#       (target node)
#   shirudo-operator_<version>_<arch>.deb
#       shirudo + shirudo-build + BPF headers, no unit
# Rebuilds from clean with prefix=$(PKG_PREFIX) because the libexec path is
# compiled into the binary and make cannot see the changed -D otherwise.
bindeb-pkg:
	$(Q)command -v dpkg-deb >/dev/null 2>&1 || { \
	    printf 'shirudo: dpkg-deb not found; install the dpkg-dev package\n' >&2; \
	    exit 1; }
	@printf '  CLEAN   (rebuild with prefix=$(PKG_PREFIX) for packaging)\n'
	+$(Q)$(MAKE) clean
	+$(Q)$(MAKE) $(PKG_PATHS) all $(if $(filter operator,$(PKG_ROLES)),shirudo-build)
	$(Q)rm -rf $(DEB_STAGE) $(DEB_TARGET_PKG) $(DEB_OPERATOR_PKG)
	$(if $(filter target,$(PKG_ROLES)),@printf '  STAGE   $(DEB_STAGE)/target\n')
	$(if $(filter target,$(PKG_ROLES)),+$(Q)$(MAKE) $(PKG_PATHS) DESTDIR=$(abspath $(DEB_STAGE)/target) install-target)
	$(if $(filter operator,$(PKG_ROLES)),@printf '  STAGE   $(DEB_STAGE)/operator\n')
	$(if $(filter operator,$(PKG_ROLES)),+$(Q)$(MAKE) $(PKG_PATHS) DESTDIR=$(abspath $(DEB_STAGE)/operator) install-operator)
	$(if $(filter target,$(PKG_ROLES)),$(Q)packaging/deb/builddeb.sh target $(abspath $(DEB_STAGE)/target) \
	    '$(DEB_VERSION)' '$(DEB_ARCH)' '$(PKG_MAINTAINER)' $(abspath $(DEB_TARGET_PKG)))
	$(if $(filter operator,$(PKG_ROLES)),$(Q)packaging/deb/builddeb.sh operator $(abspath $(DEB_STAGE)/operator) \
	    '$(DEB_VERSION)' '$(DEB_ARCH)' '$(PKG_MAINTAINER)' $(abspath $(DEB_OPERATOR_PKG)))
	@printf 'shirudo: wrote %s\n' "$(strip $(if $(filter target,$(PKG_ROLES)),$(DEB_TARGET_PKG)) $(if $(filter operator,$(PKG_ROLES)),$(DEB_OPERATOR_PKG)))"

# Build the same two packages as binary RPMs (kernel-style `make
# binrpm-pkg`). The staged trees are identical to the deb ones; only the
# metadata and scriptlets differ. Library dependencies are rpm's
# automatic soname requires, so the output installs on any RPM
# distribution shipping those libraries.
binrpm-pkg:
	$(Q)command -v rpmbuild >/dev/null 2>&1 || { \
	    printf 'shirudo: rpmbuild not found; install rpm (Debian/Ubuntu) or rpm-build (Fedora)\n' >&2; \
	    exit 1; }
	@printf '  CLEAN   (rebuild with prefix=$(PKG_PREFIX) for packaging)\n'
	+$(Q)$(MAKE) clean
	+$(Q)$(MAKE) $(PKG_PATHS) all $(if $(filter operator,$(PKG_ROLES)),shirudo-build)
	$(Q)rm -rf $(RPM_STAGE) $(RPM_TARGET_PKG) $(RPM_OPERATOR_PKG)
	$(if $(filter target,$(PKG_ROLES)),@printf '  STAGE   $(RPM_STAGE)/target\n')
	$(if $(filter target,$(PKG_ROLES)),+$(Q)$(MAKE) $(PKG_PATHS) DESTDIR=$(abspath $(RPM_STAGE)/target) install-target)
	$(if $(filter operator,$(PKG_ROLES)),@printf '  STAGE   $(RPM_STAGE)/operator\n')
	$(if $(filter operator,$(PKG_ROLES)),+$(Q)$(MAKE) $(PKG_PATHS) DESTDIR=$(abspath $(RPM_STAGE)/operator) install-operator)
	$(if $(filter target,$(PKG_ROLES)),$(Q)packaging/rpm/buildrpm.sh target $(abspath $(RPM_STAGE)/target) \
	    '$(RPM_VERSION)' '$(RPM_RELEASE)' '$(RPM_ARCH)' '$(PKG_MAINTAINER)' $(abspath $(RPM_TARGET_PKG)))
	$(if $(filter operator,$(PKG_ROLES)),$(Q)packaging/rpm/buildrpm.sh operator $(abspath $(RPM_STAGE)/operator) \
	    '$(RPM_VERSION)' '$(RPM_RELEASE)' '$(RPM_ARCH)' '$(PKG_MAINTAINER)' $(abspath $(RPM_OPERATOR_PKG)))
	@printf 'shirudo: wrote %s\n' "$(strip $(if $(filter target,$(PKG_ROLES)),$(RPM_TARGET_PKG)) $(if $(filter operator,$(PKG_ROLES)),$(RPM_OPERATOR_PKG)))"

# config.mk is regenerated by Makefile.config from the host's pkg-config
# state. Caches results until `make distclean`.
bpf-deps:
	$(Q)KERNEL_SRC="$(KERNEL_SRC)" contrib/bpf-deps.sh

config: config.mk

config.mk: Makefile.config
	$(Q)$(MAKE) -f Makefile.config config.mk

install: all
	+$(Q)$(MAKE) -f Makefile.shirudo install

install-target: all
	+$(Q)$(MAKE) target-deps
	+$(Q)$(MAKE) target-config
	+$(Q)$(MAKE) -f Makefile.shirudo PROFILE=target CONFIG_MK=config-target.mk install-target

install-operator: all
	+$(Q)$(MAKE) -f Makefile.shirudo install-operator

test-op: all shirudo-build test-helpers
	+$(Q)$(MAKE) -f Makefile.shirudo check

bundle: test-vm-bundle

test-vm: test-tgt

test:
	+$(Q)$(MAKE) bundle
	+$(Q)$(MAKE) test-op
	+$(Q)$(MAKE) test-tgt

clean:
	$(Q)rm -rf $(DOCS_HTML_DIR)
	+$(Q)set -eu; \
		bundle_dir="$(abspath $(TEST_VM_BUNDLE_DIR))"; \
		mkdir -p "$$(dirname "$$bundle_dir")"; \
		exec 9>"$$bundle_dir.lock"; \
		flock 9; \
		$(MAKE) -f Makefile.shirudo clean; \
		rm -rf "$$bundle_dir" $(INSTALLER_STAGE) $(STATIC_IMAGE_STAGE) \
		          $(INSTALLER_TARBALL) $(STATIC_IMAGE_TARBALL) \
		          $(DEB_STAGE) $(DEB_TARGET_PKG) $(DEB_OPERATOR_PKG) \
		          $(RPM_STAGE) $(RPM_TARGET_PKG) $(RPM_OPERATOR_PKG)

distclean: clean
	$(Q)rm -f config.mk
	+$(Q)$(MAKE) -f Makefile.target-deps \
		TARGET_DEPS_DIR="$(TARGET_DEPS_DIR)" clean
	$(Q)$(MAKE) -f Makefile.shirudo distclean
