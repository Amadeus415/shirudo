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

export prefix exec_prefix bindir libexecdir sharedir libdir mandir completionsdir \
       systemdunitdir SHIRUDO_TARGET_PKG_CONFIG_PATH \
       SHIRUDO_TARGET_MBEDTLS_INCLUDEDIR SHIRUDO_TARGET_MBEDTLS_LIBDIR
export VM_SSH_COMMAND

.PHONY: all help shirudo-target target-config shirudo-build test-helpers bundle test-vm-bundle bpf-next vm vm-console vm-ssh vm-stop vm-clean test-op test-tgt test-tgt-obs test-tgt-obs-fuzz test-vm test-vm-clean install \
        install-target install-operator bindeb-pkg bintar-pkg clean \
        distclean test examples config

KERNEL_PATCHES ?= $(if $(wildcard kernel/*.patch),kernel/,)

INSTALLER_TARBALL    ?= shirudo.tar.gz
INSTALLER_STAGE      ?= build/shirudo-installer
INSTALLER_ROOT       := $(INSTALLER_STAGE)/root
INSTALLER_PRIVATE_LIBDIR ?= $(libdir)/shirudo

STATIC_IMAGE_TARBALL ?= shirudo-static.tar.gz
STATIC_IMAGE_STAGE   ?= build/shirudo-static-image
STATIC_IMAGE_ROOT    := $(STATIC_IMAGE_STAGE)/root

# Debian packaging (make bindeb-pkg). Distro packages live under /usr,
# not /usr/local, and that prefix is baked into the binary (it is how the
# core `shirudo` finds shirudo-build), so bindeb-pkg rebuilds with this.
DEB_PREFIX     ?= /usr
DEB_STAGE      ?= build/deb
DEB_RAW_VERSION ?= $(shell $(SHIRUDO_GIT_DESCRIBE) 2>/dev/null || cat VERSION)
DEB_VERSION    ?= $(shell printf '%s' "$(DEB_RAW_VERSION)" | sed 's/^v//; s/[^A-Za-z0-9.+:~-]/./g; /^[0-9]/!s/^/0~/')
DEB_ARCH       ?= $(shell dpkg --print-architecture 2>/dev/null || echo amd64)
DEB_MAINTAINER ?= $(shell git config user.name 2>/dev/null || echo shirudo) <$(shell git config user.email 2>/dev/null || echo shirudo@localhost)>
DEB_TARGET_PKG   ?= shirudo-target_$(DEB_VERSION)_$(DEB_ARCH).deb
DEB_OPERATOR_PKG ?= shirudo-operator_$(DEB_VERSION)_$(DEB_ARCH).deb

# The outer make exports bindir/libexecdir/... derived from the default
# prefix, and a sub-make's `?=` will not recompute an already-set (env)
# value -- so we must hand the whole path set to the packaging sub-makes
# as command-line overrides (which beat the environment and propagate).
DEB_PATHS := prefix=$(DEB_PREFIX) exec_prefix=$(DEB_PREFIX) \
             bindir=$(DEB_PREFIX)/bin libexecdir=$(DEB_PREFIX)/libexec \
             sharedir=$(DEB_PREFIX)/share libdir=$(DEB_PREFIX)/lib \
             mandir=$(DEB_PREFIX)/share/man \
             completionsdir=$(DEB_PREFIX)/share/bash-completion/completions \
             systemdunitdir=/usr/lib/systemd/system

all: config
	+$(Q)$(MAKE) -f Makefile.shirudo PROFILE=operator CONFIG_MK=config.mk all

shirudo-target: target-config
	+$(Q)$(MAKE) -f Makefile.shirudo PROFILE=target CONFIG_MK=config-target.mk shirudo-target

target-config:
	+$(Q)$(MAKE) -f Makefile.config -B SHIRUDO_PROFILE=target \
		CONFIG_OUT=config-target.mk \
		SHIRUDO_TARGET_PKG_CONFIG_PATH="$(SHIRUDO_TARGET_PKG_CONFIG_PATH)" \
		SHIRUDO_TARGET_MBEDTLS_INCLUDEDIR="$(SHIRUDO_TARGET_MBEDTLS_INCLUDEDIR)" \
		SHIRUDO_TARGET_MBEDTLS_LIBDIR="$(SHIRUDO_TARGET_MBEDTLS_LIBDIR)" \
		SHIRUDO_TARGET_STATIC_LIBDIR="$(SHIRUDO_TARGET_STATIC_LIBDIR)" config.mk

define HELP_TEXT

shirudo make targets (run from the repo root):

  Build
    make                   build the shirudo binary (default target)
    make shirudo-target    build the target binary with static mbedTLS and
                           a static mbedTLS-backed libcurl and runtime
                           libraries (set SHIRUDO_TARGET_STATIC_LIBDIR when
                           static system archives use a custom directory)
    make ... SHIRUDO_DEBUG=0
                           omit DWARF debug information from C objects
    make shirudo-build     build the operator-only artifact builder
                           (compile + sign .upatch; ships in the operator
                           package, never to a target)
    make bpf-next          build bpf-next kernel DEBs, BTF, and BPF tools
                           (KERNEL_CONFIG=path overrides x86_64_defconfig)
    make clean             remove build artifacts
    make distclean         clean and drop the cached config.mk

  Test
    make test-op           build the operator tools, then run only the
                           host/operator-side TAP suite under t/; safe without
                           root, LSM, or a target kernel
    make test              run the full pipeline: bundle, host checks, and
                           target-side VM tests
    make test-tgt          boot a prepared target VM and run the complete
                           target-side suite, including LSM, load/unload,
                           uprobe, and OTEL map-export coverage
    make vm                boot a uniquely named persistent vTPM VM, prepare
                           Shirudo, and return without running the test suite
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
    make bintar-pkg        Two distro-agnostic target-installer tarballs:
                           both use the target binary with static mbedTLS and
                           mbedTLS-backed libcurl; shirudo-static.tar.gz also
                           bundles the remaining dynamic libraries via rpath.

  Other
    make examples          build the examples/ tree
    make config            run feature probes, write config.mk
    make help              show this overview

  Variables: prefix (=/usr/local), bindir, libexecdir, systemdunitdir,
             SHIRUDO_TARGET_PKG_CONFIG_PATH (target mbedTLS/libcurl .pc dirs),
             SHIRUDO_TARGET_MBEDTLS_INCLUDEDIR/LIBDIR (non-system mbedTLS),
             VM_NAME (optional unique VM name), VM_TENANT (OTEL tenant),
             VM_SSH_COMMAND (optional one-off command for make vm-ssh),
             TEST_VM_SSH_PORT (optional fixed localhost SSH port),
             TEST_VM_MAP_EXPORT_ENDPOINT (OTLP base URL),
             TEST_VM_MAP_EXPORT_CA (optional PEM CA file),
             TEST_VM_MAP_EXPORT_INSECURE=true (explicit HTTP only),
             TEST_VM_OCI_CA (optional PEM CA file for guest OCI trust),
             TEST_VM_PACKAGE_CERT (optional public package cert.der),
             TEST_VM_BPM_OCI_REPOSITORY (optional name=oci://endpoint),
             TEST_VM_BPM_OCI_INDEX_CERT (repository index certificate),
             TEST_VM_ROOTFS_URL/SHA256 (custom base image selection),
             TEST_VM_UBUNTU_CODENAME (kernel archive codename; default resolute),
             TEST_VM_BUNDLE_DIR (host VM payload cache),
             TEST_VM_RUNTIME_CACHE_DIR (prepared runtime image cache),
             TEST_VM_VERBOSE=1 (stream test VM QEMU output; otherwise show TAP progress),
             DNS_OBS_FUZZ_SEED / DNS_OBS_FUZZ_CASES (override the optional DNS
             mutation run),
             DESTDIR (staged install), V=1 (echo full command lines).

endef
export HELP_TEXT

help:
	@printf '%s\n' "$$HELP_TEXT"

shirudo-build: config
	+$(Q)$(MAKE) -f Makefile.shirudo shirudo-build

test-helpers: config
	+$(Q)$(MAKE) -f Makefile.shirudo test-helpers

TEST_VM_WORK_DIR ?= build/test-vm
TEST_VM_BUNDLE_DIR ?= $(TEST_VM_WORK_DIR)/host-bundle
TEST_VM_RUNTIME_CACHE_DIR ?= $(TEST_VM_WORK_DIR)/cache/runtime
TEST_VM_UBUNTU_CODENAME ?= resolute
TEST_VM_VERBOSE ?= 0
DNS_OBS_FUZZ_SEED ?= 0x53484952
DNS_OBS_FUZZ_CASES ?= 5000
TEST_VM_BUNDLE_STAMP := $(TEST_VM_BUNDLE_DIR)/.stamp
TEST_VM_BUNDLE_SOURCES := $(sort $(wildcard \
	*.c *.h include/*.h util/*.c util/*.h \
	bpf/*.c bpf/lib/*.h \
	bpf/vmlinux.h \
	tools/shirudo-build/*.c tools/shirudo-build/*.h \
	t/helper/*.c t/helper/*.py completion/* systemd/*.in systemd/*.timer \
	test-vm/fixtures/*.c test-vm/fixtures/*.lua \
	test-vm/fixtures/decoders/* \
	shields/linux_obs/*.c shields/linux_obs/*.h shields/linux_obs/Beefile \
	shields/linux_obs/decoders/* \
	shields/java_sql_inj/Beefile shields/java_sql_inj/README.md \
	shields/java_sql_inj/javaagent_metrics.bpf.c \
	shields/java_sql_inj/decoders/* \
	shields/java_sql_inj/build.sh shields/java_sql_inj/pom.xml \
	shields/java_sql_inj/agent/pom.xml shields/java_sql_inj/app/pom.xml \
	shields/java_sql_inj/agent/src/main/java/com/security/rasp/*.java \
	shields/java_sql_inj/app/src/main/java/com/test/*.java))
TEST_VM_BUNDLE_ARTIFACTS := $(sort $(wildcard \
	artifacts/bpf-next-kernel-debs \
	artifacts/bpf-next-kernel-debs/* \
	artifacts/bpf-next-kernel-debs/shirudo-bpf-deps \
	artifacts/bpf-next-kernel-debs/shirudo-bpf-deps/* \
	artifacts/bpf-next-kernel-debs/shirudo-bpf-deps/bpf/*))
TEST_VM_BUNDLE_INPUTS := $(sort \
	Makefile Makefile.config Makefile.shirudo Makefile.version config.mk \
	contrib/build-test-vm-bundle.sh contrib/test-vm-guest.sh \
	contrib/prepare-test-vm-runtime.sh contrib/test-vm-runtime-packages \
	$(TEST_VM_BUNDLE_SOURCES) $(TEST_VM_BUNDLE_ARTIFACTS) \
	$(if $(strip $(TEST_VM_PACKAGE_CERT)),$(TEST_VM_PACKAGE_CERT)))


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

bpf-next:
	$(Q)KERNEL_PATCHES='$(KERNEL_PATCHES)' contrib/build-kernel-deb.sh

vm: test-vm-bundle
	$(Q)VM_MODE=interactive VM_NAME="$(VM_NAME)" VM_TENANT="$(VM_TENANT)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" \
		TEST_VM_RUNTIME_CACHE_DIR="$(TEST_VM_RUNTIME_CACHE_DIR)" \
		TEST_VM_SSH_PORT="$(TEST_VM_SSH_PORT)" \
		TEST_VM_MAP_EXPORT_ENDPOINT="$(TEST_VM_MAP_EXPORT_ENDPOINT)" \
		TEST_VM_MAP_EXPORT_TENANT_ID="$(TEST_VM_MAP_EXPORT_TENANT_ID)" \
		TEST_VM_MAP_EXPORT_INSECURE="$(TEST_VM_MAP_EXPORT_INSECURE)" \
		TEST_VM_MAP_EXPORT_CA="$(TEST_VM_MAP_EXPORT_CA)" \
		TEST_VM_OCI_CA="$(TEST_VM_OCI_CA)" \
		TEST_VM_BPM_OCI_REPOSITORY="$(TEST_VM_BPM_OCI_REPOSITORY)" \
		TEST_VM_BPM_OCI_INDEX_CERT="$(TEST_VM_BPM_OCI_INDEX_CERT)" \
		TEST_VM_HOST_BUNDLE="$(abspath $(TEST_VM_BUNDLE_DIR))" \
		contrib/test-vm.sh

vm-console:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" contrib/test-vm.sh --console

vm-ssh:
	$(Q)VM_NAME="$(VM_NAME)" \
		TEST_VM_WORK_DIR="$(TEST_VM_WORK_DIR)" contrib/test-vm.sh --ssh

test-tgt: test-vm-bundle
	$(Q)VM_MODE=test VM_VERBOSE="$(TEST_VM_VERBOSE)" VM_NAME="$(VM_NAME)" VM_TENANT="$(VM_TENANT)" \
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

test-tgt-obs: test-vm-bundle
	$(Q)VM_MODE=test TEST_VM_SUITE=obs TEST_VM_DNS_FUZZ=0 VM_VERBOSE="$(TEST_VM_VERBOSE)" VM_NAME="$(VM_NAME)" VM_TENANT="$(VM_TENANT)" \
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

test-tgt-obs-fuzz: test-vm-bundle
	$(Q)VM_MODE=test TEST_VM_SUITE=obs TEST_VM_DNS_FUZZ=1 \
		TEST_VM_DNS_FUZZ_SEED="$(DNS_OBS_FUZZ_SEED)" \
		TEST_VM_DNS_FUZZ_CASES="$(DNS_OBS_FUZZ_CASES)" \
		VM_VERBOSE="$(TEST_VM_VERBOSE)" VM_NAME="$(VM_NAME)" VM_TENANT="$(VM_TENANT)" \
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
# binaries statically link mbedTLS and mbedTLS-backed libcurl. The static image
# additionally bundles the remaining dynamic libraries into lib/shirudo/ via
# an $ORIGIN-relative rpath for embedded / legacy / minimal targets.
# Each tarball contains a staged install-target tree under root/ plus an
# install.sh wrapper. The two flavors need different target binary builds (the
# bundled one carries an rpath), so the recipe rebuilds the target artifact
# between them.
bintar-pkg: config packaging/tar/install.sh packaging/tar/bundle-libs.sh
	+$(Q)$(MAKE) target-config
	@printf '  STAGE   $(INSTALLER_STAGE)  (system libs)\n'
	$(Q)rm -rf $(INSTALLER_STAGE) $(INSTALLER_TARBALL)
	$(Q)rm -f shirudo shirudo-target
	$(Q)install -d $(INSTALLER_STAGE) $(dir $(INSTALLER_TARBALL))
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
# Rebuilds from clean with prefix=$(DEB_PREFIX) because the libexec path is
# compiled into the binary and make cannot see the changed -D otherwise.
bindeb-pkg:
	$(Q)command -v dpkg-deb >/dev/null 2>&1 || { \
	    printf 'shirudo: dpkg-deb not found; install the dpkg-dev package\n' >&2; \
	    exit 1; }
	@printf '  CLEAN   (rebuild with prefix=$(DEB_PREFIX) for packaging)\n'
	+$(Q)$(MAKE) clean
	+$(Q)$(MAKE) $(DEB_PATHS) all shirudo-build
	$(Q)rm -rf $(DEB_STAGE) $(DEB_TARGET_PKG) $(DEB_OPERATOR_PKG)
	@printf '  STAGE   $(DEB_STAGE)/target\n'
	+$(Q)$(MAKE) $(DEB_PATHS) DESTDIR=$(abspath $(DEB_STAGE)/target) \
	    install-target
	@printf '  STAGE   $(DEB_STAGE)/operator\n'
	+$(Q)$(MAKE) $(DEB_PATHS) DESTDIR=$(abspath $(DEB_STAGE)/operator) \
	    install-operator
	$(Q)packaging/deb/builddeb.sh target $(abspath $(DEB_STAGE)/target) \
	    '$(DEB_VERSION)' '$(DEB_ARCH)' '$(DEB_MAINTAINER)' \
	    $(abspath $(DEB_TARGET_PKG))
	$(Q)packaging/deb/builddeb.sh operator $(abspath $(DEB_STAGE)/operator) \
	    '$(DEB_VERSION)' '$(DEB_ARCH)' '$(DEB_MAINTAINER)' \
	    $(abspath $(DEB_OPERATOR_PKG))
	@printf 'shirudo: wrote $(DEB_TARGET_PKG) and $(DEB_OPERATOR_PKG)\n'

# config.mk is regenerated by Makefile.config from the host's pkg-config
# state. Caches results until `make distclean`.
config: config.mk

config.mk: Makefile.config
	$(Q)$(MAKE) -f Makefile.config config.mk

install: all
	+$(Q)$(MAKE) -f Makefile.shirudo install

install-target: all target-config
	+$(Q)$(MAKE) -f Makefile.shirudo PROFILE=target CONFIG_MK=config-target.mk install-target

install-operator: all
	+$(Q)$(MAKE) -f Makefile.shirudo install-operator

examples:
	+$(Q)$(MAKE) -C examples

test-op: all shirudo-build test-helpers
	+$(Q)$(MAKE) -f Makefile.shirudo check

bundle: test-vm-bundle

test-vm: test-tgt

test:
	+$(Q)$(MAKE) bundle
	+$(Q)$(MAKE) test-op
	+$(Q)$(MAKE) test-tgt

clean:
	+$(Q)set -eu; \
		bundle_dir="$(abspath $(TEST_VM_BUNDLE_DIR))"; \
		mkdir -p "$$(dirname "$$bundle_dir")"; \
		exec 9>"$$bundle_dir.lock"; \
		flock 9; \
		$(MAKE) -f Makefile.shirudo clean; \
		$(MAKE) -C examples clean; \
		rm -rf "$$bundle_dir" $(INSTALLER_STAGE) $(STATIC_IMAGE_STAGE) \
		          $(INSTALLER_TARBALL) $(STATIC_IMAGE_TARBALL) \
		          $(DEB_STAGE) $(DEB_TARGET_PKG) $(DEB_OPERATOR_PKG)

distclean: clean
	$(Q)rm -f config.mk
	$(Q)$(MAKE) -f Makefile.shirudo distclean
