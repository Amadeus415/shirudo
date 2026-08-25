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
       systemdunitdir

.PHONY: all help shirudo-build bpf-next test-vm test-vm-clean install \
        install-target install-operator bindeb-pkg bintar-pkg clean \
        distclean check test examples config

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
	+$(Q)$(MAKE) -f Makefile.shirudo all

define HELP_TEXT

shirudo make targets (run from the repo root):

  Build
    make                   build the shirudo binary (default target)
    make shirudo-build     build the operator-only artifact builder
                           (compile + sign .upatch; ships in the operator
                           package, never to a target)
    make bpf-next          build the bpf-next kernel DEBs and raw bzImage
                           (KERNEL_CONFIG=path overrides x86_64_defconfig)
    make clean             remove build artifacts
    make distclean         clean and drop the cached config.mk

  Test
    make check             build, then run the TAP suite under t/
                           (unit tests always; t11xx integration skip
                           unless opted in). `make test` is an alias.
    SHIRUDO_INTEGRATION=1 make check
                           additionally run the live integration suite
                           (needs root and a host where `shirudo init`
                           has attached the LSM)
    make test-vm           boot the built bzImage with QEMU + swtpm and run
                           SHIRUDO_INTEGRATION=1 make check in the guest
    make test-vm-clean     remove cached rootfs and disposable VM state

  Install   (honors DESTDIR and prefix=/bindir=/libexecdir=/systemdunitdir=)
    make install           shirudo binary + bash completion (common)
    make install-target    install + the systemd reboot-persistence unit
                           (target host)
    make install-operator  install + shirudo-build + BPF headers
                           (operator host)

  Package   (each rebuilds; pick by target environment)
    make bindeb-pkg        Two binary .deb's for Debian/Ubuntu targets:
                           shirudo-target_<version>_<arch>.deb (binary +
                           systemd unit) and
                           shirudo-operator_<version>_<arch>.deb (binary +
                           shirudo-build).
                           Rebuilds from clean with prefix=/usr.
    make bintar-pkg        Two distro-agnostic target-installer tarballs:
                           shirudo.tar.gz (expects system libssh/libtss2/
                           libcrypto on the target) and shirudo-static.tar.gz
                           (bundles those libs via rpath; for embedded,
                           legacy, or minimal targets).

  Other
    make examples          build the examples/ tree
    make config            run feature probes, write config.mk
    make help              show this overview

  Variables: prefix (=/usr/local), bindir, libexecdir, systemdunitdir,
             DESTDIR (staged install), V=1 (echo full command lines).

endef
export HELP_TEXT

help:
	@printf '%s\n' "$$HELP_TEXT"

shirudo-build: config
	+$(Q)$(MAKE) -f Makefile.shirudo shirudo-build

bpf-next:
	$(Q)KERNEL_PATCHES='$(KERNEL_PATCHES)' contrib/build-kernel-deb.sh

test-vm:
	$(Q)contrib/test-vm.sh

test-vm-clean:
	$(Q)rm -rf build/test-vm

# Build two target-installer tarballs (kernel-style `bin*-pkg`):
#   shirudo.tar.gz         -- expects system libssh/libtss2/libcrypto on
#                             the target (any distro with matching ABI).
#   shirudo-static.tar.gz  -- bundles those libs into lib/shirudo/ via
#                             $ORIGIN-relative rpath, for embedded / legacy
#                             / minimal targets where the system libs are
#                             missing or too old.
# Each tarball contains a staged install-target tree under root/ plus an
# install.sh wrapper. The two flavors need different binary builds (the
# bundled one carries an rpath), so the recipe rebuilds the binary
# between them.
bintar-pkg: config packaging/tar/install.sh packaging/tar/bundle-libs.sh
	@printf '  STAGE   $(INSTALLER_STAGE)  (system libs)\n'
	$(Q)rm -rf $(INSTALLER_STAGE) $(INSTALLER_TARBALL)
	$(Q)rm -f shirudo
	$(Q)install -d $(INSTALLER_STAGE) $(dir $(INSTALLER_TARBALL))
	+$(Q)$(MAKE) -f Makefile.shirudo \
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
	$(Q)rm -f shirudo
	$(Q)install -d $(STATIC_IMAGE_STAGE) $(dir $(STATIC_IMAGE_TARBALL))
	+$(Q)$(MAKE) -f Makefile.shirudo \
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
#       shirudo + the systemd reboot unit (target node)
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

install-target: all
	+$(Q)$(MAKE) -f Makefile.shirudo install-target

install-operator: all
	+$(Q)$(MAKE) -f Makefile.shirudo install-operator

examples:
	+$(Q)$(MAKE) -C examples

check test: all
	+$(Q)$(MAKE) -f Makefile.shirudo $@

clean:
	+$(Q)$(MAKE) -f Makefile.shirudo clean
	$(Q)$(MAKE) -C examples clean
	$(Q)rm -rf $(INSTALLER_STAGE) $(STATIC_IMAGE_STAGE) \
	          $(INSTALLER_TARBALL) $(STATIC_IMAGE_TARBALL) \
	          $(DEB_STAGE) $(DEB_TARGET_PKG) $(DEB_OPERATOR_PKG)

distclean: clean
	$(Q)rm -f config.mk
	$(Q)$(MAKE) -f Makefile.shirudo distclean
