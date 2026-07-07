# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

MAKEFLAGS += -rR --no-print-directory

include ../Makefile.version

ifeq ($(V),1)
  Q =
else
  Q = @
endif

GO ?= go
BINARY ?= bpm
DOCKER ?= docker
NFPM_IMAGE ?= goreleaser/nfpm:latest
NFPM_DOCKER_FLAGS ?=
NFPM_DOCKER_USER ?= $(shell id -u):$(shell id -g)
NFPM ?= $(DOCKER) run --rm --user "$(NFPM_DOCKER_USER)" $(NFPM_DOCKER_FLAGS) -v "$(CURDIR):$(CURDIR)" -w "$(CURDIR)" "$(NFPM_IMAGE)"

RELEASE_GOOS ?= linux
GOARCHES ?= amd64 arm64

DISTDIR ?= dist
TARBALLDIR ?= $(DISTDIR)/tarballs
PACKAGEDIR ?= $(DISTDIR)/packages

VERSION ?= $(shell $(SHIRUDO_GIT_DESCRIBE) 2>/dev/null || cat ../VERSION)
RPM_RELEASE ?= 1
PACKAGE_VERSION ?= $(shell printf '%s' '$(VERSION)' | sed 's/^v//; s/-/+/g; s/[^A-Za-z0-9.+:~]/+/g')

MAINTAINER ?= shirudo <shirudo@localhost>
SUMMARY ?= eBPF package manager for Shirudo

GOFLAGS ?= -trimpath
LDFLAGS ?= -s -w
VERSION_LDFLAGS := -X main.version=$(VERSION)

.PHONY: all release tarballs packages

all:
	@printf '  GO      $(BINARY)\n'
	$(Q)$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS) $(VERSION_LDFLAGS)' -o $(BINARY) .

release: tarballs packages

tarballs:
	$(Q)rm -rf $(TARBALLDIR)
	$(Q)install -d $(TARBALLDIR)
	$(Q)set -eu; \
	for arch in $(GOARCHES); do \
		name="bpm-$(VERSION)-$(RELEASE_GOOS)-$$arch"; \
		stage="$(TARBALLDIR)/$$name"; \
		printf '  GO      %s\n' "$$stage/bpm"; \
		rm -rf "$$stage"; \
		install -d "$$stage"; \
		GOOS=$(RELEASE_GOOS) GOARCH=$$arch CGO_ENABLED=0 \
			$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS) $(VERSION_LDFLAGS)' -o "$$stage/bpm" .; \
		install -m 0644 ../LICENSE "$$stage/LICENSE"; \
		printf '  TAR     %s\n' "$(DISTDIR)/$$name.tar.gz"; \
		tar -C "$(TARBALLDIR)" -czf "$(DISTDIR)/$$name.tar.gz" "$$name"; \
	done

packages:
	$(Q)command -v $(DOCKER) >/dev/null 2>&1 || { \
		printf 'bpm: docker not found; install docker or override NFPM\n' >&2; \
		exit 1; \
	}
	$(Q)$(DOCKER) version >/dev/null 2>&1 || { \
		printf 'bpm: docker daemon unavailable; start docker/colima or override NFPM\n' >&2; \
		exit 1; \
	}
	$(Q)rm -rf $(PACKAGEDIR)
	$(Q)install -d $(PACKAGEDIR)
	$(Q)set -eu; \
	for arch in $(GOARCHES); do \
		case "$$arch" in \
			amd64) rpmarch=x86_64 ;; \
			arm64) rpmarch=aarch64 ;; \
			*) printf 'bpm: unsupported package arch %s\n' "$$arch" >&2; exit 1 ;; \
		esac; \
		bin="$(PACKAGEDIR)/bpm-$(RELEASE_GOOS)-$$arch"; \
		printf '  GO      %s\n' "$$bin"; \
		GOOS=$(RELEASE_GOOS) GOARCH=$$arch CGO_ENABLED=0 \
			$(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS) $(VERSION_LDFLAGS)' -o "$$bin" .; \
		config="$(PACKAGEDIR)/nfpm-$$arch.yaml"; \
		src="$$(pwd)/$$bin"; \
		printf 'name: bpm\narch: %s\nplatform: $(RELEASE_GOOS)\nversion: "%s"\nrelease: "%s"\nsection: utils\npriority: optional\nmaintainer: "%s"\ndescription: "%s"\nlicense: BSD-2-Clause\ncontents:\n  - src: "%s"\n    dst: /usr/bin/bpm\n' \
			"$$arch" "$(PACKAGE_VERSION)" "$(RPM_RELEASE)" \
			"$(MAINTAINER)" "$(SUMMARY)" "$$src" > "$$config"; \
		printf '  DEB     %s\n' "$(DISTDIR)/bpm_$(PACKAGE_VERSION)_$$arch.deb"; \
		$(NFPM) package --config "$$config" --packager deb \
			--target "$(DISTDIR)/bpm_$(PACKAGE_VERSION)_$$arch.deb"; \
		printf '  RPM     %s\n' "$(DISTDIR)/bpm-$(PACKAGE_VERSION)-$(RPM_RELEASE).$$rpmarch.rpm"; \
		$(NFPM) package --config "$$config" --packager rpm \
			--target "$(DISTDIR)/bpm-$(PACKAGE_VERSION)-$(RPM_RELEASE).$$rpmarch.rpm"; \
	done
