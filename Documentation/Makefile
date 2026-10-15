# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# Documentation rendering. Run with make -C Documentation html-docs.

ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
MAKEFLAGS += -rR --no-print-directory

ifeq ($(V),1)
  Q =
else
  Q = @
endif
export Q V

root-path = $(if $(filter /%,$(1)),$(1),$(ROOT)/$(1))
.DEFAULT_GOAL := help
RST2HTML ?= rst2html
DOCS_HTML_DIR ?= output
DOCS_RST := $(sort $(wildcard *.rst))

.PHONY: help clean html-docs

# Render every document with docutils and fail on anything it reports, so a
# Sphinx-only role, a duplicate link target or a mis-parsed table breaks the
# build rather than the rendered page. coding-style.rst is the kernel's text
# verbatim; its restarted enumerated list is an informational note that is not
# ours to fix, so that one file halts at warnings instead.
html-docs:
	$(Q)command -v $(RST2HTML) >/dev/null 2>&1 || { \
	    printf 'shirudo: %s not found; install python3-docutils\n' '$(RST2HTML)' >&2; \
	    exit 1; }
	$(Q)mkdir -p $(DOCS_HTML_DIR)
	$(Q)for f in $(DOCS_RST); do \
	    out=$(DOCS_HTML_DIR)/$$(basename $$f .rst).html; \
	    case $$f in \
	    coding-style.rst) halt=--halt=warning ;; \
	    *) halt=--strict ;; \
	    esac; \
	    printf '  HTML    %s\n' "$$out"; \
	    $(RST2HTML) $$halt --no-generator "$$f" > "$$out" || { \
	        rm -f "$$out"; exit 1; }; \
	done

help:
	@printf '%s\n' 'make -C Documentation html-docs'

clean:
	$(Q)rm -rf "$(DOCS_HTML_DIR)"
