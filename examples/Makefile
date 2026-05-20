# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
#
# examples/Makefile - build reference BPF upatches under examples/.
#
# Driven from the top-level Makefile via `make examples`. The
# top-level provides $(CLANG_BPF), $(VMLINUX_H), and the
# bpf/lib/ include path. Standalone use (`cd examples && make`)
# requires those to be discoverable; the simplest path is to
# always invoke this Makefile from the repository root.

EXAMPLE_SRCS := $(wildcard *.bpf.c)
EXAMPLE_OBJS := $(EXAMPLE_SRCS:.bpf.c=.bpf.o)

# Inherited from the top-level Makefile.shirudo when called from
# there; fall back to defaults if invoked standalone.
CLANG_BPF   ?= clang -target bpf -O2 -g -Wall -Wextra
VMLINUX_H   ?= ../bpf/vmlinux.h
BPF_LIB_DIR ?= ../bpf/lib
# Vendored BPF-side headers, populated by the top-level Makefile.
# Falls back to the third_party submodule if a standalone make is
# invoked here before the parent build has run.
BPF_NEXT    ?= ../bpf/include

CFLAGS_BPF := \
	-I$(dir $(VMLINUX_H)) \
	-I$(BPF_LIB_DIR) \
	-I$(BPF_NEXT) \
	-I.

.PHONY: all clean
all: $(EXAMPLE_OBJS)

%.bpf.o: %.bpf.c $(VMLINUX_H)
	$(CLANG_BPF) $(CFLAGS_BPF) -c $< -o $@

clean:
	rm -f $(EXAMPLE_OBJS)
