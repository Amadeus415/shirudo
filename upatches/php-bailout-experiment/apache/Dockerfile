# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
FROM ubuntu:26.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    apache2 apache2-dev build-essential libxml2-dev pkg-config \
    ca-certificates xz-utils && \
    rm -rf /var/lib/apt/lists/*
