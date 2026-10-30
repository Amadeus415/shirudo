#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
set -eu

fixtures=${SHIRUDO_TEST_FIXTURES_DIR:?}/php2shell
if [ ! -f "$fixtures/APACHE-SHA256SUMS" ]; then
    echo 'SKIP: Apache PHP fixtures were not prepared'
    exit 0
fi
bash /mnt/shirudo-src/upatches/php-bailout-experiment/apache/guard-test.sh
if [ -f "${SHIRUDO_TEST_FIXTURES_DIR}/php2shell-8.5.11/APACHE-SHA256SUMS" ]; then
    PHP_DEMO_VERSION=8.5.11 \
        bash /mnt/shirudo-src/upatches/php-bailout-experiment/apache/guard-test.sh
fi
