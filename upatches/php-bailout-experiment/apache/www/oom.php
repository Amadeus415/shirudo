<?php
// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
echo "PID=" . getmypid() . "\n";
register_shutdown_function(function () { echo "SHUTDOWN_REACHED\n"; });
str_repeat("x", 32 * 1024 * 1024);
