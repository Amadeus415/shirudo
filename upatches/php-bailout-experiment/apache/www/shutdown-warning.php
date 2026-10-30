<?php
// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
echo "PID=" . getmypid() . "\n";
register_shutdown_function(function () {
    trigger_error("benign shutdown warning", E_USER_WARNING);
    echo "SHUTDOWN_REACHED\n";
});
echo "NORMAL\n";
