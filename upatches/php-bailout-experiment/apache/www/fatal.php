<?php
// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
echo "PID=" . getmypid() . "\n";
register_shutdown_function(function () { echo "SHUTDOWN_REACHED\n"; });
trigger_error("benign fatal test", E_USER_ERROR);
