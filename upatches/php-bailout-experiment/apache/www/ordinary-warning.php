<?php
// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
echo "PID=" . getmypid() . "\n";
trigger_error("benign request warning", E_USER_WARNING);
echo "HEALTHY\n";
