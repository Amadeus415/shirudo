<?php
// SPDX-License-Identifier: BSD-2-Clause
register_shutdown_function(function () {
    echo "SHUTDOWN_REACHED\n";
});
str_repeat("A", 32 * 1024 * 1024);
echo "AFTER_ALLOCATION\n";
