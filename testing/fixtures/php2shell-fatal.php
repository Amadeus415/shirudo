<?php
// SPDX-License-Identifier: BSD-2-Clause
register_shutdown_function(function () {
    echo "SHUTDOWN_REACHED\n";
});
trigger_error("benign fatal control", E_USER_ERROR);
