<?php
// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
header('Content-Type: text/plain');
echo 'PID=' . getmypid() . "\n";
$method = $_GET['method'] ?? 'direct';
if ($method === 'direct') {
    $command = ['/usr/bin/printf', 'PROGRAM_STARTED'];
} elseif ($method === 'shell') {
    $command = '/usr/bin/printf PROGRAM_STARTED';
} else {
    http_response_code(400);
    exit("Choose direct or shell.\n");
}
$process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
if (is_resource($process)) {
    $output = stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $status = proc_close($process);
    echo "$method: status=$status output=$output\n";
} else {
    echo "$method: START_FAILED\n";
}
echo "PHP_STILL_RUNNING\n";
