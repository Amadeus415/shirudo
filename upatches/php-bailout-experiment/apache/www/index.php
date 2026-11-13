<?php
// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2026 Authors of shirudo
$version = htmlspecialchars(PHP_VERSION, ENT_QUOTES, 'UTF-8');
?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Shirudo PHP worker demo</title>
<style>
body { font: 1rem/1.5 system-ui, sans-serif; max-width: 48rem; margin: 3rem auto; padding: 0 1rem; }
li { margin: .75rem 0; }
code { background: #eee; padding: .15rem .3rem; }
</style>
</head>
<body>
<h1>Apache is serving PHP</h1>
<p>PHP <?= $version ?>. This page is a normal request.</p>
<p>These harmless controls show what the signed broad and selective guards stop. The page does not run a PHP2Shell payload.</p>
<ul>
<li><a href="/healthy.php">Healthy request</a>: keeps working in either mode.</li>
<li><a href="/ordinary-warning.php">Ordinary warning</a>: stopped by the broad guard, allowed by the selective guard.</li>
<li>Start a harmless program <a href="/exec.php?method=direct">directly</a> or <a href="/exec.php?method=shell">through a shell</a>: both guards refuse it. The broad guard also stops the worker when PHP reports the failure.</li>
<li><a href="/fatal.php">Application fatal error</a>: both guards drop the connection.</li>
<li><a href="/oom.php">Application memory limit</a>: both guards drop the connection.</li>
<li><a href="/shutdown-warning.php">Warning during shutdown</a>: both guards drop the connection.</li>
</ul>
<p>Check the worker IDs in the request responses and the BPF counters with <code>shirudo-runtime upatch get</code>.</p>
</body>
</html>
