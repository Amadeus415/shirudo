#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
import argparse
import concurrent.futures
import json
from pathlib import Path
import signal
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument("--phase", choices=["baseline", "guarded", "detached"], required=True)
parser.add_argument("--php", required=True)
parser.add_argument("--fixture", required=True)
parser.add_argument(
    "--inputs", type=Path,
    default=Path(__file__).resolve().parent.parent / "fixtures",
)
parser.add_argument("--repetitions", type=int, default=100)
args = parser.parse_args()
if args.repetitions < 1:
    parser.error("--repetitions must be positive")
guarded = args.phase == "guarded"
summary = {"phase": args.phase, "checks": {}}


def invoke(command):
    return subprocess.run(command, capture_output=True, text=True, timeout=10)


def fixture(_):
    result = invoke([args.fixture, "guarded" if guarded else "plain"])
    expected = "signal=9 exit=-1 marker=0\n" if guarded else "signal=0 exit=42 marker=1\n"
    if result.returncode != 0 or result.stdout != expected:
        raise RuntimeError(
            f"fixture failure: {result.returncode}, "
            f"{result.stdout!r}, {result.stderr!r}"
        )


for count in range(args.repetitions):
    fixture(count)
summary["checks"]["serial_marker"] = args.repetitions
with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
    list(pool.map(fixture, range(args.repetitions)))
summary["checks"]["concurrent_marker"] = args.repetitions

for name in ["healthy", "oom", "fatal"]:
    result = invoke(
        [args.php, "-n", "-d", "memory_limit=8M",
         str(args.inputs / f"php2shell-{name}.php")]
    )
    if name == "healthy":
        assert result.returncode == 0 and result.stdout == "HEALTHY\n", result
    elif guarded:
        assert result.returncode == -signal.SIGKILL, result
        assert "SHUTDOWN_REACHED" not in result.stdout, result
        assert "AFTER_ALLOCATION" not in result.stdout, result
    else:
        assert result.returncode == 255, result
        assert "SHUTDOWN_REACHED" in result.stdout, result
        assert "AFTER_ALLOCATION" not in result.stdout, result
    summary["checks"][name] = {
        "returncode": result.returncode,
        "shutdown_marker": "SHUTDOWN_REACHED" in result.stdout,
    }
print(json.dumps(summary, sort_keys=True))
