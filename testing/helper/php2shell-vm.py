#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

runtime = os.environ["SHIRUDO_BIN"]
bundle = Path(os.environ["SHIRUDO_TEST_FIXTURES_DIR"]) / "php2shell"
result = Path("/mnt/shirudo-out/php2shell")
result.mkdir(exist_ok=True)
php = Path((bundle / "php.path").read_text().strip())
fixture = Path((bundle / "fixture.path").read_text().strip())
assert php.is_absolute() and fixture.is_absolute()
php.parent.mkdir(parents=True, exist_ok=True)
fixture.parent.mkdir(parents=True, exist_ok=True)
shutil.copy2(bundle / "php", php)
shutil.copy2(bundle / "bailout-target", fixture)
names = ["php-bailout-fixture", "php-bailout-cli"]
loaded = []


def command(label, argv, expected=0):
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=180)
    (result / (label + ".stdout")).write_text(proc.stdout)
    (result / (label + ".stderr")).write_text(proc.stderr)
    if expected is not None and proc.returncode != expected:
        raise RuntimeError(
            f"{label}: rc={proc.returncode}, "
            f"stdout={proc.stdout}, stderr={proc.stderr}"
        )
    return proc


def workload(phase):
    proc = command(
        phase,
        ["python3", "helper/php2shell-experiment.py", "--phase", phase,
         "--php", str(php), "--fixture", str(fixture)],
    )
    print(proc.stdout, end="", flush=True)


command("kernel", ["uname", "-a"])
command("status-before", [runtime, "status", "--json"])
workload("baseline")
note = (
    (4).to_bytes(4, "little") + (20).to_bytes(4, "little")
    + (3).to_bytes(4, "little") + b"GNU\0"
)
binary = bytearray(php.read_bytes())
assert binary.count(note) == 1
binary[binary.index(note) + len(note)] ^= 1
php.write_bytes(binary)
try:
    probe = command(
        "build-mismatch",
        [runtime, "upatch", "load", str(bundle / "php-bailout-cli.upatch"),
         "--report=-"],
        None,
    )
    assert probe.returncode != 0, probe
    assert json.loads(probe.stdout)["category"] == "binary_mismatch", probe
    assert not Path("/run/shirudo/bpffs/upatches/php-bailout-cli/link").exists()
    print("build_mismatch=refused", flush=True)
finally:
    shutil.copy2(bundle / "php", php)
try:
    for name in names:
        command(
            name + "-load",
            [runtime, "upatch", "load", str(bundle / (name + ".upatch")),
             "--report=-"],
        )
        loaded.append(name)
    workload("guarded")
    for name, hits in zip(names, [200, 2]):
        proc = command(name + "-stats", [runtime, "upatch", "get", name, "--json"])
        maps = json.loads(proc.stdout)["upatch"]["maps"]
        stats = next(m for m in maps if m["name"] == "stats")
        value = stats["entries"][0]["value"]
        match = re.fullmatch(r"\{ hits=([^,]+), signal_errors=([^ }]+) \}", value)
        assert match and int(match[1], 0) == hits and int(match[2], 0) == 0, value
        print(name + " " + value, flush=True)
finally:
    for name in reversed(loaded):
        command(
            name + "-unload",
            [runtime, "upatch", "unload",
             str(bundle / (name + ".unload.upatch")), "--report=-"],
        )
workload("detached")
command("status-after", [runtime, "status", "--json"])
print("PHP2SHELL_EXPERIMENT_PASS", flush=True)
