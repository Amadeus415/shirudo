#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

"""Extract the prepared candidates with already installed, pinned tools."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

from prepare import HERE, ROOT, prepare


def capture(*command, cwd=None):
    return subprocess.check_output(command, cwd=cwd, text=True).strip()


def check_checkout(path, revision, local_sources=None):
    if capture("git", "rev-parse", "HEAD", cwd=path) != revision:
        raise ValueError(f"{path}: expected commit {revision}")
    changed = capture("git", "diff", "HEAD", "--name-only", cwd=path).splitlines()
    actual = {name: hashlib.sha256((path / name).read_bytes()).hexdigest()
              for name in changed if (path / name).is_file()}
    if actual != (local_sources or {}):
        raise ValueError(f"{path}: local tool sources differ from the recorded hashes")


def extract(aeneas, output, candidate, sysroot):
    pins = json.loads((HERE / "toolchain.json").read_text())
    charon = aeneas / "charon"
    check_checkout(aeneas, pins["aeneas"], pins.get("local_sources"))
    check_checkout(charon, pins["charon"])
    if (aeneas / "backends/lean/lean-toolchain").read_text().strip() != pins["lean"]:
        raise ValueError("Aeneas Lean toolchain differs from the pilot pin")
    tools = {"aeneas": aeneas / "src/_build/default/main.exe",
             "charon": aeneas.parent / "toolchain/charon-target/release/charon"}
    for name, binary in tools.items():
        if not os.access(binary, os.X_OK):
            raise ValueError(f"missing built {name}: {binary}; install only with approval")
    if not shutil.which("rustup"):
        raise ValueError("rustup is missing; install only with approval")
    installed = capture("rustup", "toolchain", "list")
    if not any(line.split()[0].startswith(pins["rust"] + "-")
               for line in installed.splitlines() if line.split()):
        raise ValueError(f"{pins['rust']} is not installed; install only with approval")
    targets = capture("rustup", "target", "list", "--installed", "--toolchain", pins["rust"])
    if pins["target"] not in targets.splitlines():
        raise ValueError(f"{pins['target']} is not installed for {pins['rust']}")
    version = capture(str(tools["aeneas"]), "-version")
    if pins["aeneas"] not in version and version != pins.get("aeneas_version"):
        raise ValueError(f"Aeneas binary does not report the pinned revision: {version}")
    version = capture(str(tools["charon"]), "version")
    if pins["charon"] not in version:
        raise ValueError(f"Charon binary does not report the pinned revision: {version}")
    if capture(str(tools["charon"]), "toolchain-version") != pins["rust"]:
        raise ValueError("Charon binary's Rust toolchain differs from the pilot pin")
    capture("rustup", "run", pins["rust"], "rustc", "--version")
    if sysroot != "default":
        sysroot = str(Path(sysroot).resolve())
        if not (Path(sysroot) / "lib/rustlib" / pins["target"]).is_dir():
            raise ValueError(f"{sysroot}: missing target libraries")
    scratch = Path("/opt/Data/scratch/shirudo/aeneas")
    scratch.mkdir(parents=True, exist_ok=True)

    prepare(output)
    lean = output / "lean"
    (lean / "lakefile.toml").write_text(
        '# SPDX-License-Identifier: BSD-2-Clause\n'
        '# Copyright (c) 2026 Authors of shirudo\n\n'
        'name = "shirudo-aeneas-pilot"\n'
        'defaultTargets = ["Contracts"]\n\n'
        '[[require]]\nname = "aeneas"\n'
        f'path = {json.dumps(str(aeneas / "backends/lean"))}\n\n'
        '[[lean_lib]]\nname = "Shirudo"\nglobs = ["Shirudo.+"]\n'
        'leanOptions = { warningAsError = true }\n\n'
        '[[lean_lib]]\nname = "PinCodec"\n'
        'leanOptions = { warningAsError = true }\n\n'
        '[[lean_lib]]\nname = "ConfigRefinement"\n'
        'leanOptions = { warningAsError = true }\n\n'
        '[[lean_lib]]\nname = "Contracts"\n'
        'leanOptions = { warningAsError = true }\n\n'
        '[[lean_lib]]\nname = "ConfigPredicates"\n'
        'srcDir = "generated/config_predicates"\nglobs = ["ConfigPredicates.+"]\n'
        'leanOptions = { warningAsError = true }\n\n'
        '[[lean_lib]]\nname = "ArchivePath"\n'
        'srcDir = "generated/archive_path"\nglobs = ["ArchivePath.+"]\n'
        'leanOptions = { warningAsError = true }\n\n'
        '[[lean_lib]]\nname = "PinCodecGenerated"\n'
        'srcDir = "generated/pin_codec"\nglobs = ["PinCodecGenerated.+"]\n'
        'leanOptions = { warningAsError = true }\n\n'
        '[[lean_lib]]\nname = "PinEncodeGenerated"\n'
        'srcDir = "generated/pin_encode"\nglobs = ["PinEncodeGenerated.+"]\n'
        'leanOptions = { warningAsError = true }\n')
    with (lean / "lakefile.toml").open("a") as config:
        for name in ("ArchiveModels", "ArchiveList", "ArchiveSlice",
                     "ArchiveRefinement", "PinDecode"):
            config.write(f'\n[[lean_lib]]\nname = "{name}"\n'
                         'leanOptions = { warningAsError = true }\n')
    backend = aeneas / "backends/lean"
    manifest = json.loads((backend / "lake-manifest.json").read_text())
    for dependency in manifest["packages"]:
        name = dependency["name"]
        installed = backend / ".lake/packages" / name
        if not installed.is_dir():
            raise ValueError(f"missing installed Lean dependency: {installed}")
        dependency.update(type="path", dir=str(installed), copy=False)
        for key in ("url", "subDir", "rev", "inputRev"):
            dependency.pop(key, None)
    manifest["packages"].insert(0, {
        "type": "path", "scope": "", "name": "aeneas",
        "manifestFile": "lake-manifest.json", "inherited": False,
        "dir": str(backend), "copy": False, "configFile": "lakefile.lean",
    })
    manifest["name"] = "shirudo-aeneas-pilot"
    (lean / "lake-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    env = dict(os.environ, CARGO_NET_OFFLINE="true", RUSTUP_TOOLCHAIN=pins["rust"],
               CHARON_TOOLCHAIN_IS_IN_PATH="1", TMPDIR=str(scratch))
    roots = {
        "config_predicates": "crate::subject::same_event,crate::subject::event_follows",
        "archive_path": "crate::subject::archive_rel_ok,crate::subject::package_member_name_ok",
        "pin_codec": "crate::subject::pin_name,crate::subject::name_from_pin",
        "pin_encode": "crate::subject::pin_name",
    }
    for crate in roots if candidate == "all" else [candidate]:
        directory = output / crate
        generated = lean / "generated" / crate
        if generated.exists() and any(generated.iterdir()):
            raise ValueError(f"{generated}: use a fresh --output directory for regeneration")
        generated.mkdir(parents=True, exist_ok=True)
        module = {"config_predicates": "ConfigPredicates", "archive_path": "ArchivePath",
                  "pin_codec": "PinCodecGenerated", "pin_encode": "PinEncodeGenerated"}[crate]
        # An existing translation must not survive a failed regeneration.
        llbc = directory / f"{crate}.llbc"
        llbc.unlink(missing_ok=True)
        commands = [
            ["rustup", "run", pins["rust"], str(tools["charon"]),
             "cargo", "--preset=aeneas", "--sysroot", sysroot,
             "--start-from", roots[crate], "--", "--target", pins["target"]],
            [str(tools["aeneas"]), "-backend", "lean", "-checks", "-strict-joins",
             "-print-error-emitters", "-no-progress-bar", "-sequential", "-split-files",
             "-dest", str(generated), "-subdir", module, str(llbc)],
        ]
        record = {
            "pins": pins, "commands": commands, "status": "started",
            "aeneas_checkout": str(aeneas),
            "sources": json.loads((output / "sources.json").read_text())[crate],
            "subject_sha256": hashlib.sha256((directory / "subject.rs").read_bytes()).hexdigest(),
            "lean_sources": {
                str(path.relative_to(lean)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in [lean / "Contracts.lean", *sorted((lean / "Shirudo").glob("*.lean"))]
            },
            "binaries": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                         for name, path in tools.items()},
        }
        report = directory / "extraction.json"
        report.write_text(json.dumps(record, indent=2) + "\n")
        for command in commands:
            print(" ".join(command), flush=True)
            try:
                subprocess.run(command, cwd=directory, env=env, check=True)
            except subprocess.CalledProcessError as error:
                record["status"] = "failed"
                record["failed_command"] = command
                record["exit_code"] = error.returncode
                report.write_text(json.dumps(record, indent=2) + "\n")
                raise
        if crate == "archive_path":
            (generated / module / "FunsExternal.lean").write_bytes(
                (HERE / "ArchiveModels.lean").read_bytes())
            record["provided_models"] = {
                f"{module}/FunsExternal.lean": "testing/proofs/aeneas/ArchiveModels.lean",
            }
        record["status"] = "extracted; refinement obligations remain unproved"
        record["llbc_sha256"] = hashlib.sha256(llbc.read_bytes()).hexdigest()
        record["generated_lean_sha256"] = {
            str(path.relative_to(lean)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(generated.rglob("*.lean"))
        }
        report.write_text(json.dumps(record, indent=2) + "\n")
    print("Extraction finished. Review external templates; no Lean proofs were run.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aeneas", type=Path, required=True,
                        help="recorded combined Aeneas checkout, with Charon in charon/")
    parser.add_argument("--output", type=Path, default=ROOT / "build/aeneas")
    parser.add_argument("--candidate", choices=("all", "config_predicates", "archive_path",
                                               "pin_codec", "pin_encode"),
                        default="all")
    parser.add_argument("--sysroot", default="default",
                        help="default distributed sysroot, or an already built full-MIR sysroot")
    args = parser.parse_args()
    try:
        extract(args.aeneas.resolve(), args.output.resolve(), args.candidate, args.sysroot)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"{error}\n")
