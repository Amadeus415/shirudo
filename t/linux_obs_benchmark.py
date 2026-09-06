#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
# Copyright (c) 2026 Authors of shirudo

"""Run and summarize Linux observability target-VM benchmarks."""

from __future__ import annotations

import argparse
import csv
import math
import os
from pathlib import Path
import re
import shutil
import statistics
import subprocess
import sys
import time


VARIANTS = {"baseline", "empty", "firewall"}
EXEC_HELPER = Path(__file__).resolve().parent / "helper/test-exec-churn"
NETPERF_PORT = "12865"
NETSERVER_CPU = "0"
NETPERF_CPU = "1"


def positive_env(name: str, default: int) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as error:
        raise ValueError(f"{name} must be a positive integer") from error
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def run_command(command: list[str], output: Path, timeout: int) -> str:
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        completed = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            check=True,
            timeout=timeout,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        if isinstance(error, subprocess.CalledProcessError):
            output.write_text(error.stdout or "")
        raise RuntimeError(f"benchmark command failed: {' '.join(command)}") from error
    output.write_text(completed.stdout)
    return completed.stdout


def parse_exec_rate(output: str) -> float:
    match = re.search(r"(?:^|\s)execs_per_sec=([0-9]+(?:\.[0-9]+)?)", output)
    if not match:
        raise ValueError("exec churn helper did not report execs_per_sec")
    return float(match.group(1))


def parse_netperf_rate(output: str) -> float:
    table_rates = []
    scalar_values = []
    for line in output.splitlines():
        fields = line.split()
        if len(fields) >= 6 and all(
                re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", field)
                for field in fields):
            table_rates.append(float(fields[-1]))
            continue
        match = re.fullmatch(r"\s*([0-9]+(?:\.[0-9]+)?)\s*", line)
        if match:
            scalar_values.append(float(match.group(1)))
    if table_rates:
        return table_rates[-1]
    if not scalar_values:
        raise ValueError("netperf did not report a numeric transaction rate")
    return scalar_values[-1]


def append_row(writer: csv.writer, case: str, variant: str, sample: int,
               metric: str, value: float, unit: str) -> None:
    writer.writerow([case, variant, sample, metric, f"{value:.3f}", unit])


def run_exec_case(writer: csv.writer, variant: str, raw_dir: Path,
                  warmup: int, duration: int, samples: int, workers: int) -> None:
    helper = Path(os.environ.get("BENCH_EXEC_HELPER", str(EXEC_HELPER)))
    if not helper.is_file() or not os.access(helper, os.X_OK):
        raise RuntimeError(f"exec churn helper is unavailable: {helper}")
    affinity = f"0-{max(workers - 1, 0)}"
    run_command(
        ["taskset", "-c", affinity, str(helper), "--duration", str(warmup),
         "--workers", str(workers)],
        raw_dir / "exec-warmup.log", warmup + 30,
    )
    for sample in range(1, samples + 1):
        output = run_command(
            ["taskset", "-c", affinity, str(helper), "--duration", str(duration),
             "--workers", str(workers)],
            raw_dir / f"exec-{sample:02d}.log", duration + 30,
        )
        append_row(writer, "exec_churn", variant, sample,
                   "execs_per_sec", parse_exec_rate(output), "exec/s")


def netserver_start(raw_dir: Path) -> tuple[subprocess.Popen[str], object]:
    output = (raw_dir / "netserver.log").open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            ["taskset", "-c", NETSERVER_CPU, "netserver", "-D", "-f",
             "-p", NETPERF_PORT, "-L", "127.0.0.1,inet"],
            stdout=output,
            stderr=subprocess.STDOUT,
            text=True,
        )
    except OSError:
        output.close()
        raise
    time.sleep(1)
    if process.poll() is not None:
        output.close()
        raise RuntimeError("netserver exited before the benchmark started")
    return process, output


def run_tcp_case(writer: csv.writer, variant: str, case: str,
                 raw_dir: Path, warmup: int, duration: int, samples: int) -> None:
    run_command(
        ["taskset", "-c", NETPERF_CPU, "netperf", "-H", "127.0.0.1,inet",
         "-p", NETPERF_PORT, "-t", "TCP_CRR", "-l", str(warmup), "-P", "0",
         "-f", "x", "--", "-r", "1,1"],
        raw_dir / f"{case}-warmup.log", warmup + 30,
    )
    for sample in range(1, samples + 1):
        output = run_command(
            ["taskset", "-c", NETPERF_CPU, "netperf", "-H", "127.0.0.1,inet",
             "-p", NETPERF_PORT, "-t", "TCP_CRR", "-l", str(duration), "-P", "0",
             "-f", "x", "--", "-r", "1,1"],
            raw_dir / f"{case}-{sample:02d}.log", duration + 30,
        )
        append_row(writer, case, variant, sample,
                   "transactions_per_sec", parse_netperf_rate(output), "txn/s")


def run_benchmark(args: argparse.Namespace) -> int:
    if args.variant not in VARIANTS:
        raise ValueError(f"variant must be one of: {', '.join(sorted(VARIANTS))}")
    warmup = positive_env("BENCH_WARMUP_SEC", 5)
    duration = positive_env("BENCH_DURATION_SEC", 10)
    samples = positive_env("BENCH_SAMPLES", 5)
    workers = positive_env("BENCH_EXEC_WORKERS", os.cpu_count() or 1)
    if not shutil.which("netperf") or not shutil.which("netserver"):
        raise RuntimeError("netperf and netserver are required in the benchmark VM")
    if not shutil.which("taskset"):
        raise RuntimeError("taskset is required in the benchmark VM")

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    raw_dir = output.parent / "benchmark-raw"
    raw_dir.mkdir(parents=True, exist_ok=True)
    loaded = args.variant != "baseline"
    if loaded:
        fixture = (Path("/mnt/shirudo-bundle/fixtures/benchmark") /
                   args.variant / "linux-observability.upatch")
        run_command(
            ["/usr/local/bin/shirudo", "upatch", "load", str(fixture),
             "--no-precheck", "--report=-"],
            raw_dir / "upatch-load.log", 120,
        )

    netserver = None
    netserver_log = None
    try:
        with output.open("w", newline="", encoding="utf-8") as result_file:
            writer = csv.writer(result_file)
            writer.writerow(["case", "variant", "sample", "metric", "value", "unit"])
            if args.variant in {"baseline", "empty"}:
                run_exec_case(writer, args.variant, raw_dir, warmup, duration,
                              samples, workers)
            netserver, netserver_log = netserver_start(raw_dir)
            if args.variant == "baseline":
                run_tcp_case(writer, args.variant, "tcp_crr_ipv4_empty", raw_dir,
                             warmup, duration, samples)
                run_tcp_case(writer, args.variant, "tcp_crr_ipv4_firewall", raw_dir,
                             warmup, duration, samples)
            elif args.variant == "empty":
                run_tcp_case(writer, args.variant, "tcp_crr_ipv4_empty", raw_dir,
                             warmup, duration, samples)
            else:
                run_tcp_case(writer, args.variant, "tcp_crr_ipv4_firewall", raw_dir,
                             warmup, duration, samples)
    finally:
        if netserver is not None:
            netserver.terminate()
            try:
                netserver.wait(timeout=5)
            except subprocess.TimeoutExpired:
                netserver.kill()
                netserver.wait()
            netserver_log.close()
    return 0


def read_rows(directory: Path) -> list[dict[str, str]]:
    rows = []
    for path in sorted(directory.glob("*.csv")):
        if path.name == "results.csv":
            continue
        with path.open(newline="", encoding="utf-8") as result_file:
            rows.extend(csv.DictReader(result_file))
    if not rows:
        raise ValueError(f"no benchmark CSV files found in {directory}")
    return rows


def summarize(args: argparse.Namespace) -> int:
    directory = Path(args.directory)
    rows = read_rows(directory)
    combined = directory / "results.csv"
    with combined.open("w", newline="", encoding="utf-8") as result_file:
        writer = csv.writer(result_file)
        writer.writerow(["case", "variant", "sample", "metric", "value", "unit"])
        for row in rows:
            writer.writerow([row[key] for key in
                             ("case", "variant", "sample", "metric", "value", "unit")])

    comparisons = [
        ("exec_churn", "execs_per_sec", "baseline", "empty"),
        ("tcp_crr_ipv4_empty", "transactions_per_sec", "baseline", "empty"),
        ("tcp_crr_ipv4_firewall", "transactions_per_sec", "baseline", "firewall"),
    ]
    lines = ["Linux observability benchmark", "",
             "case,baseline_mean,enabled_mean,delta_pct"]
    for case, metric, baseline, enabled in comparisons:
        def values(which: str) -> list[float]:
            return [float(row["value"]) for row in rows
                    if row["case"] == case and row["metric"] == metric and
                    row["variant"] == which]

        base_values = values(baseline)
        enabled_values = values(enabled)
        if not base_values or not enabled_values:
            raise ValueError(f"missing paired samples for {case}")
        base_mean = statistics.mean(base_values)
        enabled_mean = statistics.mean(enabled_values)
        delta = (enabled_mean - base_mean) * 100 / base_mean if base_mean else math.nan
        lines.append(f"{case},{base_mean:.3f},{enabled_mean:.3f},{delta:.2f}%")
    summary = "\n".join(lines) + "\n"
    (directory / "summary.txt").write_text(summary, encoding="utf-8")
    print(summary, end="")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run")
    run_parser.add_argument("--variant", required=True)
    run_parser.add_argument("--output", required=True)
    summary_parser = subparsers.add_parser("summarize")
    summary_parser.add_argument("--directory", required=True)
    args = parser.parse_args()
    try:
        if args.command == "run":
            return run_benchmark(args)
        return summarize(args)
    except (RuntimeError, ValueError) as error:
        print(f"linux_obs_benchmark.py: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
