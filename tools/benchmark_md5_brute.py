#!/usr/bin/env python3
"""Compile, sanity-test, and benchmark gpu/md5_brute.cu."""

from __future__ import annotations

import argparse
import hashlib
import re
import statistics
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "gpu" / "md5_brute.cu"
BIN = ROOT / "bin" / "md5_brute_bench"

HASH_RE = re.compile(
    r"Hashes/sec:\s*([0-9.]+)\s*\((\d+)\s+hashes in\s+([0-9.]+)\s+seconds\)"
)


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=ROOT,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


def compile_binary(nvcc: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    cmd = [nvcc, "-O3", "-arch=native", "-o", str(output), str(SRC)]
    print("$ " + " ".join(cmd))
    try:
        result = run(cmd)
    except subprocess.CalledProcessError as exc:
        print(exc.stdout, end="")
        print(exc.stderr, end="", file=sys.stderr)
        raise SystemExit(exc.returncode) from exc
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)


def md5_hex(text: str) -> str:
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def parse_perf(stdout: str) -> tuple[float, int, float]:
    match = HASH_RE.search(stdout)
    if not match:
        raise ValueError("could not parse Hashes/sec line from md5_brute output")
    return float(match.group(1)), int(match.group(2)), float(match.group(3))


def run_case(binary: Path, name: str, target: str, charset: str, length: int) -> dict[str, float | int | str]:
    start = time.perf_counter()
    result = run([str(binary), target, charset, str(length)])
    wall_s = time.perf_counter() - start
    hashes_per_sec, hashes, cuda_s = parse_perf(result.stdout)
    return {
        "name": name,
        "charset_len": len(charset),
        "length": length,
        "space": len(charset) ** length,
        "hashes": hashes,
        "cuda_s": cuda_s,
        "wall_s": wall_s,
        "hashes_per_sec": hashes_per_sec,
    }


def sanity_test(binary: Path) -> None:
    target = md5_hex("ba")
    result = run([str(binary), target, "ab", "2"])
    if 'FOUND: "ba"' not in result.stdout:
        print(result.stdout, end="")
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit("sanity test failed: expected to find password 'ba'")
    hashes_per_sec, hashes, cuda_s = parse_perf(result.stdout)
    print(
        "Sanity test: FOUND ba "
        f"({hashes} hashes, {cuda_s:.6f}s CUDA, {hashes_per_sec:,.2f} H/s)"
    )


def print_table(rows: list[dict[str, float | int | str]]) -> None:
    headers = [
        "case",
        "charset",
        "len",
        "space",
        "hashes",
        "cuda_s",
        "wall_s",
        "hashes/sec",
    ]
    print()
    print("Benchmark results")
    print("-" * 108)
    print(
        f"{headers[0]:<16} {headers[1]:>7} {headers[2]:>3} {headers[3]:>14} "
        f"{headers[4]:>14} {headers[5]:>10} {headers[6]:>10} {headers[7]:>16}"
    )
    print("-" * 108)
    for row in rows:
        print(
            f"{str(row['name']):<16} "
            f"{int(row['charset_len']):>7} "
            f"{int(row['length']):>3} "
            f"{int(row['space']):>14,} "
            f"{int(row['hashes']):>14,} "
            f"{float(row['cuda_s']):>10.3f} "
            f"{float(row['wall_s']):>10.3f} "
            f"{float(row['hashes_per_sec']):>16,.2f}"
        )
    print("-" * 108)
    rates = [float(row["hashes_per_sec"]) for row in rows]
    print(f"Average throughput: {statistics.mean(rates):,.2f} H/s")
    if len(rates) > 1:
        print(f"Best throughput:    {max(rates):,.2f} H/s")
        print(f"Worst throughput:   {min(rates):,.2f} H/s")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nvcc", default="nvcc", help="nvcc executable to use")
    parser.add_argument("--binary", type=Path, default=BIN, help="output binary path")
    parser.add_argument("--skip-compile", action="store_true", help="reuse the existing binary")
    parser.add_argument("--runs", type=int, default=1, help="repeat each benchmark case")
    args = parser.parse_args()

    binary = args.binary if args.binary.is_absolute() else ROOT / args.binary
    if not args.skip_compile:
        compile_binary(args.nvcc, binary)

    sanity_test(binary)

    cases = [
        ("small_full", md5_hex("zzzzzz"), "abcdefghijklmnopqrstuvwxyz", 6), # intentionally placed at end of search space
        ("medium_full", md5_hex("zzzzzzz"), "abcdefghijklmnopqrstuvwxyz", 7),
        ("hex_full", md5_hex("gggggggg"), "0123456789abcdef", 8),
    ]

    rows: list[dict[str, float | int | str]] = []
    for run_idx in range(args.runs):
        for name, target, charset, length in cases:
            label = name if args.runs == 1 else f"{name}_{run_idx + 1}"
            print(f"Running {label}: charset_len={len(charset)} length={length}")
            rows.append(run_case(binary, label, target, charset, length))

    print_table(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
