#!/usr/bin/env python3
"""Build and run allocation-free codec and simulated-stream benchmarks."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import shlex
import statistics
import subprocess
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
BENCHMARK = ROOT / "benchmark"
RESULTS = BENCHMARK / "codec_results.json"
BASELINE = BENCHMARK / "codec_baseline.json"
PRIMITIVE_CASES = {
    "varint_decode",
    "movement_decode",
    "position_look_decode",
    "attack_decode",
    "nbt_validate",
    "canonical_movement",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compiler_identity(compiler: list[str]) -> str:
    output = subprocess.check_output(
        [*compiler, "--version"], text=True, stderr=subprocess.STDOUT
    )
    return output.splitlines()[0]


def median_cases(samples: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    names = [case["name"] for case in samples[0]]
    result = []
    for index, name in enumerate(names):
        cases = [sample[index] for sample in samples]
        if any(case["name"] != name for case in cases):
            raise AssertionError("benchmark case order changed between repetitions")
        median_ns = statistics.median(
            float(case["ns_per_operation"]) for case in cases
        )
        median_ops = statistics.median(
            float(case["operations_per_second"]) for case in cases
        )
        median_bytes = statistics.median(
            float(case["bytes_per_second"]) for case in cases
        )
        result.append(
            {
                "name": name,
                "median_ns_per_operation": median_ns,
                "median_operations_per_second": median_ops,
                "median_bytes_per_second": median_bytes,
                "allocations_per_operation": max(
                    float(case["allocations_per_operation"]) for case in cases
                ),
                "peak_retained_bytes": max(
                    int(case["peak_retained_bytes"]) for case in cases
                ),
                "samples_ns_per_operation": [
                    float(case["ns_per_operation"]) for case in cases
                ],
            }
        )
    return result


def check_invariants(document: dict[str, Any]) -> None:
    for case in document["cases"]:
        if case["name"] in PRIMITIVE_CASES:
            if case["allocations_per_operation"] != 0.0:
                raise AssertionError(f"hot-path allocation in {case['name']}")
        elif case["allocations_per_operation"] > 0.01:
            raise AssertionError(f"per-packet allocation in {case['name']}")
        if case["peak_retained_bytes"] > 4 * 1024 * 1024:
            raise AssertionError(f"unbounded retained stream storage in {case['name']}")
    if document["peak_resident_bytes"] > 256 * 1024 * 1024:
        raise AssertionError("benchmark process resident memory exceeds 256 MiB")


def check_baseline(document: dict[str, Any]) -> None:
    if not BASELINE.is_file():
        print("performance baseline absent; run make benchmark-baseline")
        return
    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    if baseline.get("environment") != document["environment"]:
        print("performance gate skipped: baseline environment differs")
        return
    expected = {case["name"]: case for case in baseline["cases"]}
    failures = []
    for case in document["cases"]:
        reference = expected.get(case["name"])
        if reference is None:
            failures.append(f"{case['name']}: no baseline")
            continue
        tolerance = 0.05 if case["name"] in PRIMITIVE_CASES else 0.10
        calibrated = reference.get(
            "calibrated_reference_ns_per_operation",
            reference["median_ns_per_operation"],
        )
        maximum = calibrated * (1.0 + tolerance)
        if case["median_ns_per_operation"] > maximum:
            failures.append(
                f"{case['name']}: {case['median_ns_per_operation']:.3f} ns/op "
                f"> {maximum:.3f} ns/op ({tolerance:.0%} gate above the "
                "calibrated noise envelope)"
            )
    if failures:
        raise AssertionError("performance regressions:\n" + "\n".join(failures))
    print("PASS calibrated performance gates")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1_000_000)
    parser.add_argument("--repetitions", type=int, default=9)
    parser.add_argument("--write-baseline", action="store_true")
    parser.add_argument("--no-gate", action="store_true")
    arguments = parser.parse_args()
    if arguments.iterations < 1_000 or arguments.repetitions < 3:
        parser.error("iterations must be >= 1000 and repetitions >= 3")
    compiler = shlex.split(os.environ.get("CC", "cc"))
    if not compiler:
        parser.error("CC resolves to an empty command")
    warnings = [
        "-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wshadow",
        "-Werror", "-Wcast-align", "-Wstrict-prototypes",
        "-Wmissing-prototypes", "-Wformat=2", "-Wundef",
        "-Wdouble-promotion", "-Wnull-dereference",
    ]
    environment = {
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "compiler": compiler_identity(compiler),
    }
    with tempfile.TemporaryDirectory(prefix="mcprotocol-codec-bench-") as directory:
        executable = Path(directory) / "codec_bench"
        api_object = Path(directory) / "api.o"
        subprocess.run(
            [
                *compiler, "-O3", "-DNDEBUG", "-std=c11", *warnings,
                "-include", str(BENCHMARK / "alloc_hooks.h"),
                "-Dmalloc=mc_benchmark_malloc",
                "-Dcalloc=mc_benchmark_calloc",
                "-Drealloc=mc_benchmark_realloc",
                "-Dfree=mc_benchmark_free",
                "-c", str(ROOT / "api.c"), "-o", str(api_object),
            ],
            cwd=ROOT,
            check=True,
        )
        subprocess.run(
            [
                *compiler, "-O3", "-DNDEBUG", "-std=c11", *warnings,
                str(BENCHMARK / "codec_bench.c"), str(api_object),
                "-lz", "-o", str(executable),
            ],
            cwd=ROOT,
            check=True,
        )
        for _ in range(2):
            subprocess.run(
                [str(executable), str(arguments.iterations // 4)],
                cwd=ROOT,
                check=True,
                stdout=subprocess.DEVNULL,
            )
        samples = []
        resident_samples = []
        for _ in range(arguments.repetitions):
            output = subprocess.check_output(
                [str(executable), str(arguments.iterations)], cwd=ROOT, text=True
            )
            sample = json.loads(output)
            samples.append(sample["cases"])
            resident_samples.append(int(sample["peak_resident_bytes"]))
    document = {
        "format_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "environment": environment,
        "method": {
            "iterations": arguments.iterations,
            "repetitions": arguments.repetitions,
            "aggregation": (
                "median ns/op; maximum allocation, retained-buffer and "
                "process resident-memory values"
            ),
            "allocation_instrumentation": (
                "malloc/calloc/realloc calls made directly by api.c"
            ),
            "compiler_flags": ["-O3", "-DNDEBUG", "-std=c11", *warnings],
        },
        "peak_resident_bytes": max(resident_samples),
        "sources": {
            "api.c": digest(ROOT / "api.c"),
            "api.h": digest(ROOT / "api.h"),
            "benchmark/codec_bench.c": digest(BENCHMARK / "codec_bench.c"),
            "benchmark/alloc_hooks.h": digest(BENCHMARK / "alloc_hooks.h"),
            "benchmark/codec_run.py": digest(BENCHMARK / "codec_run.py"),
        },
        "cases": median_cases(samples),
    }
    check_invariants(document)
    RESULTS.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    if arguments.write_baseline:
        baseline = {
            "format_version": 1,
            "environment": environment,
            "calibration": (
                "reference is median plus two median absolute deviations; "
                "the 5%/10% regression gate is applied above that CI-noise envelope"
            ),
            "cases": [],
        }
        for case in document["cases"]:
            median = case["median_ns_per_operation"]
            deviations = [
                abs(sample - median)
                for sample in case["samples_ns_per_operation"]
            ]
            mad = statistics.median(deviations)
            baseline["cases"].append(
                {
                    "name": case["name"],
                    "median_ns_per_operation": median,
                    "median_absolute_deviation": mad,
                    "calibrated_reference_ns_per_operation": median
                    + max(2.0 * mad, median * 0.01),
                }
            )
        BASELINE.write_text(json.dumps(baseline, indent=2) + "\n", encoding="utf-8")
        print(f"updated {BASELINE.relative_to(ROOT)}")
    elif not arguments.no_gate:
        check_baseline(document)
    print(f"PASS pure-codec benchmark ({len(document['cases'])} cases)")


if __name__ == "__main__":
    main()
