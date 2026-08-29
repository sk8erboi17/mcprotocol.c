#!/usr/bin/env python3
"""Build, run and plot the public mcprotocol.c comparison benchmark."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
BENCHMARK = ROOT / "benchmark"
PROTOCOL = 47
UPSTREAM_PACKAGE = "minecraft-protocol"
UPSTREAM_VERSION = "1.68.0"

CASES = (
    {
        "id": "sequential_login",
        "mode": "login",
        "label": "Sequential offline login",
        "clients": 32,
        "messages": 1,
        "operation": "completed login sessions",
    },
    {
        "id": "keepalive_stream",
        "mode": "stream",
        "label": "Keepalive stream",
        "clients": 1,
        "messages": 10_000,
        "operation": "validated keepalive echoes",
    },
    {
        "id": "concurrent_keepalive",
        "mode": "concurrent",
        "label": "Concurrent keepalive",
        "clients": 32,
        "messages": 256,
        "operation": "validated keepalive echoes",
    },
)


def command_output(command: list[str]) -> str:
    completed = subprocess.run(
        command, check=True, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return completed.stdout.strip()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    weight = position - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def compile_runners(build: Path, compiler: str) -> tuple[Path, Path, list[str]]:
    warnings = [
        "-Wall", "-Wextra", "-Wpedantic", "-Wconversion", "-Wshadow",
        "-Werror",
    ]
    common = [compiler, "-O3", "-DNDEBUG", "-std=c11", *warnings, "-pthread"]
    server = build / "mock_server"
    c_client = build / "c_client"
    server_command = [*common, str(BENCHMARK / "mock_server.c"), "-o", str(server)]
    client_command = [
        *common, str(BENCHMARK / "c_client.c"), str(ROOT / "api.c"),
        "-lz", "-o", str(c_client),
    ]
    subprocess.run(server_command, check=True)
    subprocess.run(client_command, check=True)
    return server, c_client, client_command


def install_node_dependencies(build: Path) -> Path:
    project = build / "node"
    project.mkdir()
    shutil.copy2(BENCHMARK / "package.json", project / "package.json")
    shutil.copy2(BENCHMARK / "package-lock.json", project / "package-lock.json")
    subprocess.run(
        ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
        cwd=project, check=True,
    )
    return project / "node_modules"


def run_trial(
    implementation: str,
    case: dict[str, Any],
    server_binary: Path,
    c_client: Path,
    node_modules: Path,
) -> dict[str, int]:
    server = subprocess.Popen(
        [
            str(server_binary), case["mode"], str(case["clients"]),
            str(case["messages"]),
        ],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    assert server.stdout is not None
    port_text = server.stdout.readline().strip()
    if not port_text.isdecimal():
        _, server_error = server.communicate(timeout=5)
        raise RuntimeError(f"mock server failed to publish a port: {server_error}")

    if implementation == "c":
        command = [
            str(c_client), case["mode"], "127.0.0.1", port_text,
            str(case["clients"]), str(case["messages"]),
        ]
    else:
        command = [
            "node", str(BENCHMARK / "node_client.js"), str(node_modules),
            case["mode"], "127.0.0.1", port_text, str(case["clients"]),
            str(case["messages"]),
        ]

    try:
        client = subprocess.run(
            command, text=True, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=180,
        )
        _, server_error = server.communicate(timeout=15)
    except BaseException:
        server.kill()
        server.wait()
        raise

    if client.returncode != 0:
        raise RuntimeError(
            f"{implementation} runner failed for {case['id']}: {client.stderr.strip()}"
        )
    if server.returncode != 0:
        raise RuntimeError(
            f"mock server rejected {implementation} for {case['id']}: "
            f"{server_error.strip()}"
        )
    try:
        sample = json.loads(client.stdout.strip().splitlines()[-1])
        elapsed_ns = int(sample["elapsed_ns"])
        operations = int(sample["operations"])
    except (IndexError, KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError(f"invalid {implementation} result: {client.stdout!r}") from error
    expected = case["clients"] if case["mode"] == "login" \
        else case["clients"] * case["messages"]
    if elapsed_ns <= 0 or operations != expected:
        raise RuntimeError(f"invalid operation count from {implementation}: {sample}")
    return {"elapsed_ns": elapsed_ns, "operations": operations}


def summarize(samples: list[dict[str, int]]) -> dict[str, Any]:
    elapsed_ms = [sample["elapsed_ns"] / 1_000_000.0 for sample in samples]
    rates = [
        sample["operations"] * 1_000_000_000.0 / sample["elapsed_ns"]
        for sample in samples
    ]
    return {
        "elapsed_ms": elapsed_ms,
        "operations_per_second": rates,
        "median_elapsed_ms": statistics.median(elapsed_ms),
        "median_operations_per_second": statistics.median(rates),
        "q1_operations_per_second": percentile(rates, 0.25),
        "q3_operations_per_second": percentile(rates, 0.75),
    }


def plot_results(results: dict[str, Any], output: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError as error:
        raise RuntimeError("matplotlib is required to generate results.png") from error

    labels = []
    c_rates = []
    node_rates = []
    c_errors = [[], []]
    node_errors = [[], []]
    speedups = []
    for case in results["cases"]:
        suffix = (f"{case['clients']} sessions" if case["mode"] == "login"
                  else f"{case['clients']} x {case['messages']:,} echoes")
        labels.append(f"{case['label']}\n{suffix}")
        c_summary = case["implementations"]["mcprotocol.c"]
        node_summary = case["implementations"]["node-minecraft-protocol"]
        c_rate = c_summary["median_operations_per_second"]
        node_rate = node_summary["median_operations_per_second"]
        c_rates.append(c_rate)
        node_rates.append(node_rate)
        c_errors[0].append(c_rate - c_summary["q1_operations_per_second"])
        c_errors[1].append(c_summary["q3_operations_per_second"] - c_rate)
        node_errors[0].append(node_rate - node_summary["q1_operations_per_second"])
        node_errors[1].append(node_summary["q3_operations_per_second"] - node_rate)
        speedups.append(case["mcprotocol_c_speedup"])

    positions = list(range(len(labels)))
    width = 0.36
    figure, axis = plt.subplots(figsize=(11, 6.5))
    figure.subplots_adjust(left=0.10, right=0.98, top=0.91, bottom=0.24)
    c_bars = axis.bar(
        [position - width / 2 for position in positions], c_rates, width,
        yerr=c_errors, capsize=5, label="mcprotocol.c", color="#0f766e",
    )
    node_bars = axis.bar(
        [position + width / 2 for position in positions], node_rates, width,
        yerr=node_errors, capsize=5, label=f"{UPSTREAM_PACKAGE} {UPSTREAM_VERSION}",
        color="#f59e0b",
    )
    axis.set_yscale("log")
    axis.set_ylabel("Operations per second (median, log scale; higher is better)")
    axis.set_xticks(positions, labels)
    axis.set_title(f"Minecraft protocol {PROTOCOL} client workloads")
    axis.grid(axis="y", which="both", alpha=0.22)
    axis.legend(loc="upper left")
    for bars, values in ((c_bars, c_rates), (node_bars, node_rates)):
        axis.bar_label(bars, labels=[f"{value:,.0f}" for value in values],
                       padding=5, fontsize=9)
    for position, speedup in zip(positions, speedups):
        axis.text(position, 0.02, f"C: {speedup:.2f}x throughput",
                  ha="center", va="bottom", transform=axis.get_xaxis_transform(),
                  fontsize=9, fontweight="bold")
    environment = results["environment"]
    figure.text(
        0.5, 0.035,
        f"{environment['system']} {environment['machine']} | "
        f"{results['method']['repetitions']} measured runs; bars show IQR",
        fontsize=9, ha="center",
    )
    figure.savefig(output, dpi=180, metadata={"Software": "matplotlib"})
    plt.close(figure)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--warmups", type=int, default=2)
    parser.add_argument("--repetitions", type=int, default=7)
    parser.add_argument("--compiler", default=os.environ.get("CC", "cc"))
    arguments = parser.parse_args()
    if arguments.warmups < 0 or arguments.repetitions < 3:
        parser.error("warmups must be >= 0 and repetitions must be >= 3")

    required = [arguments.compiler, "node", "npm"]
    missing = [program for program in required if shutil.which(program) is None]
    if missing:
        parser.error("missing required tools: " + ", ".join(missing))

    source_paths = (
        ROOT / "api.c", ROOT / "api.h", BENCHMARK / "mock_server.c",
        BENCHMARK / "c_client.c", BENCHMARK / "node_client.js",
        BENCHMARK / "package.json", BENCHMARK / "package-lock.json",
        Path(__file__).resolve(),
    )
    results: dict[str, Any] = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "protocol": PROTOCOL,
        "comparison": {
            "c": "mcprotocol.c working tree",
            "node": f"{UPSTREAM_PACKAGE} {UPSTREAM_VERSION}",
        },
        "method": {
            "warmups": arguments.warmups,
            "repetitions": arguments.repetitions,
            "order": "alternated by case and repetition",
            "timing": (
                "client-internal monotonic time; process and dependency loading "
                "excluded, client creation/login and protocol work included"
            ),
            "validation": (
                "the same loopback mock server validates every login packet and "
                "every keepalive token echoed by both implementations"
            ),
        },
        "environment": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "node": command_output(["node", "--version"]),
            "npm": command_output(["npm", "--version"]),
            "compiler": command_output([arguments.compiler, "--version"]).splitlines()[0],
        },
        "sources": {
            str(path.relative_to(ROOT)): sha256(path) for path in source_paths
        },
        "cases": [],
    }

    with tempfile.TemporaryDirectory(prefix="mcprotocol-benchmark-") as directory:
        build = Path(directory)
        server, c_client, compile_command = compile_runners(build, arguments.compiler)
        results["method"]["c_compile_command"] = [
            str(item).replace(str(build), "$BUILD").replace(str(ROOT), "$ROOT")
            for item in compile_command
        ]
        node_modules = install_node_dependencies(build)

        total = len(CASES) * (arguments.warmups + arguments.repetitions) * 2
        current = 0
        for case_index, definition in enumerate(CASES):
            case = dict(definition)
            measured: dict[str, list[dict[str, int]]] = {"c": [], "node": []}
            warmups: dict[str, list[dict[str, int]]] = {"c": [], "node": []}
            for round_index in range(arguments.warmups + arguments.repetitions):
                order = ["c", "node"] if (case_index + round_index) % 2 == 0 \
                    else ["node", "c"]
                for implementation in order:
                    current += 1
                    phase = "warmup" if round_index < arguments.warmups else "measured"
                    print(
                        f"[{current:02d}/{total}] {case['id']} {implementation} {phase}",
                        flush=True,
                    )
                    sample = run_trial(
                        implementation, case, server, c_client, node_modules,
                    )
                    target = warmups if round_index < arguments.warmups else measured
                    target[implementation].append(sample)

            c_summary = summarize(measured["c"])
            node_summary = summarize(measured["node"])
            case["operations_per_run"] = measured["c"][0]["operations"]
            case["warmup_samples"] = {
                "mcprotocol.c": warmups["c"],
                "node-minecraft-protocol": warmups["node"],
            }
            case["raw_samples"] = {
                "mcprotocol.c": measured["c"],
                "node-minecraft-protocol": measured["node"],
            }
            case["implementations"] = {
                "mcprotocol.c": c_summary,
                "node-minecraft-protocol": node_summary,
            }
            case["mcprotocol_c_speedup"] = (
                c_summary["median_operations_per_second"]
                / node_summary["median_operations_per_second"]
            )
            results["cases"].append(case)

    result_path = BENCHMARK / "results.json"
    plot_path = BENCHMARK / "results.png"
    result_path.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    plot_results(results, plot_path)
    print(f"wrote {result_path.relative_to(ROOT)} and {plot_path.relative_to(ROOT)}")
    for case in results["cases"]:
        print(f"{case['label']}: mcprotocol.c {case['mcprotocol_c_speedup']:.2f}x")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
