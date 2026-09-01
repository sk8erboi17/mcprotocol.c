"""Load compact packet/version matrices as ordinary golden cases."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _protocol_value(row: dict[str, Any], key: str, protocol: int) -> Any:
    mapped = row.get(f"{key}_by_protocol")
    if mapped is not None:
        if not isinstance(mapped, dict) or str(protocol) not in mapped:
            raise ValueError(f"matrix row has no {key} for protocol {protocol}")
        return mapped[str(protocol)]
    if key not in row:
        raise ValueError(f"matrix row has no {key}")
    return row[key]


def load_cases(path: Path) -> list[dict[str, Any]]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if document.get("format_version") != 1:
        raise ValueError("unsupported golden fixture version")
    raw_cases = document.get("cases")
    if not isinstance(raw_cases, list):
        raise ValueError("golden fixture cases must be an array")
    cases = [dict(case) for case in raw_cases]
    matrix = document.get("matrix", [])
    if not isinstance(matrix, list):
        raise ValueError("golden fixture matrix must be an array")
    for row in matrix:
        if not isinstance(row, dict) or not isinstance(row.get("protocols"), list):
            raise ValueError("invalid golden matrix row")
        for raw_protocol in row["protocols"]:
            protocol = int(raw_protocol)
            cases.append({
                "protocol": protocol,
                "state": row.get("state", "play"),
                "direction": row["direction"],
                "packet_id": int(_protocol_value(row, "packet_id", protocol)),
                "packet_name": str(_protocol_value(row, "packet_name", protocol)),
                "family": str(_protocol_value(row, "family", protocol)),
                "raw_hex": str(_protocol_value(row, "raw_hex", protocol)),
                "expected": _protocol_value(row, "expected", protocol),
                "strict": bool(row.get("strict", True)),
                "compat": bool(row.get("compat", True)),
            })
    if not cases:
        raise ValueError("golden fixture has no cases")
    seen: set[tuple[int, str, int, str]] = set()
    for case in cases:
        key = (
            int(case["protocol"]), str(case["direction"]),
            int(case["packet_id"]), str(case["raw_hex"]),
        )
        if key in seen:
            raise ValueError(f"duplicate golden case {key}")
        seen.add(key)
    return cases
