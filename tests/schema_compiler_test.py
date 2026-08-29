#!/usr/bin/env python3
"""Focused contracts for schema_compiler.py manifest mode."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "mcprotocol_schema_compiler", ROOT / "tools" / "schema_compiler.py"
)
assert SPEC is not None and SPEC.loader is not None
COMPILER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = COMPILER
SPEC.loader.exec_module(COMPILER)


DOCUMENT = {
    "types": {},
    "play": {
        "toClient": {
            "types": {
                "packet": [
                    "container",
                    [
                        {
                            "name": "name",
                            "type": [
                                "mapper",
                                {
                                    "type": "varint",
                                    "mappings": {
                                        "0x1": "sample",
                                        "0x2": "attributes",
                                    },
                                },
                            ],
                        },
                        {
                            "name": "params",
                            "type": [
                                "switch",
                                {
                                    "compareTo": "name",
                                    "fields": {
                                        "sample": "packet_sample",
                                        "attributes": "packet_attributes",
                                    },
                                },
                            ],
                        },
                    ],
                ],
                "packet_sample": [
                    "container",
                    [
                        {
                            "name": "flags",
                            "type": ["bitflags", {"type": "u8", "flags": []}],
                        },
                        {
                            "name": "kind",
                            "type": [
                                "mapper",
                                {"type": "varint", "mappings": {"0": "zero"}},
                            ],
                        },
                        {"name": "duration", "type": "varint"},
                    ],
                ],
                "packet_attributes": [
                    "container",
                    [
                        {"name": "entityId", "type": "varint"},
                        {
                            "name": "properties",
                            "type": [
                                "array",
                                {
                                    "countType": "varint",
                                    "type": [
                                        "container",
                                        [
                                            {"name": "key", "type": "string"},
                                            {"name": "value", "type": "f64"},
                                            {
                                                "name": "modifiers",
                                                "type": [
                                                    "array",
                                                    {
                                                        "countType": "varint",
                                                        "type": [
                                                            "container",
                                                            [
                                                                {"name": "uuid", "type": "UUID"},
                                                                {"name": "amount", "type": "f64"},
                                                            ],
                                                        ],
                                                    },
                                                ],
                                            },
                                        ],
                                    ],
                                },
                            ],
                        },
                    ],
                ],
            }
        }
    },
}


def main() -> None:
    compiler = COMPILER.Compiler(DOCUMENT, 999, {})
    sample = COMPILER.compile_manifest_packet(
        compiler,
        {
            "state": "play",
            "direction": "toClient",
            "name": "sample",
            "expected_id": 1,
            "field_type_overrides": {
                "duration": {
                    "from": "varint",
                    "to": "varlong",
                    "reason": "synthetic boundary contract",
                }
            },
        },
    )
    assert [field.wire.suffix for field in sample.fields] == [
        "u8",
        "varint",
        "varlong",
    ]

    attributes = COMPILER.compile_manifest_packet(
        compiler,
        {
            "state": "play",
            "direction": "toClient",
            "name": "attributes",
            "expected_id": 2,
            "projection": "single_attribute_no_modifiers",
        },
    )
    assert [field.c_field for field in attributes.fields] == [
        "entity_id",
        "property_count",
        "key",
        "value",
        "modifier_count",
    ]
    assert attributes.fields[1].expected_value == 1
    assert attributes.fields[4].expected_value == 0

    profile = COMPILER.ManifestProfile(
        "test",
        "test",
        999,
        "synthetic",
        999,
        "0" * 64,
        (("movement_speed", 22, "synthetic registry contract"),),
        (sample, attributes),
    )
    header = COMPILER.render_manifest_header(profile, "0" * 40)
    source = COMPILER.render_manifest_source(profile, "0" * 40)
    assert "PERRY_MC_TEST_MOVEMENT_SPEED INT32_C(22)" in header
    assert "mc_reader_varlong(&reader, &decoded.duration)" in source
    assert "decoded.property_count != 1" in source
    assert "decoded.modifier_count != 0" in source

    outputs = {
        "protocol_test.h": header,
        "protocol_test.c": source,
        "schema_stamp.json": "{}\n",
    }
    with tempfile.TemporaryDirectory(prefix="mcprotocol-schema-") as temporary:
        output = Path(temporary)
        COMPILER.write_manifest_outputs(outputs, output, check=False)
        COMPILER.write_manifest_outputs(outputs, output, check=True)
        (output / "protocol_unexpected.c").write_text("stale\n", encoding="utf-8")
        try:
            COMPILER.write_manifest_outputs(outputs, output, check=True)
        except ValueError as error:
            assert "protocol_unexpected.c" in str(error)
        else:
            raise AssertionError("staleness check accepted an unexpected generated file")

    print("PASS schema compiler manifest, overrides, projections and staleness")


if __name__ == "__main__":
    main()
