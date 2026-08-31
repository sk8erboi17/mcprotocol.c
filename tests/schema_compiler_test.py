#!/usr/bin/env python3
"""Focused contracts for schema_compiler.py manifest mode."""

from __future__ import annotations

import copy
import importlib.util
import subprocess
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


PLAIN_SLOT = [
    "container",
    [
        {"name": "itemCount", "type": "varint"},
        {
            "anon": True,
            "type": [
                "switch",
                {
                    "compareTo": "itemCount",
                    "fields": {"0": "void"},
                    "default": [
                        "container",
                        [
                            {"name": "itemId", "type": "varint"},
                            {"name": "addedComponentCount", "type": "varint"},
                            {"name": "removedComponentCount", "type": "varint"},
                            {
                                "name": "components",
                                "type": [
                                    "array",
                                    {"count": "addedComponentCount", "type": "SlotComponent"},
                                ],
                            },
                            {
                                "name": "removeComponents",
                                "type": [
                                    "array",
                                    {
                                        "count": "removedComponentCount",
                                        "type": "SlotComponentType",
                                    },
                                ],
                            },
                        ],
                    ],
                },
            ],
        },
    ],
]


DOCUMENT = {
    "types": {
        "Slot": PLAIN_SLOT,
        "UntrustedSlot": PLAIN_SLOT,
        "HashedSlot": ["container", []],
        "chunkBlockEntity": ["container", []],
        "entityMetadata": "native",
        "vec3f": [
            "container",
            [
                {"name": "x", "type": "f32"},
                {"name": "y", "type": "f32"},
                {"name": "z", "type": "f32"},
            ],
        ],
        "Particle": [
            "container",
            [
                {
                    "name": "type",
                    "type": [
                        "mapper",
                        {"type": "varint", "mappings": {"58": "note"}},
                    ],
                },
                {
                    "name": "data",
                    "type": [
                        "switch",
                        {
                            "compareTo": "type",
                            "fields": {},
                            "default": "void",
                        },
                    ],
                },
            ],
        ],
    },
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
                                        "0x3": "scoreboard_objective",
                                        "0x4": "scoreboard_display_objective",
                                        "0x5": "scoreboard_score",
                                        "0x6": "reset_score",
                                        "0x7": "set_creative_slot",
                                        "0x8": "set_cursor_item",
                                        "0x9": "window_items",
                                        "0xa": "window_click",
                                        "0xb": "map_chunk",
                                        "0xc": "modern_chunk",
                                        "0xd": "tile_entity_data",
                                        "0xe": "move_minecart",
                                        "0xf": "entity_metadata",
                                        "0x10": "world_particles",
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
                                        "scoreboard_objective": "packet_scoreboard_objective",
                                        "scoreboard_display_objective": "packet_scoreboard_display_objective",
                                        "scoreboard_score": "packet_scoreboard_score",
                                        "reset_score": "packet_reset_score",
                                        "set_creative_slot": "packet_set_creative_slot",
                                        "set_cursor_item": "packet_set_cursor_item",
                                        "window_items": "packet_window_items",
                                        "window_click": "packet_window_click",
                                        "map_chunk": "packet_map_chunk",
                                        "modern_chunk": "packet_modern_chunk",
                                        "tile_entity_data": "packet_tile_entity_data",
                                        "move_minecart": "packet_move_minecart",
                                        "entity_metadata": "packet_entity_metadata",
                                        "world_particles": "packet_world_particles",
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
                        {
                            "name": "legacyBlob",
                            "type": ["buffer", {"countType": "i32"}],
                        },
                        {
                            "name": "modernBlob",
                            "type": ["buffer", {"countType": "varint"}],
                        },
                    ],
                ],
                "packet_tile_entity_data": [
                    "container",
                    [
                        {"name": "location", "type": "position"},
                        {"name": "action", "type": "varint"},
                        {"name": "nbtData", "type": "anonOptionalNbt"},
                    ],
                ],
                "packet_move_minecart": [
                    "container",
                    [
                        {"name": "entityId", "type": "varint"},
                        {
                            "name": "steps",
                            "type": [
                                "array",
                                {
                                    "countType": "varint",
                                    "type": [
                                        "container",
                                        [
                                            {"name": "position", "type": "vec3f"},
                                            {"name": "movement", "type": "vec3f"},
                                            {"name": "yaw", "type": "f32"},
                                            {"name": "pitch", "type": "f32"},
                                            {"name": "weight", "type": "f32"},
                                        ],
                                    ],
                                },
                            ],
                        },
                    ],
                ],
                "packet_entity_metadata": [
                    "container",
                    [
                        {"name": "entityId", "type": "varint"},
                        {"name": "metadata", "type": "entityMetadata"},
                    ],
                ],
                "packet_world_particles": [
                    "container",
                    [
                        {"name": "longDistance", "type": "bool"},
                        {"name": "alwaysShow", "type": "bool"},
                        {"name": "x", "type": "f64"},
                        {"name": "y", "type": "f64"},
                        {"name": "z", "type": "f64"},
                        {"name": "offsetX", "type": "f32"},
                        {"name": "offsetY", "type": "f32"},
                        {"name": "offsetZ", "type": "f32"},
                        {"name": "velocityOffset", "type": "f32"},
                        {"name": "amount", "type": "i32"},
                        {"name": "particle", "type": "Particle"},
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
                "packet_scoreboard_objective": [
                    "container",
                    [
                        {"name": "name", "type": "string"},
                        {"name": "action", "type": "i8"},
                        {
                            "name": "displayText",
                            "type": [
                                "switch",
                                {
                                    "compareTo": "action",
                                    "fields": {"0": "anonymousNbt", "2": "anonymousNbt"},
                                    "default": "void",
                                },
                            ],
                        },
                        {
                            "name": "type",
                            "type": [
                                "switch",
                                {
                                    "compareTo": "action",
                                    "fields": {"0": "varint", "2": "varint"},
                                    "default": "void",
                                },
                            ],
                        },
                        {
                            "name": "number_format",
                            "type": [
                                "switch",
                                {
                                    "compareTo": "action",
                                    "fields": {
                                        "0": ["option", "varint"],
                                        "2": ["option", "varint"],
                                    },
                                    "default": "void",
                                },
                            ],
                        },
                        {
                            "name": "styling",
                            "type": [
                                "switch",
                                {
                                    "compareTo": "action",
                                    "fields": {
                                        "0": [
                                            "switch",
                                            {
                                                "compareTo": "number_format",
                                                "fields": {
                                                    "1": "anonymousNbt",
                                                    "2": "anonymousNbt",
                                                },
                                                "default": "void",
                                            },
                                        ],
                                        "2": [
                                            "switch",
                                            {
                                                "compareTo": "number_format",
                                                "fields": {
                                                    "1": "anonymousNbt",
                                                    "2": "anonymousNbt",
                                                },
                                                "default": "void",
                                            },
                                        ],
                                    },
                                    "default": "void",
                                },
                            ],
                        },
                    ],
                ],
                "packet_scoreboard_display_objective": [
                    "container",
                    [
                        {"name": "position", "type": "varint"},
                        {"name": "name", "type": "string"},
                    ],
                ],
                "packet_scoreboard_score": [
                    "container",
                    [
                        {"name": "itemName", "type": "string"},
                        {"name": "scoreName", "type": "string"},
                        {"name": "value", "type": "varint"},
                        {"name": "display_name", "type": ["option", "anonymousNbt"]},
                        {"name": "number_format", "type": ["option", "varint"]},
                        {
                            "name": "styling",
                            "type": [
                                "switch",
                                {
                                    "compareTo": "number_format",
                                    "fields": {
                                        "1": "anonymousNbt",
                                        "2": "anonymousNbt",
                                    },
                                    "default": "void",
                                },
                            ],
                        },
                    ],
                ],
                "packet_reset_score": [
                    "container",
                    [
                        {"name": "entity_name", "type": "string"},
                        {"name": "objective_name", "type": ["option", "string"]},
                    ],
                ],
                "packet_set_creative_slot": [
                    "container",
                    [
                        {"name": "slot", "type": "i16"},
                        {"name": "item", "type": "UntrustedSlot"},
                    ],
                ],
                "packet_set_cursor_item": [
                    "container",
                    [{"name": "contents", "type": "Slot"}],
                ],
                "packet_window_items": [
                    "container",
                    [
                        {"name": "windowId", "type": "varint"},
                        {"name": "stateId", "type": "varint"},
                        {
                            "name": "items",
                            "type": [
                                "array",
                                {"countType": "varint", "type": "Slot"},
                            ],
                        },
                        {"name": "carriedItem", "type": "Slot"},
                    ],
                ],
                "packet_window_click": [
                    "container",
                    [
                        {"name": "windowId", "type": "varint"},
                        {"name": "stateId", "type": "varint"},
                        {"name": "slot", "type": "i16"},
                        {"name": "mouseButton", "type": "i8"},
                        {"name": "mode", "type": "varint"},
                        {
                            "name": "changedSlots",
                            "type": [
                                "array",
                                {"countType": "varint", "type": "HashedSlot"},
                            ],
                        },
                        {"name": "cursorItem", "type": ["option", "HashedSlot"]},
                    ],
                ],
                "packet_map_chunk": [
                    "container",
                    [
                        {"name": "x", "type": "i32"},
                        {"name": "z", "type": "i32"},
                        {
                            "name": "bitMap",
                            "type": [
                                "array",
                                {"countType": "varint", "type": "i64"},
                            ],
                        },
                        {"name": "heightmaps", "type": "nbt"},
                        {
                            "name": "biomes",
                            "type": [
                                "array",
                                {"countType": "varint", "type": "varint"},
                            ],
                        },
                        {
                            "name": "chunkData",
                            "type": ["buffer", {"countType": "varint"}],
                        },
                        {
                            "name": "blockEntities",
                            "type": [
                                "array",
                                {"countType": "varint", "type": "nbt"},
                            ],
                        },
                    ],
                ],
                "packet_modern_chunk": [
                    "container",
                    [
                        {"name": "x", "type": "i32"},
                        {"name": "z", "type": "i32"},
                        {
                            "name": "heightmaps",
                            "type": [
                                "array",
                                {
                                    "countType": "varint",
                                    "type": [
                                        "container",
                                        [
                                            {"name": "type", "type": "varint"},
                                            {
                                                "name": "data",
                                                "type": [
                                                    "array",
                                                    {"countType": "varint", "type": "i64"},
                                                ],
                                            },
                                        ],
                                    ],
                                },
                            ],
                        },
                        {
                            "name": "chunkData",
                            "type": ["buffer", {"countType": "varint"}],
                        },
                        {
                            "name": "blockEntities",
                            "type": [
                                "array",
                                {"countType": "varint", "type": "chunkBlockEntity"},
                            ],
                        },
                        *[
                            {
                                "name": name,
                                "type": [
                                    "array",
                                    {"countType": "varint", "type": "i64"},
                                ],
                            }
                            for name in (
                                "skyLightMask",
                                "blockLightMask",
                                "emptySkyLightMask",
                                "emptyBlockLightMask",
                            )
                        ],
                        *[
                            {
                                "name": name,
                                "type": [
                                    "array",
                                    {
                                        "countType": "varint",
                                        "type": [
                                            "array",
                                            {"countType": "varint", "type": "u8"},
                                        ],
                                    },
                                ],
                            }
                            for name in ("skyLight", "blockLight")
                        ],
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
        "buffer_i32",
        "buffer_varint",
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

    scoreboard_packets = []
    for name, packet_id, projection in (
        ("scoreboard_objective", 3, "scoreboard_objective"),
        ("scoreboard_display_objective", 4, None),
        ("scoreboard_score", 5, "scoreboard_score"),
        ("reset_score", 6, "scoreboard_reset"),
    ):
        packet_spec = {
            "state": "play",
            "direction": "toClient",
            "name": name,
            "expected_id": packet_id,
        }
        if projection is not None:
            packet_spec["projection"] = projection
        scoreboard_packets.append(
            COMPILER.compile_manifest_packet(compiler, packet_spec)
        )
    objective, display, score, reset = scoreboard_packets
    assert objective.projection == "scoreboard_objective:modern"
    assert [field.wire.suffix for field in objective.fields] == [
        "string", "i8", "nbt", "varint", "bool", "varint", "nbt"
    ]
    assert display.projection is None
    assert score.projection == "scoreboard_score:modern"
    assert reset.projection == "scoreboard_reset"

    inventory_packets = []
    for name, packet_id, projection in (
        ("set_creative_slot", 7, "plain_item_slot"),
        ("set_cursor_item", 8, "plain_item_contents"),
        ("window_items", 9, "plain_window_items"),
        ("window_click", 10, "empty_window_click"),
    ):
        inventory_packets.append(
            COMPILER.compile_manifest_packet(
                compiler,
                {
                    "state": "play",
                    "direction": "toClient",
                    "name": name,
                    "expected_id": packet_id,
                    "projection": projection,
                },
            )
        )
    creative, cursor, window_items, window_click = inventory_packets
    assert creative.projection == "inventory:plain_item_slot"
    assert cursor.projection == "inventory:plain_item_contents"
    assert window_items.projection == "inventory:plain_window_items"
    assert window_click.projection == "inventory:empty_window_click"

    chunk = COMPILER.compile_manifest_packet(
        compiler,
        {
            "state": "play",
            "direction": "toClient",
            "name": "map_chunk",
            "expected_id": 11,
            "projection": "chunk_envelope",
        },
    )
    assert chunk.projection == "chunk:1_17"

    modern_chunk = COMPILER.compile_manifest_packet(
        compiler,
        {
            "state": "play",
            "direction": "toClient",
            "name": "modern_chunk",
            "expected_id": 12,
            "projection": "chunk_envelope",
        },
    )
    assert modern_chunk.projection == "chunk:modern:registry"

    tile_entity = COMPILER.compile_manifest_packet(
        compiler,
        {
            "state": "play",
            "direction": "toClient",
            "name": "tile_entity_data",
            "expected_id": 13,
        },
    )
    assert [field.wire.suffix for field in tile_entity.fields] == [
        "position", "varint", "nbt"
    ]

    minecart = COMPILER.compile_manifest_packet(
        compiler,
        {
            "state": "play",
            "direction": "toClient",
            "name": "move_minecart",
            "expected_id": 14,
            "projection": "source_validated_minecart_steps",
            "source_validation": (
                "Vanilla MinecartStep STREAM_CODEC uses Vec3 doubles and rotation bytes"
            ),
        },
    )
    assert minecart.projection == "minecart_steps:movement"
    assert [field.wire.suffix for field in minecart.fields] == ["varint", "varint"]
    try:
        COMPILER.compile_manifest_packet(
            compiler,
            {
                "state": "play",
                "direction": "toClient",
                "name": "move_minecart",
                "expected_id": 14,
                "projection": "source_validated_minecart_steps",
            },
        )
    except ValueError as error:
        assert "requires source_validation" in str(error)
    else:
        raise AssertionError("minecart projection accepted no source validation")

    minecart_metadata = COMPILER.compile_manifest_packet(
        compiler,
        {
            "state": "play",
            "direction": "toClient",
            "name": "entity_metadata",
            "expected_id": 15,
            "projection": "source_validated_minecart_metadata",
            "metadata_layout": "optional_block_state",
            "metadata_first_index": 8,
            "source_validation": (
                "Vanilla minecart accessors and EntityDataSerializers wire IDs"
            ),
        },
    )
    assert minecart_metadata.projection == "minecart_metadata:optional_block_state:8:varint"
    assert [field.wire.suffix for field in minecart_metadata.fields] == ["varint"]
    legacy_minecart_metadata = COMPILER.compile_manifest_packet(
        COMPILER.Compiler(DOCUMENT, 769, {}),
        {
            "state": "play",
            "direction": "toClient",
            "name": "entity_metadata",
            "expected_id": 15,
            "projection": "source_validated_minecart_metadata",
            "metadata_layout": "block_state_and_flag",
            "metadata_first_index": 8,
            "source_validation": "Vanilla 1.21.4 minecart accessor layout",
        },
    )
    assert legacy_minecart_metadata.projection == (
        "minecart_metadata:block_state_and_flag:8:varint"
    )
    packed_document = copy.deepcopy(DOCUMENT)
    packed_document["play"]["toClient"]["types"]["packet_entity_metadata"][1][0][
        "type"
    ] = "i32"
    packed_minecart_metadata = COMPILER.compile_manifest_packet(
        COMPILER.Compiler(packed_document, 4, {}),
        {
            "state": "play",
            "direction": "toClient",
            "name": "entity_metadata",
            "expected_id": 15,
            "projection": "source_validated_minecart_metadata",
            "metadata_layout": "packed_block_state_and_flag",
            "metadata_first_index": 17,
            "source_validation": "Vanilla 1.8 packed DataWatcher layout",
        },
    )
    assert packed_minecart_metadata.projection == (
        "minecart_metadata:packed_block_state_and_flag:17:i32"
    )
    for incomplete in (
        {"metadata_layout": "optional_block_state", "metadata_first_index": 8},
        {"source_validation": "source checked", "metadata_first_index": 8},
        {
            "metadata_layout": "optional_block_state",
            "source_validation": "source checked",
        },
    ):
        try:
            COMPILER.compile_manifest_packet(
                compiler,
                {
                    "state": "play",
                    "direction": "toClient",
                    "name": "entity_metadata",
                    "expected_id": 15,
                    "projection": "source_validated_minecart_metadata",
                    **incomplete,
                },
            )
        except ValueError as error:
            assert "requires" in str(error)
        else:
            raise AssertionError("minecart metadata accepted an incomplete source contract")

    primed_tnt_metadata = COMPILER.compile_manifest_packet(
        compiler,
        {
            "state": "play",
            "direction": "toClient",
            "name": "entity_metadata",
            "expected_id": 15,
            "projection": "source_validated_primed_tnt_metadata",
            "metadata_layout": "fuse_and_block_state",
            "source_validation": (
                "Vanilla PrimedTnt accessors and EntityDataSerializers wire IDs"
            ),
        },
    )
    assert primed_tnt_metadata.projection == (
        "primed_tnt_metadata:fuse_and_block_state:8"
    )
    legacy_primed_tnt_metadata = COMPILER.compile_manifest_packet(
        COMPILER.Compiler(DOCUMENT, 340, {}),
        {
            "state": "play",
            "direction": "toClient",
            "name": "entity_metadata",
            "expected_id": 15,
            "projection": "source_validated_primed_tnt_metadata",
            "metadata_layout": "fuse",
            "source_validation": "Vanilla 1.12.2 PrimedTnt accessor layout",
        },
    )
    assert legacy_primed_tnt_metadata.projection == "primed_tnt_metadata:fuse:6"
    for incomplete in (
        {"metadata_layout": "fuse_and_block_state"},
        {"source_validation": "source checked"},
    ):
        try:
            COMPILER.compile_manifest_packet(
                compiler,
                {
                    "state": "play",
                    "direction": "toClient",
                    "name": "entity_metadata",
                    "expected_id": 15,
                    "projection": "source_validated_primed_tnt_metadata",
                    **incomplete,
                },
            )
        except ValueError as error:
            assert "requires" in str(error)
        else:
            raise AssertionError("primed TNT metadata accepted an incomplete source contract")

    note_particle_spec = {
        "state": "play",
        "direction": "toClient",
        "name": "world_particles",
        "expected_id": 16,
        "projection": "source_validated_note_particle",
        "particle_name": "note",
        "particle_id": 58,
        "source_validation": "synthetic release source pins NOTE as data-free ID 58",
    }
    note_particle = COMPILER.compile_manifest_packet(compiler, note_particle_spec)
    assert note_particle.projection == "note_particle:tail_varint_double_always:58"
    assert [field.wire.suffix for field in note_particle.fields] == [
        "bool", "bool", "double", "double", "double", "float", "float",
        "float", "float", "i32",
    ]
    try:
        COMPILER.compile_manifest_packet(
            compiler,
            {**note_particle_spec, "particle_id": 65},
        )
    except ValueError as error:
        assert "registry_override_reason" in str(error)
    else:
        raise AssertionError("NOTE registry drift accepted without a source reason")
    note_particle_registry_override = COMPILER.compile_manifest_packet(
        compiler,
        {
            **note_particle_spec,
            "particle_id": 65,
            "registry_override_reason": "26.2 adds registry entries before NOTE",
        },
    )
    assert note_particle_registry_override.projection == (
        "note_particle:tail_varint_double_always:65"
    )

    tail_document = copy.deepcopy(DOCUMENT)
    del tail_document["play"]["toClient"]["types"]["packet_world_particles"][1][1]
    tail_note_particle = COMPILER.compile_manifest_packet(
        COMPILER.Compiler(tail_document, 766, {}), note_particle_spec
    )
    assert tail_note_particle.projection == "note_particle:tail_varint_double:58"

    named_document = copy.deepcopy(DOCUMENT)
    named_document["play"]["toClient"]["types"]["packet_world_particles"] = [
        "container",
        [
            {"name": "particleName", "type": "string"},
            {"name": "x", "type": "f32"},
            {"name": "y", "type": "f32"},
            {"name": "z", "type": "f32"},
            {"name": "offsetX", "type": "f32"},
            {"name": "offsetY", "type": "f32"},
            {"name": "offsetZ", "type": "f32"},
            {"name": "particleData", "type": "f32"},
            {"name": "particles", "type": "i32"},
        ],
    ]
    named_note_particle = COMPILER.compile_manifest_packet(
        COMPILER.Compiler(named_document, 4, {}),
        {key: value for key, value in note_particle_spec.items() if key != "particle_id"},
    )
    assert named_note_particle.projection == "note_particle:name_f32"

    head_document = copy.deepcopy(DOCUMENT)
    head_document["play"]["toClient"]["types"]["packet_world_particles"] = [
        "container",
        [
            {"name": "particleId", "type": "i32"},
            {"name": "longDistance", "type": "bool"},
            {"name": "x", "type": "f32"},
            {"name": "y", "type": "f32"},
            {"name": "z", "type": "f32"},
            {"name": "offsetX", "type": "f32"},
            {"name": "offsetY", "type": "f32"},
            {"name": "offsetZ", "type": "f32"},
            {"name": "particleData", "type": "f32"},
            {"name": "particles", "type": "i32"},
            {
                "name": "data",
                "type": [
                    "switch",
                    {
                        "compareTo": "particleId",
                        "fields": {"36": "varint"},
                        "default": "void",
                    },
                ],
            },
        ],
    ]
    head_note_particle = COMPILER.compile_manifest_packet(
        COMPILER.Compiler(head_document, 47, {}),
        {**note_particle_spec, "particle_id": 23},
    )
    assert head_note_particle.projection == "note_particle:head_i32_float:23"

    head_varint_document = copy.deepcopy(head_document)
    head_fields = head_varint_document["play"]["toClient"]["types"][
        "packet_world_particles"
    ][1]
    head_fields[0]["type"] = "varint"
    for field in head_fields[2:5]:
        field["type"] = "f64"
    head_varint_note_particle = COMPILER.compile_manifest_packet(
        COMPILER.Compiler(head_varint_document, 759, {}),
        {**note_particle_spec, "particle_id": 46},
    )
    assert head_varint_note_particle.projection == (
        "note_particle:head_varint_double:46"
    )

    try:
        COMPILER.compile_manifest_packet(
            compiler,
            {key: value for key, value in note_particle_spec.items()
             if key != "source_validation"},
        )
    except ValueError as error:
        assert "requires source_validation" in str(error)
    else:
        raise AssertionError("NOTE particle projection accepted no source validation")

    profile = COMPILER.ManifestProfile(
        "test",
        "test",
        999,
        "synthetic",
        999,
        "0" * 64,
        (("movement_speed", 22, "synthetic registry contract"),),
        (
            sample,
            attributes,
            *scoreboard_packets,
            *inventory_packets,
            chunk,
            modern_chunk,
            tile_entity,
            minecart,
            minecart_metadata,
            note_particle,
        ),
    )
    header = COMPILER.render_manifest_header(profile, "0" * 40)
    source = COMPILER.render_manifest_source(profile, "0" * 40)
    primed_tnt_profile = COMPILER.ManifestProfile(
        "primed_tnt_test",
        "primed_tnt_test",
        999,
        "synthetic",
        999,
        "0" * 64,
        (),
        (primed_tnt_metadata,),
    )
    primed_tnt_header = COMPILER.render_manifest_header(
        primed_tnt_profile, "0" * 40
    )
    primed_tnt_source = COMPILER.render_manifest_source(
        primed_tnt_profile, "0" * 40
    )
    legacy_minecart_profile = COMPILER.ManifestProfile(
        "legacy_minecart_test",
        "legacy_minecart_test",
        769,
        "synthetic",
        769,
        "0" * 64,
        (),
        (legacy_minecart_metadata,),
    )
    legacy_minecart_source = COMPILER.render_manifest_source(
        legacy_minecart_profile, "0" * 40
    )
    legacy_minecart_header = COMPILER.render_manifest_header(
        legacy_minecart_profile, "0" * 40
    )
    packed_minecart_profile = COMPILER.ManifestProfile(
        "packed_minecart_test",
        "packed_minecart_test",
        4,
        "synthetic",
        4,
        "0" * 64,
        (),
        (packed_minecart_metadata,),
    )
    packed_minecart_source = COMPILER.render_manifest_source(
        packed_minecart_profile, "0" * 40
    )
    packed_minecart_header = COMPILER.render_manifest_header(
        packed_minecart_profile, "0" * 40
    )
    note_profiles = (
        COMPILER.ManifestProfile(
            "named_note_test", "named_note_test", 4, "synthetic", 4,
            "0" * 64, (), (named_note_particle,),
        ),
        COMPILER.ManifestProfile(
            "head_note_test", "head_note_test", 47, "synthetic", 47,
            "0" * 64, (), (head_note_particle,),
        ),
        COMPILER.ManifestProfile(
            "head_varint_note_test", "head_varint_note_test", 759,
            "synthetic", 759, "0" * 64, (), (head_varint_note_particle,),
        ),
        COMPILER.ManifestProfile(
            "tail_note_test", "tail_note_test", 766, "synthetic", 766,
            "0" * 64, (), (tail_note_particle,),
        ),
        COMPILER.ManifestProfile(
            "override_note_test", "override_note_test", 776, "synthetic", 775,
            "0" * 64, (), (note_particle_registry_override,),
        ),
    )
    note_outputs = {}
    for note_profile in note_profiles:
        note_outputs[f"protocol_{note_profile.c_profile}.h"] = (
            COMPILER.render_manifest_header(note_profile, "0" * 40)
        )
        note_outputs[f"protocol_{note_profile.c_profile}.c"] = (
            COMPILER.render_manifest_source(note_profile, "0" * 40)
        )
    assert "PERRY_MC_TEST_MOVEMENT_SPEED INT32_C(22)" in header
    assert "mc_reader_varlong(&reader, &decoded.duration)" in source
    assert "mc_reader_buffer_i32(&reader, &decoded.legacy_blob)" in source
    assert "mc_packet_buffer_varint(packet, &value->modern_blob)" in source
    assert "decoded.property_count != 1" in source
    assert "decoded.modifier_count != 0" in source
    assert "mc_reader_nbt(&reader, false, &decoded.display_text)" in source
    assert "mc_packet_nbt(packet, false, &value->display_text)" in source
    assert "decoded.number_format_present" in source
    assert "decoded.display_name_present" in source
    assert "decoded.objective_name_present" in source
    assert "int32_t item_ids[128]" in header
    assert "FIELD_FUSE (UINT32_C(1) << 0U)" in primed_tnt_header
    assert "FIELD_BLOCK_STATE (UINT32_C(1) << 1U)" in primed_tnt_header
    assert "index == UINT8_C(8)" in primed_tnt_source
    assert "index == UINT8_C(9)" in primed_tnt_source
    assert "!mc_packet_varint(packet, 14)" in primed_tnt_source
    assert "mc_reader_plain_item(&reader, 999" in source
    assert "mc_packet_plain_item(packet, 999" in source
    assert "changed_slot_count != 0" in source
    assert "mc_packet_varint(packet, 0) && mc_packet_bool(packet, false)" in source
    assert "uint64_t section_mask" in header
    assert "int32_t biomes[1024]" in header
    assert "mc_reader_nbt(&reader, true, &decoded.heightmaps)" in source
    assert "mask_word_count > 1" in source
    assert "mc_packet_buffer_varint(packet, &value->chunk_data)" in source
    assert "decoded.auxiliary_data" in source
    assert "modern_chunk_heightmaps" in source
    assert "heightmap_count > 16" in source
    assert "byte_count > 2048" in source
    assert "PerryMcTestTileEntityData" in header
    assert "mc_reader_nbt(&reader, false, &decoded.nbt_data)" in source
    assert "mc_packet_nbt(packet, false, &value->nbt_data)" in source
    assert "double position_x" in header
    assert "double movement_z" in header
    assert "int8_t yaw" in header
    assert "steps[65]" in header
    assert "mc_reader_double(&reader, &decoded.steps[index].position_x)" in source
    assert "mc_reader_i8(&reader, &decoded.steps[index].yaw)" in source
    assert "mc_packet_double(packet, value->steps[index].movement_z)" in source
    assert "mc_packet_i8(packet, value->steps[index].pitch)" in source
    assert "PERRY_MC_TEST_ENTITY_METADATA_FIELD_CUSTOM_DISPLAY_BLOCK" in header
    assert "bool has_custom_display_block" in header
    assert "serializer != 15" in source
    assert "case 11U:\n            if (serializer != 1 || saw_display_state" in legacy_minecart_source
    assert (
        "mc_packet_u8(packet, UINT8_C(11)) || !mc_packet_varint(packet, 1)"
        in legacy_minecart_source
    )
    assert "serializer != 14 || saw_display_state" not in legacy_minecart_source
    assert "header == UINT8_C(0x7f)" in packed_minecart_source
    assert "mc_packet_u8(packet, UINT8_C(0x51))" in packed_minecart_source
    assert "mc_reader_i32(&reader, &decoded.entity_id)" in packed_minecart_source
    assert "mc_packet_i32(packet, value->entity_id)" in packed_minecart_source
    assert "mc_packet_i32(packet, value->hurt_time)" in packed_minecart_source
    assert "mc_packet_u8(packet, UINT8_C(11))" in source
    assert "mc_packet_u8(packet, UINT8_C(0xff))" in source
    assert "particle_id != INT32_C(58)" in source
    assert "mc_packet_varint(packet, INT32_C(58))" in source
    assert 'memcmp(particle_name.data, "note", 4U)' in note_outputs[
        "protocol_named_note_test.c"
    ]
    assert 'mc_packet_string_n(packet, "note", 4U)' in note_outputs[
        "protocol_named_note_test.c"
    ]
    assert "mc_packet_i32(packet, INT32_C(23))" in note_outputs[
        "protocol_head_note_test.c"
    ]
    assert "mc_packet_varint(packet, INT32_C(46))" in note_outputs[
        "protocol_head_varint_note_test.c"
    ]
    assert "mc_packet_varint(packet, INT32_C(65))" in note_outputs[
        "protocol_override_note_test.c"
    ]

    outputs = {
        "protocol_test.h": header,
        "protocol_test.c": source,
        "protocol_legacy_minecart_test.h": legacy_minecart_header,
        "protocol_legacy_minecart_test.c": legacy_minecart_source,
        "protocol_packed_minecart_test.h": packed_minecart_header,
        "protocol_packed_minecart_test.c": packed_minecart_source,
        **note_outputs,
        "schema_stamp.json": "{}\n",
    }
    with tempfile.TemporaryDirectory(prefix="mcprotocol-schema-") as temporary:
        output = Path(temporary)
        COMPILER.write_manifest_outputs(outputs, output, check=False)
        COMPILER.write_manifest_outputs(outputs, output, check=True)
        for source_name in (
            "protocol_test.c",
            "protocol_legacy_minecart_test.c",
            "protocol_packed_minecart_test.c",
            *sorted(name for name in note_outputs if name.endswith(".c")),
        ):
            subprocess.run(
                [
                    "cc",
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    f"-I{ROOT}",
                    f"-I{output}",
                    "-c",
                    str(output / source_name),
                    "-o",
                    str(output / source_name.replace(".c", ".o")),
                ],
                check=True,
            )
        (output / "protocol_unexpected.c").write_text("stale\n", encoding="utf-8")
        try:
            COMPILER.write_manifest_outputs(outputs, output, check=True)
        except ValueError as error:
            assert "protocol_unexpected.c" in str(error)
        else:
            raise AssertionError("staleness check accepted an unexpected generated file")

    with tempfile.TemporaryDirectory(prefix="mcprotocol-single-schema-") as temporary:
        output = Path(temporary)
        single_outputs = COMPILER.single_schema_outputs(
            999, header, source, {"generator_version": 1, "protocol": 999}
        )
        COMPILER.write_single_schema_outputs(single_outputs, output, check=False)
        COMPILER.write_single_schema_outputs(single_outputs, output, check=True)
        COMPILER.verify_existing_single_schema(output, 999, None)
        generated_source = output / "mc_protocol_999.c"
        generated_source.write_text(source + "/* stale */\n", encoding="utf-8")
        try:
            COMPILER.verify_existing_single_schema(output, 999, None)
        except ValueError as error:
            assert "hash mismatch" in str(error)
        else:
            raise AssertionError("integrity check accepted modified generated source")

    print(
        "PASS schema compiler manifest, overrides, minecart, NOTE particle, "
        "scoreboard/inventory/chunk projections, integrity and staleness"
    )


if __name__ == "__main__":
    main()
