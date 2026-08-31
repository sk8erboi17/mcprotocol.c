#!/usr/bin/env python3
"""Compile selected minecraft-data packet schemas into allocation-free C11 codecs.

The compiler deliberately fails on an unsupported schema node. Generated code
must never guess a field layout or silently expose an opaque remainder.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


PRIMITIVES = {
    "bool": ("bool", "bool"),
    "i8": ("int8_t", "i8"),
    "u8": ("uint8_t", "u8"),
    "i16": ("int16_t", "i16"),
    "u16": ("uint16_t", "u16"),
    "i32": ("int32_t", "i32"),
    "u32": ("uint32_t", "u32"),
    "i64": ("int64_t", "i64"),
    "u64": ("uint64_t", "u64"),
    "f32": ("float", "float"),
    "f64": ("double", "double"),
    "varint": ("int32_t", "varint"),
    "varlong": ("int64_t", "varlong"),
    "string": ("McBytes", "string"),
    "UUID": ("McUuid", "uuid"),
    "uuid": ("McUuid", "uuid"),
    "anonymousNbt": ("McBytes", "nbt"),
    "anonOptionalNbt": ("McBytes", "nbt"),
}

STATE_ORDER = ("handshaking", "status", "login", "configuration", "play")
DIRECTIONS = {"serverbound": "toServer", "clientbound": "toClient"}
STATE_CONSTANTS = {
    "status": "MC_STATE_STATUS",
    "login": "MC_STATE_LOGIN",
    "configuration": "MC_STATE_CONFIGURATION",
    "play": "MC_STATE_PLAY",
}
DIRECTION_CONSTANTS = {
    "serverbound": "MC_PACKET_SERVERBOUND",
    "clientbound": "MC_PACKET_CLIENTBOUND",
}

PUBLIC_BEGIN = "/* MC_GENERATED_PUBLIC_BEGIN */"
PUBLIC_END = "/* MC_GENERATED_PUBLIC_END */"
PRIVATE_BEGIN = "/* MC_GENERATED_PRIVATE_BEGIN */"
PRIVATE_END = "/* MC_GENERATED_PRIVATE_END */"


def marked_region(text: str, begin: str, end: str) -> str:
    """Return the exact bytes between one unambiguous pair of markers."""
    if text.count(begin) != 1 or text.count(end) != 1:
        raise ValueError(f"expected exactly one {begin} / {end} marker pair")
    start = text.index(begin) + len(begin)
    finish = text.index(end)
    if finish <= start:
        raise ValueError(f"misordered {begin} / {end} markers")
    return text[start:finish]


def replace_marked_region(text: str, begin: str, end: str,
                          contents: str) -> str:
    """Replace only one generated region, preserving every manual byte."""
    current = marked_region(text, begin, end)
    start = text.index(begin) + len(begin)
    finish = start + len(current)
    replacement = "\n" + contents.strip("\n") + "\n"
    return text[:start] + replacement + text[finish:]


def c_name(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
    if not value or value[0].isdigit():
        value = "field_" + value
    return value


def title_name(value: str) -> str:
    return "".join(part.capitalize() for part in c_name(value).split("_"))


class Compiler:
    def __init__(self, document: dict[str, Any], protocol: int, overlay: dict[str, Any]):
        self.document = document
        self.protocol = protocol
        self.overlay = overlay

    def direction_types(self, state: str, direction: str) -> dict[str, Any]:
        return self.document[state][DIRECTIONS[direction]]["types"]

    def resolve(self, schema: Any, types: dict[str, Any]) -> Any:
        seen: set[str] = set()
        while True:
            if isinstance(schema, str):
                if schema in PRIMITIVES or schema in {"position", "void"}:
                    return schema
                if schema in seen:
                    raise ValueError(f"recursive schema alias: {schema}")
                seen.add(schema)
                if schema in types:
                    schema = types[schema]
                elif schema in self.document["types"]:
                    schema = self.document["types"][schema]
                else:
                    raise ValueError(f"unknown schema type: {schema}")
                continue
            if (
                isinstance(schema, list)
                and len(schema) == 2
                and schema[0] in {"bitflags", "mapper"}
                and isinstance(schema[1], dict)
            ):
                schema = schema[1].get("type")
                continue
            return schema

    def buffer_suffix(self, schema: Any, types: dict[str, Any]) -> str | None:
        resolved = self.resolve(schema, types)
        if not isinstance(resolved, list) or not resolved or resolved[0] != "buffer":
            return None
        if len(resolved) != 2 or not isinstance(resolved[1], dict):
            raise ValueError(f"invalid buffer schema: {resolved!r}")
        count_type = self.resolve(resolved[1].get("countType"), types)
        if count_type not in {"i32", "varint"}:
            raise ValueError(f"unsupported buffer count type: {count_type!r}")
        return f"buffer_{count_type}"

    def packet_table(self, state: str, direction: str) -> tuple[dict[str, int], dict[str, Any]]:
        types = self.direction_types(state, direction)
        packet = self.resolve(types["packet"], types)
        if not isinstance(packet, list) or packet[0] != "container":
            raise ValueError(f"{state}/{direction}: packet root is not a container")
        fields = packet[1]
        mapper = next(field["type"] for field in fields if field["name"] == "name")
        switch = next(field["type"] for field in fields if field["name"] == "params")
        if mapper[0] != "mapper" or switch[0] != "switch":
            raise ValueError(f"{state}/{direction}: unexpected packet mapper shape")
        ids = {name: int(raw_id, 0) for raw_id, name in mapper[1]["mappings"].items()}
        schemas = dict(switch[1]["fields"])
        prefix = f"{state}:{direction}:"
        for selector, replacement in self.overlay.get("packet_renames", {}).items():
            if not selector.startswith(prefix):
                continue
            original = selector[len(prefix):]
            if original not in ids or original not in schemas or replacement in ids:
                raise ValueError(f"invalid packet rename: {selector} -> {replacement}")
            ids[replacement] = ids.pop(original)
            schemas[replacement] = schemas.pop(original)
        return ids, schemas

    def declaration(self, schema: Any, name: str, types: dict[str, Any], indent: str) -> list[str]:
        if schema == "position":
            return [f"{indent}McPosition {name};"]
        schema = self.resolve(schema, types)
        if isinstance(schema, str):
            if schema not in PRIMITIVES:
                raise ValueError(f"unsupported scalar type: {schema}")
            return [f"{indent}{PRIMITIVES[schema][0]} {name};"]
        if self.buffer_suffix(schema, types) is not None:
            return [f"{indent}McBytes {name};"]
        if not isinstance(schema, list) or not schema:
            raise ValueError(f"invalid schema node for {name}: {schema!r}")
        if schema[0] != "container":
            raise ValueError(f"unsupported schema node {schema[0]} for {name}")
        lines = [f"{indent}struct {{"]
        for field in schema[1]:
            lines.extend(self.declaration(field["type"], c_name(field["name"]), types, indent + "    "))
        lines.append(f"{indent}}} {name};")
        return lines

    def codec(self, schema: Any, expression: str, types: dict[str, Any], encode: bool) -> list[str]:
        if schema == "position":
            if encode:
                return [f"    if (!mc_packet_position(packet, {self.protocol}, value->{expression})) return false;"]
            return [f"    if (!mc_reader_position(reader, {self.protocol}, &value->{expression})) return false;"]
        schema = self.resolve(schema, types)
        if isinstance(schema, str):
            if schema not in PRIMITIVES:
                raise ValueError(f"unsupported scalar type: {schema}")
            _, suffix = PRIMITIVES[schema]
            if encode:
                if suffix == "string":
                    return [f"    if (!mc_packet_string_n(packet, (const char *)value->{expression}.data, value->{expression}.size)) return false;"]
                if suffix == "nbt":
                    return [f"    if (!mc_packet_nbt(packet, false, &value->{expression})) return false;"]
                if suffix == "uuid":
                    return [f"    if (!mc_packet_uuid(packet, &value->{expression})) return false;"]
                return [f"    if (!mc_packet_{suffix}(packet, value->{expression})) return false;"]
            if suffix == "nbt":
                return [f"    if (!mc_reader_nbt(reader, false, &value->{expression})) return false;"]
            return [f"    if (!mc_reader_{suffix}(reader, &value->{expression})) return false;"]
        buffer_suffix = self.buffer_suffix(schema, types)
        if buffer_suffix is not None:
            if encode:
                return [f"    if (!mc_packet_{buffer_suffix}(packet, &value->{expression})) return false;"]
            return [f"    if (!mc_reader_{buffer_suffix}(reader, &value->{expression})) return false;"]
        if not isinstance(schema, list) or not schema or schema[0] != "container":
            kind = schema[0] if isinstance(schema, list) and schema else repr(schema)
            raise ValueError(f"unsupported schema node {kind} for {expression}")
        lines: list[str] = []
        for field in schema[1]:
            lines.extend(self.codec(field["type"], f"{expression}.{c_name(field['name'])}", types, encode))
        return lines

    def all_packet_constants(self) -> list[tuple[str, str, str, int]]:
        constants: list[tuple[str, str, str, int]] = []
        for state in STATE_ORDER:
            if state not in self.document:
                continue
            for direction in ("serverbound", "clientbound"):
                ids, _ = self.packet_table(state, direction)
                for packet_name, packet_id in sorted(ids.items(), key=lambda item: item[1]):
                    constants.append((state, direction, packet_name, packet_id))
        return constants

    def selected_packet(self, selector: str) -> tuple[str, str, str, int, Any, dict[str, Any]]:
        parts = selector.split(":")
        if len(parts) != 3 or parts[0] not in STATE_ORDER or parts[1] not in DIRECTIONS:
            raise ValueError(f"invalid packet selector: {selector}")
        state, direction, packet_name = parts
        ids, schemas = self.packet_table(state, direction)
        if packet_name not in ids or packet_name not in schemas:
            raise ValueError(f"packet not found: {selector}")
        types = self.direction_types(state, direction)
        schema = self.resolve(schemas[packet_name], types)
        if not isinstance(schema, list) or schema[0] != "container":
            raise ValueError(f"packet is not a container: {selector}")
        return state, direction, packet_name, ids[packet_name], schema, types


def generate(document: dict[str, Any], protocol: int, selectors: list[str], source_sha: str,
             overlay: dict[str, Any], overlay_sha: str | None) -> tuple[str, str, dict[str, Any]]:
    compiler = Compiler(document, protocol, overlay)
    guard = f"MC_PROTOCOL_GENERATED_{protocol}_H"
    header = [
        "/* Generated from minecraft-data; do not edit. */",
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        '#include "api.h"',
        "",
    ]
    constants = compiler.all_packet_constants()
    for state, direction, packet_name, packet_id in constants:
        constant = f"MC{protocol}_{state}_{direction}_{packet_name}".upper()
        header.append(f"#define {constant} {packet_id}")
    catalog_constants = [entry for entry in constants if entry[0] in STATE_CONSTANTS]
    header.extend([
        "",
        f"extern const McPacketInfo mc{protocol}_generated_packet_ids[];",
        f"extern const size_t mc{protocol}_generated_packet_id_count;",
        "",
    ])
    source = [
        "/* Generated from minecraft-data; do not edit. */",
        f'#include "mc_protocol_{protocol}.h"',
        "",
    ]
    source.append(f"const McPacketInfo mc{protocol}_generated_packet_ids[] = {{")
    for state, direction, packet_name, packet_id in catalog_constants:
        source.append(
            f'    {{{STATE_CONSTANTS[state]}, {DIRECTION_CONSTANTS[direction]}, '
            f'{packet_id}, "{packet_name}"}},')
    source.extend([
        "};",
        f"const size_t mc{protocol}_generated_packet_id_count =",
        f"    sizeof(mc{protocol}_generated_packet_ids) / sizeof(mc{protocol}_generated_packet_ids[0]);",
        "",
    ])
    manifest_packets: list[dict[str, Any]] = []
    for selector in selectors:
        state, direction, packet_name, packet_id, schema, types = compiler.selected_packet(selector)
        type_name = f"Mc{protocol}{title_name(state)}{title_name(direction)}{title_name(packet_name)}"
        function = f"mc{protocol}_{c_name(state)}_{c_name(direction)}_{c_name(packet_name)}"
        header.append(f"typedef struct {type_name} {{")
        for field in schema[1]:
            header.extend(compiler.declaration(field["type"], c_name(field["name"]), types, "    "))
        header.extend([
            f"}} {type_name};",
            "",
            f"bool {function}_encode(McPacket *packet, const {type_name} *value);",
            f"bool {function}_decode(McReader *reader, {type_name} *value);",
            "",
        ])
        source.extend([
            f"bool {function}_encode(McPacket *packet, const {type_name} *value)",
            "{",
            "    if (packet == NULL || value == NULL) return false;",
        ])
        for field in schema[1]:
            source.extend(compiler.codec(field["type"], c_name(field["name"]), types, True))
        source.extend(["    return !packet->failed;", "}", ""])
        source.extend([
            f"bool {function}_decode(McReader *reader, {type_name} *value)",
            "{",
            "    if (reader == NULL || value == NULL) return false;",
        ])
        for field in schema[1]:
            source.extend(compiler.codec(field["type"], c_name(field["name"]), types, False))
        source.extend(["    return mc_reader_remaining(reader) == 0U;", "}", ""])
        manifest_packets.append({"selector": selector, "packet_id": packet_id, "type": type_name})
    header.extend([f"#endif /* {guard} */", ""])
    manifest = {
        "generator_version": 1,
        "protocol": protocol,
        "source_sha256": source_sha,
        "overlay_sha256": overlay_sha,
        "packet_id_count": len(constants),
        "catalog_validation_count": len(catalog_constants),
        "generated_packets": manifest_packets,
    }
    return "\n".join(header), "\n".join(source), manifest


@dataclass(frozen=True)
class ManifestWire:
    schema_name: str
    c_type: str
    suffix: str
    protocol_argument: bool = False


@dataclass(frozen=True)
class ManifestField:
    source_name: str
    c_field: str
    wire: ManifestWire
    expected_value: int | None = None


@dataclass(frozen=True)
class ManifestPacket:
    name: str
    c_packet: str
    packet_id: int
    state: str
    direction: str
    fields: tuple[ManifestField, ...]
    projection: str | None = None


@dataclass(frozen=True)
class ManifestProfile:
    name: str
    c_profile: str
    protocol: int
    schema: str
    schema_protocol: int
    schema_hash: str
    constants: tuple[tuple[str, int, str], ...]
    packets: tuple[ManifestPacket, ...]


def manifest_c_name(value: str) -> str:
    value = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", value)
    value = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_").lower()
    if not value:
        raise ValueError("cannot derive an empty C identifier")
    return value


def manifest_wire(compiler: Compiler, schema: Any,
                  types: dict[str, Any]) -> ManifestWire | None:
    resolved = compiler.resolve(schema, types)
    if resolved == "position":
        return ManifestWire("position", "McPosition", "position", True)
    buffer_suffix = compiler.buffer_suffix(resolved, types)
    if buffer_suffix is not None:
        return ManifestWire(buffer_suffix, "McBytes", buffer_suffix)
    if not isinstance(resolved, str) or resolved not in PRIMITIVES:
        return None
    c_type, suffix = PRIMITIVES[resolved]
    return ManifestWire(resolved, c_type, suffix)


def manifest_array(compiler: Compiler, schema: Any, types: dict[str, Any],
                   description: str) -> tuple[Any, Any]:
    resolved = compiler.resolve(schema, types)
    if (
        not isinstance(resolved, list)
        or len(resolved) != 2
        or resolved[0] != "array"
        or not isinstance(resolved[1], dict)
    ):
        raise ValueError(f"{description} is not a counted array")
    count_type = resolved[1].get("countType")
    if count_type is None:
        raise ValueError(f"{description} has no count type")
    return count_type, resolved[1].get("type")


def manifest_container(compiler: Compiler, schema: Any, types: dict[str, Any],
                       description: str) -> list[dict[str, Any]]:
    resolved = compiler.resolve(schema, types)
    if (
        not isinstance(resolved, list)
        or len(resolved) != 2
        or resolved[0] != "container"
        or not isinstance(resolved[1], list)
        or not all(isinstance(field, dict) for field in resolved[1])
    ):
        raise ValueError(f"{description} is not a container")
    return resolved[1]


def manifest_attribute_projection(compiler: Compiler, packet_name: str,
                                  raw_fields: list[dict[str, Any]],
                                  types: dict[str, Any]) -> tuple[ManifestField, ...]:
    if (
        len(raw_fields) != 2
        or raw_fields[0].get("name") != "entityId"
        or raw_fields[1].get("name") != "properties"
    ):
        raise ValueError(
            f"packet {packet_name} no longer matches single_attribute_no_modifiers"
        )
    property_count_schema, property_schema = manifest_array(
        compiler, raw_fields[1].get("type"), types,
        f"packet {packet_name} properties")
    properties = manifest_container(
        compiler, property_schema, types, f"packet {packet_name} property")
    if (
        len(properties) != 3
        or properties[0].get("name") not in {"key", "name"}
        or properties[1].get("name") != "value"
        or properties[2].get("name") != "modifiers"
    ):
        raise ValueError(f"packet {packet_name} property projection changed")
    modifier_count_schema, modifier_schema = manifest_array(
        compiler, properties[2].get("type"), types,
        f"packet {packet_name} modifiers")
    manifest_container(
        compiler, modifier_schema, types, f"packet {packet_name} modifier")
    candidates = (
        ("entityId", "entity_id", raw_fields[0].get("type"), None),
        ("properties.count", "property_count", property_count_schema, 1),
        (str(properties[0]["name"]), "key", properties[0].get("type"), None),
        ("value", "value", properties[1].get("type"), None),
        ("modifiers.count", "modifier_count", modifier_count_schema, 0),
    )
    fields = []
    for source_name, field_name, schema, expected in candidates:
        wire = manifest_wire(compiler, schema, types)
        if wire is None:
            raise ValueError(
                f"packet {packet_name} projection field {source_name} is unsupported"
            )
        fields.append(ManifestField(source_name, field_name, wire, expected))
    return tuple(fields)


def validate_manifest_vec3f(compiler: Compiler, schema: Any,
                            types: dict[str, Any], description: str) -> None:
    fields = manifest_container(compiler, schema, types, description)
    if [field.get("name") for field in fields] != ["x", "y", "z"]:
        raise ValueError(f"{description} is not an x/y/z vector")
    if any(
        required_manifest_wire(
            compiler, field.get("type"), types, description
        ).suffix != "float"
        for field in fields
    ):
        raise ValueError(f"{description} is not a float vector")


def manifest_minecart_steps_projection(
    compiler: Compiler,
    packet_name: str,
    raw_fields: list[dict[str, Any]],
    types: dict[str, Any],
) -> tuple[tuple[ManifestField, ...], str]:
    if (
        len(raw_fields) != 2
        or raw_fields[0].get("name") != "entityId"
        or raw_fields[1].get("name") != "steps"
    ):
        raise ValueError(f"packet {packet_name} minecart step envelope changed")
    entity_wire = required_manifest_wire(
        compiler, raw_fields[0].get("type"), types, "minecart entity ID"
    )
    count_schema, step_schema = manifest_array(
        compiler, raw_fields[1].get("type"), types,
        f"packet {packet_name} steps",
    )
    count_wire = required_manifest_wire(
        compiler, count_schema, types, "minecart step count"
    )
    if entity_wire.suffix != "varint" or count_wire.suffix != "varint":
        raise ValueError(f"packet {packet_name} minecart envelope is not VarInt based")
    step_fields = manifest_container(
        compiler, step_schema, types, f"packet {packet_name} step"
    )
    step_names = [field.get("name") for field in step_fields]
    if (
        len(step_fields) != 5
        or step_names[0] != "position"
        or step_names[1] not in {"movement", "velocity"}
        or step_names[2:] != ["yaw", "pitch", "weight"]
    ):
        raise ValueError(f"packet {packet_name} minecart step fields changed")
    validate_manifest_vec3f(
        compiler, step_fields[0].get("type"), types,
        f"packet {packet_name} step position",
    )
    validate_manifest_vec3f(
        compiler, step_fields[1].get("type"), types,
        f"packet {packet_name} step movement",
    )
    for field in step_fields[2:]:
        if required_manifest_wire(
            compiler,
            field.get("type"),
            types,
            f"packet {packet_name} step {field.get('name')}",
        ).suffix != "float":
            raise ValueError(f"packet {packet_name} minecart scalar fields changed")
    fields = (
        ManifestField("entityId", "entity_id", entity_wire),
        ManifestField("steps.count", "step_count", count_wire),
    )
    return fields, f"minecart_steps:{step_names[1]}"


def manifest_minecart_metadata_projection(
    compiler: Compiler,
    packet_name: str,
    raw_fields: list[dict[str, Any]],
    types: dict[str, Any],
    layout: Any,
    first_index: Any,
) -> tuple[tuple[ManifestField, ...], str]:
    if (
        len(raw_fields) != 2
        or raw_fields[0].get("name") != "entityId"
        or raw_fields[1].get("name") != "metadata"
        or raw_fields[1].get("type") != "entityMetadata"
    ):
        raise ValueError(f"packet {packet_name} minecart metadata envelope changed")
    entity_wire = required_manifest_wire(
        compiler, raw_fields[0].get("type"), types, "minecart metadata entity ID"
    )
    if entity_wire.suffix not in {"i32", "varint"}:
        raise ValueError(
            f"packet {packet_name} minecart metadata entity ID is not i32/VarInt"
        )
    if layout not in {
        "packed_block_state_and_flag",
        "block_state_and_flag",
        "optional_block_state",
    }:
        raise ValueError(
            "source_validated_minecart_metadata requires metadata_layout "
            "packed_block_state_and_flag, block_state_and_flag or optional_block_state"
        )
    expected_first_index = (
        17
        if compiler.protocol <= 47
        else 5
        if compiler.protocol <= 110
        else 6
        if compiler.protocol <= 404
        else 7
        if compiler.protocol <= 754
        else 8
    )
    if not isinstance(first_index, int) or first_index != expected_first_index:
        raise ValueError(
            "source_validated_minecart_metadata requires metadata_first_index "
            f"{expected_first_index} for protocol {compiler.protocol}"
        )
    expected_layout = (
        "packed_block_state_and_flag"
        if compiler.protocol <= 47
        else "block_state_and_flag"
        if compiler.protocol < 770
        else "optional_block_state"
    )
    if layout != expected_layout:
        raise ValueError(
            f"protocol {compiler.protocol} requires minecart metadata layout {expected_layout}"
        )
    return (
        (ManifestField("entityId", "entity_id", entity_wire),),
        f"minecart_metadata:{layout}:{first_index}:{entity_wire.suffix}",
    )


def manifest_primed_tnt_metadata_projection(
    compiler: Compiler,
    packet_name: str,
    raw_fields: list[dict[str, Any]],
    types: dict[str, Any],
    layout: Any,
) -> tuple[tuple[ManifestField, ...], str]:
    if (
        len(raw_fields) != 2
        or raw_fields[0].get("name") != "entityId"
        or raw_fields[1].get("name") != "metadata"
        or raw_fields[1].get("type") != "entityMetadata"
    ):
        raise ValueError(f"packet {packet_name} primed TNT metadata envelope changed")
    entity_wire = required_manifest_wire(
        compiler, raw_fields[0].get("type"), types, "primed TNT metadata entity ID"
    )
    if entity_wire.suffix != "varint":
        raise ValueError(f"packet {packet_name} primed TNT metadata entity ID is not VarInt")
    if compiler.protocol < 107:
        raise ValueError("source_validated_primed_tnt_metadata requires protocol 107 or later")
    expected_layout = (
        "fuse_and_block_state" if compiler.protocol >= 765 else "fuse"
    )
    if layout != expected_layout:
        raise ValueError(
            "source_validated_primed_tnt_metadata requires metadata_layout "
            f"{expected_layout} for protocol {compiler.protocol}"
        )
    fuse_index = (
        5 if compiler.protocol <= 110
        else 6 if compiler.protocol <= 404
        else 7 if compiler.protocol <= 754
        else 8
    )
    return (
        (ManifestField("entityId", "entity_id", entity_wire),),
        f"primed_tnt_metadata:{expected_layout}:{fuse_index}",
    )


def manifest_note_particle_projection(
    compiler: Compiler,
    packet_name: str,
    raw_fields: list[dict[str, Any]],
    types: dict[str, Any],
    particle_name: Any,
    particle_id: Any,
    registry_override_reason: Any,
) -> tuple[tuple[ManifestField, ...], str]:
    """Project the data-free NOTE particle without accepting opaque options.

    Particle packets use several envelopes across Java releases.  The NOTE
    option itself has no trailing payload, but the generic Particle schema can
    carry registry-dependent data.  This projection therefore validates the
    complete envelope and pins the NOTE selector supplied by release sources.
    """
    if particle_name != "note":
        raise ValueError(
            "source_validated_note_particle requires particle_name note"
        )
    names = [field.get("name") for field in raw_fields]
    name_layout = names == [
        "particleName", "x", "y", "z", "offsetX", "offsetY", "offsetZ",
        "particleData", "particles",
    ]
    head_layout = names == [
        "particleId", "longDistance", "x", "y", "z", "offsetX", "offsetY",
        "offsetZ", "particleData", "particles", "data",
    ]
    tail_without_always = names == [
        "longDistance", "x", "y", "z", "offsetX", "offsetY", "offsetZ",
        "velocityOffset", "amount", "particle",
    ]
    tail_with_always = names == [
        "longDistance", "alwaysShow", "x", "y", "z", "offsetX", "offsetY",
        "offsetZ", "velocityOffset", "amount", "particle",
    ]
    if not any((name_layout, head_layout, tail_without_always, tail_with_always)):
        raise ValueError(f"packet {packet_name} NOTE particle envelope changed")

    if name_layout:
        if particle_id is not None or registry_override_reason is not None:
            raise ValueError(
                "named NOTE particle projection does not accept a particle ID override"
            )
        particle_name_wire = required_manifest_wire(
            compiler, raw_fields[0].get("type"), types, "NOTE particle name"
        )
        if particle_name_wire.suffix != "string":
            raise ValueError(f"packet {packet_name} NOTE particle name is not a string")
        selected_fields = raw_fields[1:]
        layout = "name_f32"
    else:
        if (
            not isinstance(particle_id, int)
            or isinstance(particle_id, bool)
            or particle_id < 0
            or particle_id > 0x7fffffff
        ):
            raise ValueError(
                "source_validated_note_particle requires a non-negative particle_id"
            )
        selected_fields = raw_fields[1:-1] if head_layout else raw_fields[:-1]
        if head_layout:
            if registry_override_reason is not None:
                raise ValueError(
                    "head-selector NOTE particle projection does not accept a registry override"
                )
            selector_wire = required_manifest_wire(
                compiler, raw_fields[0].get("type"), types, "NOTE particle ID"
            )
            if selector_wire.suffix not in {"i32", "varint"}:
                raise ValueError(
                    f"packet {packet_name} NOTE particle ID is not i32/VarInt"
                )
            data_schema = raw_fields[-1].get("type")
            resolved_data = compiler.resolve(data_schema, types)
            if (
                isinstance(resolved_data, list)
                and len(resolved_data) == 2
                and resolved_data[0] == "switch"
            ):
                data_switch = resolved_data
            elif (
                isinstance(data_schema, list)
                and len(data_schema) == 2
                and isinstance(data_schema[0], str)
            ):
                parameterized = types.get(
                    data_schema[0], compiler.document.get("types", {}).get(data_schema[0])
                )
                data_switch = (
                    compiler.resolve(parameterized, types)
                    if parameterized is not None
                    else None
                )
            else:
                data_switch = None
            if (
                not isinstance(data_switch, list)
                or len(data_switch) != 2
                or data_switch[0] != "switch"
                or not isinstance(data_switch[1], dict)
                or not isinstance(data_switch[1].get("fields"), dict)
            ):
                raise ValueError(f"packet {packet_name} NOTE particle data schema changed")
            option_schema = data_switch[1].get("default", "void")
            for raw_id, candidate_schema in data_switch[1]["fields"].items():
                try:
                    candidate_id = int(raw_id, 0)
                except (TypeError, ValueError):
                    continue
                if candidate_id == particle_id:
                    option_schema = candidate_schema
                    break
            if compiler.resolve(option_schema, types) != "void":
                raise ValueError(
                    f"packet {packet_name} particle ID {particle_id} is not data-free"
                )
            coordinate_wire = required_manifest_wire(
                compiler, raw_fields[2].get("type"), types, "NOTE particle coordinate"
            )
            layout = f"head_{selector_wire.suffix}_{coordinate_wire.suffix}"
        else:
            particle_fields = manifest_container(
                compiler,
                raw_fields[-1].get("type"),
                types,
                f"packet {packet_name} particle option",
            )
            if [field.get("name") for field in particle_fields] != ["type", "data"]:
                raise ValueError(f"packet {packet_name} Particle option changed")
            selector_schema = particle_fields[0].get("type")
            if (
                not isinstance(selector_schema, list)
                or len(selector_schema) != 2
                or selector_schema[0] != "mapper"
                or not isinstance(selector_schema[1], dict)
                or not isinstance(selector_schema[1].get("mappings"), dict)
            ):
                raise ValueError(f"packet {packet_name} Particle selector changed")
            selector_wire = required_manifest_wire(
                compiler, selector_schema, types, "NOTE Particle selector"
            )
            if selector_wire.suffix != "varint":
                raise ValueError(f"packet {packet_name} Particle selector is not VarInt")
            mappings = selector_schema[1]["mappings"]
            schema_note_ids = [
                int(raw_id, 0)
                for raw_id, name in mappings.items()
                if name == "note"
            ]
            if len(schema_note_ids) != 1:
                raise ValueError(f"packet {packet_name} schema has no unique NOTE particle")
            if particle_id != schema_note_ids[0] and (
                not isinstance(registry_override_reason, str)
                or not registry_override_reason.strip()
            ):
                raise ValueError(
                    f"packet {packet_name} NOTE registry ID {particle_id} differs from schema "
                    f"ID {schema_note_ids[0]} without registry_override_reason"
                )
            if particle_id == schema_note_ids[0] and registry_override_reason is not None:
                raise ValueError(
                    f"packet {packet_name} has an unnecessary registry_override_reason"
                )
            data_schema = compiler.resolve(particle_fields[1].get("type"), types)
            if (
                not isinstance(data_schema, list)
                or len(data_schema) != 2
                or data_schema[0] != "switch"
                or not isinstance(data_schema[1], dict)
                or not isinstance(data_schema[1].get("fields"), dict)
            ):
                raise ValueError(f"packet {packet_name} Particle data switch changed")
            note_schema = data_schema[1]["fields"].get(
                "note", data_schema[1].get("default", "void")
            )
            if compiler.resolve(note_schema, types) != "void":
                raise ValueError(f"packet {packet_name} NOTE Particle gained option data")
            coordinate_wire = required_manifest_wire(
                compiler,
                raw_fields[2 if tail_with_always else 1].get("type"),
                types,
                "NOTE particle coordinate",
            )
            layout = (
                f"tail_{selector_wire.suffix}_{coordinate_wire.suffix}"
                + ("_always" if tail_with_always else "")
            )

    fields = []
    for field in selected_fields:
        source_name = field.get("name")
        if not isinstance(source_name, str):
            raise ValueError(f"packet {packet_name} NOTE projection has unnamed field")
        wire = required_manifest_wire(
            compiler,
            field.get("type"),
            types,
            f"packet {packet_name} NOTE field {source_name}",
        )
        fields.append(ManifestField(source_name, manifest_c_name(source_name), wire))

    suffixes = [field.wire.suffix for field in fields]
    if name_layout:
        expected = ["float"] * 7 + ["i32"]
    elif head_layout:
        expected = ["bool"] + [coordinate_wire.suffix] * 3 + ["float"] * 4 + ["i32"]
    else:
        expected = ["bool"] + (["bool"] if tail_with_always else [])
        expected += ["double"] * 3 + ["float"] * 4 + ["i32"]
    if suffixes != expected:
        raise ValueError(
            f"packet {packet_name} NOTE particle scalar layout changed: {suffixes}"
        )
    return tuple(fields), (
        f"note_particle:{layout}"
        if name_layout
        else f"note_particle:{layout}:{particle_id}"
    )


def required_manifest_wire(compiler: Compiler, schema: Any,
                           types: dict[str, Any], description: str) -> ManifestWire:
    wire = manifest_wire(compiler, schema, types)
    if wire is None:
        raise ValueError(f"{description} uses unsupported schema {schema!r}")
    return wire


def switch_payload(compiler: Compiler, schema: Any, types: dict[str, Any],
                   description: str) -> Any:
    resolved = compiler.resolve(schema, types)
    if (
        not isinstance(resolved, list)
        or len(resolved) != 2
        or resolved[0] != "switch"
        or not isinstance(resolved[1], dict)
        or not isinstance(resolved[1].get("fields"), dict)
    ):
        raise ValueError(f"{description} is not a switch")
    payloads = []
    for candidate in resolved[1]["fields"].values():
        candidate = compiler.resolve(candidate, types)
        if candidate != "void" and candidate not in payloads:
            payloads.append(candidate)
    default = compiler.resolve(resolved[1].get("default", "void"), types)
    if default != "void" and default not in payloads:
        payloads.append(default)
    if len(payloads) != 1:
        raise ValueError(f"{description} does not have one non-void payload")
    return payloads[0]


def option_payload(compiler: Compiler, schema: Any, types: dict[str, Any],
                   description: str) -> Any:
    resolved = compiler.resolve(schema, types)
    if not isinstance(resolved, list) or len(resolved) != 2 or resolved[0] != "option":
        raise ValueError(f"{description} is not an option")
    return resolved[1]


def validate_plain_item_schema(compiler: Compiler, schema: Any,
                               types: dict[str, Any], description: str) -> None:
    fields = manifest_container(compiler, schema, types, description)
    if (
        len(fields) != 2
        or fields[0].get("name") != "itemCount"
        or fields[1].get("anon") is not True
        or compiler.resolve(fields[0].get("type"), types) != "varint"
    ):
        raise ValueError(f"{description} is not a modern plain-item slot")
    item_switch = compiler.resolve(fields[1].get("type"), types)
    if (
        not isinstance(item_switch, list)
        or len(item_switch) != 2
        or item_switch[0] != "switch"
        or not isinstance(item_switch[1], dict)
        or item_switch[1].get("compareTo") != "itemCount"
        or not isinstance(item_switch[1].get("fields"), dict)
        or compiler.resolve(item_switch[1].get("fields", {}).get("0"), types)
        != "void"
    ):
        raise ValueError(f"{description} item-count switch changed")
    contents = manifest_container(
        compiler, item_switch[1].get("default"), types, f"{description} contents")
    names = [field.get("name") for field in contents]
    if names != [
        "itemId", "addedComponentCount", "removedComponentCount",
        "components", "removeComponents",
    ] or any(
        compiler.resolve(contents[index].get("type"), types) != "varint"
        for index in range(3)
    ):
        raise ValueError(f"{description} component-free prefix changed")
    component_schema = compiler.resolve(contents[3].get("type"), types)
    removal_schema = compiler.resolve(contents[4].get("type"), types)
    if (
        not isinstance(component_schema, list)
        or len(component_schema) != 2
        or component_schema[0] != "array"
        or not isinstance(component_schema[1], dict)
        or component_schema[1].get("count") != "addedComponentCount"
        or not isinstance(removal_schema, list)
        or len(removal_schema) != 2
        or removal_schema[0] != "array"
        or not isinstance(removal_schema[1], dict)
        or removal_schema[1].get("count") != "removedComponentCount"
    ):
        raise ValueError(f"{description} component arrays changed")


def inventory_projection(compiler: Compiler, packet_name: str,
                         projection: str, raw_fields: list[dict[str, Any]],
                         types: dict[str, Any]) -> tuple[tuple[ManifestField, ...], str]:
    names = [field.get("name") for field in raw_fields]
    varint_wire = required_manifest_wire(
        compiler, "varint", types, "inventory varint")
    if projection == "plain_item_slot":
        if names != ["slot", "item"]:
            raise ValueError(f"packet {packet_name} plain-item slot schema changed")
        validate_plain_item_schema(
            compiler, raw_fields[1]["type"], types, f"packet {packet_name} item")
        return (
            ManifestField("slot", "slot", required_manifest_wire(
                compiler, raw_fields[0]["type"], types, "inventory slot")),
            ManifestField("item.itemId", "item_id", varint_wire),
            ManifestField("item.itemCount", "item_count", varint_wire),
        ), "inventory:plain_item_slot"
    if projection == "plain_item_contents":
        if names != ["contents"]:
            raise ValueError(f"packet {packet_name} plain contents schema changed")
        validate_plain_item_schema(
            compiler, raw_fields[0]["type"], types, f"packet {packet_name} contents")
        return (
            ManifestField("contents.itemId", "item_id", varint_wire),
            ManifestField("contents.itemCount", "item_count", varint_wire),
        ), "inventory:plain_item_contents"
    if projection == "plain_window_items":
        if names != ["windowId", "stateId", "items", "carriedItem"]:
            raise ValueError(f"packet {packet_name} window-items schema changed")
        count_schema, item_schema = manifest_array(
            compiler, raw_fields[2]["type"], types, f"packet {packet_name} items")
        if compiler.resolve(count_schema, types) != "varint":
            raise ValueError(f"packet {packet_name} item count is not a VarInt")
        validate_plain_item_schema(
            compiler, item_schema, types, f"packet {packet_name} item")
        validate_plain_item_schema(
            compiler, raw_fields[3]["type"], types, f"packet {packet_name} carried item")
        return (
            ManifestField("windowId", "window_id", required_manifest_wire(
                compiler, raw_fields[0]["type"], types, "window ID")),
            ManifestField("stateId", "state_id", required_manifest_wire(
                compiler, raw_fields[1]["type"], types, "window state ID")),
        ), "inventory:plain_window_items"
    if projection == "empty_window_click":
        if names != [
            "windowId", "stateId", "slot", "mouseButton", "mode",
            "changedSlots", "cursorItem",
        ]:
            raise ValueError(f"packet {packet_name} click schema changed")
        count_schema, _ = manifest_array(
            compiler, raw_fields[5]["type"], types,
            f"packet {packet_name} changed slots")
        option_payload(
            compiler, raw_fields[6]["type"], types,
            f"packet {packet_name} cursor item")
        if compiler.resolve(count_schema, types) != "varint":
            raise ValueError(f"packet {packet_name} changed-slot count is not a VarInt")
        return tuple(
            ManifestField(str(raw_fields[index]["name"]),
                          manifest_c_name(str(raw_fields[index]["name"])),
                          required_manifest_wire(
                              compiler, raw_fields[index]["type"], types,
                              f"packet {packet_name} click field"))
            for index in range(5)
        ), "inventory:empty_window_click"
    raise ValueError(f"unknown inventory projection {projection}")


def validate_nbt_array(compiler: Compiler, schema: Any,
                       types: dict[str, Any], description: str) -> None:
    count_schema, item_schema = manifest_array(compiler, schema, types, description)
    if compiler.resolve(count_schema, types) != "varint" or item_schema != "nbt":
        raise ValueError(f"{description} is not a VarInt-counted named-NBT array")


def validate_biome_switch(compiler: Compiler, schema: Any,
                          types: dict[str, Any]) -> bool:
    resolved = compiler.resolve(schema, types)
    if (
        not isinstance(resolved, list)
        or len(resolved) != 2
        or resolved[0] != "switch"
        or not isinstance(resolved[1], dict)
        or resolved[1].get("compareTo") != "groundUp"
        or not isinstance(resolved[1].get("fields"), dict)
    ):
        raise ValueError("chunk biomes are not selected by groundUp")
    fields = resolved[1]["fields"]
    if compiler.resolve(fields.get("false"), types) != "void":
        raise ValueError("chunk biomes false branch changed")
    true_schema = compiler.resolve(fields.get("true"), types)
    if (
        not isinstance(true_schema, list)
        or len(true_schema) != 2
        or true_schema[0] != "array"
        or not isinstance(true_schema[1], dict)
        or compiler.resolve(true_schema[1].get("type"), types) not in {"i32", "varint"}
    ):
        raise ValueError("chunk biome array changed")
    if "countType" in true_schema[1]:
        if (compiler.resolve(true_schema[1].get("countType"), types) != "varint" or
                compiler.resolve(true_schema[1].get("type"), types) != "varint"):
            raise ValueError("chunk counted biomes are not VarInts")
        return True
    if (true_schema[1].get("count") != 1024 or
            compiler.resolve(true_schema[1].get("type"), types) != "i32"):
        raise ValueError("chunk fixed biome array changed")
    return False


def validate_varint_array(compiler: Compiler, schema: Any,
                          types: dict[str, Any], item_type: str,
                          description: str) -> None:
    count_schema, item_schema = manifest_array(compiler, schema, types, description)
    if (compiler.resolve(count_schema, types) != "varint" or
            compiler.resolve(item_schema, types) != item_type):
        raise ValueError(
            f"{description} is not a VarInt-counted {item_type} array")


def validate_light_byte_arrays(compiler: Compiler, schema: Any,
                               types: dict[str, Any], description: str) -> None:
    count_schema, item_schema = manifest_array(compiler, schema, types, description)
    if compiler.resolve(count_schema, types) != "varint":
        raise ValueError(f"{description} outer count is not a VarInt")
    validate_varint_array(
        compiler, item_schema, types, "u8", f"{description} entry")


def validate_registry_heightmaps(compiler: Compiler, schema: Any,
                                 types: dict[str, Any]) -> None:
    count_schema, item_schema = manifest_array(
        compiler, schema, types, "registry heightmaps")
    if compiler.resolve(count_schema, types) != "varint":
        raise ValueError("registry heightmap count is not a VarInt")
    fields = manifest_container(
        compiler, item_schema, types, "registry heightmap entry")
    if (
        [field.get("name") for field in fields] != ["type", "data"]
        or required_manifest_wire(
            compiler, fields[0]["type"], types,
            "registry heightmap type").suffix != "varint"
    ):
        raise ValueError("registry heightmap entry changed")
    validate_varint_array(
        compiler, fields[1]["type"], types, "i64", "registry heightmap data")


def modern_chunk_envelope_projection(
        compiler: Compiler, packet_name: str,
        raw_fields: list[dict[str, Any]],
        types: dict[str, Any]) -> tuple[tuple[ManifestField, ...], str] | None:
    names = [field.get("name") for field in raw_fields]
    without_trust = [
        "x", "z", "heightmaps", "chunkData", "blockEntities",
        "skyLightMask", "blockLightMask", "emptySkyLightMask",
        "emptyBlockLightMask", "skyLight", "blockLight",
    ]
    with_trust = without_trust[:5] + ["trustEdges"] + without_trust[5:]
    if names not in (without_trust, with_trust):
        return None
    if (required_manifest_wire(
            compiler, raw_fields[0]["type"], types, "chunk x").suffix != "i32" or
            required_manifest_wire(
                compiler, raw_fields[1]["type"], types, "chunk z").suffix != "i32"):
        raise ValueError("chunk coordinates are not signed 32-bit integers")
    heightmaps_schema = raw_fields[2]["type"]
    if heightmaps_schema == "nbt":
        heightmap_variant = "named_nbt"
    elif heightmaps_schema == "anonymousNbt":
        heightmap_variant = "anonymous_nbt"
    else:
        validate_registry_heightmaps(compiler, heightmaps_schema, types)
        heightmap_variant = "registry"
    if compiler.buffer_suffix(raw_fields[3]["type"], types) != "buffer_varint":
        raise ValueError("modern chunk data is not a VarInt-length buffer")
    block_count, block_item = manifest_array(
        compiler, raw_fields[4]["type"], types, "modern chunk block entities")
    if (compiler.resolve(block_count, types) != "varint" or
            block_item != "chunkBlockEntity"):
        raise ValueError("modern chunk block-entity array changed")
    offset = 5
    trust_edges = names == with_trust
    if trust_edges:
        if compiler.resolve(raw_fields[offset]["type"], types) != "bool":
            raise ValueError("chunk trustEdges is not boolean")
        offset += 1
    for index in range(4):
        validate_varint_array(
            compiler, raw_fields[offset + index]["type"], types, "i64",
            f"chunk light mask {index}")
    offset += 4
    for index in range(2):
        validate_light_byte_arrays(
            compiler, raw_fields[offset + index]["type"], types,
            f"chunk light array {index}")
    return (), f"chunk:modern:{heightmap_variant}" + (":trust" if trust_edges else "")


def chunk_envelope_projection(compiler: Compiler, packet_name: str,
                              raw_fields: list[dict[str, Any]],
                              types: dict[str, Any]) -> tuple[tuple[ManifestField, ...], str]:
    names = [field.get("name") for field in raw_fields]
    variants = {
        ("x", "z", "groundUp", "bitMap", "chunkData", "blockEntities"):
            "chunk:1_13",
        ("x", "z", "groundUp", "bitMap", "heightmaps", "chunkData", "blockEntities"):
            "chunk:1_14",
        ("x", "z", "groundUp", "bitMap", "heightmaps", "biomes", "chunkData", "blockEntities"):
            "chunk:1_15_or_1_16_2",
        ("x", "z", "groundUp", "ignoreOldData", "bitMap", "heightmaps", "biomes", "chunkData", "blockEntities"):
            "chunk:1_16",
        ("x", "z", "bitMap", "heightmaps", "biomes", "chunkData", "blockEntities"):
            "chunk:1_17",
    }
    variant = variants.get(tuple(names))
    if variant is None:
        modern = modern_chunk_envelope_projection(
            compiler, packet_name, raw_fields, types)
        if modern is not None:
            return modern
        raise ValueError(f"packet {packet_name} chunk envelope changed")
    if (required_manifest_wire(
            compiler, raw_fields[0]["type"], types, "chunk x").suffix != "i32" or
            required_manifest_wire(
                compiler, raw_fields[1]["type"], types, "chunk z").suffix != "i32"):
        raise ValueError("chunk coordinates are not signed 32-bit integers")
    offset = 2
    if variant != "chunk:1_17":
        if compiler.resolve(raw_fields[offset]["type"], types) != "bool":
            raise ValueError("chunk groundUp is not boolean")
        offset += 1
    if variant == "chunk:1_16":
        if compiler.resolve(raw_fields[offset]["type"], types) != "bool":
            raise ValueError("chunk ignoreOldData is not boolean")
        offset += 1
    mask_schema = compiler.resolve(raw_fields[offset]["type"], types)
    if variant == "chunk:1_17":
        mask_count, mask_item = manifest_array(
            compiler, mask_schema, types, "chunk section mask")
        if (compiler.resolve(mask_count, types) != "varint" or
                compiler.resolve(mask_item, types) != "i64"):
            raise ValueError("chunk section mask is not a VarInt-counted long array")
    elif mask_schema != "varint":
        raise ValueError("chunk section mask is not a VarInt")
    offset += 1
    if variant != "chunk:1_13":
        if raw_fields[offset]["type"] != "nbt":
            raise ValueError("chunk heightmaps are not named NBT")
        offset += 1
    if variant in {"chunk:1_15_or_1_16_2", "chunk:1_16", "chunk:1_17"}:
        if variant == "chunk:1_17":
            count_schema, biome_schema = manifest_array(
                compiler, raw_fields[offset]["type"], types, "chunk biomes")
            if (compiler.resolve(count_schema, types) != "varint" or
                    compiler.resolve(biome_schema, types) != "varint"):
                raise ValueError("1.17 biomes are not a VarInt-counted VarInt array")
        else:
            counted = validate_biome_switch(
                compiler, raw_fields[offset]["type"], types)
            variant += ":counted" if counted else ":fixed"
        offset += 1
    if compiler.buffer_suffix(raw_fields[offset]["type"], types) != "buffer_varint":
        raise ValueError("chunk data is not a VarInt-length buffer")
    offset += 1
    validate_nbt_array(
        compiler, raw_fields[offset]["type"], types, "chunk block entities")
    return (), variant


def scoreboard_projection(compiler: Compiler, packet_name: str,
                          projection: str, raw_fields: list[dict[str, Any]],
                          types: dict[str, Any]) -> tuple[tuple[ManifestField, ...], str]:
    names = [field.get("name") for field in raw_fields]
    bool_wire = required_manifest_wire(compiler, "bool", types, "scoreboard bool")
    if projection == "scoreboard_objective":
        if names == ["name", "displayText", "action"]:
            fields = (
                ManifestField("name", "name", required_manifest_wire(
                    compiler, raw_fields[0]["type"], types, "objective name")),
                ManifestField("displayText", "display_text", required_manifest_wire(
                    compiler, raw_fields[1]["type"], types, "objective display text")),
                ManifestField("action", "action", required_manifest_wire(
                    compiler, raw_fields[2]["type"], types, "objective action")),
            )
            return fields, "scoreboard_objective:1_7"
        if names not in (
            ["name", "action", "displayText", "type"],
            ["name", "action", "displayText", "type", "number_format", "styling"],
        ):
            raise ValueError("scoreboard objective schema changed")
        name_wire = required_manifest_wire(
            compiler, raw_fields[0]["type"], types, "objective name")
        action_wire = required_manifest_wire(
            compiler, raw_fields[1]["type"], types, "objective action")
        display_schema = switch_payload(
            compiler, raw_fields[2]["type"], types, "objective display text")
        render_schema = switch_payload(
            compiler, raw_fields[3]["type"], types, "objective render type")
        display_wire = required_manifest_wire(
            compiler, display_schema, types, "objective display text")
        render_wire = required_manifest_wire(
            compiler, render_schema, types, "objective render type")
        fields = [
            ManifestField("name", "name", name_wire),
            ManifestField("action", "action", action_wire),
            ManifestField("displayText", "display_text", display_wire),
            ManifestField("type", "render_type", render_wire),
        ]
        if len(raw_fields) == 4:
            variant = "string_type" if render_wire.suffix == "string" else "numeric_type"
            return tuple(fields), f"scoreboard_objective:{variant}"
        number_option = switch_payload(
            compiler, raw_fields[4]["type"], types, "objective number format")
        number_schema = option_payload(
            compiler, number_option, types, "objective number format")
        number_wire = required_manifest_wire(
            compiler, number_schema, types, "objective number format")
        style_outer = switch_payload(
            compiler, raw_fields[5]["type"], types, "objective styling")
        style_schema = switch_payload(
            compiler, style_outer, types, "objective styling format")
        style_wire = required_manifest_wire(
            compiler, style_schema, types, "objective styling")
        fields.extend([
            ManifestField("number_format.present", "number_format_present", bool_wire),
            ManifestField("number_format", "number_format", number_wire),
            ManifestField("styling", "styling", style_wire),
        ])
        return tuple(fields), "scoreboard_objective:modern"

    if projection == "scoreboard_score":
        if names == ["itemName", "action", "scoreName", "value"]:
            score_schema = switch_payload(
                compiler, raw_fields[2]["type"], types, "1.7 score objective") \
                if compiler.resolve(raw_fields[2]["type"], types)[0] == "switch" \
                else raw_fields[2]["type"]
            value_schema = switch_payload(
                compiler, raw_fields[3]["type"], types, "score value")
            fields = (
                ManifestField("itemName", "item_name", required_manifest_wire(
                    compiler, raw_fields[0]["type"], types, "score owner")),
                ManifestField("action", "action", required_manifest_wire(
                    compiler, raw_fields[1]["type"], types, "score action")),
                ManifestField("scoreName", "score_name", required_manifest_wire(
                    compiler, score_schema, types, "score objective")),
                ManifestField("value", "value", required_manifest_wire(
                    compiler, value_schema, types, "score value")),
            )
            action_suffix = fields[1].wire.suffix
            return fields, (
                "scoreboard_score:1_7" if action_suffix == "i8"
                else "scoreboard_score:legacy"
            )
        if names != [
            "itemName", "scoreName", "value", "display_name", "number_format", "styling"
        ]:
            raise ValueError("modern scoreboard score schema changed")
        display_schema = option_payload(
            compiler, raw_fields[3]["type"], types, "score display name")
        number_schema = option_payload(
            compiler, raw_fields[4]["type"], types, "score number format")
        style_schema = switch_payload(
            compiler, raw_fields[5]["type"], types, "score styling")
        fields = (
            ManifestField("itemName", "item_name", required_manifest_wire(
                compiler, raw_fields[0]["type"], types, "score owner")),
            ManifestField("scoreName", "score_name", required_manifest_wire(
                compiler, raw_fields[1]["type"], types, "score objective")),
            ManifestField("value", "value", required_manifest_wire(
                compiler, raw_fields[2]["type"], types, "score value")),
            ManifestField("display_name.present", "display_name_present", bool_wire),
            ManifestField("display_name", "display_name", required_manifest_wire(
                compiler, display_schema, types, "score display name")),
            ManifestField("number_format.present", "number_format_present", bool_wire),
            ManifestField("number_format", "number_format", required_manifest_wire(
                compiler, number_schema, types, "score number format")),
            ManifestField("styling", "styling", required_manifest_wire(
                compiler, style_schema, types, "score styling")),
        )
        return fields, "scoreboard_score:modern"

    if projection == "scoreboard_reset":
        if names != ["entity_name", "objective_name"]:
            raise ValueError("scoreboard reset schema changed")
        objective_schema = option_payload(
            compiler, raw_fields[1]["type"], types, "reset objective")
        fields = (
            ManifestField("entity_name", "entity_name", required_manifest_wire(
                compiler, raw_fields[0]["type"], types, "reset owner")),
            ManifestField("objective_name.present", "objective_name_present", bool_wire),
            ManifestField("objective_name", "objective_name", required_manifest_wire(
                compiler, objective_schema, types, "reset objective")),
        )
        return fields, "scoreboard_reset"
    raise ValueError(f"unknown scoreboard projection {projection}")


def compile_manifest_packet(compiler: Compiler, spec: dict[str, Any]) -> ManifestPacket:
    name = spec.get("name")
    state = spec.get("state")
    raw_direction = spec.get("direction")
    direction = {"toClient": "clientbound", "toServer": "serverbound"}.get(
        raw_direction)
    if (
        not isinstance(name, str)
        or not isinstance(state, str)
        or direction is None
    ):
        raise ValueError("manifest packet requires name, state and direction")
    ids, schemas = compiler.packet_table(state, direction)
    if name not in ids or name not in schemas:
        raise ValueError(f"packet not found: {state}:{direction}:{name}")
    packet_id = ids[name]
    expected_id = spec.get("expected_id")
    if expected_id is not None and packet_id != int(expected_id):
        raise ValueError(
            f"packet {name} ID is 0x{packet_id:x}, expected 0x{int(expected_id):x}"
        )
    types = compiler.direction_types(state, direction)
    raw_fields = manifest_container(
        compiler, schemas[name], types, f"packet {name}")
    projection = spec.get("projection")
    if projection is not None:
        if spec.get("field_type_overrides"):
            raise ValueError("projected packet cannot also override field types")
        if projection == "single_attribute_no_modifiers":
            fields = manifest_attribute_projection(compiler, name, raw_fields, types)
            return ManifestPacket(
                name, manifest_c_name(name), packet_id, state, str(raw_direction), fields)
        if projection == "source_validated_minecart_steps":
            source_validation = spec.get("source_validation")
            if not isinstance(source_validation, str) or not source_validation.strip():
                raise ValueError(
                    "source_validated_minecart_steps requires source_validation"
                )
            fields, variant = manifest_minecart_steps_projection(
                compiler, name, raw_fields, types
            )
            return ManifestPacket(
                name,
                manifest_c_name(name),
                packet_id,
                state,
                str(raw_direction),
                fields,
                variant,
            )
        if projection == "source_validated_minecart_metadata":
            source_validation = spec.get("source_validation")
            if not isinstance(source_validation, str) or not source_validation.strip():
                raise ValueError(
                    "source_validated_minecart_metadata requires source_validation"
                )
            fields, variant = manifest_minecart_metadata_projection(
                compiler,
                name,
                raw_fields,
                types,
                spec.get("metadata_layout"),
                spec.get("metadata_first_index"),
            )
            return ManifestPacket(
                name,
                manifest_c_name(name),
                packet_id,
                state,
                str(raw_direction),
                fields,
                variant,
            )
        if projection == "source_validated_primed_tnt_metadata":
            source_validation = spec.get("source_validation")
            if not isinstance(source_validation, str) or not source_validation.strip():
                raise ValueError(
                    "source_validated_primed_tnt_metadata requires source_validation"
                )
            fields, variant = manifest_primed_tnt_metadata_projection(
                compiler,
                name,
                raw_fields,
                types,
                spec.get("metadata_layout"),
            )
            return ManifestPacket(
                name,
                manifest_c_name(name),
                packet_id,
                state,
                str(raw_direction),
                fields,
                variant,
            )
        if projection == "source_validated_note_particle":
            source_validation = spec.get("source_validation")
            if not isinstance(source_validation, str) or not source_validation.strip():
                raise ValueError(
                    "source_validated_note_particle requires source_validation"
                )
            fields, variant = manifest_note_particle_projection(
                compiler,
                name,
                raw_fields,
                types,
                spec.get("particle_name"),
                spec.get("particle_id"),
                spec.get("registry_override_reason"),
            )
            return ManifestPacket(
                name,
                manifest_c_name(name),
                packet_id,
                state,
                str(raw_direction),
                fields,
                variant,
            )
        if projection in {
            "scoreboard_objective", "scoreboard_score", "scoreboard_reset"
        }:
            fields, variant = scoreboard_projection(
                compiler, name, projection, raw_fields, types)
            return ManifestPacket(
                name,
                manifest_c_name(name),
                packet_id,
                state,
                str(raw_direction),
                fields,
                variant,
            )
        if projection in {
            "plain_item_slot", "plain_item_contents", "plain_window_items",
            "empty_window_click",
        }:
            fields, variant = inventory_projection(
                compiler, name, projection, raw_fields, types)
            return ManifestPacket(
                name,
                manifest_c_name(name),
                packet_id,
                state,
                str(raw_direction),
                fields,
                variant,
            )
        if projection == "chunk_envelope":
            fields, variant = chunk_envelope_projection(
                compiler, name, raw_fields, types)
            return ManifestPacket(
                name,
                manifest_c_name(name),
                packet_id,
                state,
                str(raw_direction),
                fields,
                variant,
            )
        raise ValueError(f"unknown packet projection: {projection}")

    overrides = spec.get("field_type_overrides", {})
    if not isinstance(overrides, dict):
        raise ValueError(f"packet {name} field_type_overrides must be an object")
    fields = []
    used_overrides: set[str] = set()
    used_names: set[str] = set()
    for raw_field in raw_fields:
        source_name = raw_field.get("name")
        source_schema = raw_field.get("type")
        if not isinstance(source_name, str):
            raise ValueError(f"packet {name} contains an unnamed field")
        selected_schema = source_schema
        override = overrides.get(source_name)
        if override is not None:
            if (
                not isinstance(override, dict)
                or override.get("from") != source_schema
                or not isinstance(override.get("to"), str)
                or not isinstance(override.get("reason"), str)
                or not override["reason"]
            ):
                raise ValueError(f"invalid override for {name}.{source_name}")
            selected_schema = override["to"]
            used_overrides.add(source_name)
        wire = manifest_wire(compiler, selected_schema, types)
        if wire is None:
            raise ValueError(
                f"packet {name} field {source_name} uses unsupported schema "
                f"{selected_schema!r}"
            )
        field_name = manifest_c_name(source_name)
        if field_name in used_names:
            raise ValueError(f"packet {name} repeats generated field {field_name}")
        used_names.add(field_name)
        fields.append(ManifestField(source_name, field_name, wire))
    unused = sorted(set(overrides) - used_overrides)
    if unused:
        raise ValueError(f"packet {name} has unused overrides: {unused}")
    if not fields:
        raise ValueError(f"packet {name} has no fields")
    return ManifestPacket(
        name, manifest_c_name(name), packet_id, state, str(raw_direction), tuple(fields))


def git_revision(repository: Path) -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=repository, text=True).strip()
    except (OSError, subprocess.CalledProcessError) as error:
        raise ValueError(f"cannot resolve git revision for {repository}: {error}") from error


def compile_manifest_profile(minecraft_data: Path,
                             spec: dict[str, Any]) -> ManifestProfile:
    name = spec.get("name")
    schema = spec.get("schema")
    protocol = spec.get("protocol")
    if not isinstance(name, str) or not isinstance(schema, str) or not isinstance(protocol, int):
        raise ValueError("manifest profile requires name, schema and integer protocol")
    schema_root = minecraft_data / "data" / "pc" / schema
    protocol_path = schema_root / "protocol.json"
    version_path = schema_root / "version.json"
    raw = protocol_path.read_bytes()
    document = json.loads(raw)
    version = json.loads(version_path.read_text(encoding="utf-8")).get("version")
    if not isinstance(version, int):
        raise ValueError(f"schema {schema} has no protocol version")
    if version != protocol:
        reason = spec.get("protocol_override_reason")
        if not isinstance(reason, str) or not reason:
            raise ValueError(
                f"profile {name} changes protocol {version} to {protocol} without reason"
            )
    compiler = Compiler(document, protocol, {})
    packet_specs = spec.get("packets")
    if not isinstance(packet_specs, list) or not packet_specs:
        raise ValueError(f"profile {name} has no packet selections")
    packets = tuple(compile_manifest_packet(compiler, packet) for packet in packet_specs)
    constants = []
    for constant in spec.get("constants", []):
        if not isinstance(constant, dict):
            raise ValueError(f"profile {name} has a non-object constant")
        constant_name = constant.get("name")
        value = constant.get("value")
        reason = constant.get("reason")
        if (
            not isinstance(constant_name, str)
            or not isinstance(value, int)
            or not isinstance(reason, str)
            or not reason
        ):
            raise ValueError(f"profile {name} has an invalid constant")
        constants.append((manifest_c_name(constant_name), value, reason))
    return ManifestProfile(
        name,
        manifest_c_name(name),
        protocol,
        schema,
        version,
        hashlib.sha256(raw).hexdigest(),
        tuple(constants),
        packets,
    )


def manifest_macro(*parts: str) -> str:
    return "_".join(manifest_c_name(part).upper() for part in parts)


def render_manifest_header(profile: ManifestProfile, revision: str) -> str:
    guard = manifest_macro("PERRY_MC_GENERATED_PROTOCOL", profile.c_profile, "H")
    lines = [
        "/* Generated by mcprotocol.c/tools/schema_compiler.py; do not edit. */",
        f"/* minecraft-data {revision}; {profile.schema}/protocol.json sha256 {profile.schema_hash} */",
        f"#ifndef {guard}",
        f"#define {guard}",
        "",
        '#include "api.h"',
        "",
        "#include <stdbool.h>",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "",
        f"#define {manifest_macro('PERRY_MC_PROTOCOL', profile.c_profile)} {profile.protocol}",
    ]
    for name, value, _ in profile.constants:
        lines.append(
            f"#define {manifest_macro('PERRY_MC', profile.c_profile, name)} INT32_C({value})"
        )
    for packet in profile.packets:
        lines.append(
            f"#define {manifest_macro('PERRY_MC', profile.c_profile, packet.direction, packet.state, packet.c_packet, 'ID')} "
            f"INT32_C(0x{packet.packet_id:x})"
        )
    lines.append("")
    for packet in profile.packets:
        type_name = f"PerryMc{profile.c_profile.title().replace('_', '')}{packet.c_packet.title().replace('_', '')}"
        if (
            packet.projection is not None
            and packet.projection.startswith("minecart_metadata:")
        ):
            mask_prefix = manifest_macro(
                "PERRY_MC", profile.c_profile, packet.c_packet, "FIELD"
            )
            lines.extend([
                f"#define {mask_prefix}_HURT_TIME (UINT32_C(1) << 0U)",
                f"#define {mask_prefix}_HURT_DIRECTION (UINT32_C(1) << 1U)",
                f"#define {mask_prefix}_DAMAGE (UINT32_C(1) << 2U)",
                f"#define {mask_prefix}_CUSTOM_DISPLAY_BLOCK (UINT32_C(1) << 3U)",
                f"#define {mask_prefix}_DISPLAY_OFFSET (UINT32_C(1) << 4U)",
                f"#define {mask_prefix}_ALL ((UINT32_C(1) << 5U) - UINT32_C(1))",
                "",
            ])
        if (
            packet.projection is not None
            and packet.projection.startswith("primed_tnt_metadata:")
        ):
            mask_prefix = manifest_macro(
                "PERRY_MC", profile.c_profile, packet.c_packet, "FIELD"
            )
            primed_tnt_field_count = (
                2 if ":fuse_and_block_state:" in packet.projection else 1
            )
            lines.extend([
                f"#define {mask_prefix}_FUSE (UINT32_C(1) << 0U)",
                f"#define {mask_prefix}_BLOCK_STATE (UINT32_C(1) << 1U)",
                f"#define {mask_prefix}_ALL ((UINT32_C(1) << {primed_tnt_field_count}U) - UINT32_C(1))",
                "",
            ])
        lines.append(f"typedef struct {type_name} {{")
        if packet.projection is not None and packet.projection.startswith("chunk:"):
            lines.extend([
                "    int32_t x;",
                "    int32_t z;",
                "    bool ground_up;",
                "    bool ignore_old_data;",
                "    size_t section_mask_word_count;",
                "    uint64_t section_mask;",
                "    McBytes heightmaps;",
                "    size_t biome_count;",
                "    int32_t biomes[1024];",
                "    McBytes chunk_data;",
                "    McBytes auxiliary_data;",
            ])
        elif (
            packet.projection is not None
            and packet.projection.startswith("minecart_steps:")
        ):
            lines.extend([
                "    int32_t entity_id;",
                "    size_t step_count;",
                "    struct {",
                "        double position_x;",
                "        double position_y;",
                "        double position_z;",
                "        double movement_x;",
                "        double movement_y;",
                "        double movement_z;",
                "        int8_t yaw;",
                "        int8_t pitch;",
                "        float weight;",
                "    } steps[65];",
            ])
        elif (
            packet.projection is not None
            and packet.projection.startswith("minecart_metadata:")
        ):
            lines.extend([
                "    int32_t entity_id;",
                "    int32_t hurt_time;",
                "    int32_t hurt_direction;",
                "    float damage;",
                "    int32_t display_block_state;",
                "    int32_t display_offset;",
                "    uint32_t fields;",
                "    bool has_custom_display_block;",
            ])
        elif (
            packet.projection is not None
            and packet.projection.startswith("primed_tnt_metadata:")
        ):
            lines.extend([
                "    int32_t entity_id;",
                "    int32_t fuse;",
                "    int32_t block_state;",
                "    uint32_t fields;",
            ])
        elif packet.projection == "inventory:plain_window_items":
            lines.extend([
                f"    {packet.fields[0].wire.c_type} window_id;",
                f"    {packet.fields[1].wire.c_type} state_id;",
                "    size_t item_count;",
                "    int32_t item_ids[128];",
                "    int32_t item_counts[128];",
                "    int32_t carried_item_id;",
                "    int32_t carried_item_count;",
            ])
        else:
            for field in packet.fields:
                lines.append(f"    {field.wire.c_type} {field.c_field};")
        lines.extend([
            f"}} {type_name};",
            "",
            f"bool perry_mc_{profile.c_profile}_decode_{packet.c_packet}(",
            f"    const void *payload, size_t payload_size, {type_name} *value);",
            f"bool perry_mc_{profile.c_profile}_encode_{packet.c_packet}(",
            f"    McPacket *packet, const {type_name} *value);",
            "",
        ])
    lines.extend([f"#endif /* {guard} */", ""])
    return "\n".join(lines)


def manifest_reader(profile: ManifestProfile, field: ManifestField) -> str:
    if field.wire.suffix == "nbt":
        return f"mc_reader_nbt(&reader, false, &decoded.{field.c_field})"
    if field.wire.protocol_argument:
        return (
            f"mc_reader_{field.wire.suffix}(&reader, {profile.protocol}, "
            f"&decoded.{field.c_field})"
        )
    return f"mc_reader_{field.wire.suffix}(&reader, &decoded.{field.c_field})"


def manifest_writer(profile: ManifestProfile, field: ManifestField) -> str:
    if field.wire.suffix == "string":
        return (
            f"mc_packet_string_n(packet, (const char *)value->{field.c_field}.data, "
            f"value->{field.c_field}.size)"
        )
    if field.wire.suffix == "nbt":
        return f"mc_packet_nbt(packet, false, &value->{field.c_field})"
    address = "&" if field.wire.suffix in {
        "uuid", "buffer_i32", "buffer_varint"
    } else ""
    if field.wire.protocol_argument:
        return (
            f"mc_packet_{field.wire.suffix}(packet, {profile.protocol}, "
            f"{address}value->{field.c_field})"
        )
    return f"mc_packet_{field.wire.suffix}(packet, {address}value->{field.c_field})"


def render_minecart_steps_projection(
    profile: ManifestProfile,
    packet: ManifestPacket,
    type_name: str,
) -> list[str]:
    if packet.projection not in {
        "minecart_steps:movement", "minecart_steps:velocity"
    }:
        raise ValueError(f"unknown minecart step projection {packet.projection}")
    decode_function = f"perry_mc_{profile.c_profile}_decode_{packet.c_packet}"
    encode_function = f"perry_mc_{profile.c_profile}_encode_{packet.c_packet}"
    return [
        f"bool {decode_function}(",
        f"    const void *payload, size_t payload_size, {type_name} *value) {{",
        "    if ((payload == NULL && payload_size != 0U) || value == NULL) return false;",
        "    McReader reader;",
        f"    {type_name} decoded = {{0}};",
        "    int32_t step_count = -1;",
        "    mc_reader_init(&reader, payload, payload_size);",
        "    if (!mc_reader_varint(&reader, &decoded.entity_id) ||",
        "        !mc_reader_varint(&reader, &step_count) || step_count < 0 ||",
        "        (size_t)step_count > sizeof(decoded.steps) / sizeof(decoded.steps[0]))",
        "        return false;",
        "    decoded.step_count = (size_t)step_count;",
        "    for (size_t index = 0U; index < decoded.step_count; ++index) {",
        "        if (!mc_reader_double(&reader, &decoded.steps[index].position_x) ||",
        "            !mc_reader_double(&reader, &decoded.steps[index].position_y) ||",
        "            !mc_reader_double(&reader, &decoded.steps[index].position_z) ||",
        "            !mc_reader_double(&reader, &decoded.steps[index].movement_x) ||",
        "            !mc_reader_double(&reader, &decoded.steps[index].movement_y) ||",
        "            !mc_reader_double(&reader, &decoded.steps[index].movement_z) ||",
        "            !mc_reader_i8(&reader, &decoded.steps[index].yaw) ||",
        "            !mc_reader_i8(&reader, &decoded.steps[index].pitch) ||",
        "            !mc_reader_float(&reader, &decoded.steps[index].weight)) return false;",
        "    }",
        "    if (mc_reader_remaining(&reader) != 0U) return false;",
        "    *value = decoded;",
        "    return true;",
        "}",
        "",
        f"bool {encode_function}(",
        f"    McPacket *packet, const {type_name} *value) {{",
        "    if (packet == NULL || value == NULL ||",
        "        value->step_count > sizeof(value->steps) / sizeof(value->steps[0]) ||",
        "        !mc_packet_varint(packet, value->entity_id) ||",
        "        !mc_packet_varint(packet, (int32_t)value->step_count)) return false;",
        "    for (size_t index = 0U; index < value->step_count; ++index) {",
        "        if (!mc_packet_double(packet, value->steps[index].position_x) ||",
        "            !mc_packet_double(packet, value->steps[index].position_y) ||",
        "            !mc_packet_double(packet, value->steps[index].position_z) ||",
        "            !mc_packet_double(packet, value->steps[index].movement_x) ||",
        "            !mc_packet_double(packet, value->steps[index].movement_y) ||",
        "            !mc_packet_double(packet, value->steps[index].movement_z) ||",
        "            !mc_packet_i8(packet, value->steps[index].yaw) ||",
        "            !mc_packet_i8(packet, value->steps[index].pitch) ||",
        "            !mc_packet_float(packet, value->steps[index].weight)) return false;",
        "    }",
        "    return !packet->failed;",
        "}",
        "",
    ]


def render_minecart_metadata_projection(
    profile: ManifestProfile,
    packet: ManifestPacket,
    type_name: str,
) -> list[str]:
    parts = packet.projection.split(":") if packet.projection is not None else []
    if (
        len(parts) != 4
        or parts[0] != "minecart_metadata"
        or parts[1]
        not in {
            "packed_block_state_and_flag",
            "block_state_and_flag",
            "optional_block_state",
        }
        or parts[2] not in {"5", "6", "7", "8", "17"}
        or parts[3] not in {"i32", "varint"}
    ):
        raise ValueError(f"unknown minecart metadata projection {packet.projection}")
    layout = parts[1]
    first_index = int(parts[2])
    entity_wire = parts[3]
    packed = layout == "packed_block_state_and_flag"
    has_display_flag = layout != "optional_block_state"
    int_serializer = 2 if packed else 1
    float_serializer = 3 if packed or profile.protocol >= 761 else 2
    bool_serializer = (
        0
        if packed
        else 6
        if profile.protocol <= 340
        else 7
        if profile.protocol <= 760
        else 8
    )
    display_serializer = int_serializer if has_display_flag else 15
    display_index = first_index + 3
    offset_index = first_index + 4
    flag_index = first_index + 5
    value_reader = "mc_reader_i32" if packed else "mc_reader_varint"
    value_writer = "mc_packet_i32" if packed else "mc_packet_varint"
    decode_function = f"perry_mc_{profile.c_profile}_decode_{packet.c_packet}"
    encode_function = f"perry_mc_{profile.c_profile}_encode_{packet.c_packet}"
    mask = manifest_macro("PERRY_MC", profile.c_profile, packet.c_packet, "FIELD")
    lines = [
        f"bool {decode_function}(",
        f"    const void *payload, size_t payload_size, {type_name} *value) {{",
        "    if ((payload == NULL && payload_size != 0U) || value == NULL) return false;",
        "    McReader reader;",
        f"    {type_name} decoded = {{0}};",
        "    uint32_t seen = 0U;",
        "    bool saw_display_state = false;",
        *(["    bool saw_display_flag = false;"] if has_display_flag else []),
        "    bool terminated = false;",
        *(["    uint8_t byte_value = 0U;"] if packed else []),
        "    mc_reader_init(&reader, payload, payload_size);",
        f"    if (!mc_reader_{entity_wire}(&reader, &decoded.entity_id) || decoded.entity_id <= 0)",
        "        return false;",
        "    while (mc_reader_remaining(&reader) != 0U) {",
        "        uint8_t index = 0U;",
        "        int32_t serializer = -1;",
    ]
    if packed:
        lines.extend([
            "        uint8_t header = 0U;",
            "        if (!mc_reader_u8(&reader, &header)) return false;",
            "        if (header == UINT8_C(0x7f)) {",
            "            terminated = true;",
            "            break;",
            "        }",
            "        index = (uint8_t)(header & UINT8_C(0x1f));",
            "        serializer = (int32_t)(header >> 5U);",
        ])
    else:
        lines.extend([
            "        if (!mc_reader_u8(&reader, &index)) return false;",
            "        if (index == UINT8_C(0xff)) {",
            "            terminated = true;",
            "            break;",
            "        }",
        ])
        if profile.protocol <= 340:
            lines.extend([
                "        uint8_t serializer_u8 = 0U;",
                "        if (!mc_reader_u8(&reader, &serializer_u8)) return false;",
                "        serializer = serializer_u8;",
            ])
        else:
            lines.append("        if (!mc_reader_varint(&reader, &serializer)) return false;")
    lines.extend([
        "        switch (index) {",
        f"        case {first_index}U:",
        f"            if (serializer != {int_serializer} || (seen & {mask}_HURT_TIME) != 0U ||",
        f"                !{value_reader}(&reader, &decoded.hurt_time)) return false;",
        f"            seen |= {mask}_HURT_TIME;",
        "            break;",
        f"        case {first_index + 1}U:",
        f"            if (serializer != {int_serializer} || (seen & {mask}_HURT_DIRECTION) != 0U ||",
        f"                !{value_reader}(&reader, &decoded.hurt_direction)) return false;",
        f"            seen |= {mask}_HURT_DIRECTION;",
        "            break;",
        f"        case {first_index + 2}U:",
        f"            if (serializer != {float_serializer} || (seen & {mask}_DAMAGE) != 0U ||",
        "                !mc_reader_float(&reader, &decoded.damage) ||",
        "                !isfinite(decoded.damage)) return false;",
        f"            seen |= {mask}_DAMAGE;",
        "            break;",
        f"        case {display_index}U:",
        f"            if (serializer != {display_serializer} || saw_display_state ||",
        f"                !{value_reader}(&reader, &decoded.display_block_state) ||",
        "                decoded.display_block_state < 0) return false;",
        "            saw_display_state = true;",
        f"            seen |= {mask}_CUSTOM_DISPLAY_BLOCK;",
    ])
    if not has_display_flag:
        lines.append(
            "            decoded.has_custom_display_block = decoded.display_block_state != 0;"
        )
    lines.extend([
        "            break;",
        f"        case {offset_index}U:",
        f"            if (serializer != {int_serializer} || (seen & {mask}_DISPLAY_OFFSET) != 0U ||",
        f"                !{value_reader}(&reader, &decoded.display_offset)) return false;",
        f"            seen |= {mask}_DISPLAY_OFFSET;",
        "            break;",
    ])
    if has_display_flag:
        if packed:
            lines.extend([
                f"        case {flag_index}U:",
                f"            if (serializer != {bool_serializer} || saw_display_flag ||",
                "                !mc_reader_u8(&reader, &byte_value) || byte_value > 1U)",
                "                return false;",
                "            decoded.has_custom_display_block = byte_value != 0U;",
                "            saw_display_flag = true;",
                "            break;",
            ])
        else:
            lines.extend([
                f"        case {flag_index}U:",
                f"            if (serializer != {bool_serializer} || saw_display_flag ||",
                "                !mc_reader_bool(&reader, &decoded.has_custom_display_block))",
                "                return false;",
                "            saw_display_flag = true;",
                "            break;",
            ])
    lines.extend([
        "        default:",
        "            return false;",
        "        }",
        "    }",
        "    if (!terminated || mc_reader_remaining(&reader) != 0U || seen == 0U)",
        "        return false;",
    ])
    if has_display_flag:
        lines.extend([
            "    if (saw_display_state != saw_display_flag) return false;",
        ])
    lines.extend([
        "    decoded.fields = seen;",
        "    *value = decoded;",
        "    return true;",
        "}",
        "",
        f"bool {encode_function}(",
        f"    McPacket *packet, const {type_name} *value) {{",
        "    if (packet == NULL || value == NULL || value->entity_id <= 0 ||",
        f"        value->fields == 0U || (value->fields & ~{mask}_ALL) != 0U ||",
        "        !isfinite(value->damage) || value->display_block_state < 0 ||",
    ])
    if not has_display_flag:
        lines.append(
            "        (value->has_custom_display_block && value->display_block_state == 0) ||"
        )
    lines.append(
        f"        !mc_packet_{entity_wire}(packet, value->entity_id)) return false;"
    )

    def header_failures(index: int, serializer: int) -> list[str]:
        if packed:
            header = (serializer << 5) | index
            return [f"!mc_packet_u8(packet, UINT8_C(0x{header:02x}))"]
        failures = [f"!mc_packet_u8(packet, UINT8_C({index}))"]
        failures.append(
            f"!mc_packet_u8(packet, UINT8_C({serializer}))"
            if profile.protocol <= 340
            else f"!mc_packet_varint(packet, {serializer})"
        )
        return failures

    def emit_field(field: str, index: int, serializer: int, writer: str) -> None:
        failures = header_failures(index, serializer) + [f"!{writer}"]
        lines.extend([
            f"    if ((value->fields & {mask}_{field}) != 0U &&",
            "        (" + " || ".join(failures) + ")) return false;",
        ])

    emit_field(
        "HURT_TIME",
        first_index,
        int_serializer,
        f"{value_writer}(packet, value->hurt_time)",
    )
    emit_field(
        "HURT_DIRECTION",
        first_index + 1,
        int_serializer,
        f"{value_writer}(packet, value->hurt_direction)",
    )
    emit_field(
        "DAMAGE",
        first_index + 2,
        float_serializer,
        "mc_packet_float(packet, value->damage)",
    )
    display_value = (
        "value->has_custom_display_block ? value->display_block_state : 0"
    )
    emit_field(
        "CUSTOM_DISPLAY_BLOCK",
        display_index,
        display_serializer,
        f"{value_writer}(packet, {display_value})",
    )
    emit_field(
        "DISPLAY_OFFSET",
        offset_index,
        int_serializer,
        f"{value_writer}(packet, value->display_offset)",
    )
    if has_display_flag:
        flag_writer = (
            "mc_packet_u8(packet, value->has_custom_display_block ? UINT8_C(1) : UINT8_C(0))"
            if packed
            else "mc_packet_bool(packet, value->has_custom_display_block)"
        )
        emit_field(
            "CUSTOM_DISPLAY_BLOCK",
            flag_index,
            bool_serializer,
            flag_writer,
        )
    lines.extend([
        f"    return mc_packet_u8(packet, UINT8_C({'0x7f' if packed else '0xff'})) && !packet->failed;",
        "}",
        "",
    ])
    return lines


def render_primed_tnt_metadata_projection(
    profile: ManifestProfile,
    packet: ManifestPacket,
    type_name: str,
) -> list[str]:
    parts = packet.projection.split(":") if packet.projection is not None else []
    if (
        len(parts) != 3
        or parts[0] != "primed_tnt_metadata"
        or parts[1] not in {"fuse", "fuse_and_block_state"}
        or parts[2] not in {"5", "6", "7", "8"}
    ):
        raise ValueError(f"unknown primed TNT metadata projection {packet.projection}")
    with_block_state = parts[1] == "fuse_and_block_state"
    fuse_index = int(parts[2])
    block_state_index = fuse_index + 1
    decode_function = f"perry_mc_{profile.c_profile}_decode_{packet.c_packet}"
    encode_function = f"perry_mc_{profile.c_profile}_encode_{packet.c_packet}"
    mask = manifest_macro("PERRY_MC", profile.c_profile, packet.c_packet, "FIELD")
    lines = [
        f"bool {decode_function}(",
        f"    const void *payload, size_t payload_size, {type_name} *value) {{",
        "    if ((payload == NULL && payload_size != 0U) || value == NULL) return false;",
        "    McReader reader;",
        f"    {type_name} decoded = {{0}};",
        "    uint32_t seen = 0U;",
        "    bool terminated = false;",
        "    mc_reader_init(&reader, payload, payload_size);",
        "    if (!mc_reader_varint(&reader, &decoded.entity_id) || decoded.entity_id <= 0)",
        "        return false;",
        "    while (mc_reader_remaining(&reader) != 0U) {",
        "        uint8_t index = 0U;",
        "        int32_t serializer = -1;",
        "        if (!mc_reader_u8(&reader, &index)) return false;",
        "        if (index == UINT8_C(0xff)) {",
        "            terminated = true;",
        "            break;",
        "        }",
        "        if (!mc_reader_varint(&reader, &serializer)) return false;",
        f"        if (index == UINT8_C({fuse_index})) {{",
        f"            if (serializer != 1 || (seen & {mask}_FUSE) != 0U ||",
        "                !mc_reader_varint(&reader, &decoded.fuse)) return false;",
        f"            seen |= {mask}_FUSE;",
        "            continue;",
        "        }",
    ]
    if with_block_state:
        lines.extend([
            f"        if (index == UINT8_C({block_state_index})) {{",
            f"            if (serializer != 14 || (seen & {mask}_BLOCK_STATE) != 0U ||",
            "                !mc_reader_varint(&reader, &decoded.block_state) ||",
            "                decoded.block_state < 0) return false;",
            f"            seen |= {mask}_BLOCK_STATE;",
            "            continue;",
            "        }",
        ])
    lines.extend([
        "        return false;",
        "    }",
        "    if (!terminated || mc_reader_remaining(&reader) != 0U || seen == 0U)",
        "        return false;",
        "    decoded.fields = seen;",
        "    *value = decoded;",
        "    return true;",
        "}",
        "",
        f"bool {encode_function}(",
        f"    McPacket *packet, const {type_name} *value) {{",
        "    if (packet == NULL || value == NULL || value->entity_id <= 0 ||",
        f"        value->fields == 0U || (value->fields & ~{mask}_ALL) != 0U ||",
        *(["        value->block_state < 0 ||"] if with_block_state else []),
        "        !mc_packet_varint(packet, value->entity_id)) return false;",
        f"    if ((value->fields & {mask}_FUSE) != 0U &&",
        f"        (!mc_packet_u8(packet, UINT8_C({fuse_index})) || !mc_packet_varint(packet, 1) ||",
        "         !mc_packet_varint(packet, value->fuse))) return false;",
    ])
    if with_block_state:
        lines.extend([
            f"    if ((value->fields & {mask}_BLOCK_STATE) != 0U &&",
            f"        (!mc_packet_u8(packet, UINT8_C({block_state_index})) || !mc_packet_varint(packet, 14) ||",
            "         !mc_packet_varint(packet, value->block_state))) return false;",
        ])
    lines.extend([
        "    return mc_packet_u8(packet, UINT8_C(0xff)) && !packet->failed;",
        "}",
        "",
    ])
    return lines


def render_note_particle_projection(
    profile: ManifestProfile,
    packet: ManifestPacket,
    type_name: str,
) -> list[str]:
    parts = packet.projection.split(":") if packet.projection is not None else []
    layouts = {
        "name_f32",
        "head_i32_float",
        "head_i32_double",
        "head_varint_double",
        "tail_varint_double",
        "tail_varint_double_always",
    }
    named = len(parts) == 2 and parts[0] == "note_particle" and parts[1] == "name_f32"
    numbered = (
        len(parts) == 3
        and parts[0] == "note_particle"
        and parts[1] in layouts
        and parts[1] != "name_f32"
        and parts[2].isdigit()
    )
    if not named and not numbered:
        raise ValueError(f"unknown NOTE particle projection {packet.projection}")
    layout = parts[1]
    head = layout.startswith("head_")
    selector_wire = "i32" if layout.startswith("head_i32_") else "varint"
    particle_id = int(parts[2]) if numbered else None
    decode_function = f"perry_mc_{profile.c_profile}_decode_{packet.c_packet}"
    encode_function = f"perry_mc_{profile.c_profile}_encode_{packet.c_packet}"
    lines = [
        f"bool {decode_function}(",
        f"    const void *payload, size_t payload_size, {type_name} *value) {{",
        "    if ((payload == NULL && payload_size != 0U) || value == NULL) return false;",
        "    McReader reader;",
        f"    {type_name} decoded = {{0}};",
    ]
    if named:
        lines.append("    McBytes particle_name = {0};")
    else:
        lines.append("    int32_t particle_id = -1;")
    lines.append("    mc_reader_init(&reader, payload, payload_size);")
    checks = []
    if named:
        checks.extend([
            "!mc_reader_string(&reader, &particle_name)",
            "particle_name.size != 4U",
            'memcmp(particle_name.data, "note", 4U) != 0',
        ])
    elif head:
        checks.extend([
            f"!mc_reader_{selector_wire}(&reader, &particle_id)",
            f"particle_id != INT32_C({particle_id})",
        ])
    checks.extend(f"!{manifest_reader(profile, field)}" for field in packet.fields)
    if numbered and not head:
        checks.extend([
            f"!mc_reader_{selector_wire}(&reader, &particle_id)",
            f"particle_id != INT32_C({particle_id})",
        ])
    checks.append("mc_reader_remaining(&reader) != 0U")
    lines.extend([
        "    if (" + " ||\n        ".join(checks) + ") return false;",
        "    *value = decoded;",
        "    return true;",
        "}",
        "",
        f"bool {encode_function}(",
        f"    McPacket *packet, const {type_name} *value) {{",
        "    if (packet == NULL || value == NULL) return false;",
    ])
    writers = []
    if named:
        writers.append('mc_packet_string_n(packet, "note", 4U)')
    elif head:
        writers.append(f"mc_packet_{selector_wire}(packet, INT32_C({particle_id}))")
    writers.extend(manifest_writer(profile, field) for field in packet.fields)
    if numbered and not head:
        writers.append(f"mc_packet_{selector_wire}(packet, INT32_C({particle_id}))")
    lines.extend([
        "    return " + " &&\n           ".join(writers) + " && !packet->failed;",
        "}",
        "",
    ])
    return lines


def render_scoreboard_projection(profile: ManifestProfile,
                                 packet: ManifestPacket,
                                 type_name: str) -> list[str]:
    decode_function = f"perry_mc_{profile.c_profile}_decode_{packet.c_packet}"
    encode_function = f"perry_mc_{profile.c_profile}_encode_{packet.c_packet}"
    variant = packet.projection
    lines = [
        f"bool {decode_function}(",
        f"    const void *payload, size_t payload_size, {type_name} *value) {{",
        "    if ((payload == NULL && payload_size != 0U) || value == NULL) return false;",
        "    McReader reader;",
        f"    {type_name} decoded = {{0}};",
        "    mc_reader_init(&reader, payload, payload_size);",
    ]
    if variant == "scoreboard_objective:1_7":
        lines.extend([
            "    if (!mc_reader_string(&reader, &decoded.name) ||",
            "        !mc_reader_string(&reader, &decoded.display_text) ||",
            "        !mc_reader_i8(&reader, &decoded.action) ||",
            "        (decoded.action != 0 && decoded.action != 1 && decoded.action != 2) ||",
            "        mc_reader_remaining(&reader) != 0U) return false;",
        ])
    elif variant in {
        "scoreboard_objective:string_type", "scoreboard_objective:numeric_type"
    }:
        render_reader = (
            "mc_reader_string(&reader, &decoded.render_type)"
            if variant.endswith("string_type")
            else "mc_reader_varint(&reader, &decoded.render_type)"
        )
        lines.extend([
            "    if (!mc_reader_string(&reader, &decoded.name) ||",
            "        !mc_reader_i8(&reader, &decoded.action) ||",
            "        (decoded.action != 0 && decoded.action != 1 && decoded.action != 2)) return false;",
            "    if ((decoded.action == 0 || decoded.action == 2) &&",
            f"        (!mc_reader_string(&reader, &decoded.display_text) || !{render_reader})) return false;",
            "    if (mc_reader_remaining(&reader) != 0U) return false;",
        ])
    elif variant == "scoreboard_objective:modern":
        lines.extend([
            "    if (!mc_reader_string(&reader, &decoded.name) ||",
            "        !mc_reader_i8(&reader, &decoded.action) ||",
            "        (decoded.action != 0 && decoded.action != 1 && decoded.action != 2)) return false;",
            "    if (decoded.action == 0 || decoded.action == 2) {",
            "        if (!mc_reader_nbt(&reader, false, &decoded.display_text) ||",
            "            !mc_reader_varint(&reader, &decoded.render_type) ||",
            "            !mc_reader_bool(&reader, &decoded.number_format_present)) return false;",
            "        if (decoded.number_format_present &&",
            "            !mc_reader_varint(&reader, &decoded.number_format)) return false;",
            "        if (decoded.number_format_present &&",
            "            (decoded.number_format == 1 || decoded.number_format == 2) &&",
            "            !mc_reader_nbt(&reader, false, &decoded.styling)) return false;",
            "    }",
            "    if (mc_reader_remaining(&reader) != 0U) return false;",
        ])
    elif variant in {"scoreboard_score:1_7", "scoreboard_score:legacy"}:
        action_reader = "mc_reader_i8" if variant.endswith("1_7") else "mc_reader_varint"
        lines.extend([
            "    if (!mc_reader_string(&reader, &decoded.item_name) ||",
            f"        !{action_reader}(&reader, &decoded.action) ||",
            "        (decoded.action != 0 && decoded.action != 1)) return false;",
        ])
        if variant.endswith("1_7"):
            lines.extend([
                "    if (decoded.action == 0 &&",
                "        (!mc_reader_string(&reader, &decoded.score_name) ||",
                "         !mc_reader_i32(&reader, &decoded.value))) return false;",
            ])
        else:
            lines.extend([
                "    if (!mc_reader_string(&reader, &decoded.score_name)) return false;",
                "    if (decoded.action == 0 &&",
                "        !mc_reader_varint(&reader, &decoded.value)) return false;",
            ])
        lines.append("    if (mc_reader_remaining(&reader) != 0U) return false;")
    elif variant == "scoreboard_score:modern":
        lines.extend([
            "    if (!mc_reader_string(&reader, &decoded.item_name) ||",
            "        !mc_reader_string(&reader, &decoded.score_name) ||",
            "        !mc_reader_varint(&reader, &decoded.value) ||",
            "        !mc_reader_bool(&reader, &decoded.display_name_present)) return false;",
            "    if (decoded.display_name_present &&",
            "        !mc_reader_nbt(&reader, false, &decoded.display_name)) return false;",
            "    if (!mc_reader_bool(&reader, &decoded.number_format_present)) return false;",
            "    if (decoded.number_format_present &&",
            "        !mc_reader_varint(&reader, &decoded.number_format)) return false;",
            "    if (decoded.number_format_present &&",
            "        (decoded.number_format == 1 || decoded.number_format == 2) &&",
            "        !mc_reader_nbt(&reader, false, &decoded.styling)) return false;",
            "    if (mc_reader_remaining(&reader) != 0U) return false;",
        ])
    elif variant == "scoreboard_reset":
        lines.extend([
            "    if (!mc_reader_string(&reader, &decoded.entity_name) ||",
            "        !mc_reader_bool(&reader, &decoded.objective_name_present)) return false;",
            "    if (decoded.objective_name_present &&",
            "        !mc_reader_string(&reader, &decoded.objective_name)) return false;",
            "    if (mc_reader_remaining(&reader) != 0U) return false;",
        ])
    else:
        raise ValueError(f"unknown rendered projection {variant}")
    lines.extend([
        "    *value = decoded;",
        "    return true;",
        "}",
        "",
        f"bool {encode_function}(",
        f"    McPacket *packet, const {type_name} *value) {{",
        "    if (packet == NULL || value == NULL) return false;",
    ])
    if variant == "scoreboard_objective:1_7":
        lines.extend([
            "    if (value->action != 0 && value->action != 1 && value->action != 2) return false;",
            "    return mc_packet_string_n(packet, (const char *)value->name.data, value->name.size) &&",
            "           mc_packet_string_n(packet, (const char *)value->display_text.data, value->display_text.size) &&",
            "           mc_packet_i8(packet, value->action);",
        ])
    elif variant in {
        "scoreboard_objective:string_type", "scoreboard_objective:numeric_type"
    }:
        render_writer = (
            "mc_packet_string_n(packet, (const char *)value->render_type.data, value->render_type.size)"
            if variant.endswith("string_type")
            else "mc_packet_varint(packet, value->render_type)"
        )
        lines.extend([
            "    if (value->action != 0 && value->action != 1 && value->action != 2) return false;",
            "    if (!mc_packet_string_n(packet, (const char *)value->name.data, value->name.size) ||",
            "        !mc_packet_i8(packet, value->action)) return false;",
            "    if (value->action == 0 || value->action == 2) {",
            "        if (!mc_packet_string_n(packet, (const char *)value->display_text.data, value->display_text.size) ||",
            f"            !{render_writer}) return false;",
            "    }",
            "    return !packet->failed;",
        ])
    elif variant == "scoreboard_objective:modern":
        lines.extend([
            "    if (value->action != 0 && value->action != 1 && value->action != 2) return false;",
            "    if (!mc_packet_string_n(packet, (const char *)value->name.data, value->name.size) ||",
            "        !mc_packet_i8(packet, value->action)) return false;",
            "    if (value->action == 0 || value->action == 2) {",
            "        if (!mc_packet_nbt(packet, false, &value->display_text) ||",
            "            !mc_packet_varint(packet, value->render_type) ||",
            "            !mc_packet_bool(packet, value->number_format_present)) return false;",
            "        if (value->number_format_present &&",
            "            !mc_packet_varint(packet, value->number_format)) return false;",
            "        if (value->number_format_present &&",
            "            (value->number_format == 1 || value->number_format == 2) &&",
            "            !mc_packet_nbt(packet, false, &value->styling)) return false;",
            "    }",
            "    return !packet->failed;",
        ])
    elif variant in {"scoreboard_score:1_7", "scoreboard_score:legacy"}:
        action_writer = "mc_packet_i8" if variant.endswith("1_7") else "mc_packet_varint"
        lines.extend([
            "    if (value->action != 0 && value->action != 1) return false;",
            "    if (!mc_packet_string_n(packet, (const char *)value->item_name.data, value->item_name.size) ||",
            f"        !{action_writer}(packet, value->action)) return false;",
        ])
        if variant.endswith("1_7"):
            lines.extend([
                "    if (value->action == 0 &&",
                "        (!mc_packet_string_n(packet, (const char *)value->score_name.data, value->score_name.size) ||",
                "         !mc_packet_i32(packet, value->value))) return false;",
            ])
        else:
            lines.extend([
                "    if (!mc_packet_string_n(packet, (const char *)value->score_name.data, value->score_name.size)) return false;",
                "    if (value->action == 0 && !mc_packet_varint(packet, value->value)) return false;",
            ])
        lines.append("    return !packet->failed;")
    elif variant == "scoreboard_score:modern":
        lines.extend([
            "    if (!mc_packet_string_n(packet, (const char *)value->item_name.data, value->item_name.size) ||",
            "        !mc_packet_string_n(packet, (const char *)value->score_name.data, value->score_name.size) ||",
            "        !mc_packet_varint(packet, value->value) ||",
            "        !mc_packet_bool(packet, value->display_name_present)) return false;",
            "    if (value->display_name_present &&",
            "        !mc_packet_nbt(packet, false, &value->display_name)) return false;",
            "    if (!mc_packet_bool(packet, value->number_format_present)) return false;",
            "    if (value->number_format_present &&",
            "        !mc_packet_varint(packet, value->number_format)) return false;",
            "    if (value->number_format_present &&",
            "        (value->number_format == 1 || value->number_format == 2) &&",
            "        !mc_packet_nbt(packet, false, &value->styling)) return false;",
            "    return !packet->failed;",
        ])
    else:
        lines.extend([
            "    if (!mc_packet_string_n(packet, (const char *)value->entity_name.data, value->entity_name.size) ||",
            "        !mc_packet_bool(packet, value->objective_name_present)) return false;",
            "    if (value->objective_name_present &&",
            "        !mc_packet_string_n(packet, (const char *)value->objective_name.data, value->objective_name.size)) return false;",
            "    return !packet->failed;",
        ])
    lines.extend(["}", ""])
    return lines


def render_inventory_projection(profile: ManifestProfile,
                                packet: ManifestPacket,
                                type_name: str) -> list[str]:
    decode_function = f"perry_mc_{profile.c_profile}_decode_{packet.c_packet}"
    encode_function = f"perry_mc_{profile.c_profile}_encode_{packet.c_packet}"
    variant = packet.projection
    lines = [
        f"bool {decode_function}(",
        f"    const void *payload, size_t payload_size, {type_name} *value) {{",
        "    if ((payload == NULL && payload_size != 0U) || value == NULL) return false;",
        "    McReader reader;",
        f"    {type_name} decoded = {{0}};",
        "    mc_reader_init(&reader, payload, payload_size);",
    ]
    if variant == "inventory:plain_item_slot":
        lines.extend([
            f"    if (!{manifest_reader(profile, packet.fields[0])} ||",
            f"        !mc_reader_plain_item(&reader, {profile.protocol},",
            "            &decoded.item_id, &decoded.item_count) ||",
            "        mc_reader_remaining(&reader) != 0U) return false;",
        ])
    elif variant == "inventory:plain_item_contents":
        lines.extend([
            f"    if (!mc_reader_plain_item(&reader, {profile.protocol},",
            "            &decoded.item_id, &decoded.item_count) ||",
            "        mc_reader_remaining(&reader) != 0U) return false;",
        ])
    elif variant == "inventory:plain_window_items":
        lines.extend([
            "    int32_t item_count = -1;",
            f"    if (!{manifest_reader(profile, packet.fields[0])} ||",
            f"        !{manifest_reader(profile, packet.fields[1])} ||",
            "        !mc_reader_varint(&reader, &item_count) || item_count < 0 ||",
            "        (size_t)item_count > sizeof(decoded.item_ids) / sizeof(decoded.item_ids[0])) return false;",
            "    decoded.item_count = (size_t)item_count;",
            "    for (size_t index = 0U; index < decoded.item_count; ++index) {",
            f"        if (!mc_reader_plain_item(&reader, {profile.protocol},",
            "                &decoded.item_ids[index], &decoded.item_counts[index])) return false;",
            "    }",
            f"    if (!mc_reader_plain_item(&reader, {profile.protocol},",
            "            &decoded.carried_item_id, &decoded.carried_item_count) ||",
            "        mc_reader_remaining(&reader) != 0U) return false;",
        ])
    elif variant == "inventory:empty_window_click":
        lines.extend([
            "    int32_t changed_slot_count = -1;",
            "    bool cursor_present = true;",
            "    if (" + " ||\n        ".join(
                "!" + manifest_reader(profile, field) for field in packet.fields
            ) + " ||",
            "        !mc_reader_varint(&reader, &changed_slot_count) ||",
            "        changed_slot_count != 0 ||",
            "        !mc_reader_bool(&reader, &cursor_present) || cursor_present ||",
            "        mc_reader_remaining(&reader) != 0U) return false;",
        ])
    else:
        raise ValueError(f"unknown inventory projection renderer {variant}")
    lines.extend([
        "    *value = decoded;",
        "    return true;",
        "}",
        "",
        f"bool {encode_function}(",
        f"    McPacket *packet, const {type_name} *value) {{",
        "    if (packet == NULL || value == NULL) return false;",
    ])
    if variant == "inventory:plain_item_slot":
        lines.extend([
            f"    return {manifest_writer(profile, packet.fields[0])} &&",
            f"           mc_packet_plain_item(packet, {profile.protocol},",
            "               value->item_id, value->item_count);",
        ])
    elif variant == "inventory:plain_item_contents":
        lines.extend([
            f"    return mc_packet_plain_item(packet, {profile.protocol},",
            "        value->item_id, value->item_count);",
        ])
    elif variant == "inventory:plain_window_items":
        lines.extend([
            "    if (value->item_count > sizeof(value->item_ids) / sizeof(value->item_ids[0]) ||",
            f"        !{manifest_writer(profile, packet.fields[0])} ||",
            f"        !{manifest_writer(profile, packet.fields[1])} ||",
            "        !mc_packet_varint(packet, (int32_t)value->item_count)) return false;",
            "    for (size_t index = 0U; index < value->item_count; ++index) {",
            f"        if (!mc_packet_plain_item(packet, {profile.protocol},",
            "                value->item_ids[index], value->item_counts[index])) return false;",
            "    }",
            f"    return mc_packet_plain_item(packet, {profile.protocol},",
            "        value->carried_item_id, value->carried_item_count);",
        ])
    else:
        lines.extend([
            "    if (" + " ||\n        ".join(
                "!" + manifest_writer(profile, field) for field in packet.fields
            ) + ") return false;",
            "    return mc_packet_varint(packet, 0) && mc_packet_bool(packet, false);",
        ])
    lines.extend(["}", ""])
    return lines


def render_modern_chunk_projection(profile: ManifestProfile,
                                   packet: ManifestPacket,
                                   type_name: str) -> list[str]:
    decode_function = f"perry_mc_{profile.c_profile}_decode_{packet.c_packet}"
    encode_function = f"perry_mc_{profile.c_profile}_encode_{packet.c_packet}"
    auxiliary_function = f"perry_mc_{profile.c_profile}_{packet.c_packet}_auxiliary"
    heightmap_function = f"perry_mc_{profile.c_profile}_{packet.c_packet}_heightmaps"
    variant = packet.projection
    trust_edges = variant == "chunk:modern:named_nbt:trust"
    registry_heightmaps = variant == "chunk:modern:registry"
    if variant not in {
        "chunk:modern:named_nbt:trust",
        "chunk:modern:named_nbt",
        "chunk:modern:anonymous_nbt",
        "chunk:modern:registry",
    }:
        raise ValueError(f"unknown modern chunk projection renderer {variant}")
    lines: list[str] = []
    if registry_heightmaps:
        lines.extend([
            f"static bool {heightmap_function}(McReader *reader) {{",
            "    int32_t heightmap_count = -1;",
            "    if (reader == NULL || !mc_reader_varint(reader, &heightmap_count) ||",
            "        heightmap_count < 0 || heightmap_count > 16) return false;",
            "    for (int32_t heightmap_index = 0;",
            "         heightmap_index < heightmap_count; ++heightmap_index) {",
            "        int32_t type = -1;",
            "        int32_t long_count = -1;",
            "        if (!mc_reader_varint(reader, &type) || type < 0 ||",
            "            !mc_reader_varint(reader, &long_count) ||",
            "            long_count < 0 || long_count > 64 ||",
            "            !mc_reader_skip(reader, (size_t)long_count * 8U)) return false;",
            "    }",
            "    return true;",
            "}",
            "",
        ])
    lines.extend([
        f"static bool {auxiliary_function}(McReader *reader) {{",
        "    if (reader == NULL) return false;",
    ])
    if trust_edges:
        lines.extend([
            "    bool trust_edges = false;",
            "    if (!mc_reader_bool(reader, &trust_edges)) return false;",
        ])
    lines.extend([
        "    for (size_t mask_index = 0U; mask_index < 4U; ++mask_index) {",
        "        int32_t word_count = -1;",
        "        if (!mc_reader_varint(reader, &word_count) ||",
        "            word_count < 0 || word_count > 64 ||",
        "            !mc_reader_skip(reader, (size_t)word_count * 8U)) return false;",
        "    }",
        "    for (size_t light_index = 0U; light_index < 2U; ++light_index) {",
        "        int32_t light_count = -1;",
        "        if (!mc_reader_varint(reader, &light_count) ||",
        "            light_count < 0 || light_count > 64) return false;",
        "        for (int32_t light_entry = 0; light_entry < light_count; ++light_entry) {",
        "            int32_t byte_count = -1;",
        "            if (!mc_reader_varint(reader, &byte_count) ||",
        "                byte_count < 0 || byte_count > 2048 ||",
        "                !mc_reader_skip(reader, (size_t)byte_count)) return false;",
        "        }",
        "    }",
        "    return mc_reader_remaining(reader) == 0U;",
        "}",
        "",
        f"bool {decode_function}(",
        f"    const void *payload, size_t payload_size, {type_name} *value) {{",
        "    if ((payload == NULL && payload_size != 0U) || value == NULL) return false;",
        "    McReader reader;",
        f"    {type_name} decoded = {{0}};",
        "    int32_t block_entity_count = -1;",
        "    mc_reader_init(&reader, payload, payload_size);",
        "    if (!mc_reader_i32(&reader, &decoded.x) ||",
        "        !mc_reader_i32(&reader, &decoded.z)) return false;",
    ])
    if registry_heightmaps:
        lines.extend([
            "    const size_t heightmaps_start = reader.offset;",
            f"    if (!{heightmap_function}(&reader)) return false;",
            "    decoded.heightmaps.data = reader.data + heightmaps_start;",
            "    decoded.heightmaps.size = reader.offset - heightmaps_start;",
        ])
    else:
        named_root = "true" if variant.startswith("chunk:modern:named_nbt") else "false"
        lines.append(
            f"    if (!mc_reader_nbt(&reader, {named_root}, &decoded.heightmaps)) return false;")
    lines.extend([
        "    if (!mc_reader_buffer_varint(&reader, &decoded.chunk_data) ||",
        "        !mc_reader_varint(&reader, &block_entity_count) ||",
        "        block_entity_count != 0 ||",
        "        !mc_reader_bytes(&reader, mc_reader_remaining(&reader),",
        "                         &decoded.auxiliary_data)) return false;",
        "    McReader auxiliary_reader;",
        "    mc_reader_init(&auxiliary_reader,",
        "                   decoded.auxiliary_data.data, decoded.auxiliary_data.size);",
        f"    if (!{auxiliary_function}(&auxiliary_reader)) return false;",
        "    *value = decoded;",
        "    return true;",
        "}",
        "",
        f"bool {encode_function}(",
        f"    McPacket *packet, const {type_name} *value) {{",
        "    if (packet == NULL || value == NULL || value->ground_up ||",
        "        value->ignore_old_data || value->section_mask_word_count != 0U ||",
        "        value->section_mask != 0U || value->biome_count != 0U) return false;",
        "    McReader auxiliary_reader;",
        "    mc_reader_init(&auxiliary_reader,",
        "                   value->auxiliary_data.data, value->auxiliary_data.size);",
        f"    if (!{auxiliary_function}(&auxiliary_reader)) return false;",
    ])
    if registry_heightmaps:
        lines.extend([
            "    McReader heightmap_reader;",
            "    mc_reader_init(&heightmap_reader, value->heightmaps.data,",
            "                   value->heightmaps.size);",
            f"    if (!{heightmap_function}(&heightmap_reader) ||",
            "        mc_reader_remaining(&heightmap_reader) != 0U) return false;",
            "    if (!mc_packet_i32(packet, value->x) ||",
            "        !mc_packet_i32(packet, value->z) ||",
            "        !mc_packet_bytes(packet, value->heightmaps.data,",
            "                         value->heightmaps.size)) return false;",
        ])
    else:
        named_root = "true" if variant.startswith("chunk:modern:named_nbt") else "false"
        lines.extend([
            "    if (!mc_packet_i32(packet, value->x) ||",
            "        !mc_packet_i32(packet, value->z) ||",
            f"        !mc_packet_nbt(packet, {named_root}, &value->heightmaps)) return false;",
        ])
    lines.extend([
        "    return mc_packet_buffer_varint(packet, &value->chunk_data) &&",
        "           mc_packet_varint(packet, 0) &&",
        "           mc_packet_bytes(packet, value->auxiliary_data.data,",
        "                           value->auxiliary_data.size);",
        "}",
        "",
    ])
    return lines


def render_chunk_projection(profile: ManifestProfile,
                            packet: ManifestPacket,
                            type_name: str) -> list[str]:
    if packet.projection is not None and packet.projection.startswith("chunk:modern:"):
        return render_modern_chunk_projection(profile, packet, type_name)
    decode_function = f"perry_mc_{profile.c_profile}_decode_{packet.c_packet}"
    encode_function = f"perry_mc_{profile.c_profile}_encode_{packet.c_packet}"
    variant = packet.projection
    is_1_13 = variant == "chunk:1_13"
    is_1_17 = variant == "chunk:1_17"
    has_ignore_old_data = variant == "chunk:1_16:fixed"
    has_heightmaps = not is_1_13
    fixed_biomes = variant in {
        "chunk:1_15_or_1_16_2:fixed", "chunk:1_16:fixed"
    }
    counted_biomes = variant == "chunk:1_15_or_1_16_2:counted"
    has_biomes = fixed_biomes or counted_biomes or is_1_17
    if variant not in {
        "chunk:1_13",
        "chunk:1_14",
        "chunk:1_15_or_1_16_2:fixed",
        "chunk:1_15_or_1_16_2:counted",
        "chunk:1_16:fixed",
        "chunk:1_17",
    }:
        raise ValueError(f"unknown chunk projection renderer {variant}")

    lines = [
        f"bool {decode_function}(",
        f"    const void *payload, size_t payload_size, {type_name} *value) {{",
        "    if ((payload == NULL && payload_size != 0U) || value == NULL) return false;",
        "    McReader reader;",
        f"    {type_name} decoded = {{0}};",
        "    mc_reader_init(&reader, payload, payload_size);",
        "    if (!mc_reader_i32(&reader, &decoded.x) ||",
        "        !mc_reader_i32(&reader, &decoded.z)) return false;",
    ]
    if is_1_17:
        lines.extend([
            "    int32_t mask_word_count = -1;",
            "    int64_t mask_word = 0;",
            "    decoded.ground_up = true;",
            "    if (!mc_reader_varint(&reader, &mask_word_count) ||",
            "        mask_word_count < 0 || mask_word_count > 1) return false;",
            "    decoded.section_mask_word_count = (size_t)mask_word_count;",
            "    if (mask_word_count == 1 && !mc_reader_i64(&reader, &mask_word)) return false;",
            "    decoded.section_mask = (uint64_t)mask_word;",
        ])
    else:
        lines.extend([
            "    int32_t section_mask = -1;",
            "    if (!mc_reader_bool(&reader, &decoded.ground_up)) return false;",
        ])
        if has_ignore_old_data:
            lines.append(
                "    if (!mc_reader_bool(&reader, &decoded.ignore_old_data)) return false;")
        lines.extend([
            "    if (!mc_reader_varint(&reader, &section_mask) ||",
            "        section_mask < 0 || section_mask > (int32_t)UINT16_MAX) return false;",
            "    decoded.section_mask_word_count = 1U;",
            "    decoded.section_mask = (uint64_t)(uint32_t)section_mask;",
        ])
    if has_heightmaps:
        lines.append(
            "    if (!mc_reader_nbt(&reader, true, &decoded.heightmaps)) return false;")
    if fixed_biomes:
        lines.extend([
            "    if (decoded.ground_up) {",
            "        decoded.biome_count = 1024U;",
            "        for (size_t index = 0U; index < decoded.biome_count; ++index) {",
            "            if (!mc_reader_i32(&reader, &decoded.biomes[index])) return false;",
            "        }",
            "    }",
        ])
    elif counted_biomes or is_1_17:
        if counted_biomes:
            lines.append("    if (decoded.ground_up) {")
            indent = "    "
        else:
            indent = ""
        lines.extend([
            f"{indent}    int32_t biome_count = -1;",
            f"{indent}    if (!mc_reader_varint(&reader, &biome_count) ||",
            f"{indent}        biome_count < 0 || biome_count > 1024) return false;",
            f"{indent}    decoded.biome_count = (size_t)biome_count;",
            f"{indent}    for (size_t index = 0U; index < decoded.biome_count; ++index) {{",
            f"{indent}        if (!mc_reader_varint(&reader, &decoded.biomes[index])) return false;",
            f"{indent}    }}",
        ])
        if counted_biomes:
            lines.append("    }")
    lines.extend([
        "    int32_t block_entity_count = -1;",
        "    if (!mc_reader_buffer_varint(&reader, &decoded.chunk_data) ||",
        "        !mc_reader_varint(&reader, &block_entity_count) ||",
        "        block_entity_count != 0 || mc_reader_remaining(&reader) != 0U) return false;",
        "    *value = decoded;",
        "    return true;",
        "}",
        "",
        f"bool {encode_function}(",
        f"    McPacket *packet, const {type_name} *value) {{",
        "    if (packet == NULL || value == NULL) return false;",
        "    if (!mc_packet_i32(packet, value->x) ||",
        "        !mc_packet_i32(packet, value->z)) return false;",
    ])
    if is_1_17:
        lines.extend([
            "    if (!value->ground_up || value->ignore_old_data ||",
            "        value->section_mask_word_count > 1U ||",
            "        (value->section_mask_word_count == 0U && value->section_mask != 0U) ||",
            "        !mc_packet_varint(packet, (int32_t)value->section_mask_word_count)) return false;",
            "    if (value->section_mask_word_count == 1U &&",
            "        !mc_packet_i64(packet, (int64_t)value->section_mask)) return false;",
        ])
    else:
        lines.extend([
            "    if (value->section_mask_word_count != 1U ||",
            "        value->section_mask > UINT16_MAX ||",
            "        !mc_packet_bool(packet, value->ground_up)) return false;",
        ])
        if has_ignore_old_data:
            lines.append(
                "    if (!mc_packet_bool(packet, value->ignore_old_data)) return false;")
        else:
            lines.append("    if (value->ignore_old_data) return false;")
        lines.append(
            "    if (!mc_packet_varint(packet, (int32_t)value->section_mask)) return false;")
    if has_heightmaps:
        lines.append(
            "    if (!mc_packet_nbt(packet, true, &value->heightmaps)) return false;")
    else:
        lines.append("    if (value->heightmaps.size != 0U) return false;")
    if fixed_biomes:
        lines.extend([
            "    if (value->biome_count != (value->ground_up ? 1024U : 0U)) return false;",
            "    for (size_t index = 0U; index < value->biome_count; ++index) {",
            "        if (!mc_packet_i32(packet, value->biomes[index])) return false;",
            "    }",
        ])
    elif counted_biomes:
        lines.extend([
            "    if (value->biome_count > 1024U ||",
            "        (!value->ground_up && value->biome_count != 0U)) return false;",
            "    if (value->ground_up) {",
            "        if (!mc_packet_varint(packet, (int32_t)value->biome_count)) return false;",
            "        for (size_t index = 0U; index < value->biome_count; ++index) {",
            "            if (!mc_packet_varint(packet, value->biomes[index])) return false;",
            "        }",
            "    }",
        ])
    elif is_1_17:
        lines.extend([
            "    if (value->biome_count > 1024U ||",
            "        !mc_packet_varint(packet, (int32_t)value->biome_count)) return false;",
            "    for (size_t index = 0U; index < value->biome_count; ++index) {",
            "        if (!mc_packet_varint(packet, value->biomes[index])) return false;",
            "    }",
        ])
    elif not has_biomes:
        lines.append("    if (value->biome_count != 0U) return false;")
    lines.extend([
        "    if (value->auxiliary_data.size != 0U) return false;",
        "    return mc_packet_buffer_varint(packet, &value->chunk_data) &&",
        "           mc_packet_varint(packet, 0);",
        "}",
        "",
    ])
    return lines


def render_manifest_source(profile: ManifestProfile, revision: str) -> str:
    lines = [
        "/* Generated by mcprotocol.c/tools/schema_compiler.py; do not edit. */",
        f"/* minecraft-data {revision}; {profile.schema}/protocol.json sha256 {profile.schema_hash} */",
        f'#include "protocol_{profile.c_profile}.h"',
        "",
    ]
    if any(
        packet.projection is not None
        and packet.projection.startswith("minecart_metadata:")
        for packet in profile.packets
    ):
        lines.extend(["#include <math.h>", ""])
    if any(
        packet.projection == "note_particle:name_f32"
        for packet in profile.packets
    ):
        lines.extend(["#include <string.h>", ""])
    for packet in profile.packets:
        type_name = f"PerryMc{profile.c_profile.title().replace('_', '')}{packet.c_packet.title().replace('_', '')}"
        if packet.projection is not None:
            if packet.projection.startswith("minecart_steps:"):
                renderer = render_minecart_steps_projection
            elif packet.projection.startswith("minecart_metadata:"):
                renderer = render_minecart_metadata_projection
            elif packet.projection.startswith("primed_tnt_metadata:"):
                renderer = render_primed_tnt_metadata_projection
            elif packet.projection.startswith("note_particle:"):
                renderer = render_note_particle_projection
            elif packet.projection.startswith("inventory:"):
                renderer = render_inventory_projection
            elif packet.projection.startswith("scoreboard_"):
                renderer = render_scoreboard_projection
            elif packet.projection.startswith("chunk:"):
                renderer = render_chunk_projection
            else:
                raise ValueError(f"unknown packet projection renderer {packet.projection}")
            lines.extend(renderer(profile, packet, type_name))
            continue
        checks = [
            "!" + manifest_reader(profile, field) for field in packet.fields
        ]
        checks.extend(
            f"decoded.{field.c_field} != {field.expected_value}"
            for field in packet.fields if field.expected_value is not None)
        checks.append("mc_reader_remaining(&reader) != 0U")
        invalid_value = " ||\n        ".join(
            f"value->{field.c_field} != {field.expected_value}"
            for field in packet.fields if field.expected_value is not None)
        lines.extend([
            f"bool perry_mc_{profile.c_profile}_decode_{packet.c_packet}(",
            f"    const void *payload, size_t payload_size, {type_name} *value) {{",
            "    if ((payload == NULL && payload_size != 0U) || value == NULL) return false;",
            "    McReader reader;",
            f"    {type_name} decoded = {{0}};",
            "    mc_reader_init(&reader, payload, payload_size);",
            "    if (" + " ||\n        ".join(checks) + ") return false;",
            "    *value = decoded;",
            "    return true;",
            "}",
            "",
            f"bool perry_mc_{profile.c_profile}_encode_{packet.c_packet}(",
            f"    McPacket *packet, const {type_name} *value) {{",
            "    if (packet == NULL || value == NULL" +
            (f" ||\n        {invalid_value}" if invalid_value else "") + ") return false;",
            "    return " + " &&\n           ".join(
                manifest_writer(profile, field) for field in packet.fields) + ";",
            "}",
            "",
        ])
    return "\n".join(lines)


def expected_manifest_outputs(minecraft_data: Path, manifest_path: Path) -> dict[str, str]:
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw)
    if manifest.get("version") != 1:
        raise ValueError("schema manifest version must be 1")
    expected_revision = manifest.get("minecraft_data_revision")
    revision = git_revision(minecraft_data)
    if expected_revision != revision:
        raise ValueError(
            f"minecraft-data revision mismatch: found {revision}, expected {expected_revision}"
        )
    profile_specs = manifest.get("profiles")
    if not isinstance(profile_specs, list) or not profile_specs:
        raise ValueError("schema manifest has no profiles")
    profiles = [compile_manifest_profile(minecraft_data, spec) for spec in profile_specs]
    outputs: dict[str, str] = {}
    for profile in profiles:
        outputs[f"protocol_{profile.c_profile}.h"] = render_manifest_header(profile, revision)
        outputs[f"protocol_{profile.c_profile}.c"] = render_manifest_source(profile, revision)
    stamp = {
        "generator_version": 2,
        "generator": "mcprotocol.c/tools/schema_compiler.py",
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "minecraft_data_revision": revision,
        "outputs": {
            name: hashlib.sha256(contents.encode("utf-8")).hexdigest()
            for name, contents in sorted(outputs.items())
        },
    }
    outputs["schema_stamp.json"] = json.dumps(stamp, indent=2, sort_keys=True) + "\n"
    return outputs


def write_manifest_outputs(outputs: dict[str, str], output_root: Path,
                           check: bool) -> None:
    stale = []
    if check and output_root.is_dir():
        managed = {
            path.name
            for pattern in ("protocol_*.c", "protocol_*.h", "schema_stamp.json")
            for path in output_root.glob(pattern)
        }
        stale.extend(str(output_root / name) for name in sorted(managed - set(outputs)))
    for name, contents in sorted(outputs.items()):
        path = output_root / name
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current == contents:
            continue
        if check:
            stale.append(str(path))
        else:
            output_root.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
            print(f"generated {path}")
    if stale:
        raise ValueError("generated schema files are stale or missing: " + ", ".join(stale))


def single_schema_outputs(protocol: int, header: str, source: str,
                          manifest: dict[str, Any]) -> dict[str, str]:
    """Return the complete deterministic output set for legacy schema mode."""
    stem = f"mc_protocol_{protocol}"
    manifest = dict(manifest)
    manifest["outputs"] = {
        f"{stem}.c": hashlib.sha256(source.encode("utf-8")).hexdigest(),
        f"{stem}.h": hashlib.sha256(header.encode("utf-8")).hexdigest(),
    }
    return {
        f"{stem}.c": source,
        f"{stem}.h": header,
        f"{stem}.json": json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    }


def write_single_schema_outputs(outputs: dict[str, str], output_root: Path,
                                check: bool) -> None:
    stale = []
    for name, contents in sorted(outputs.items()):
        path = output_root / name
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current == contents:
            continue
        if check:
            stale.append(str(path))
        else:
            output_root.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
            print(f"generated {path}")
    if stale:
        raise ValueError("generated schema files are stale or missing: " + ", ".join(stale))


def verify_existing_single_schema(output_root: Path, protocol: int,
                                  overlay_path: Path | None) -> None:
    """Verify committed generated bytes when minecraft-data is unavailable.

    Full staleness checking still requires --protocol-json --check. This
    integrity mode makes an offline checkout detect edits, missing files and a
    mismatched overlay without pretending to regenerate from absent source
    data.
    """
    stem = f"mc_protocol_{protocol}"
    manifest_path = output_root / f"{stem}.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("protocol") != protocol:
        raise ValueError(f"generated protocol mismatch in {manifest_path}")
    expected_outputs = manifest.get("outputs")
    if not isinstance(expected_outputs, dict) or not expected_outputs:
        raise ValueError(f"generated output hashes missing in {manifest_path}")
    expected_names = {f"{stem}.c", f"{stem}.h"}
    if set(expected_outputs) != expected_names:
        raise ValueError(f"generated output set mismatch in {manifest_path}")
    for name in sorted(expected_names):
        path = output_root / name
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected_outputs[name]:
            raise ValueError(f"generated output hash mismatch: {path}")
    if overlay_path is not None:
        overlay_digest = hashlib.sha256(overlay_path.read_bytes()).hexdigest()
        if manifest.get("overlay_sha256") != overlay_digest:
            raise ValueError(f"generated overlay hash mismatch: {overlay_path}")


def normalize_generated_lines(lines: list[str]) -> str:
    """Remove accidental blank-line runs without changing generated tokens."""
    normalized: list[str] = []
    for line in lines:
        if line == "" and (not normalized or normalized[-1] == ""):
            continue
        normalized.append(line)
    while normalized and normalized[-1] == "":
        normalized.pop()
    return "\n".join(normalized)


def embedded_regions(protocol: int, header: str, source: str,
                     source_sha: str) -> tuple[str, str]:
    """Convert legacy standalone output into api.h/api.c marker contents."""
    guard = f"MC_PROTOCOL_GENERATED_{protocol}_H"
    public_skip = {
        "/* Generated from minecraft-data; do not edit. */",
        f"#ifndef {guard}",
        f"#define {guard}",
        '#include "api.h"',
        f"#endif /* {guard} */",
        f"extern const McPacketInfo mc{protocol}_generated_packet_ids[];",
        f"extern const size_t mc{protocol}_generated_packet_id_count;",
    }
    public_lines = [
        line for line in header.splitlines()
        if line not in public_skip
    ]
    codec = re.search(rf"^bool mc{protocol}_[A-Za-z0-9_]+\(", source, re.MULTILINE)
    private_body = source[codec.start():].strip() if codec is not None else ""
    banner = [
        "/* Generated by tools/schema_compiler.py from minecraft-data.",
        f" * Protocol {protocol}; protocol.json sha256 {source_sha}.",
        " * Do not edit inside the generated markers. */",
        "",
    ]
    public = normalize_generated_lines(banner + public_lines)
    private = normalize_generated_lines(
        banner + (private_body.splitlines() if private_body else []))
    return public + "\n", private + "\n"


def embedded_schema_outputs(protocol: int, header: str, source: str,
                            manifest: dict[str, Any], api_header: Path,
                            api_source: Path, report: Path) -> dict[Path, str]:
    """Build deterministic complete files while replacing marker regions only."""
    public, private = embedded_regions(
        protocol, header, source, str(manifest["source_sha256"]))
    header_text = replace_marked_region(
        api_header.read_text(encoding="utf-8"), PUBLIC_BEGIN, PUBLIC_END, public)
    source_text = replace_marked_region(
        api_source.read_text(encoding="utf-8"), PRIVATE_BEGIN, PRIVATE_END, private)
    embedded_manifest = dict(manifest)
    embedded_manifest["generator_version"] = 2
    embedded_manifest["embedded_outputs"] = {
        "api.c": hashlib.sha256(
            marked_region(source_text, PRIVATE_BEGIN, PRIVATE_END).encode("utf-8")
        ).hexdigest(),
        "api.h": hashlib.sha256(
            marked_region(header_text, PUBLIC_BEGIN, PUBLIC_END).encode("utf-8")
        ).hexdigest(),
    }
    embedded_manifest.pop("outputs", None)
    return {
        api_header: header_text,
        api_source: source_text,
        report: json.dumps(embedded_manifest, indent=2, sort_keys=True) + "\n",
    }


def write_embedded_schema_outputs(outputs: dict[Path, str], check: bool) -> None:
    stale = []
    for path, contents in outputs.items():
        current = path.read_text(encoding="utf-8") if path.is_file() else None
        if current == contents:
            continue
        if check:
            stale.append(str(path))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(contents, encoding="utf-8")
            print(f"updated generated region in {path}")
    if stale:
        raise ValueError("embedded generated regions are stale or missing: " + ", ".join(stale))


def verify_existing_embedded(api_header: Path, api_source: Path, report: Path,
                             protocol: int, overlay_path: Path | None) -> None:
    """Verify embedded region hashes without requiring minecraft-data."""
    manifest = json.loads(report.read_text(encoding="utf-8"))
    if manifest.get("protocol") != protocol:
        raise ValueError(f"embedded protocol mismatch in {report}")
    expected = manifest.get("embedded_outputs")
    if not isinstance(expected, dict) or set(expected) != {"api.c", "api.h"}:
        raise ValueError(f"embedded output hashes missing in {report}")
    actual = {
        "api.c": hashlib.sha256(marked_region(
            api_source.read_text(encoding="utf-8"), PRIVATE_BEGIN, PRIVATE_END
        ).encode("utf-8")).hexdigest(),
        "api.h": hashlib.sha256(marked_region(
            api_header.read_text(encoding="utf-8"), PUBLIC_BEGIN, PUBLIC_END
        ).encode("utf-8")).hexdigest(),
    }
    for name in sorted(actual):
        if actual[name] != expected[name]:
            raise ValueError(f"embedded generated region hash mismatch: {name}")
    if overlay_path is not None:
        overlay_digest = hashlib.sha256(overlay_path.read_bytes()).hexdigest()
        if manifest.get("overlay_sha256") != overlay_digest:
            raise ValueError(f"generated overlay hash mismatch: {overlay_path}")
    legacy_stem = f"mc_protocol_{protocol}"
    for suffix in (".c", ".h"):
        legacy = report.parent / f"{legacy_stem}{suffix}"
        if legacy.exists():
            raise ValueError(f"legacy generated production file must be removed: {legacy}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--protocol-json", type=Path)
    parser.add_argument("--protocol-number", type=int)
    parser.add_argument("--out-dir", type=Path)
    parser.add_argument("--overlay", type=Path)
    parser.add_argument("--packet", action="append", default=[])
    parser.add_argument("--minecraft-data", type=Path)
    parser.add_argument("--manifest", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--verify-existing", action="store_true")
    parser.add_argument("--embed", action="store_true")
    parser.add_argument("--api-header", type=Path)
    parser.add_argument("--api-source", type=Path)
    parser.add_argument("--embedded-report", type=Path)
    parser.add_argument("--verify-embedded", action="store_true")
    args = parser.parse_args()
    if args.manifest is not None:
        if args.minecraft_data is None or args.output is None:
            parser.error("--manifest requires --minecraft-data and --output")
        if any(value is not None for value in (
            args.protocol_json, args.protocol_number, args.out_dir, args.overlay,
            args.api_header, args.api_source, args.embedded_report,
        )) or args.packet or args.verify_existing or args.embed or args.verify_embedded:
            parser.error("manifest mode cannot be combined with single-schema options")
        outputs = expected_manifest_outputs(
            args.minecraft_data.expanduser().resolve(),
            args.manifest.expanduser().resolve())
        write_manifest_outputs(outputs, args.output.expanduser().resolve(), args.check)
        return 0
    if args.verify_existing:
        if args.protocol_number is None or args.out_dir is None:
            parser.error("--verify-existing requires --protocol-number and --out-dir")
        if args.protocol_json is not None or args.packet:
            parser.error("--verify-existing cannot regenerate a schema")
        verify_existing_single_schema(
            args.out_dir.expanduser().resolve(), args.protocol_number,
            args.overlay.expanduser().resolve() if args.overlay is not None else None)
        print(f"verified committed generated protocol {args.protocol_number}")
        return 0
    if args.verify_embedded:
        if (
            args.protocol_number is None
            or args.api_header is None
            or args.api_source is None
            or args.embedded_report is None
        ):
            parser.error(
                "--verify-embedded requires --protocol-number, --api-header, "
                "--api-source and --embedded-report"
            )
        if args.protocol_json is not None or args.packet or args.embed:
            parser.error("--verify-embedded cannot regenerate a schema")
        verify_existing_embedded(
            args.api_header.expanduser().resolve(),
            args.api_source.expanduser().resolve(),
            args.embedded_report.expanduser().resolve(),
            args.protocol_number,
            args.overlay.expanduser().resolve() if args.overlay is not None else None,
        )
        print(f"verified embedded generated protocol {args.protocol_number}")
        return 0
    if args.protocol_json is None or args.protocol_number is None:
        parser.error("single-schema mode requires --protocol-json and --protocol-number")
    if args.embed:
        if (
            args.api_header is None
            or args.api_source is None
            or args.embedded_report is None
            or args.out_dir is not None
        ):
            parser.error(
                "--embed requires --api-header, --api-source and "
                "--embedded-report, and does not accept --out-dir"
            )
    elif args.out_dir is None:
        parser.error("standalone single-schema mode requires --out-dir")
    raw = args.protocol_json.read_bytes()
    overlay_raw = args.overlay.read_bytes() if args.overlay is not None else None
    overlay = json.loads(overlay_raw) if overlay_raw is not None else {}
    header, source, manifest = generate(
        json.loads(raw),
        args.protocol_number,
        args.packet,
        hashlib.sha256(raw).hexdigest(),
        overlay,
        hashlib.sha256(overlay_raw).hexdigest() if overlay_raw is not None else None)
    if args.embed:
        outputs = embedded_schema_outputs(
            args.protocol_number,
            header,
            source,
            manifest,
            args.api_header.expanduser().resolve(),
            args.api_source.expanduser().resolve(),
            args.embedded_report.expanduser().resolve(),
        )
        write_embedded_schema_outputs(outputs, args.check)
    else:
        outputs = single_schema_outputs(args.protocol_number, header, source, manifest)
        write_single_schema_outputs(
            outputs, args.out_dir.expanduser().resolve(), args.check)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
