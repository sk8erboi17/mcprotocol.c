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
}

STATE_ORDER = ("handshaking", "status", "login", "configuration", "play")
DIRECTIONS = {"serverbound": "toServer", "clientbound": "toClient"}
STATE_CONSTANTS = {
    "login": "MC_STATE_LOGIN",
    "configuration": "MC_STATE_CONFIGURATION",
    "play": "MC_STATE_PLAY",
}
DIRECTION_CONSTANTS = {
    "serverbound": "MC_PACKET_SERVERBOUND",
    "clientbound": "MC_PACKET_CLIENTBOUND",
}


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
                if schema in PRIMITIVES or schema == "position":
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
                if suffix == "uuid":
                    return [f"    if (!mc_packet_uuid(packet, &value->{expression})) return false;"]
                return [f"    if (!mc_packet_{suffix}(packet, value->{expression})) return false;"]
            return [f"    if (!mc_reader_{suffix}(reader, &value->{expression})) return false;"]
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
        if projection != "single_attribute_no_modifiers":
            raise ValueError(f"unknown packet projection: {projection}")
        if spec.get("field_type_overrides"):
            raise ValueError("projected packet cannot also override field types")
        fields = manifest_attribute_projection(compiler, name, raw_fields, types)
        return ManifestPacket(
            name, manifest_c_name(name), packet_id, state, str(raw_direction), fields)

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
        lines.append(f"typedef struct {type_name} {{")
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
    address = "&" if field.wire.suffix == "uuid" else ""
    if field.wire.protocol_argument:
        return (
            f"mc_packet_{field.wire.suffix}(packet, {profile.protocol}, "
            f"{address}value->{field.c_field})"
        )
    return f"mc_packet_{field.wire.suffix}(packet, {address}value->{field.c_field})"


def render_manifest_source(profile: ManifestProfile, revision: str) -> str:
    lines = [
        "/* Generated by mcprotocol.c/tools/schema_compiler.py; do not edit. */",
        f"/* minecraft-data {revision}; {profile.schema}/protocol.json sha256 {profile.schema_hash} */",
        f'#include "protocol_{profile.c_profile}.h"',
        "",
    ]
    for packet in profile.packets:
        type_name = f"PerryMc{profile.c_profile.title().replace('_', '')}{packet.c_packet.title().replace('_', '')}"
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
    args = parser.parse_args()
    if args.manifest is not None:
        if args.minecraft_data is None or args.output is None:
            parser.error("--manifest requires --minecraft-data and --output")
        if any(value is not None for value in (
            args.protocol_json, args.protocol_number, args.out_dir, args.overlay
        )) or args.packet:
            parser.error("manifest mode cannot be combined with single-schema options")
        outputs = expected_manifest_outputs(
            args.minecraft_data.expanduser().resolve(),
            args.manifest.expanduser().resolve())
        write_manifest_outputs(outputs, args.output.expanduser().resolve(), args.check)
        return 0
    if args.check:
        parser.error("--check is available only in manifest mode")
    if args.protocol_json is None or args.protocol_number is None or args.out_dir is None:
        parser.error("single-schema mode requires --protocol-json, --protocol-number and --out-dir")
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
    args.out_dir.mkdir(parents=True, exist_ok=True)
    stem = f"mc_protocol_{args.protocol_number}"
    (args.out_dir / f"{stem}.h").write_text(header, encoding="utf-8")
    (args.out_dir / f"{stem}.c").write_text(source, encoding="utf-8")
    (args.out_dir / f"{stem}.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
