#include "api.h"

#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <zlib.h>

typedef union {
    max_align_t alignment;
    unsigned char bytes[2048];
    McEntityMetadataPacket metadata;
    McExplosionPacket explosion;
    McEntityEffectPacket effect;
    McRemoveEntityEffectPacket remove_effect;
    McUpdateAttributesPacket attributes;
    McAttachEntityPacket attach;
    McPassengersPacket passengers;
    McUnloadChunkPacket unload;
    McRespawnPacket respawn;
    McGameStateChangePacket game_state;
    McChunkEnvelope chunk;
} EnvelopeStorage;

static int32_t packet_id(int protocol, const char *name)
{
    return mc_packet_id(protocol, MC_STATE_PLAY, MC_PACKET_CLIENTBOUND, name);
}

static McPacketFamily decode(int protocol, const char *name,
    const unsigned char *payload, size_t payload_size, EnvelopeStorage *output)
{
    const int32_t id = packet_id(protocol, name);
    assert(id >= 0);
    McPacketFamily family = MC_FAMILY_UNKNOWN;
    McError error;
    memset(output, 0, sizeof(*output));
    assert(mc_decode_packet(protocol, MC_STATE_PLAY, MC_PACKET_CLIENTBOUND,
        id, payload, payload_size, MC_DECODE_STRICT, output, sizeof(*output),
        &family, &error) == 0);
    assert(error.code == MC_ERROR_NONE);
    return family;
}

static void assert_exact(int protocol, const char *name,
    const unsigned char *payload, size_t payload_size)
{
    const int32_t id = packet_id(protocol, name);
    assert(id >= 0);
    for (size_t prefix = 0U; prefix < payload_size; ++prefix) {
        EnvelopeStorage output;
        EnvelopeStorage before;
        memset(&output, 0xa5, sizeof(output));
        before = output;
        McPacketFamily family = MC_FAMILY_UNKNOWN;
        McError error;
        assert(mc_decode_packet(protocol, MC_STATE_PLAY,
            MC_PACKET_CLIENTBOUND, id, payload, prefix, MC_DECODE_STRICT,
            &output, sizeof(output), &family, &error) != 0);
        assert(error.code != MC_ERROR_NONE);
        assert(memcmp(&output, &before, sizeof(output)) == 0);
    }
    unsigned char trailing[2049];
    assert(payload_size + 1U <= sizeof(trailing));
    memcpy(trailing, payload, payload_size);
    trailing[payload_size] = 0U;
    EnvelopeStorage output;
    McPacketFamily family = MC_FAMILY_UNKNOWN;
    McError error;
    assert(mc_decode_packet(protocol, MC_STATE_PLAY, MC_PACKET_CLIENTBOUND,
        id, trailing, payload_size + 1U, MC_DECODE_STRICT, &output,
        sizeof(output), &family, &error) != 0);
    assert(error.code == MC_ERROR_TRAILING_BYTES
        || error.code == MC_ERROR_INVALID_PACKET_BODY);
}

static void test_entity_metadata(void)
{
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    for (size_t index = 0U; index < protocol_count; ++index) {
        const int protocol = protocols[index];
        unsigned char bytes[64];
        McPacket packet;
        mc_packet_init(&packet, bytes, sizeof(bytes));
        assert(protocol <= 5 ? mc_packet_i32(&packet, 7)
                             : mc_packet_varint(&packet, 7));
        if (protocol <= 47) {
            assert(mc_packet_u8(&packet, 1U));
        } else {
            assert(mc_packet_u8(&packet, 1U));
            assert(mc_packet_varint(&packet, 0));
        }
        assert(mc_packet_i8(&packet, -3));
        assert(mc_packet_u8(&packet,
            protocol <= 47 ? UINT8_C(0x7f) : UINT8_MAX));

        EnvelopeStorage decoded;
        assert(decode(protocol, "entity_metadata", packet.data,
            packet.length, &decoded) == MC_FAMILY_ENTITY_METADATA);
        assert(decoded.metadata.entity_id == 7);
        assert(decoded.metadata.entry_count == 1U);
        assert(decoded.metadata.terminated);
        assert(decoded.metadata.entries.size == (protocol <= 47 ? 3U : 4U));
        assert_exact(protocol, "entity_metadata", packet.data, packet.length);
    }
}

static void test_simple_tier_b_envelopes(void)
{
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    for (size_t index = 0U; index < protocol_count; ++index) {
        const int protocol = protocols[index];
        unsigned char bytes[256];
        McPacket packet;
        EnvelopeStorage decoded;

        if (packet_id(protocol, "attach_entity") >= 0) {
            mc_packet_init(&packet, bytes, sizeof(bytes));
            assert(mc_packet_i32(&packet, 7));
            assert(mc_packet_i32(&packet, 2));
            if (protocol <= 47) assert(mc_packet_bool(&packet, true));
            assert(decode(protocol, "attach_entity", packet.data,
                packet.length, &decoded) == MC_FAMILY_ATTACH_ENTITY);
            assert(decoded.attach.entity_id == 7);
            assert(decoded.attach.vehicle_id == 2);
            assert(decoded.attach.has_leash == (protocol <= 47));
            assert_exact(protocol, "attach_entity", packet.data,
                packet.length);
        }

        if (packet_id(protocol, "update_attributes") >= 0) {
            mc_packet_init(&packet, bytes, sizeof(bytes));
            assert(protocol <= 5 ? mc_packet_i32(&packet, 4)
                                 : mc_packet_varint(&packet, 4));
            assert(protocol >= 755 ? mc_packet_varint(&packet, 0)
                                   : mc_packet_i32(&packet, 0));
            assert(decode(protocol, "update_attributes", packet.data,
                packet.length, &decoded) == MC_FAMILY_UPDATE_ATTRIBUTES);
            assert(decoded.attributes.entity_id == 4);
            assert(decoded.attributes.attribute_count == 0U);
            assert_exact(protocol, "update_attributes", packet.data,
                packet.length);
        }

        if (packet_id(protocol, "set_passengers") >= 0) {
            mc_packet_init(&packet, bytes, sizeof(bytes));
            assert(mc_packet_varint(&packet, 2));
            assert(mc_packet_varint(&packet, 0));
            assert(decode(protocol, "set_passengers", packet.data,
                packet.length, &decoded) == MC_FAMILY_SET_PASSENGERS);
            assert(decoded.passengers.entity_id == 2);
            assert(decoded.passengers.passenger_count == 0U);
            assert_exact(protocol, "set_passengers", packet.data,
                packet.length);
        }

        if (packet_id(protocol, "game_state_change") >= 0) {
            mc_packet_init(&packet, bytes, sizeof(bytes));
            assert(mc_packet_u8(&packet, 1U));
            assert(mc_packet_float(&packet, 0.0F));
            assert(decode(protocol, "game_state_change", packet.data,
                packet.length, &decoded) == MC_FAMILY_GAME_STATE_CHANGE);
            assert(decoded.game_state.reason == 1U);
            assert(decoded.game_state.value == 0.0F);
            assert_exact(protocol, "game_state_change", packet.data,
                packet.length);
        }
    }
}

static void test_explosion_envelope(void)
{
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    for (size_t index = 0U; index < protocol_count; ++index) {
        const int protocol = protocols[index];
        if (packet_id(protocol, "explosion") < 0) continue;
        unsigned char bytes[256];
        McPacket packet;
        mc_packet_init(&packet, bytes, sizeof(bytes));
        if (protocol >= 761) {
            assert(mc_packet_double(&packet, 1.0));
            assert(mc_packet_double(&packet, 2.0));
            assert(mc_packet_double(&packet, 3.0));
        } else {
            assert(mc_packet_float(&packet, 1.0F));
            assert(mc_packet_float(&packet, 2.0F));
            assert(mc_packet_float(&packet, 3.0F));
        }
        if (protocol >= 773) {
            assert(mc_packet_float(&packet, 4.0F));
            assert(mc_packet_i32(&packet, 0));
            assert(mc_packet_bool(&packet, false));
            assert(mc_packet_varint(&packet, 0));
            assert(mc_packet_varint(&packet, 1));
            assert(mc_packet_varint(&packet, 0));
        } else if (protocol >= 768) {
            assert(mc_packet_bool(&packet, false));
            assert(mc_packet_varint(&packet, 0));
            assert(mc_packet_varint(&packet, 1));
        } else {
            assert(mc_packet_float(&packet, 4.0F));
            assert(protocol >= 755 ? mc_packet_varint(&packet, 0)
                                   : mc_packet_i32(&packet, 0));
            assert(mc_packet_float(&packet, 0.0F));
            assert(mc_packet_float(&packet, 0.0F));
            assert(mc_packet_float(&packet, 0.0F));
            if (protocol >= 765) {
                assert(mc_packet_varint(&packet, 0));
                assert(mc_packet_varint(&packet, 0));
                assert(mc_packet_varint(&packet, 0));
                assert(mc_packet_varint(&packet, 1));
            }
        }
        EnvelopeStorage decoded;
        assert(decode(protocol, "explosion", packet.data, packet.length,
            &decoded) == MC_FAMILY_EXPLOSION);
        assert(decoded.explosion.x == 1.0);
        assert(decoded.explosion.y == 2.0);
        assert(decoded.explosion.z == 3.0);
        assert_exact(protocol, "explosion", packet.data, packet.length);
    }
}

static void encode_respawn(McPacket *packet, int protocol)
{
    static const unsigned char empty_compound_bytes[] = {10U, 0U, 0U, 0U};
    const McBytes empty_compound = {
        empty_compound_bytes, sizeof(empty_compound_bytes)
    };
    if (protocol < 735) {
        assert(mc_packet_i32(packet, 0));
        if (protocol <= 404) assert(mc_packet_u8(packet, 2U));
        if (protocol >= 573) assert(mc_packet_i64(packet, 123));
        assert(mc_packet_u8(packet, 1U));
        assert(mc_packet_string(packet, "default"));
        return;
    }
    if (protocol >= 766) {
        assert(mc_packet_varint(packet, 0));
    } else if (protocol < 751 || protocol >= 759) {
        assert(mc_packet_string(packet, "minecraft:overworld"));
    } else {
        assert(mc_packet_nbt(packet, true, &empty_compound));
    }
    assert(mc_packet_string(packet, "minecraft:overworld"));
    assert(mc_packet_i64(packet, 123));
    assert(mc_packet_u8(packet, 1U));
    assert(mc_packet_u8(packet, UINT8_MAX));
    assert(mc_packet_bool(packet, false));
    assert(mc_packet_bool(packet, false));
    if (protocol < 759) {
        assert(mc_packet_bool(packet, true));
    } else if (protocol <= 763) {
        assert(mc_packet_bool(packet, true));
        assert(mc_packet_bool(packet, false));
        if (protocol == 763) assert(mc_packet_varint(packet, 0));
    } else {
        assert(mc_packet_bool(packet, false));
        assert(mc_packet_varint(packet, 0));
        if (protocol >= 768) assert(mc_packet_varint(packet, 63));
        if (protocol >= 766) assert(mc_packet_u8(packet, 1U));
        else assert(mc_packet_bool(packet, true));
    }
}

static void test_effects_respawn_and_chunk_unload(void)
{
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    for (size_t index = 0U; index < protocol_count; ++index) {
        const int protocol = protocols[index];
        unsigned char bytes[512];
        McPacket packet;
        EnvelopeStorage decoded;

        mc_packet_init(&packet, bytes, sizeof(bytes));
        assert(protocol <= 5 ? mc_packet_i32(&packet, 7)
                             : mc_packet_varint(&packet, 7));
        assert(protocol >= 759 ? mc_packet_varint(&packet, 2)
                               : mc_packet_u8(&packet, 2U));
        assert(protocol >= 766 ? mc_packet_varint(&packet, 3)
                               : mc_packet_u8(&packet, 3U));
        assert(protocol <= 5 ? mc_packet_i16(&packet, 20)
                             : mc_packet_varint(&packet, 20));
        if (protocol == 47) assert(mc_packet_bool(&packet, false));
        else if (protocol >= 107) assert(mc_packet_u8(&packet, 2U));
        if (protocol >= 759 && protocol < 766) {
            assert(mc_packet_bool(&packet, false));
        }
        assert(decode(protocol, "entity_effect", packet.data, packet.length,
            &decoded) == MC_FAMILY_ENTITY_EFFECT);
        assert(decoded.effect.entity_id == 7);
        assert(decoded.effect.effect_id == 2);
        assert(decoded.effect.amplifier == 3);
        assert(decoded.effect.duration == 20);
        assert_exact(protocol, "entity_effect", packet.data, packet.length);

        mc_packet_init(&packet, bytes, sizeof(bytes));
        assert(protocol <= 5 ? mc_packet_i32(&packet, 7)
                             : mc_packet_varint(&packet, 7));
        assert(protocol >= 759 ? mc_packet_varint(&packet, 2)
                               : mc_packet_u8(&packet, 2U));
        assert(decode(protocol, "remove_entity_effect", packet.data,
            packet.length, &decoded) == MC_FAMILY_REMOVE_ENTITY_EFFECT);
        assert(decoded.remove_effect.entity_id == 7);
        assert(decoded.remove_effect.effect_id == 2);
        assert_exact(protocol, "remove_entity_effect", packet.data,
            packet.length);

        if (packet_id(protocol, "unload_chunk") >= 0) {
            mc_packet_init(&packet, bytes, sizeof(bytes));
            if (protocol >= 764) {
                assert(mc_packet_i32(&packet, -3));
                assert(mc_packet_i32(&packet, 4));
            } else {
                assert(mc_packet_i32(&packet, 4));
                assert(mc_packet_i32(&packet, -3));
            }
            assert(decode(protocol, "unload_chunk", packet.data,
                packet.length, &decoded) == MC_FAMILY_UNLOAD_CHUNK);
            assert(decoded.unload.chunk_x == 4);
            assert(decoded.unload.chunk_z == -3);
            assert_exact(protocol, "unload_chunk", packet.data,
                packet.length);
        }

        mc_packet_init(&packet, bytes, sizeof(bytes));
        encode_respawn(&packet, protocol);
        assert(decode(protocol, "respawn", packet.data, packet.length,
            &decoded) == MC_FAMILY_RESPAWN);
        assert(decoded.respawn.game_mode == 1);
        if (protocol >= 768) {
            assert(decoded.respawn.has_sea_level);
            assert(decoded.respawn.sea_level == 63);
        }
        assert_exact(protocol, "respawn", packet.data, packet.length);
    }
}

static void encode_chunk(McPacket *packet, int protocol)
{
    static const unsigned char named_empty_compound[] = {
        UINT8_C(0x0a), 0U, 0U, 0U
    };
    static const unsigned char anonymous_empty_compound[] = {
        UINT8_C(0x0a), 0U
    };
    static const unsigned char modern_section[] = {
        0U, 0U, /* non-air block count */
        0U, 0U, 0U, /* singleton block palette and empty packed data */
        0U, 0U, 0U  /* singleton biome palette and empty packed data */
    };
    const McBytes named_nbt = {
        named_empty_compound, sizeof(named_empty_compound)
    };
    const McBytes anonymous_nbt = {
        anonymous_empty_compound, sizeof(anonymous_empty_compound)
    };
    const McBytes section = {modern_section, sizeof(modern_section)};

    assert(mc_packet_i32(packet, 3));
    assert(mc_packet_i32(packet, -2));
    if (protocol <= 5) {
        unsigned char compressed[32];
        static const unsigned char empty = 0U;
        uLongf compressed_size = (uLongf)sizeof(compressed);
        assert(compress2(compressed, &compressed_size, &empty, 0U,
            Z_BEST_SPEED) == Z_OK);
        assert(compressed_size <= (uLongf)INT32_MAX);
        assert(mc_packet_bool(packet, false));
        assert(mc_packet_u16(packet, 0U));
        assert(mc_packet_u16(packet, 0U));
        assert(mc_packet_i32(packet, (int32_t)compressed_size));
        assert(mc_packet_bytes(packet, compressed, (size_t)compressed_size));
        return;
    }
    if (protocol == 47) {
        assert(mc_packet_bool(packet, false));
        assert(mc_packet_u16(packet, 0U));
        assert(mc_packet_varint(packet, 0));
        return;
    }
    if (protocol < 757) {
        if (protocol <= 754) {
            assert(mc_packet_bool(packet, false));
            if (protocol == 735 || protocol == 736) {
                assert(mc_packet_bool(packet, false));
            }
            assert(mc_packet_varint(packet, 0));
        } else {
            assert(mc_packet_varint(packet, 0));
        }
        if (protocol >= 477) assert(mc_packet_nbt(packet, true, &named_nbt));
        if (protocol >= 755) assert(mc_packet_varint(packet, 0));
        assert(mc_packet_varint(packet, 0));
        if (protocol >= 110) assert(mc_packet_varint(packet, 0));
        return;
    }

    if (protocol >= 770) {
        assert(mc_packet_varint(packet, 0));
    } else {
        assert(mc_packet_nbt(packet, protocol < 764,
            protocol < 764 ? &named_nbt : &anonymous_nbt));
    }
    assert(mc_packet_buffer_varint(packet, &section));
    assert(mc_packet_varint(packet, 0));
    if (protocol <= 762) assert(mc_packet_bool(packet, false));
    for (size_t mask = 0U; mask < 4U; ++mask) {
        assert(mc_packet_varint(packet, 0));
    }
    assert(mc_packet_varint(packet, 0));
    assert(mc_packet_varint(packet, 0));
}

static void test_chunk_envelopes_and_sections(void)
{
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    for (size_t index = 0U; index < protocol_count; ++index) {
        const int protocol = protocols[index];
        unsigned char bytes[512];
        McPacket packet;
        EnvelopeStorage decoded;
        mc_packet_init(&packet, bytes, sizeof(bytes));
        encode_chunk(&packet, protocol);
        assert(decode(protocol, "map_chunk", packet.data, packet.length,
            &decoded) == MC_FAMILY_MAP_CHUNK);
        assert(decoded.chunk.chunk_x == 3);
        assert(decoded.chunk.chunk_z == -2);
        assert(decoded.chunk.block_entity_count == 0U);
        assert(decoded.chunk.sky_light_count == 0U);
        assert(decoded.chunk.block_light_count == 0U);
        assert_exact(protocol, "map_chunk", packet.data, packet.length);

        if (protocol >= 757) {
            McChunkSectionIterator iterator;
            McChunkSectionView section;
            int32_t state_id = -1;
            assert(mc_chunk_section_iterator_init(&decoded.chunk, protocol,
                1U, &iterator));
            assert(mc_chunk_section_iterator_next(&iterator, &section));
            assert(section.non_air_block_count == 0U);
            assert(section.block_palette_count == 1U);
            assert(section.biome_palette_count == 1U);
            assert(mc_chunk_section_block_state(&section, 0U, &state_id));
            assert(state_id == 0);
            assert(!mc_chunk_section_iterator_next(&iterator, &section));
        } else {
            McChunkSectionIterator iterator;
            assert(!mc_chunk_section_iterator_init(&decoded.chunk, protocol,
                0U, &iterator));
        }
    }
}

int main(void)
{
    test_entity_metadata();
    test_simple_tier_b_envelopes();
    test_explosion_envelope();
    test_effects_respawn_and_chunk_unload();
    test_chunk_envelopes_and_sections();
    puts("PASS bounded Tier B envelopes and exact metadata decoding");
    return 0;
}
