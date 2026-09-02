#include "api.h"

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static bool bytes_equal(McBytes value, const char *expected)
{
    const size_t size = strlen(expected);
    return value.size == size
        && (size == 0U || memcmp(value.data, expected, size) == 0);
}

static McUuid sample_uuid(void)
{
    McUuid uuid = {{0}};
    for (size_t index = 0U; index < sizeof(uuid.bytes); ++index) {
        uuid.bytes[index] = (unsigned char)(index + 1U);
    }
    return uuid;
}

static void append_player_info_add(McPacket *packet, int protocol,
    const McUuid *uuid)
{
    if (protocol <= 5) {
        assert(mc_packet_string(packet, "Perry"));
        assert(mc_packet_bool(packet, true));
        assert(mc_packet_i16(packet, 42));
        return;
    }
    if (protocol <= 760) {
        assert(mc_packet_varint(packet, 0));
        assert(mc_packet_varint(packet, 1));
        assert(mc_packet_uuid(packet, uuid));
        assert(mc_packet_string(packet, "Perry"));
        assert(mc_packet_varint(packet, 0));
        assert(mc_packet_varint(packet, 1));
        assert(mc_packet_varint(packet, 42));
        assert(mc_packet_bool(packet, false));
        if (protocol >= 759) assert(mc_packet_bool(packet, false));
        return;
    }
    const uint8_t mask = protocol <= 767 ? UINT8_C(0x3f)
        : protocol == 768 ? UINT8_C(0x7f) : UINT8_MAX;
    assert(mc_packet_u8(packet, mask));
    assert(mc_packet_varint(packet, 1));
    assert(mc_packet_uuid(packet, uuid));
    assert(mc_packet_string(packet, "Perry"));
    assert(mc_packet_varint(packet, 0));
    assert(mc_packet_bool(packet, false));
    assert(mc_packet_varint(packet, 1));
    assert(mc_packet_varint(packet, 1));
    assert(mc_packet_varint(packet, 42));
    assert(mc_packet_bool(packet, false));
    if (protocol >= 768) assert(mc_packet_varint(packet, 7));
    if (protocol >= 769) assert(mc_packet_bool(packet, true));
}

static void append_player_info_remove(McPacket *packet, int protocol,
    const McUuid *uuid)
{
    if (protocol <= 5) {
        assert(mc_packet_string(packet, "Perry"));
        assert(mc_packet_bool(packet, false));
        assert(mc_packet_i16(packet, 0));
        return;
    }
    if (protocol <= 760) assert(mc_packet_varint(packet, 4));
    assert(mc_packet_varint(packet, 1));
    assert(mc_packet_uuid(packet, uuid));
}

static void player_info_is_normalized_for_every_protocol(void)
{
    size_t count = 0U;
    const int *protocols = mc_supported_protocols(&count);
    const McUuid uuid = sample_uuid();
    assert(protocols != NULL && count == 51U);
    for (size_t index = 0U; index < count; ++index) {
        const int protocol = protocols[index];
        unsigned char storage[512] = {0};
        McPacket body;
        mc_packet_init(&body, storage, sizeof(storage));
        append_player_info_add(&body, protocol, &uuid);
        assert(!body.failed);

        McReader reader;
        McClientboundPlayerInfo packet = {0};
        mc_reader_init_mode(&reader, body.data, body.length,
            MC_DECODE_STRICT, NULL);
        assert(mc_reader_clientbound_player_info(&reader, protocol, &packet));
        assert(mc_reader_finish(&reader));
        assert(packet.entry_count == 1U);
        assert((packet.fields & MC_PLAYER_INFO_ADD_PLAYER) != 0U);

        McPlayerInfoIterator iterator;
        McPlayerInfoEntry entry = {0};
        assert(mc_player_info_iterator(&packet, protocol, &iterator));
        assert(mc_player_info_iterator_next(&iterator, &entry));
        assert(!mc_player_info_iterator_next(&iterator, &entry));
        assert(entry.has_player_name && bytes_equal(entry.player_name, "Perry"));
        assert((entry.fields & MC_PLAYER_INFO_ADD_PLAYER) != 0U);
        assert(entry.latency == 42);
        if (protocol <= 5) {
            assert(!entry.has_profile_id && entry.listed);
        } else {
            assert(entry.has_profile_id);
            assert(memcmp(entry.profile_id.bytes, uuid.bytes,
                sizeof(uuid.bytes)) == 0);
            assert(entry.game_mode == 1);
            assert(entry.property_count == 0U);
        }
        if (protocol >= 761) {
            assert(entry.listed);
            assert(entry.list_order == (protocol >= 768 ? 7 : -1));
            assert(entry.show_hat == (protocol >= 769));
        }

        mc_packet_init(&body, storage, sizeof(storage));
        append_player_info_remove(&body, protocol, &uuid);
        mc_reader_init_mode(&reader, body.data, body.length,
            MC_DECODE_STRICT, NULL);
        if (protocol <= 760) {
            packet = (McClientboundPlayerInfo){0};
            const bool decoded_remove =
                mc_reader_clientbound_player_info(&reader, protocol, &packet);
            if (!decoded_remove) {
                fprintf(stderr, "player-info remove failed for protocol %d\n",
                    protocol);
            }
            assert(decoded_remove);
            assert(mc_reader_finish(&reader));
            assert((packet.fields & MC_PLAYER_INFO_REMOVE_PLAYER) != 0U);
            assert(mc_player_info_iterator(&packet, protocol, &iterator));
            assert(mc_player_info_iterator_next(&iterator, &entry));
            assert((entry.fields & MC_PLAYER_INFO_REMOVE_PLAYER) != 0U);
            assert(!mc_player_info_iterator_next(&iterator, &entry));
        } else {
            McClientboundPlayerRemove removal = {0};
            assert(mc_reader_clientbound_player_remove(&reader, protocol,
                &removal));
            assert(mc_reader_finish(&reader));
            assert(removal.profile_count == 1U);
            McUuidIterator ids;
            McUuid removed = {{0}};
            assert(mc_player_remove_iterator(&removal, &ids));
            assert(mc_uuid_iterator_next(&ids, &removed));
            assert(memcmp(removed.bytes, uuid.bytes, sizeof(uuid.bytes)) == 0);
            assert(!mc_uuid_iterator_next(&ids, &removed));
        }
    }
}

static void append_entity_movement(McPacket *packet, int protocol,
    bool position, bool rotation)
{
    if (protocol <= 5) assert(mc_packet_i32(packet, 42));
    else assert(mc_packet_varint(packet, 42));
    if (position && protocol <= 47) {
        assert(mc_packet_i8(packet, 32));
        assert(mc_packet_i8(packet, -16));
        assert(mc_packet_i8(packet, 0));
    } else if (position) {
        assert(mc_packet_i16(packet, 4096));
        assert(mc_packet_i16(packet, -2048));
        assert(mc_packet_i16(packet, 0));
    }
    if (rotation) {
        assert(mc_packet_u8(packet, 64U));
        assert(mc_packet_u8(packet, 32U));
    }
    if (protocol > 5) assert(mc_packet_bool(packet, true));
}

static void assert_movement(const McClientboundEntityMovement *movement,
    bool position, bool rotation, int protocol)
{
    assert(movement->entity_id == 42);
    assert(movement->has_position == position);
    assert(movement->has_rotation == rotation);
    assert(movement->has_on_ground == (protocol > 5));
    if (protocol > 5) assert(movement->on_ground);
    if (position) {
        assert(fabs(movement->delta_x - 1.0) < 1.0e-12);
        assert(fabs(movement->delta_y + 0.5) < 1.0e-12);
        assert(fabs(movement->delta_z) < 1.0e-12);
    }
    if (rotation) {
        assert(fabsf(movement->yaw - 90.0F) < 1.0e-6F);
        assert(fabsf(movement->pitch - 45.0F) < 1.0e-6F);
    }
}

static void relative_movement_is_normalized_for_every_protocol(void)
{
    size_t count = 0U;
    const int *protocols = mc_supported_protocols(&count);
    assert(protocols != NULL && count == 51U);
    for (size_t index = 0U; index < count; ++index) {
        const int protocol = protocols[index];
        for (unsigned int kind = 0U; kind < 3U; ++kind) {
            const bool position = kind != 2U;
            const bool rotation = kind != 0U;
            unsigned char storage[32] = {0};
            McPacket body;
            mc_packet_init(&body, storage, sizeof(storage));
            append_entity_movement(&body, protocol, position, rotation);

            McReader reader;
            McClientboundEntityMovement movement = {0};
            mc_reader_init_mode(&reader, body.data, body.length,
                MC_DECODE_STRICT, NULL);
            const bool decoded = kind == 0U
                ? mc_reader_clientbound_entity_move(&reader, protocol,
                    &movement)
                : kind == 1U
                    ? mc_reader_clientbound_entity_move_look(&reader, protocol,
                        &movement)
                    : mc_reader_clientbound_entity_look(&reader, protocol,
                        &movement);
            assert(decoded && mc_reader_finish(&reader));
            assert_movement(&movement, position, rotation, protocol);
        }
    }
}

static void living_spawn_is_normalized_for_every_applicable_protocol(void)
{
    size_t count = 0U;
    const int *protocols = mc_supported_protocols(&count);
    const McUuid uuid = sample_uuid();
    size_t applicable = 0U;
    assert(protocols != NULL && count == 51U);
    for (size_t index = 0U; index < count; ++index) {
        const int protocol = protocols[index];
        if (protocol > 758) continue;
        ++applicable;
        unsigned char storage[128] = {0};
        McPacket body;
        mc_packet_init(&body, storage, sizeof(storage));
        assert(mc_packet_varint(&body, 300000));
        if (protocol > 47) assert(mc_packet_uuid(&body, &uuid));
        if (protocol <= 210) assert(mc_packet_u8(&body, 90U));
        else assert(mc_packet_varint(&body, 90));
        if (protocol <= 47) {
            assert(mc_packet_i32(&body, 320));
            assert(mc_packet_i32(&body, 640));
            assert(mc_packet_i32(&body, -160));
        } else {
            assert(mc_packet_double(&body, 10.0));
            assert(mc_packet_double(&body, 20.0));
            assert(mc_packet_double(&body, -5.0));
        }
        assert(mc_packet_u8(&body, 64U));
        assert(mc_packet_u8(&body, 32U));
        assert(mc_packet_u8(&body, 16U));
        assert(mc_packet_i16(&body, 800));
        assert(mc_packet_i16(&body, -400));
        assert(mc_packet_i16(&body, 0));
        if (protocol <= 47) assert(mc_packet_u8(&body, UINT8_C(0x7f)));
        else if (protocol <= 498) assert(mc_packet_u8(&body, UINT8_MAX));

        McReader reader;
        McClientboundLivingEntitySpawn spawn = {0};
        mc_reader_init_mode(&reader, body.data, body.length,
            MC_DECODE_STRICT, NULL);
        assert(mc_reader_clientbound_living_entity_spawn(
            &reader, protocol, &spawn));
        assert(mc_reader_finish(&reader));
        assert(spawn.entity_id == 300000 && spawn.entity_type == 90);
        assert(fabs(spawn.x - 10.0) < 1.0e-12);
        assert(fabs(spawn.y - 20.0) < 1.0e-12);
        assert(fabs(spawn.z + 5.0) < 1.0e-12);
        assert(fabs(spawn.velocity_x - 0.1) < 1.0e-12);
        assert(fabs(spawn.velocity_y + 0.05) < 1.0e-12);
        assert(fabs(spawn.velocity_z) < 1.0e-12);
        assert(fabsf(spawn.yaw - 90.0F) < 1.0e-6F);
        assert(fabsf(spawn.pitch - 45.0F) < 1.0e-6F);
        assert(fabsf(spawn.head_yaw - 22.5F) < 1.0e-6F);
        assert(spawn.has_entity_uuid == (protocol > 47));
        assert(spawn.fixed_point_position == (protocol <= 47));
        assert(spawn.varint_entity_type == (protocol > 210));
        assert(spawn.has_metadata == (protocol <= 498));
        assert(spawn.metadata_entry_count == 0U);
    }
    assert(applicable == 33U);
}

static void malformed_player_projection_is_rejected(void)
{
    const unsigned char invalid_mask[] = {UINT8_C(0x40), 0U};
    McReader reader;
    McClientboundPlayerInfo info = {0};
    mc_reader_init(&reader, invalid_mask, sizeof(invalid_mask));
    assert(!mc_reader_clientbound_player_info(&reader, 761, &info));

    const unsigned char invalid_ground[] = {42U, 0U, 0U, 0U, 2U};
    McClientboundEntityMovement movement = {0};
    mc_reader_init_mode(&reader, invalid_ground, sizeof(invalid_ground),
        MC_DECODE_STRICT, NULL);
    assert(!mc_reader_clientbound_entity_move(&reader, 47, &movement));
}

int main(void)
{
    player_info_is_normalized_for_every_protocol();
    relative_movement_is_normalized_for_every_protocol();
    living_spawn_is_normalized_for_every_applicable_protocol();
    malformed_player_projection_is_rejected();
    puts("player projection tests passed");
    return 0;
}
