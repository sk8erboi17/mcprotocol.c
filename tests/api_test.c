#include "api.h"

#include <assert.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

static void expect_string(McReader *reader, const char *expected)
{
    McBytes value;
    assert(mc_reader_string(reader, &value));
    assert(value.size == strlen(expected));
    assert(memcmp(value.data, expected, value.size) == 0);
}

static void status_packet_catalog_is_public(void)
{
    static const struct {
        McPacketDirection direction;
        int32_t id;
        const char *name;
    } expected[] = {
        {MC_PACKET_SERVERBOUND, 0, "ping_start"},
        {MC_PACKET_SERVERBOUND, 1, "ping"},
        {MC_PACKET_CLIENTBOUND, 0, "server_info"},
        {MC_PACKET_CLIENTBOUND, 1, "ping"},
    };
    for (size_t index = 0U; index < sizeof(expected) / sizeof(expected[0]); ++index) {
        assert(mc_packet_id(4, MC_STATE_STATUS,
            expected[index].direction, expected[index].name) == expected[index].id);
        assert(strcmp(mc_packet_name(776, MC_STATE_STATUS,
            expected[index].direction, expected[index].id), expected[index].name) == 0);
    }

    size_t status_count = 0U;
    McPacketInfo packet = {0};
    for (size_t index = 0U; mc_packet_at(776, index, &packet); ++index) {
        if (packet.state == MC_STATE_STATUS) ++status_count;
    }
    assert(status_count == sizeof(expected) / sizeof(expected[0]));
}

static void nbt_writer_validates_complete_values(void)
{
    static const unsigned char compound[] = {10U, 0U};
    static const unsigned char named_compound[] = {10U, 0U, 0U, 0U};
    static const unsigned char truncated[] = {10U};
    unsigned char storage[8];
    McPacket packet;
    const McBytes valid = {compound, sizeof(compound)};
    const McBytes invalid = {truncated, sizeof(truncated)};

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_nbt(&packet, false, &valid));
    assert(packet.length == sizeof(compound));
    assert(memcmp(packet.data, compound, sizeof(compound)) == 0);

    const McBytes named = {named_compound, sizeof(named_compound)};
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_nbt(&packet, true, &named));
    assert(packet.length == sizeof(named_compound));

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_nbt(&packet, false, &named));
    assert(packet.failed);
    assert(packet.length == 0U);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_nbt(&packet, false, &invalid));
    assert(packet.failed);
    assert(packet.length == 0U);
}

static void length_prefixed_buffers_round_trip(void)
{
    static const unsigned char bytes[] = {0x00U, 0x7fU, 0x80U, 0xffU};
    unsigned char storage[32];
    const McBytes expected = {bytes, sizeof(bytes)};
    McPacket packet;
    McReader reader;
    McBytes decoded = {0};

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_buffer_i32(&packet, &expected));
    mc_reader_init(&reader, packet.data, packet.length);
    assert(mc_reader_buffer_i32(&reader, &decoded));
    assert(mc_reader_remaining(&reader) == 0U);
    assert(decoded.size == expected.size);
    assert(memcmp(decoded.data, expected.data, expected.size) == 0);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_buffer_varint(&packet, &expected));
    mc_reader_init(&reader, packet.data, packet.length);
    assert(mc_reader_buffer_varint(&reader, &decoded));
    assert(mc_reader_remaining(&reader) == 0U);
    assert(decoded.size == expected.size);
    assert(memcmp(decoded.data, expected.data, expected.size) == 0);

    static const unsigned char negative_i32[] = {0xffU, 0xffU, 0xffU, 0xffU};
    mc_reader_init(&reader, negative_i32, sizeof(negative_i32));
    assert(!mc_reader_buffer_i32(&reader, &decoded));
    assert(reader.failed);

    static const unsigned char truncated_varint[] = {3U, 1U, 2U};
    mc_reader_init(&reader, truncated_varint, sizeof(truncated_varint));
    assert(!mc_reader_buffer_varint(&reader, &decoded));
    assert(reader.failed);
}

static void expect_command(int protocol)
{
    unsigned char storage[384];
    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_command(&packet, protocol, "/tps",
        INT64_C(1234567890), INT64_C(987654321)));

    McReader reader;
    mc_reader_init(&reader, packet.data, packet.length);
    expect_string(&reader, protocol <= 758 ? "/tps" : "tps");
    if (protocol >= 759 && protocol <= 765) {
        int64_t timestamp = 0;
        int64_t salt = 0;
        int32_t signatures = -1;
        assert(mc_reader_i64(&reader, &timestamp));
        assert(mc_reader_i64(&reader, &salt));
        assert(mc_reader_varint(&reader, &signatures));
        assert(timestamp == INT64_C(1234567890));
        assert(salt == INT64_C(987654321));
        assert(signatures == 0);
        if (protocol == 759) {
            bool signed_preview = true;
            assert(mc_reader_bool(&reader, &signed_preview));
            assert(!signed_preview);
        } else if (protocol == 760) {
            bool signed_preview = true;
            int32_t previous_messages = -1;
            bool has_last_rejected = true;
            assert(mc_reader_bool(&reader, &signed_preview));
            assert(mc_reader_varint(&reader, &previous_messages));
            assert(mc_reader_bool(&reader, &has_last_rejected));
            assert(!signed_preview);
            assert(previous_messages == 0);
            assert(!has_last_rejected);
        } else {
            int32_t message_count = -1;
            McBytes acknowledged;
            assert(mc_reader_varint(&reader, &message_count));
            assert(mc_reader_bytes(&reader, 3U, &acknowledged));
            assert(message_count == 0);
            assert(acknowledged.data[0] == 0U);
            assert(acknowledged.data[1] == 0U);
            assert(acknowledged.data[2] == 0U);
        }
    }
    assert(mc_reader_remaining(&reader) == 0U);
    const char *packet_name = protocol <= 758 ? "chat" : "chat_command";
    assert(mc_packet_id(protocol, MC_STATE_PLAY,
        MC_PACKET_SERVERBOUND, packet_name) >= 0);
}

static void invalid_commands_fail_sticky(void)
{
    unsigned char storage[512];
    char too_long[258];
    memset(too_long, 'a', sizeof(too_long));
    too_long[sizeof(too_long) - 1U] = '\0';

    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_command(&packet, 776, "", 0, 0));
    assert(packet.failed);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_command(&packet, 776, "/", 0, 0));
    assert(packet.failed);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_command(&packet, 776, too_long, 0, 0));
    assert(packet.failed);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_command(&packet, 6, "tps", 0, 0));
    assert(packet.failed);
}

static void expect_player_abilities(int protocol)
{
    const McPlayerAbilities expected = {
        .flags = 0x0dU,
        .flying_speed = 0.05F,
        .walking_speed = 0.1F,
    };
    unsigned char storage[9];
    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_player_abilities(&packet, protocol, &expected));
    assert(packet.length == (protocol < 735 ? sizeof(storage) : 1U));

    McReader reader;
    uint8_t flags = 0U;
    float flying_speed = 0.0F;
    float walking_speed = 0.0F;
    mc_reader_init(&reader, packet.data, packet.length);
    assert(mc_reader_u8(&reader, &flags));
    if (protocol < 735) {
        assert(mc_reader_float(&reader, &flying_speed));
        assert(mc_reader_float(&reader, &walking_speed));
    }
    assert(mc_reader_remaining(&reader) == 0U);
    assert(flags == expected.flags);
    if (protocol < 735) {
        assert(flying_speed == expected.flying_speed);
        assert(walking_speed == expected.walking_speed);
    }

    unsigned char short_storage[8];
    mc_packet_init(&packet, short_storage, sizeof(short_storage));
    assert(mc_packet_player_abilities(&packet, protocol, &expected) == (protocol >= 735));
    assert(packet.failed == (protocol < 735));
    if (protocol < 735) {
        assert(!mc_packet_player_abilities(&packet, protocol, &expected));
    }

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_player_abilities(&packet, protocol, NULL));
    assert(packet.failed);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_player_abilities(&packet, 6, &expected));
    assert(packet.failed);
}

static void attack_and_respawn_bodies_are_versioned(void)
{
    static const struct {
        int protocol;
        unsigned char bytes[5];
        size_t size;
    } attacks[] = {
        {5, {0x00U, 0x00U, 0x01U, 0x2cU, 0x01U}, 5U},
        {47, {0xacU, 0x02U, 0x01U}, 3U},
        {578, {0xacU, 0x02U, 0x01U}, 3U},
        {735, {0xacU, 0x02U, 0x01U, 0x00U}, 4U},
        {774, {0xacU, 0x02U, 0x01U, 0x00U}, 4U},
        {775, {0xacU, 0x02U}, 2U},
        {776, {0xacU, 0x02U}, 2U},
    };
    unsigned char storage[16];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(attacks) / sizeof(attacks[0]); ++index) {
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_attack_entity(&packet, attacks[index].protocol, 300));
        assert(packet.length == attacks[index].size);
        assert(memcmp(packet.data, attacks[index].bytes, packet.length) == 0);

        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_respawn_request(&packet, attacks[index].protocol));
        assert(packet.length == 1U && packet.data[0] == 0U);
    }

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_attack_entity(&packet, 776, 0));
    assert(packet.failed);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_attack_entity(&packet, 6, 1));
    assert(packet.failed);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_respawn_request(&packet, 6));
    assert(packet.failed);
    assert(!mc_packet_attack_entity(NULL, 776, 1));
    assert(!mc_packet_respawn_request(NULL, 776));
}

static void block_dig_bodies_are_versioned(void)
{
    static const struct {
        int protocol;
        McBlockDig dig;
        unsigned char bytes[11];
        size_t size;
    } cases[] = {
        {5, {0, {-9, 64, 11}, 1, 7},
            {0x00U,0xffU,0xffU,0xffU,0xf7U,0x40U,0x00U,0x00U,0x00U,0x0bU,0x01U}, 11U},
        {47, {0, {-9, 64, 11}, 1, 7},
            {0x00U,0xffU,0xffU,0xfdU,0xc1U,0x00U,0x00U,0x00U,0x0bU,0x01U}, 10U},
        {758, {0, {-9, -60, 11}, 1, 7},
            {0x00U,0xffU,0xffU,0xfdU,0xc0U,0x00U,0x00U,0xbfU,0xc4U,0x01U}, 10U},
        {759, {0, {-9, -60, 11}, 1, 7},
            {0x00U,0xffU,0xffU,0xfdU,0xc0U,0x00U,0x00U,0xbfU,0xc4U,0x01U,0x07U}, 11U},
        {776, {4, {0, 0, 0}, 0, 0},
            {0x04U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U}, 11U},
    };
    unsigned char storage[16];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_block_dig(
            &packet, cases[index].protocol, &cases[index].dig));
        assert(packet.length == cases[index].size);
        assert(memcmp(packet.data, cases[index].bytes, packet.length) == 0);
    }

    const McBlockDig invalid_status = {7, {0, 0, 0}, 0, 0};
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_block_dig(&packet, 776, &invalid_status));
    assert(packet.failed);
    const McBlockDig invalid_legacy_y = {0, {0, -1, 0}, 1, 0};
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_block_dig(&packet, 5, &invalid_legacy_y));
    assert(packet.failed);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_block_dig(&packet, 6, &cases[0].dig));
    assert(packet.failed);
    assert(!mc_packet_block_dig(NULL, 776, &cases[4].dig));
}

static void block_changes_are_versioned(void)
{
    static const unsigned char legacy[] = {
        0xffU,0xffU,0xffU,0xf7U,0x40U,0x00U,0x00U,0x00U,0x0bU,0x80U,0x01U,0x07U,
    };
    McReader reader;
    McPosition position = {0};
    int32_t state_id = -1;
    mc_reader_init(&reader, legacy, sizeof(legacy));
    assert(mc_reader_block_change(&reader, 4, &position, &state_id));
    assert(position.x == -9 && position.y == 64 && position.z == 11);
    assert(state_id == ((128 << 4) | 7) && mc_reader_remaining(&reader) == 0U);

    unsigned char modern[16];
    McPacket packet;
    mc_packet_init(&packet, modern, sizeof(modern));
    assert(mc_packet_position(&packet, 776, (McPosition){-9, -60, 11}));
    assert(mc_packet_varint(&packet, 30417));
    mc_reader_init(&reader, modern, packet.length);
    position = (McPosition){0};
    state_id = -1;
    assert(mc_reader_block_change(&reader, 776, &position, &state_id));
    assert(position.x == -9 && position.y == -60 && position.z == 11);
    assert(state_id == 30417 && mc_reader_remaining(&reader) == 0U);

    static const unsigned char negative_state[] = {
        0x00U,0x00U,0x00U,0x00U,0x40U,0x00U,0x00U,0x00U,0x00U,
        0xffU,0xffU,0xffU,0xffU,0x0fU,
    };
    mc_reader_init(&reader, negative_state, sizeof(negative_state));
    assert(!mc_reader_block_change(&reader, 5, &position, &state_id));
    assert(reader.failed);
    assert(!mc_reader_block_change(NULL, 776, &position, &state_id));
}

static void client_information_bodies_match_node(void)
{
    /* Bodies exclude the packet ID. They were serialized by the historical
     * node-minecraft-protocol client at each field-family boundary. */
    static const unsigned char body_1_7[] = {
        0x05U,0x65U,0x6eU,0x5fU,0x75U,0x73U,0x02U,0x00U,0x01U,0x00U,0x01U,
    };
    static const unsigned char body_1_8[] = {
        0x05U,0x65U,0x6eU,0x5fU,0x75U,0x73U,0x02U,0x00U,0x01U,0x7fU,
    };
    static const unsigned char body_1_9[] = {
        0x05U,0x65U,0x6eU,0x5fU,0x75U,0x73U,0x02U,0x00U,0x01U,0x7fU,0x01U,
    };
    static const unsigned char body_1_17[] = {
        0x05U,0x65U,0x6eU,0x5fU,0x75U,0x73U,0x02U,0x00U,0x01U,0x7fU,0x01U,0x00U,
    };
    static const unsigned char body_1_18[] = {
        0x05U,0x65U,0x6eU,0x5fU,0x75U,0x73U,0x02U,0x00U,0x01U,0x7fU,0x01U,0x00U,0x01U,
    };
    static const unsigned char body_1_21_3[] = {
        0x05U,0x65U,0x6eU,0x5fU,0x75U,0x73U,0x02U,0x00U,0x01U,0x7fU,0x01U,0x00U,0x01U,0x00U,
    };
    static const struct {
        int protocol;
        const unsigned char *bytes;
        size_t size;
    } cases[] = {
        {4, body_1_7, sizeof(body_1_7)},
        {47, body_1_8, sizeof(body_1_8)},
        {107, body_1_9, sizeof(body_1_9)},
        {755, body_1_17, sizeof(body_1_17)},
        {757, body_1_18, sizeof(body_1_18)},
        {765, body_1_18, sizeof(body_1_18)},
        {768, body_1_21_3, sizeof(body_1_21_3)},
        {776, body_1_21_3, sizeof(body_1_21_3)},
    };
    McClientInformation information = {
        .locale = "en_us",
        .view_distance = 2,
        .chat_mode = 0,
        .chat_colors = true,
        .skin_parts = 0x7fU,
        .difficulty = 0U,
        .show_cape = true,
        .main_hand = 1,
        .text_filtering = false,
        .server_listing = true,
        .particle_status = 0,
    };
    unsigned char storage[64];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_client_information(
            &packet, cases[index].protocol, &information));
        assert(packet.length == cases[index].size);
        assert(memcmp(packet.data, cases[index].bytes, packet.length) == 0);
    }

    information.view_distance = 1;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_client_information(&packet, 776, &information));
    assert(packet.failed);
    information.view_distance = 2;
    information.particle_status = 3;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_client_information(&packet, 768, &information));
    information.particle_status = 0;
    information.main_hand = 2;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_client_information(&packet, 107, &information));
    information.main_hand = 1;
    information.difficulty = 4U;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_client_information(&packet, 4, &information));
    assert(!mc_packet_client_information(NULL, 776, &information));
}

static void player_action_bodies_match_node(void)
{
    static const unsigned char sneak_1_7[] = {
        0x00U,0x00U,0x00U,0x2aU,0x01U,0x00U,0x00U,0x00U,0x00U,
    };
    static const unsigned char sneak_1_8[] = {0x2aU,0x00U,0x00U};
    static const unsigned char sprint_1_21_5[] = {0x2aU,0x03U,0x00U};
    static const unsigned char sprint_1_21_6[] = {0x2aU,0x01U,0x00U};
    static const struct {
        int protocol;
        McEntityActionKind action;
        const unsigned char *bytes;
        size_t size;
    } action_cases[] = {
        {4, MC_ENTITY_ACTION_START_SNEAKING,
            sneak_1_7, sizeof(sneak_1_7)},
        {47, MC_ENTITY_ACTION_START_SNEAKING,
            sneak_1_8, sizeof(sneak_1_8)},
        {770, MC_ENTITY_ACTION_START_SPRINTING,
            sprint_1_21_5, sizeof(sprint_1_21_5)},
        {771, MC_ENTITY_ACTION_START_SPRINTING,
            sprint_1_21_6, sizeof(sprint_1_21_6)},
    };
    unsigned char storage[32];
    McPacket packet;
    for (size_t index = 0U;
            index < sizeof(action_cases) / sizeof(action_cases[0]); ++index) {
        const McEntityAction action = {
            .entity_id = 42,
            .action = action_cases[index].action,
            .jump_boost = 0,
        };
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_entity_action(
            &packet, action_cases[index].protocol, &action));
        assert(packet.length == action_cases[index].size);
        assert(memcmp(packet.data,
            action_cases[index].bytes, packet.length) == 0);
    }

    const McEntityAction removed_sneak = {
        .entity_id = 42,
        .action = MC_ENTITY_ACTION_START_SNEAKING,
        .jump_boost = 0,
    };
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_entity_action(&packet, 771, &removed_sneak));
    assert(packet.failed);
    McEntityAction early_elytra = removed_sneak;
    early_elytra.action = MC_ENTITY_ACTION_START_ELYTRA_FLYING;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_entity_action(&packet, 47, &early_elytra));
    assert(!mc_packet_entity_action(NULL, 776, &removed_sneak));

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_player_input(&packet, 768, MC_PLAYER_INPUT_SHIFT));
    assert(packet.length == 1U && packet.data[0] == 0x20U);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_player_input(&packet, 767, MC_PLAYER_INPUT_SHIFT));
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_player_input(&packet, 776, UINT8_C(0x80)));
    assert(!mc_packet_player_input(NULL, 776, 0U));

    static const unsigned char arm_1_7[] = {
        0x00U,0x00U,0x00U,0x2aU,0x01U,
    };
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_arm_animation(&packet, 4, 42, 0));
    assert(packet.length == sizeof(arm_1_7));
    assert(memcmp(packet.data, arm_1_7, packet.length) == 0);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_arm_animation(&packet, 47, 0, 0));
    assert(packet.length == 0U);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_arm_animation(&packet, 107, 0, 0));
    assert(packet.length == 1U && packet.data[0] == 0x00U);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_arm_animation(&packet, 776, 0, 2));
    assert(!mc_packet_arm_animation(NULL, 776, 0, 0));
}

static void player_positions_are_versioned(void)
{
    unsigned char storage[64];
    McPacket packet;
    const McPlayerPosition position = {
        .x = -8.5,
        .y = 64.0,
        .z = 9.5,
        .yaw = 12.0F,
        .pitch = 34.0F,
        .on_ground = true,
    };
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_player_position(&packet, 4, &position));
    McReader reader;
    double value = 0.0;
    float rotation = 0.0F;
    bool on_ground = false;
    mc_reader_init(&reader, storage, packet.length);
    assert(mc_reader_double(&reader, &value) && value == position.x);
    assert(mc_reader_double(&reader, &value) && fabs(value - position.y) < 1.0e-12);
    assert(mc_reader_double(&reader, &value) &&
        fabs(value - (position.y + 1.62)) < 1.0e-12);
    assert(mc_reader_double(&reader, &value) && value == position.z);
    assert(mc_reader_float(&reader, &rotation) && rotation == position.yaw);
    assert(mc_reader_float(&reader, &rotation) && rotation == position.pitch);
    assert(mc_reader_bool(&reader, &on_ground) && on_ground);
    assert(mc_reader_remaining(&reader) == 0U);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_player_position(&packet, 47, &position));
    assert(packet.length == 33U);
}

static void clientbound_player_positions_are_versioned(void)
{
    static const int protocols[] = {4, 47, 107, 754, 755, 762, 763, 767, 768, 776};
    for (size_t index = 0U; index < sizeof(protocols) / sizeof(protocols[0]); ++index) {
        const int protocol = protocols[index];
        unsigned char storage[96] = {0};
        McPacket packet;
        mc_packet_init(&packet, storage, sizeof(storage));
        if (protocol >= 768) {
            assert(mc_packet_varint(&packet, 17));
        }
        assert(mc_packet_double(&packet, -8.5));
        assert(mc_packet_double(&packet,
            protocol <= 5 ? 65.6200000047683716 : 64.0));
        assert(mc_packet_double(&packet, 9.5));
        if (protocol >= 768) {
            assert(mc_packet_double(&packet, 0.25));
            assert(mc_packet_double(&packet, -0.5));
            assert(mc_packet_double(&packet, 0.75));
        }
        assert(mc_packet_float(&packet, 12.0F));
        assert(mc_packet_float(&packet, 34.0F));
        if (protocol >= 768) {
            assert(mc_packet_i32(&packet, 0x101));
        } else {
            assert(mc_packet_u8(&packet, 0x05U));
            if (protocol >= 107) assert(mc_packet_varint(&packet, 17));
            if (protocol >= 755 && protocol <= 762) {
                assert(mc_packet_bool(&packet, true));
            }
        }

        McReader reader;
        McClientboundPlayerPosition decoded = {0};
        mc_reader_init(&reader, packet.data, packet.length);
        assert(mc_reader_clientbound_player_position(
            &reader, protocol, &decoded));
        assert(mc_reader_remaining(&reader) == 0U);
        assert(decoded.position.x == -8.5);
        assert(fabs(decoded.position.y - 64.0) < 1.0e-12);
        assert(decoded.position.z == 9.5);
        assert(decoded.position.yaw == 12.0F);
        assert(decoded.position.pitch == 34.0F);
        assert(decoded.relative_flags == (protocol >= 768 ? 0x101U : 0x05U));
        assert(decoded.has_velocity_delta == (protocol >= 768));
        assert(decoded.has_teleport_id == (protocol >= 107));
        assert(decoded.teleport_id == (protocol >= 107 ? 17 : 0));
        assert(decoded.dismount_vehicle == (protocol >= 755 && protocol <= 762));
        assert(decoded.delta_x == (protocol >= 768 ? 0.25 : 0.0));
        assert(decoded.delta_y == (protocol >= 768 ? -0.5 : 0.0));
        assert(decoded.delta_z == (protocol >= 768 ? 0.75 : 0.0));
    }

    unsigned char malformed[] = {0U};
    McReader reader;
    McClientboundPlayerPosition decoded = {0};
    mc_reader_init(&reader, malformed, sizeof(malformed));
    assert(!mc_reader_clientbound_player_position(&reader, 47, &decoded));
    assert(reader.failed);
    mc_reader_init(&reader, malformed, sizeof(malformed));
    assert(!mc_reader_clientbound_player_position(&reader, 999, &decoded));
    assert(reader.failed);
    assert(!mc_reader_clientbound_player_position(NULL, 47, &decoded));
}

static void movement_and_hotbar_bodies_match_node(void)
{
    /* Bodies excluding ID. The 1.7 position pair follows the canonical
     * PacketPlayInPosition source (feet Y, then stance Y); minecraft-data's
     * inherited field labels are reversed and must not dictate wire order. */
    static const unsigned char position_1_7[] = {
        0xc0U,0x21U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,
        0x40U,0x50U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,
        0x40U,0x50U,0x67U,0xaeU,0x14U,0x7aU,0xe1U,0x48U,
        0x40U,0x23U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,
        0x42U,0xb4U,0x00U,0x00U,0x41U,0xa0U,0x00U,0x00U,0x01U,
    };
    static const unsigned char position_1_8[] = {
        0xc0U,0x21U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,
        0x40U,0x50U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,
        0x40U,0x23U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,
        0x42U,0xb4U,0x00U,0x00U,0x41U,0xa0U,0x00U,0x00U,0x01U,
    };
    static const unsigned char position_26_2[] = {
        0xc0U,0x21U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,
        0xc0U,0x4eU,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,
        0x40U,0x23U,0x00U,0x00U,0x00U,0x00U,0x00U,0x00U,
        0x42U,0xb4U,0x00U,0x00U,0x41U,0xa0U,0x00U,0x00U,0x01U,
    };
    static const struct {
        int protocol;
        double y;
        const unsigned char *bytes;
        size_t size;
    } cases[] = {
        {4, 64.0, position_1_7, sizeof(position_1_7)},
        {47, 64.0, position_1_8, sizeof(position_1_8)},
        {776, -60.0, position_26_2, sizeof(position_26_2)},
    };
    unsigned char storage[64];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const McPlayerPosition position = {
            -8.5, cases[index].y, 9.5, 90.0F, 20.0F, true
        };
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_player_position(
            &packet, cases[index].protocol, &position));
        assert(packet.length == cases[index].size);
        assert(memcmp(packet.data, cases[index].bytes, packet.length) == 0);
    }

    const McPlayerPosition non_finite = {
        NAN, 64.0, 9.5, 0.0F, 0.0F, true
    };
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_player_position(&packet, 47, &non_finite));
    assert(packet.failed);
    assert(!mc_packet_player_position(NULL, 47, &non_finite));

    static const unsigned char held_slot[] = {0x00U, 0x07U};
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_held_item_slot(&packet, cases[index].protocol, 7));
        assert(packet.length == sizeof(held_slot));
        assert(memcmp(packet.data, held_slot, packet.length) == 0);
    }
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_held_item_slot(&packet, 776, 9));
    assert(packet.failed);
    assert(!mc_packet_held_item_slot(NULL, 776, 0));
}

static void block_place_bodies_are_versioned(void)
{
    static const unsigned char body_5[] = {
        0xffU,0xffU,0xffU,0xf7U,0x3fU,0x00U,0x00U,0x00U,0x0bU,0x01U,
        0x00U,0x01U,0x40U,0x00U,0x00U,0xffU,0xffU,0x08U,0x10U,0x08U};
    static const unsigned char body_47[] = {
        0xffU,0xffU,0xfdU,0xc0U,0xfcU,0x00U,0x00U,0x0bU,0x01U,0x00U,
        0x01U,0x40U,0x00U,0x00U,0x00U,0x08U,0x10U,0x08U};
    static const unsigned char body_107[] = {
        0xffU,0xffU,0xfdU,0xc0U,0xfcU,0x00U,0x00U,0x0bU,0x01U,0x00U,
        0x08U,0x10U,0x08U};
    static const unsigned char body_315[] = {
        0xffU,0xffU,0xfdU,0xc0U,0xfcU,0x00U,0x00U,0x0bU,0x01U,0x00U,
        0x3fU,0x00U,0x00U,0x00U,0x3fU,0x80U,0x00U,0x00U,0x3fU,0x00U,
        0x00U,0x00U};
    static const unsigned char body_477[] = {
        0x00U,0xffU,0xffU,0xfdU,0xc0U,0x00U,0x00U,0xb0U,0x3fU,0x01U,
        0x3fU,0x00U,0x00U,0x00U,0x3fU,0x80U,0x00U,0x00U,0x3fU,0x00U,
        0x00U,0x00U,0x00U};
    static const unsigned char body_758[] = {
        0x00U,0xffU,0xffU,0xfdU,0xc0U,0x00U,0x00U,0xbfU,0xc3U,0x01U,
        0x3fU,0x00U,0x00U,0x00U,0x3fU,0x80U,0x00U,0x00U,0x3fU,0x00U,
        0x00U,0x00U,0x00U};
    static const unsigned char body_759[] = {
        0x00U,0xffU,0xffU,0xfdU,0xc0U,0x00U,0x00U,0xbfU,0xc3U,0x01U,
        0x3fU,0x00U,0x00U,0x00U,0x3fU,0x80U,0x00U,0x00U,0x3fU,0x00U,
        0x00U,0x00U,0x00U,0x01U};
    static const unsigned char body_768[] = {
        0x00U,0xffU,0xffU,0xfdU,0xc0U,0x00U,0x00U,0xbfU,0xc3U,0x01U,
        0x3fU,0x00U,0x00U,0x00U,0x3fU,0x80U,0x00U,0x00U,0x3fU,0x00U,
        0x00U,0x00U,0x00U,0x00U,0x01U};
    static const struct {
        int protocol;
        const unsigned char *bytes;
        size_t size;
    } cases[] = {
        {5, body_5, sizeof(body_5)},
        {47, body_47, sizeof(body_47)},
        {107, body_107, sizeof(body_107)},
        {315, body_315, sizeof(body_315)},
        {477, body_477, sizeof(body_477)},
        {758, body_758, sizeof(body_758)},
        {759, body_759, sizeof(body_759)},
        {768, body_768, sizeof(body_768)},
        {775, body_768, sizeof(body_768)},
        {776, body_768, sizeof(body_768)},
    };
    unsigned char storage[32];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        const int protocol = cases[index].protocol;
        const McBlockPlace place = {
            .location = {-9, protocol <= 756 ? 63 : -61, 11},
            .direction = 1,
            .hand = 0,
            .held_item_id = 1,
            .held_item_count = 64,
            .cursor_x = 0.5F,
            .cursor_y = 1.0F,
            .cursor_z = 0.5F,
            .inside_block = false,
            .world_border_hit = false,
            .sequence = 1,
        };
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_block_place(&packet, protocol, &place));
        assert(packet.length == cases[index].size);
        assert(memcmp(packet.data, cases[index].bytes, packet.length) == 0);
    }

    static const unsigned char reported_nbt[] = {
        0x0aU,0x00U,0x00U,
        0x0aU,0x00U,0x07U,'d','i','s','p','l','a','y',
        0x08U,0x00U,0x04U,'N','a','m','e',
        0x00U,0x0dU,'r','e','p','o','r','t','e','d','-','o','n','l','y',
        0x00U,0x00U,
    };
    const McBlockPlace tagged = {
        .location = {-9, 64, 11},
        .direction = 1,
        .held_item_id = 276,
        .held_item_count = 1,
        .held_item_damage = 7,
        .held_item_nbt = {reported_nbt, sizeof(reported_nbt)},
        .cursor_x = 0.5F,
        .cursor_y = 0.5F,
        .cursor_z = 0.5F,
    };
    unsigned char insufficient[32];
    mc_packet_init(&packet, insufficient, sizeof(insufficient));
    assert(!mc_packet_block_place(&packet, 5, &tagged));
    assert(packet.failed);
    unsigned char tagged_storage[256];
    mc_packet_init(&packet, tagged_storage, sizeof(tagged_storage));
    assert(mc_packet_block_place(&packet, 47, &tagged));
    assert(packet.length == 9U + 5U + sizeof(reported_nbt) + 3U);
    static const unsigned char tagged_header[] = {
        0x01U,0x14U,0x01U,0x00U,0x07U,
    };
    assert(memcmp(packet.data + 9U,
        tagged_header, sizeof(tagged_header)) == 0);
    assert(memcmp(packet.data + 14U,
        reported_nbt, sizeof(reported_nbt)) == 0);

    mc_packet_init(&packet, tagged_storage, sizeof(tagged_storage));
    assert(mc_packet_block_place(&packet, 5, &tagged));
    assert(memcmp(packet.data + 10U,
        tagged_header, sizeof(tagged_header)) == 0);
    const size_t gzip_size = ((size_t)packet.data[15U] << 8U)
        | (size_t)packet.data[16U];
    assert(gzip_size > 0U && 17U + gzip_size + 3U == packet.length);
    unsigned char inflated[sizeof(reported_nbt)];
    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = packet.data + 17U;
    stream.avail_in = (uInt)gzip_size;
    stream.next_out = inflated;
    stream.avail_out = (uInt)sizeof(inflated);
    assert(inflateInit2(&stream, 15 + 16) == Z_OK);
    assert(inflate(&stream, Z_FINISH) == Z_STREAM_END);
    assert(inflateEnd(&stream) == Z_OK);
    assert(stream.total_out == (uLong)sizeof(reported_nbt));
    assert(memcmp(inflated, reported_nbt, sizeof(reported_nbt)) == 0);

    McBlockPlace malformed_tag = tagged;
    malformed_tag.held_item_nbt.size = sizeof(reported_nbt) - 1U;
    mc_packet_init(&packet, tagged_storage, sizeof(tagged_storage));
    assert(!mc_packet_block_place(&packet, 47, &malformed_tag));
    assert(packet.failed);

    McBlockPlace invalid = {
        .location = {0, 0, 0}, .direction = 6, .cursor_x = 0.5F,
        .cursor_y = 1.0F, .cursor_z = 0.5F,
    };
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_block_place(&packet, 776, &invalid));
    assert(packet.failed);
    invalid.direction = 1;
    invalid.cursor_x = 0.3F;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_block_place(&packet, 47, &invalid));
    assert(packet.failed);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_block_place(&packet, 6, &invalid));
    assert(packet.failed);
    assert(!mc_packet_block_place(NULL, 776, &invalid));
}

static void use_item_bodies_match_node(void)
{
    static const unsigned char body_1_7[] = {
        0xffU,0xffU,0xffU,0xffU,0xffU,0xffU,0xffU,0xffU,
        0xffU,0xffU,0xffU,0xffU,0x00U,0x00U,0x00U,
    };
    static const unsigned char body_1_8[] = {
        0xffU,0xffU,0xffU,0xffU,0xffU,0xffU,0xffU,0xffU,
        0xffU,0xffU,0xffU,0x00U,0x00U,0x00U,
    };
    static const unsigned char body_1_9[] = {0x00U};
    static const unsigned char body_1_19[] = {0x00U,0xacU,0x02U};
    static const unsigned char body_1_21_1[] = {
        0x00U,0xacU,0x02U,0x42U,0xb4U,0x00U,0x00U,
        0x41U,0xa0U,0x00U,0x00U,
    };
    static const struct {
        int protocol;
        const unsigned char *bytes;
        size_t size;
    } cases[] = {
        {4, body_1_7, sizeof(body_1_7)},
        {47, body_1_8, sizeof(body_1_8)},
        {107, body_1_9, sizeof(body_1_9)},
        {759, body_1_19, sizeof(body_1_19)},
        {767, body_1_21_1, sizeof(body_1_21_1)},
        {776, body_1_21_1, sizeof(body_1_21_1)},
    };
    McUseItem use = {
        .hand = 0,
        .held_item_id = 0,
        .held_item_count = 0,
        .held_item_damage = 0,
        .sequence = 300,
        .yaw = 90.0F,
        .pitch = 20.0F,
    };
    unsigned char storage[64];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_use_item(&packet, cases[index].protocol, &use));
        assert(packet.length == cases[index].size);
        assert(memcmp(packet.data, cases[index].bytes, packet.length) == 0);
    }
    use.hand = 2;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_use_item(&packet, 776, &use));
    assert(packet.failed);
    use.hand = 0;
    use.sequence = -1;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_use_item(&packet, 759, &use));
    use.sequence = 0;
    use.yaw = NAN;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_use_item(&packet, 767, &use));
    assert(!mc_packet_use_item(NULL, 776, &use));
}

static void untrusted_component_items_match_node(void)
{
    static const unsigned char enchantment_data[] = {0x01U, 0x21U, 0x05U};
    const McItemComponentPatch enchantment = {
        .type_id = 13,
        .data = {enchantment_data, sizeof(enchantment_data)},
    };
    static const unsigned char expected[] = {
        0x01U,0xa9U,0x07U,0x01U,0x00U,0x0dU,0x03U,0x01U,0x21U,0x05U,
    };
    unsigned char storage[32];
    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_untrusted_component_item(
        &packet, 776, 937, 1, &enchantment, 1U, NULL, 0U));
    assert(packet.length == sizeof(expected));
    assert(memcmp(packet.data, expected, sizeof(expected)) == 0);

    static const int32_t removed[] = {42};
    static const unsigned char removed_expected[] = {
        0x01U,0xddU,0x09U,0x00U,0x01U,0x2aU,
    };
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_untrusted_component_item(
        &packet, 776, 1245, 1, NULL, 0U, removed, 1U));
    assert(packet.length == sizeof(removed_expected));
    assert(memcmp(packet.data, removed_expected, sizeof(removed_expected)) == 0);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_untrusted_component_item(
        &packet, 776, 0, 0, NULL, 0U, NULL, 0U));
    assert(packet.length == 1U && packet.data[0] == 0U);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_untrusted_component_item(
        &packet, 765, 937, 1, &enchantment, 1U, NULL, 0U));
    assert(packet.failed);
    const McItemComponentPatch invalid = {.type_id = -1, .data = {NULL, 0U}};
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_untrusted_component_item(
        &packet, 776, 937, 1, &invalid, 1U, NULL, 0U));
    assert(packet.failed);
    assert(!mc_packet_untrusted_component_item(
        NULL, 776, 937, 1, &enchantment, 1U, NULL, 0U));
}

static void empty_window_clicks_are_versioned(void)
{
    static const struct {
        int protocol;
        unsigned char bytes[9];
        size_t size;
    } cases[] = {
        {4, {0x00U,0x00U,0x24U,0x00U,0x00U,0x01U,0x00U,0xffU,0xffU}, 9U},
        {47, {0x00U,0x00U,0x24U,0x00U,0x00U,0x01U,0x00U,0xffU,0xffU}, 9U},
        {754, {0x00U,0x00U,0x24U,0x00U,0x00U,0x01U,0x00U,0x00U}, 8U},
        {755, {0x00U,0x00U,0x24U,0x00U,0x00U,0x00U}, 7U},
        {756, {0x00U,0x11U,0x00U,0x24U,0x00U,0x00U,0x00U,0x00U}, 8U},
        {765, {0x00U,0x11U,0x00U,0x24U,0x00U,0x00U,0x00U,0x00U}, 8U},
        {766, {0x00U,0x11U,0x00U,0x24U,0x00U,0x00U,0x00U,0x00U}, 8U},
        {769, {0x00U,0x11U,0x00U,0x24U,0x00U,0x00U,0x00U,0x00U}, 8U},
        {770, {0x00U,0x11U,0x00U,0x24U,0x00U,0x00U,0x00U,0x00U}, 8U},
        {776, {0x00U,0x11U,0x00U,0x24U,0x00U,0x00U,0x00U,0x00U}, 8U},
    };
    const McEmptyWindowClick click = {
        .window_id = 0,
        .state_id = 17,
        .slot = 36,
        .mouse_button = 0,
        .action_number = 1,
        .mode = 0,
    };
    unsigned char storage[16];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_empty_window_click(
            &packet, cases[index].protocol, &click));
        assert(packet.length == cases[index].size);
        assert(memcmp(packet.data, cases[index].bytes, packet.length) == 0);
    }

    McEmptyWindowClick invalid = click;
    invalid.mode = 7;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_empty_window_click(&packet, 776, &invalid));
    assert(packet.failed);
    invalid = click;
    invalid.window_id = 256;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_empty_window_click(&packet, 765, &invalid));
    assert(packet.failed);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_empty_window_click(&packet, 6, &click));
    assert(packet.failed);
    assert(!mc_packet_empty_window_click(NULL, 776, &click));
}

static void legacy_window_clicks_include_predicted_stacks(void)
{
    static const struct {
        int protocol;
        unsigned char bytes[14];
        size_t size;
    } cases[] = {
        {4, {0x00U,0x00U,0x25U,0x00U,0x00U,0x07U,0x00U,0x00U,0x80U,
             0x20U,0x00U,0x00U,0xffU,0xffU}, 14U},
        {47, {0x00U,0x00U,0x25U,0x00U,0x00U,0x07U,0x00U,0x00U,0x80U,
              0x20U,0x00U,0x00U,0x00U}, 13U},
        {754, {0x00U,0x00U,0x25U,0x00U,0x00U,0x07U,0x00U,0x01U,
               0x80U,0x01U,0x20U,0x00U}, 12U},
    };
    const McWindowClick click = {
        .window_id = 0,
        .state_id = 0,
        .slot = 37,
        .mouse_button = 0,
        .action_number = 7,
        .mode = 0,
        .clicked_item_id = 128,
        .clicked_item_count = 32,
    };
    unsigned char storage[32];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_window_click(&packet, cases[index].protocol, &click));
        assert(packet.length == cases[index].size);
        assert(memcmp(packet.data, cases[index].bytes, packet.length) == 0);
    }

    McWindowClick invalid = click;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_window_click(&packet, 755, &invalid));
    assert(packet.failed);
}

static void container_buttons_match_node_and_source(void)
{
    static const unsigned char legacy[] = {0x02U, 0x01U};
    static const unsigned char one_twenty_one_one[] = {
        0xc8U, 0xacU, 0x02U,
    };
    static const unsigned char modern[] = {
        0xacU, 0x02U, 0xacU, 0x02U,
    };
    static const struct {
        int protocol;
        int32_t window_id;
        int32_t button_id;
        const unsigned char *bytes;
        size_t size;
    } cases[] = {
        {4, 2, 1, legacy, sizeof(legacy)},
        {767, 200, 300, one_twenty_one_one, sizeof(one_twenty_one_one)},
        {768, 300, 300, modern, sizeof(modern)},
        /* minecraft-data 1.21.11 incorrectly labels buttonId i8; Mojang's
         * ServerboundContainerButtonClickPacket uses VAR_INT here. */
        {774, 300, 300, modern, sizeof(modern)},
        {775, 300, 300, modern, sizeof(modern)},
    };
    unsigned char storage[16];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_container_button(&packet,
            cases[index].protocol, cases[index].window_id,
            cases[index].button_id));
        assert(packet.length == cases[index].size);
        assert(memcmp(packet.data, cases[index].bytes, packet.length) == 0);
    }
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_container_button(&packet, 766, 128, 0));
    assert(packet.failed);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_container_button(&packet, 767, 256, 0));
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_container_button(&packet, 776, 0, -1));
    assert(!mc_packet_container_button(NULL, 776, 0, 0));
}

static void close_windows_and_container_ids_are_versioned(void)
{
    unsigned char storage[16];
    McPacket packet;

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_close_window(&packet, 767, 128));
    assert(packet.length == 1U && packet.data[0] == 0x80U);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_close_window(&packet, 768, 128));
    assert(packet.length == 2U && packet.data[0] == 0x80U
        && packet.data[1] == 0x01U);

    const McEmptyWindowClick click = {
        .window_id = 128,
        .state_id = 17,
        .slot = 36,
        .mouse_button = 0,
        .action_number = 1,
        .mode = 0,
    };
    static const unsigned char click_1_21_1[] = {
        0x80U,0x11U,0x00U,0x24U,0x00U,0x00U,0x00U,0x00U,
    };
    static const unsigned char click_1_21_3[] = {
        0x80U,0x01U,0x11U,0x00U,0x24U,0x00U,0x00U,0x00U,0x00U,
    };
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_empty_window_click(&packet, 767, &click));
    assert(packet.length == sizeof(click_1_21_1));
    assert(memcmp(packet.data, click_1_21_1, packet.length) == 0);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_empty_window_click(&packet, 768, &click));
    assert(packet.length == sizeof(click_1_21_3));
    assert(memcmp(packet.data, click_1_21_3, packet.length) == 0);

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_close_window(&packet, 767, 256));
    assert(packet.failed);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_close_window(&packet, 768, -1));
    assert(packet.failed);
    assert(!mc_packet_close_window(NULL, 768, 0));
}

static void creative_slots_match_node_release_boundaries(void)
{
    static const struct {
        int protocol;
        unsigned char bytes[9];
        size_t size;
    } cases[] = {
        {4, {0x00U,0x25U,0x00U,0x03U,0x07U,0x00U,0x00U,0xffU,0xffU}, 9U},
        {47, {0x00U,0x25U,0x00U,0x03U,0x07U,0x00U,0x00U,0x00U}, 8U},
        {340, {0x00U,0x25U,0x00U,0x03U,0x07U,0x00U,0x00U,0x00U}, 8U},
        {393, {0x00U,0x25U,0x00U,0x03U,0x07U,0x00U}, 6U},
        {401, {0x00U,0x25U,0x00U,0x03U,0x07U,0x00U}, 6U},
        {404, {0x00U,0x25U,0x01U,0x03U,0x07U,0x00U}, 6U},
        {765, {0x00U,0x25U,0x01U,0x03U,0x07U,0x00U}, 6U},
        {766, {0x00U,0x25U,0x07U,0x03U,0x00U,0x00U}, 6U},
        {770, {0x00U,0x25U,0x07U,0x03U,0x00U,0x00U}, 6U},
        {775, {0x00U,0x25U,0x07U,0x03U,0x00U,0x00U}, 6U},
        {776, {0x00U,0x25U,0x07U,0x03U,0x00U,0x00U}, 6U},
    };
    unsigned char storage[16];
    McPacket packet;
    for (size_t index = 0U; index < sizeof(cases) / sizeof(cases[0]); ++index) {
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_set_creative_slot(
            &packet, cases[index].protocol, 37, 3, 7));
        assert(packet.length == cases[index].size);
        assert(memcmp(packet.data, cases[index].bytes, packet.length) == 0);
    }

    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_set_creative_slot(&packet, 776, 37, 0, 1));
    assert(packet.failed);
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(!mc_packet_set_creative_slot(&packet, 776, 37, 3, 128));
    assert(packet.failed);
    assert(!mc_packet_set_creative_slot(NULL, 776, 37, 3, 7));
}

static void dump_command(int protocol)
{
    unsigned char storage[384];
    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_command(&packet, protocol, "/tps",
        INT64_C(1234567890), INT64_C(987654321)));
    printf("%d:", protocol);
    for (size_t index = 0U; index < packet.length; ++index) {
        printf("%02x", packet.data[index]);
    }
    putchar('\n');
}

static void dump_player_abilities(int protocol)
{
    unsigned char storage[9];
    const McPlayerAbilities abilities = {
        .flags = 0x0dU,
        .flying_speed = 0.05F,
        .walking_speed = 0.1F,
    };
    McPacket packet;
    mc_packet_init(&packet, storage, sizeof(storage));
    assert(mc_packet_player_abilities(&packet, protocol, &abilities));
    printf("%d:", protocol);
    for (size_t index = 0U; index < packet.length; ++index) {
        printf("%02x", packet.data[index]);
    }
    putchar('\n');
}

int main(int argc, char **argv)
{
    const int boundary_protocols[] = {4, 578, 735, 758, 759, 760, 761, 765, 766, 776};
    if (argc == 2 && strcmp(argv[1], "--dump-commands") == 0) {
        for (size_t index = 0U;
                index < sizeof(boundary_protocols) / sizeof(boundary_protocols[0]); ++index) {
            dump_command(boundary_protocols[index]);
        }
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--dump-abilities") == 0) {
        for (size_t index = 0U;
                index < sizeof(boundary_protocols) / sizeof(boundary_protocols[0]); ++index) {
            dump_player_abilities(boundary_protocols[index]);
        }
        return 0;
    }
    for (size_t index = 0U;
            index < sizeof(boundary_protocols) / sizeof(boundary_protocols[0]); ++index) {
        expect_command(boundary_protocols[index]);
    }
    invalid_commands_fail_sticky();
    status_packet_catalog_is_public();
    nbt_writer_validates_complete_values();
    length_prefixed_buffers_round_trip();
    expect_player_abilities(4);
    expect_player_abilities(578);
    expect_player_abilities(735);
    expect_player_abilities(776);
    attack_and_respawn_bodies_are_versioned();
    block_dig_bodies_are_versioned();
    block_changes_are_versioned();
    client_information_bodies_match_node();
    player_action_bodies_match_node();
    player_positions_are_versioned();
    clientbound_player_positions_are_versioned();
    movement_and_hotbar_bodies_match_node();
    block_place_bodies_are_versioned();
    use_item_bodies_match_node();
    untrusted_component_items_match_node();
    empty_window_clicks_are_versioned();
    legacy_window_clicks_include_predicted_stacks();
    container_buttons_match_node_and_source();
    close_windows_and_container_ids_are_versioned();
    creative_slots_match_node_release_boundaries();
    puts("PASS command, client information, movement, player actions, abilities, block actions, hotbar, inventory, component items, combat, respawn, NBT and buffer codecs");
    return 0;
}
