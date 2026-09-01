#include "api.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t test_state;

static uint64_t random_u64(void)
{
    uint64_t value = test_state;
    value ^= value << 13U;
    value ^= value >> 7U;
    value ^= value << 17U;
    test_state = value;
    return value;
}

static int32_t random_i32(void)
{
    const uint32_t bits = (uint32_t)random_u64();
    int32_t value = 0;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static int64_t random_i64(void)
{
    const uint64_t bits = random_u64();
    int64_t value = 0;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static void test_varints(void)
{
    for (size_t iteration = 0U; iteration < 50000U; ++iteration) {
        unsigned char bytes[16];
        McPacket packet;
        McReader reader;
        McError error;
        const int32_t input32 = random_i32();
        mc_packet_init(&packet, bytes, sizeof(bytes));
        assert(mc_packet_varint(&packet, input32));
        int32_t output32 = 0;
        mc_reader_init_mode(&reader, bytes, packet.length,
            MC_DECODE_STRICT, &error);
        assert(mc_reader_varint(&reader, &output32));
        assert(mc_reader_finish(&reader));
        assert(input32 == output32);

        const int64_t input64 = random_i64();
        mc_packet_init(&packet, bytes, sizeof(bytes));
        assert(mc_packet_varlong(&packet, input64));
        int64_t output64 = 0;
        mc_reader_init_mode(&reader, bytes, packet.length,
            MC_DECODE_STRICT, &error);
        assert(mc_reader_varlong(&reader, &output64));
        assert(mc_reader_finish(&reader));
        assert(input64 == output64);
    }
}

static void test_positions(void)
{
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    for (size_t iteration = 0U; iteration < 10000U; ++iteration) {
        const McPosition input = {
            .x = (int32_t)(random_u64() % UINT64_C(67108864)) - 33554432,
            .y = (int32_t)(random_u64() % UINT64_C(4096)) - 2048,
            .z = (int32_t)(random_u64() % UINT64_C(67108864)) - 33554432,
        };
        const int protocol = protocols[random_u64() % protocol_count];
        unsigned char bytes[8];
        McPacket packet;
        mc_packet_init(&packet, bytes, sizeof(bytes));
        assert(mc_packet_position(&packet, protocol, input));
        assert(packet.length == sizeof(bytes));
        McReader reader;
        McPosition output;
        mc_reader_init(&reader, bytes, sizeof(bytes));
        assert(mc_reader_position(&reader, protocol, &output));
        assert(mc_reader_finish(&reader));
        assert(memcmp(&input, &output, sizeof(input)) == 0);
    }
}

static void test_uuids(void)
{
    for (size_t iteration = 0U; iteration < 10000U; ++iteration) {
        McUuid input;
        for (size_t index = 0U; index < sizeof(input.bytes); ++index) {
            input.bytes[index] = (unsigned char)random_u64();
        }
        unsigned char bytes[16];
        McPacket packet;
        mc_packet_init(&packet, bytes, sizeof(bytes));
        assert(mc_packet_uuid(&packet, &input));
        McReader reader;
        McUuid output;
        mc_reader_init(&reader, bytes, packet.length);
        assert(mc_reader_uuid(&reader, &output));
        assert(mc_reader_finish(&reader));
        assert(memcmp(&input, &output, sizeof(input)) == 0);
    }
}

static void test_plain_items(void)
{
    size_t protocol_count = 0U;
    const int *protocols = mc_supported_protocols(&protocol_count);
    for (size_t protocol_index = 0U; protocol_index < protocol_count;
            ++protocol_index) {
        for (size_t iteration = 0U; iteration < 128U; ++iteration) {
            const int32_t item_id = 1 + (int32_t)(random_u64() % 30000U);
            const int32_t count = 1 + (int32_t)(random_u64() % 127U);
            unsigned char bytes[64];
            McPacket packet;
            mc_packet_init(&packet, bytes, sizeof(bytes));
            assert(mc_packet_plain_item(&packet, protocols[protocol_index],
                item_id, count));
            McReader reader;
            McItemStackView item;
            mc_reader_init_mode(&reader, bytes, packet.length,
                MC_DECODE_STRICT, NULL);
            assert(mc_reader_item_stack(&reader, protocols[protocol_index],
                MC_ITEM_WIRE_FULL, &item));
            assert(mc_reader_finish(&reader));
            assert(item.item_id == item_id);
            assert(item.count == count);
        }
    }
}

static int32_t container_component_id(int protocol)
{
    if (protocol == 766) return 51;
    if (protocol == 767) return 52;
    if (protocol <= 769) return 62;
    if (protocol <= 773) return 66;
    if (protocol == 774) return 73;
    return 75;
}

static void encode_component_item_count(McPacket *packet, int protocol,
    int32_t count)
{
    if (protocol == 766) {
        assert(mc_packet_i8(packet, (int8_t)count));
    } else {
        assert(mc_packet_varint(packet, count));
    }
}

static void encode_nested_component_item(McPacket *packet, int protocol,
    unsigned int nesting)
{
    if (nesting == 0U) {
        encode_component_item_count(packet, protocol, 0);
        return;
    }
    encode_component_item_count(packet, protocol, 1);
    assert(mc_packet_varint(packet, 5));
    assert(mc_packet_varint(packet, 1));
    assert(mc_packet_varint(packet, 0));
    assert(mc_packet_varint(packet, container_component_id(protocol)));
    assert(mc_packet_varint(packet, 1));
    encode_nested_component_item(packet, protocol, nesting - 1U);
}

static void test_component_items(void)
{
    static const unsigned char anonymous_empty_compound[] = {
        UINT8_C(0x0a), 0U
    };
    const McBytes custom_data = {
        anonymous_empty_compound, sizeof(anonymous_empty_compound)
    };
    for (int protocol = 766; protocol <= 776; ++protocol) {
        unsigned char bytes[2048];
        McPacket packet;
        mc_packet_init(&packet, bytes, sizeof(bytes));
        encode_component_item_count(&packet, protocol, 1);
        assert(mc_packet_varint(&packet, 5));
        assert(mc_packet_varint(&packet, 3));
        assert(mc_packet_varint(&packet, 1));
        assert(mc_packet_varint(&packet, 0));
        assert(mc_packet_nbt(&packet, false, &custom_data));
        assert(mc_packet_varint(&packet, 3));
        assert(mc_packet_varint(&packet, 4));
        assert(mc_packet_varint(&packet, container_component_id(protocol)));
        assert(mc_packet_varint(&packet, 1));
        encode_component_item_count(&packet, protocol, 0);
        assert(mc_packet_varint(&packet, 1));

        McReader reader;
        McError error;
        McItemStackView item;
        mc_reader_init_mode(&reader, packet.data, packet.length,
            MC_DECODE_STRICT, &error);
        assert(mc_reader_item_stack(&reader, protocol, MC_ITEM_WIRE_FULL,
            &item));
        assert(mc_reader_finish(&reader));
        assert(item.present && item.item_id == 5 && item.count == 1);
        assert(item.added_component_count == 3U);
        assert(item.removed_component_count == 1U);
        assert(item.components.size != 0U);
        for (size_t prefix = 0U; prefix < packet.length; ++prefix) {
            mc_reader_init_mode(&reader, packet.data, prefix,
                MC_DECODE_STRICT, &error);
            assert(!mc_reader_item_stack(&reader, protocol,
                MC_ITEM_WIRE_FULL, &item));
            assert(error.code != MC_ERROR_NONE);
        }

        mc_packet_init(&packet, bytes, sizeof(bytes));
        encode_component_item_count(&packet, protocol, 1);
        assert(mc_packet_varint(&packet, 5));
        assert(mc_packet_varint(&packet, 1));
        assert(mc_packet_varint(&packet, 0));
        assert(mc_packet_varint(&packet, 4096));
        mc_reader_init_mode(&reader, packet.data, packet.length,
            MC_DECODE_STRICT, &error);
        assert(!mc_reader_item_stack(&reader, protocol, MC_ITEM_WIRE_FULL,
            &item));
        assert(error.code == MC_ERROR_INVALID_PACKET_BODY);

        mc_packet_init(&packet, bytes, sizeof(bytes));
        encode_nested_component_item(&packet, protocol, 8U);
        mc_reader_init_mode(&reader, packet.data, packet.length,
            MC_DECODE_STRICT, &error);
        assert(mc_reader_item_stack(&reader, protocol, MC_ITEM_WIRE_FULL,
            &item));
        assert(mc_reader_finish(&reader));

        mc_packet_init(&packet, bytes, sizeof(bytes));
        encode_nested_component_item(&packet, protocol, 70U);
        mc_reader_init_mode(&reader, packet.data, packet.length,
            MC_DECODE_STRICT, &error);
        assert(!mc_reader_item_stack(&reader, protocol, MC_ITEM_WIRE_FULL,
            &item));
        assert(error.code == MC_ERROR_NBT_DEPTH);
    }
}

static McCanonicalMovement canonical_movement(int protocol,
    const McPlayerPosition *input)
{
    unsigned char bytes[64];
    McPacket packet;
    mc_packet_init(&packet, bytes, sizeof(bytes));
    assert(mc_packet_player_position(&packet, protocol, input));
    const int32_t packet_id = mc_packet_id(protocol, MC_STATE_PLAY,
        MC_PACKET_SERVERBOUND, "position_look");
    McCanonicalHeader header;
    McCanonicalMovement movement;
    McError error;
    assert(mc_canonical_header_init(&header, protocol, MC_STATE_PLAY,
        MC_PACKET_SERVERBOUND, packet_id, packet.data, packet.length, &error));
    assert(mc_decode_canonical_movement(&header, &movement,
        MC_DECODE_STRICT, &error));
    return movement;
}

static void test_canonical_equivalence(void)
{
    for (size_t iteration = 0U; iteration < 10000U; ++iteration) {
        const McPlayerPosition input = {
            .x = (double)((int32_t)(random_u64() % 100000U) - 50000) / 8.0,
            .y = (double)(random_u64() % 4096U) / 16.0,
            .z = (double)((int32_t)(random_u64() % 100000U) - 50000) / 8.0,
            .yaw = (float)(random_u64() % 36000U) / 100.0F,
            .pitch = (float)((int32_t)(random_u64() % 18000U) - 9000) / 100.0F,
            .on_ground = (random_u64() & 1U) != 0U,
        };
        const McCanonicalMovement legacy = canonical_movement(47, &input);
        const McCanonicalMovement modern = canonical_movement(776, &input);
        assert(legacy.x == modern.x && legacy.y == modern.y
            && legacy.z == modern.z);
        assert(legacy.yaw == modern.yaw && legacy.pitch == modern.pitch);
        assert(legacy.on_ground == modern.on_ground);
    }
}

int main(void)
{
    const char *configured = getenv("MC_TEST_SEED");
    test_state = configured == NULL
        ? UINT64_C(0x4d4350524f544f43)
        : (uint64_t)strtoull(configured, NULL, 0);
    if (test_state == 0U) test_state = 1U;
    fprintf(stderr, "property seed=%" PRIu64 "\n", test_state);
    test_varints();
    test_positions();
    test_uuids();
    test_plain_items();
    test_component_items();
    test_canonical_equivalence();
    puts("PASS deterministic codec properties");
    return 0;
}
