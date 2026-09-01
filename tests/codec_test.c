#include "api.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void errors_have_stable_names_and_unknown_context(void)
{
    McError error;
    mc_error_clear(&error);
    assert(error.code == MC_ERROR_NONE);
    assert(error.offset == MC_ERROR_OFFSET_UNKNOWN);
    assert(error.protocol == -1);
    assert(error.state == MC_STATE_UNKNOWN);
    assert(error.direction == MC_PACKET_DIRECTION_UNKNOWN);
    assert(error.packet_id == -1);
    assert(strcmp(mc_error_name(MC_ERROR_NONE), "MC_ERROR_NONE") == 0);
    assert(strcmp(mc_error_name(MC_ERROR_VARINT_OVERFLOW),
        "MC_ERROR_VARINT_OVERFLOW") == 0);
    assert(strcmp(mc_error_name((McErrorCode)9999), "MC_ERROR_UNKNOWN") == 0);
}

static void strict_boolean_rejects_non_binary_wire_values(void)
{
    static const unsigned char encoded[] = {2U};
    McReader reader;
    McError error;
    bool value = false;

    mc_reader_init(&reader, encoded, sizeof(encoded));
    assert(mc_reader_bool(&reader, &value));
    assert(value);
    assert(mc_reader_finish(&reader));

    value = false;
    mc_reader_init_mode(
        &reader, encoded, sizeof(encoded), MC_DECODE_STRICT, &error);
    assert(!mc_reader_bool(&reader, &value));
    assert(reader.failed);
    assert(error.code == MC_ERROR_INVALID_BOOLEAN);
    assert(error.offset == 0U);
    size_t failed_offset = reader.offset;
    uint8_t ignored = 0U;
    assert(!mc_reader_u8(&reader, &ignored));
    assert(reader.offset == failed_offset);
    assert(error.code == MC_ERROR_INVALID_BOOLEAN);
}

static void strict_varints_are_canonical_and_bounded(void)
{
    static const int32_t values[] = {
        INT32_MIN, -1, 0, 1, 127, 128, INT32_MAX,
    };
    unsigned char storage[16];
    for (size_t index = 0U; index < sizeof(values) / sizeof(values[0]); ++index) {
        McPacket packet;
        McReader reader;
        McError error;
        int32_t decoded = 0;
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_varint(&packet, values[index]));
        mc_reader_init_mode(
            &reader, packet.data, packet.length, MC_DECODE_STRICT, &error);
        assert(mc_reader_varint(&reader, &decoded));
        assert(decoded == values[index]);
        assert(mc_reader_finish(&reader));
        assert(error.code == MC_ERROR_NONE);
    }

    static const unsigned char noncanonical[] = {0x80U, 0x00U};
    McReader reader;
    McError error;
    int32_t decoded = -1;
    mc_reader_init(&reader, noncanonical, sizeof(noncanonical));
    assert(mc_reader_varint(&reader, &decoded));
    assert(decoded == 0);
    assert(mc_reader_finish(&reader));

    mc_reader_init_mode(&reader, noncanonical, sizeof(noncanonical),
        MC_DECODE_STRICT, &error);
    assert(!mc_reader_varint(&reader, &decoded));
    assert(error.code == MC_ERROR_VARINT_NON_CANONICAL);
    assert(error.offset == 1U);

    static const unsigned char overflow[] = {
        0xffU, 0xffU, 0xffU, 0xffU, 0x1fU,
    };
    mc_reader_init_mode(
        &reader, overflow, sizeof(overflow), MC_DECODE_STRICT, &error);
    assert(!mc_reader_varint(&reader, &decoded));
    assert(error.code == MC_ERROR_VARINT_OVERFLOW);
    assert(error.offset == 4U);

    static const unsigned char partial[] = {0x80U};
    mc_reader_init_mode(
        &reader, partial, sizeof(partial), MC_DECODE_STRICT, &error);
    assert(!mc_reader_varint(&reader, &decoded));
    assert(error.code == MC_ERROR_PARTIAL_INPUT);
    assert(error.offset == sizeof(partial));
}

static void strict_varlongs_are_canonical(void)
{
    static const int64_t values[] = {
        INT64_MIN, -1, 0, 1, 127, 128, INT64_MAX,
    };
    unsigned char storage[16];
    for (size_t index = 0U; index < sizeof(values) / sizeof(values[0]); ++index) {
        McPacket packet;
        McReader reader;
        McError error;
        int64_t decoded = 0;
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_varlong(&packet, values[index]));
        mc_reader_init_mode(
            &reader, packet.data, packet.length, MC_DECODE_STRICT, &error);
        assert(mc_reader_varlong(&reader, &decoded));
        assert(decoded == values[index]);
        assert(mc_reader_finish(&reader));
    }

    static const unsigned char noncanonical[] = {0x81U, 0x00U};
    McReader reader;
    McError error;
    int64_t decoded = 0;
    mc_reader_init_mode(&reader, noncanonical, sizeof(noncanonical),
        MC_DECODE_STRICT, &error);
    assert(!mc_reader_varlong(&reader, &decoded));
    assert(error.code == MC_ERROR_VARINT_NON_CANONICAL);
}

static void bounded_strings_and_exact_consumption_fail_early(void)
{
    static const unsigned char string[] = {3U, 'a', 'b', 'c'};
    McReader reader;
    McError error;
    McBytes value = {0};
    mc_reader_init_mode(
        &reader, string, sizeof(string), MC_DECODE_STRICT, &error);
    assert(!mc_reader_string_bounded(&reader, 2U, &value));
    assert(error.code == MC_ERROR_STRING_TOO_LARGE);
    assert(error.offset == 0U);

    static const unsigned char truncated[] = {3U, 'a', 'b'};
    mc_reader_init_mode(
        &reader, truncated, sizeof(truncated), MC_DECODE_STRICT, &error);
    assert(!mc_reader_string_bounded(&reader, 3U, &value));
    assert(error.code == MC_ERROR_PARTIAL_INPUT);
    assert(error.offset == sizeof(truncated));

    static const unsigned char trailing[] = {0x2aU, 0xffU};
    uint8_t first = 0U;
    mc_reader_init_mode(
        &reader, trailing, sizeof(trailing), MC_DECODE_STRICT, &error);
    assert(mc_reader_u8(&reader, &first) && first == 0x2aU);
    assert(!mc_reader_finish(&reader));
    assert(error.code == MC_ERROR_TRAILING_BYTES);
    assert(error.offset == 1U);
}

static void invalid_initialization_is_structured(void)
{
    McReader reader;
    McError error;
    mc_reader_init_mode(&reader, NULL, 1U, MC_DECODE_STRICT, &error);
    assert(reader.failed);
    assert(error.code == MC_ERROR_INVALID_ARGUMENT);
    assert(error.offset == MC_ERROR_OFFSET_UNKNOWN);

    mc_reader_init_mode(&reader, NULL, 0U, (McDecodeMode)99, &error);
    assert(reader.failed);
    assert(error.code == MC_ERROR_INVALID_ARGUMENT);
}

static void nbt_limits_are_explicit_and_structured(void)
{
    static const unsigned char negative_byte_array[] = {
        MC_NBT_BYTE_ARRAY, 0xffU, 0xffU, 0xffU, 0xffU,
    };
    McReader reader;
    McError error;
    mc_reader_init_mode(&reader, negative_byte_array,
        sizeof(negative_byte_array), MC_DECODE_STRICT, &error);
    assert(!mc_reader_nbt(&reader, false, NULL));
    assert(error.code == MC_ERROR_NBT_LENGTH);
    assert(error.offset == 1U);

    static const unsigned char oversized_byte_array[] = {
        MC_NBT_BYTE_ARRAY, 0x00U, 0x10U, 0x00U, 0x01U,
    };
    mc_reader_init_mode(&reader, oversized_byte_array,
        sizeof(oversized_byte_array), MC_DECODE_STRICT, &error);
    assert(!mc_reader_nbt(&reader, false, NULL));
    assert(error.code == MC_ERROR_NBT_LENGTH);
    assert(error.offset == 1U);

    unsigned char nested[1U + (MC_MAX_NBT_DEPTH + 1U) * 3U];
    size_t size = 0U;
    nested[size++] = MC_NBT_COMPOUND;
    for (size_t depth = 0U; depth <= MC_MAX_NBT_DEPTH; ++depth) {
        nested[size++] = MC_NBT_COMPOUND;
        nested[size++] = 0U;
        nested[size++] = 0U;
    }
    mc_reader_init_mode(&reader, nested, size, MC_DECODE_STRICT, &error);
    assert(!mc_reader_nbt(&reader, false, NULL));
    assert(error.code == MC_ERROR_NBT_DEPTH);

    static const unsigned char empty_name[] = {0U, 0U};
    McBytes name;
    mc_reader_init_mode(&reader, empty_name, sizeof(empty_name),
        MC_DECODE_STRICT, &error);
    assert(!mc_reader_nbt_name(&reader, NULL));
    assert(error.code == MC_ERROR_INVALID_ARGUMENT);
    assert(!mc_reader_nbt_name(&reader, &name));
    assert(error.code == MC_ERROR_INVALID_ARGUMENT);
}

static void cross_version_reader_errors_are_structured(void)
{
    static const unsigned char zeroes[32] = {0U};
    McReader reader;
    McError error;
    McPosition position;
    mc_reader_init_mode(&reader, zeroes, sizeof(zeroes), MC_DECODE_STRICT,
        &error);
    assert(!mc_reader_position(&reader, 9999, &position));
    assert(error.code == MC_ERROR_UNSUPPORTED_PROTOCOL);
    assert(error.protocol == 9999);
    assert(error.offset == 0U);

    McUuid uuid;
    mc_reader_init_mode(&reader, zeroes, sizeof(zeroes), MC_DECODE_STRICT,
        &error);
    assert(!mc_reader_uuid(&reader, NULL));
    assert(error.code == MC_ERROR_INVALID_ARGUMENT);
    assert(!mc_reader_uuid(&reader, &uuid));
    assert(error.code == MC_ERROR_INVALID_ARGUMENT);

    int32_t item_id = 0;
    int32_t count = 0;
    mc_reader_init_mode(&reader, zeroes, sizeof(zeroes), MC_DECODE_STRICT,
        &error);
    assert(!mc_reader_plain_item(&reader, 9999, &item_id, &count));
    assert(error.code == MC_ERROR_UNSUPPORTED_PROTOCOL);
    assert(error.protocol == 9999);

    McItemStackView item;
    mc_reader_init_mode(&reader, zeroes, sizeof(zeroes), MC_DECODE_STRICT,
        &error);
    assert(!mc_reader_item_stack(&reader, 9999, MC_ITEM_WIRE_FULL, &item));
    assert(error.code == MC_ERROR_UNSUPPORTED_PROTOCOL);
    assert(error.protocol == 9999);
}

int main(void)
{
    errors_have_stable_names_and_unknown_context();
    strict_boolean_rejects_non_binary_wire_values();
    strict_varints_are_canonical_and_bounded();
    strict_varlongs_are_canonical();
    bounded_strings_and_exact_consumption_fail_early();
    invalid_initialization_is_structured();
    nbt_limits_are_explicit_and_structured();
    cross_version_reader_errors_are_structured();
    puts("PASS structured errors, strict reader and exact consumption");
    return 0;
}
