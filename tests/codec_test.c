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

/* Bytes are from the official 26.1.2/26.2/26.3 server StreamCodec, emitted
 * by ItemData.java. These decode checks are independent of the schema used to
 * generate this library: a stale minecraft-data holder or component ID fails
 * here, even if the generator is internally consistent. */
static void official_component_streams_are_fully_validated(void)
{
    static const struct {
        int protocol;
        int32_t item, component;
        const char *name, *hex;
    } vectors[] = {
        {775, 1029, 1, "max_stack_size 1", "01"},
        {775, 1029, 1, "max_stack_size 64", "40"},
        {775, 1029, 1, "max_stack_size 99", "63"},
        {775, 1029, 2, "max_damage 1561", "990c"},
        {775, 1029, 3, "damage 0", "00"},
        {775, 1029, 3, "damage 300", "ac02"},
        {775, 1029, 19, "repair_cost 3", "03"},
        {775, 1029, 4, "unbreakable", ""},
        {775, 1029, 34, "glider", ""},
        {775, 1029, 21, "enchantment_glint_override true", "01"},
        {775, 1029, 21, "enchantment_glint_override false", "00"},
        {775, 1029, 10, "item_model oraxen", "136f726178656e3a6e6f735f73776f72645f3135"},
        {775, 1029, 10, "item_model vanilla", "0f6d696e6563726166743a7061706572"},
        {775, 1029, 35, "tooltip_style", "0c656c797a756e653a63617264"},
        {775, 1029, 12, "rarity common", "00"},
        {775, 1029, 12, "rarity epic", "03"},
        {775, 1029, 44, "dyed_color palette blue", "0088c0e8"},
        {775, 1029, 6, "custom_name plain", "0800055370616461"},
        {775, 1029, 6, "custom_name not italic", "0a08000474657874000553706164610100066974616c69630000"},
        {775, 1029, 6, "custom_name palette", "0a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000"},
        {775, 1029, 6, "custom_name named colour", "0a080005636f6c6f720004676f6c640800047465787400034f726f00"},
        {775, 1029, 6, "custom_name nested", "0a09000565787472610a00000002080005636f6c6f720007234630453844380800047465787400044c762e2000080005636f6c6f7200072346314339373501000a756e6465726c696e6564010800047465787400023135000800047465787400000100066974616c69630000"},
        {775, 1029, 6, "custom_name translatable", "0a0800097472616e736c617465001c6974656d2e6d696e6563726166742e6469616d6f6e645f73776f726400"},
        {775, 1029, 6, "custom_name translatable with args", "0a090004776974680a000000020800000005506970706f000800047465787400046369616f010004626f6c6401000800097472616e736c617465000e636861742e747970652e7465787400"},
        {775, 1029, 6, "custom_name shadow strike obfuscated", "0a03000c736861646f775f636f6c6f72ff1122330800047465787400054f6d62726101000d737472696b657468726f7567680001000a6f6266757363617465640100"},
        {775, 1029, 6, "custom_name keybind", "0a0800076b657962696e6400086b65792e6a756d7000"},
        {775, 1029, 6, "custom_name insertion", "0a080009696e73657274696f6e0003696e730800047465787400017800"},
        {775, 1029, 6, "custom_name click URL", "0a0a000b636c69636b5f6576656e74080006616374696f6e00086f70656e5f75726c08000375726c001e68747470733a2f2f6578616d706c652e696e76616c69642f736f7572636500080004746578740005537061646100"},
        {775, 1029, 6, "custom_name click command", "0a0a000b636c69636b5f6576656e74080006616374696f6e000b72756e5f636f6d6d616e64080007636f6d6d616e6400072f736f7572636500080004746578740005537061646100"},
        {775, 1029, 6, "custom_name suggest command", "0a0a000b636c69636b5f6576656e74080006616374696f6e000f737567676573745f636f6d6d616e64080007636f6d6d616e64000d2f717565737420747261636b2000080004746578740005537061646100"},
        {775, 1029, 6, "custom_name copy clipboard", "0a0a000b636c69636b5f6576656e74080006616374696f6e0011636f70795f746f5f636c6970626f61726408000576616c7565000a43697474c3a020e280a200080004746578740005537061646100"},
        {775, 1029, 6, "custom_name change page", "0a0a000b636c69636b5f6576656e74080006616374696f6e000b6368616e67655f70616765030004706167650000000200080004746578740005537061646100"},
        {775, 1029, 6, "custom_name custom click", "0a0a000b636c69636b5f6576656e740a00077061796c6f6164010004666c61670100080006616374696f6e0006637573746f6d0800026964000c656c797a756e653a7069636b00080004746578740005537061646100"},
        {775, 1029, 6, "custom_name hover text", "0a08000474657874000553706164610a000b686f7665725f6576656e74080006616374696f6e000973686f775f746578740a000576616c7565080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c696300000000"},
        {775, 1029, 6, "custom_name hover entity", "0a08000474657874000553706164610a000b686f7665725f6576656e740a00046e616d65080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000080006616374696f6e000b73686f775f656e74697479080002696400106d696e6563726166743a7a6f6d6269650b00047575696400000004069a79f444e94726a5befca90e38aaf50000"},
        {775, 1029, 6, "custom_name wire hover minecraft:slime", "0a08000474657874000950657267616d656e610a000b686f7665725f6576656e74080006616374696f6e000b73686f775f656e746974790800026964000f6d696e6563726166743a736c696d650b00047575696400000004000000010000000200000003000000040000"},
        {775, 1029, 6, "custom_name wire hover minecraft:slime", "0a08000474657874000950657267616d656e610a000b686f7665725f6576656e74080006616374696f6e000b73686f775f656e746974790800026964000f6d696e6563726166743a736c696d650b00047575696400000004000000010000000200000003000000040000"},
        {775, 1029, 6, "custom_name hover item", "0a08000474657874000553706164610a000b686f7665725f6576656e74080006616374696f6e000973686f775f6974656d0800026964000f6d696e6563726166743a70617065720000"},
        {775, 1029, 6, "custom_name hover item components", "0a08000474657874000553706164610a000b686f7665725f6576656e740a000a636f6d706f6e656e74730a001e216d696e6563726166743a6174747269627574655f6d6f64696669657273000300186d696e6563726166743a6d61785f737461636b5f73697a65000000010a00156d696e6563726166743a637573746f6d5f6e616d6508000474657874000553706164610a000b686f7665725f6576656e740a00046e616d65080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000080006616374696f6e000b73686f775f656e74697479080002696400106d696e6563726166743a7a6f6d6269650b00047575696400000004069a79f444e94726a5befca90e38aaf500000100246d696e6563726166743a656e6368616e746d656e745f676c696e745f6f76657272696465000a00156d696e6563726166743a637573746f6d5f64617461010004666c6167010000030005636f756e7400000003080006616374696f6e000973686f775f6974656d0800026964000f6d696e6563726166743a70617065720000"},
        {775, 1029, 9, "item_name palette", "0a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000"},
        {775, 1029, 11, "lore empty", "00"},
        {775, 1029, 11, "lore lines", "030a08000474657874000553706164610100066974616c696300000a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c696300000800055370616461"},
        {775, 1029, 17, "custom_model_data empty", "00000000"},
        {775, 1029, 17, "custom_model_data floats", "033f80000040200000c0500000000000"},
        {775, 1029, 17, "custom_model_data all", "0141700000020100020670756c6c5f3103626f770200ff00000088c0e8"},
        {775, 1029, 18, "tooltip_display default", "0000"},
        {775, 1029, 18, "tooltip_display hide", "0100"},
        {775, 1029, 18, "tooltip_display hidden components", "0002100d"},
        {775, 1029, 16, "attribute_modifiers empty", "00"},
        {775, 1029, 16, "attribute_modifiers sword", "02021c6d696e6563726166743a626173655f61747461636b5f64616d6167654018000000000000000100041b6d696e6563726166743a626173655f61747461636b5f7370656564c003333340000000000100"},
        {775, 1029, 16, "attribute_modifiers hidden any", "021310656c797a756e653a61726d6f725f31323fd00000000000000200010011656c797a756e653a61726d6f725f31326240080000000000000106020a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000"},
        {775, 1029, 0, "custom_data nested", "0a0c00056c6f6e6773000000020000000000000004fffffffffffffffb0a00125075626c696342756b6b697456616c75657303000c6e6f7374616c653a766e756d0000000f0800096f726178656e3a6964000c6e6f735f73776f72645f313500010004666c616701090007737472696e67730800000002000161000262620b0004696e747300000003000000010000000200000003060006646f75626c65bff400000000000002000573686f7274fffe080007756e69636f6465000d43697474c3a020c3a820e280a2050005666c6f61743f0000000400046c6f6e67000001000000000000"},
        {775, 1029, 0, "custom_data empty", "0a00"},
        {775, 1029, 32, "equippable head", "04470000000101010000a00b"},
        {775, 1029, 32, "equippable chest asset", "034701156e6f7374616c656974656d733a61726d6f725f313200000000000000a00b"},
        {775, 1029, 32, "equippable overlay entities", "044700011a6d696e6563726166743a6d6973632f70756d706b696e626c757201029b010101010100a00b"},
        {775, 1029, 26, "use_cooldown seconds", "3fc0000000"},
        {775, 1029, 26, "use_cooldown group", "3e800000010e656c797a756e653a737570706c79"},
        {775, 1029, 23, "food", "044019999a01"},
        {775, 1029, 23, "food default flag", "010000000000"},
        {775, 1029, 70, "profile name", "0001054e6f746368000000000000"},
        {775, 1029, 70, "profile id", "000001069a79f444e94726a5befca90e38aaf50000000000"},
        {775, 1029, 70, "profile resolved", "01069a79f444e94726a5befca90e38aaf5054e6f746368010874657874757265731465794a305a58683064584a6c63794936653331390000000000"},
        {775, 1029, 6, "custom_name modified UTF-8", "08000f4d757369636120eda0b4edb49ec080"},
        {775, 1029, 0, "custom_data modified UTF-8", "0a08000c636869617665eda0b4edb49e000e76616c6f7265c080eda0b4edb49e00"},
        {775, 1029, 61, "instrument inline variable sound", "00000c656c797a756e653a686f726e0040e0000043800000080005436f726e6f"},
        {775, 1029, 61, "instrument inline fixed sound", "00000c656c797a756e653a686f726e01430000003fc00000420000000a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000"},
        {775, 1029, 62, "provides_trim_material inline", "00076d69746872696c000800074d69746872696c"},
        {775, 1029, 62, "provides_trim_material inline overrides", "00076d69746872696c010e6d696e6563726166743a69726f6e0e6d69746872696c5f6461726b65720a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000"},
        {775, 1029, 56, "trim inline", "00076d69746872696c000800074d69746872696c000d656c797a756e653a7370697265080005537069726500"},
        {775, 1029, 56, "trim inline decal overrides", "00076d69746872696c010e6d696e6563726166743a69726f6e0e6d69746872696c5f6461726b65720a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000000d656c797a756e653a73706972650a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c6963000001"},
        {776, 1057, 1, "max_stack_size 1", "01"},
        {776, 1057, 1, "max_stack_size 64", "40"},
        {776, 1057, 1, "max_stack_size 99", "63"},
        {776, 1057, 2, "max_damage 1561", "990c"},
        {776, 1057, 3, "damage 0", "00"},
        {776, 1057, 3, "damage 300", "ac02"},
        {776, 1057, 19, "repair_cost 3", "03"},
        {776, 1057, 4, "unbreakable", ""},
        {776, 1057, 34, "glider", ""},
        {776, 1057, 21, "enchantment_glint_override true", "01"},
        {776, 1057, 21, "enchantment_glint_override false", "00"},
        {776, 1057, 10, "item_model oraxen", "136f726178656e3a6e6f735f73776f72645f3135"},
        {776, 1057, 10, "item_model vanilla", "0f6d696e6563726166743a7061706572"},
        {776, 1057, 35, "tooltip_style", "0c656c797a756e653a63617264"},
        {776, 1057, 12, "rarity common", "00"},
        {776, 1057, 12, "rarity epic", "03"},
        {776, 1057, 44, "dyed_color palette blue", "0088c0e8"},
        {776, 1057, 6, "custom_name plain", "0800055370616461"},
        {776, 1057, 6, "custom_name not italic", "0a08000474657874000553706164610100066974616c69630000"},
        {776, 1057, 6, "custom_name palette", "0a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000"},
        {776, 1057, 6, "custom_name named colour", "0a080005636f6c6f720004676f6c640800047465787400034f726f00"},
        {776, 1057, 6, "custom_name nested", "0a09000565787472610a00000002080005636f6c6f720007234630453844380800047465787400044c762e2000080005636f6c6f7200072346314339373501000a756e6465726c696e6564010800047465787400023135000800047465787400000100066974616c69630000"},
        {776, 1057, 6, "custom_name translatable", "0a0800097472616e736c617465001c6974656d2e6d696e6563726166742e6469616d6f6e645f73776f726400"},
        {776, 1057, 6, "custom_name translatable with args", "0a090004776974680a000000020800000005506970706f000800047465787400046369616f010004626f6c6401000800097472616e736c617465000e636861742e747970652e7465787400"},
        {776, 1057, 6, "custom_name shadow strike obfuscated", "0a03000c736861646f775f636f6c6f72ff1122330800047465787400054f6d62726101000d737472696b657468726f7567680001000a6f6266757363617465640100"},
        {776, 1057, 6, "custom_name keybind", "0a0800076b657962696e6400086b65792e6a756d7000"},
        {776, 1057, 6, "custom_name insertion", "0a080009696e73657274696f6e0003696e730800047465787400017800"},
        {776, 1057, 6, "custom_name click URL", "0a0a000b636c69636b5f6576656e74080006616374696f6e00086f70656e5f75726c08000375726c001e68747470733a2f2f6578616d706c652e696e76616c69642f736f7572636500080004746578740005537061646100"},
        {776, 1057, 6, "custom_name click command", "0a0a000b636c69636b5f6576656e74080006616374696f6e000b72756e5f636f6d6d616e64080007636f6d6d616e6400072f736f7572636500080004746578740005537061646100"},
        {776, 1057, 6, "custom_name suggest command", "0a0a000b636c69636b5f6576656e74080006616374696f6e000f737567676573745f636f6d6d616e64080007636f6d6d616e64000d2f717565737420747261636b2000080004746578740005537061646100"},
        {776, 1057, 6, "custom_name copy clipboard", "0a0a000b636c69636b5f6576656e74080006616374696f6e0011636f70795f746f5f636c6970626f61726408000576616c7565000a43697474c3a020e280a200080004746578740005537061646100"},
        {776, 1057, 6, "custom_name change page", "0a0a000b636c69636b5f6576656e74080006616374696f6e000b6368616e67655f70616765030004706167650000000200080004746578740005537061646100"},
        {776, 1057, 6, "custom_name custom click", "0a0a000b636c69636b5f6576656e740a00077061796c6f6164010004666c61670100080006616374696f6e0006637573746f6d0800026964000c656c797a756e653a7069636b00080004746578740005537061646100"},
        {776, 1057, 6, "custom_name hover text", "0a08000474657874000553706164610a000b686f7665725f6576656e74080006616374696f6e000973686f775f746578740a000576616c7565080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c696300000000"},
        {776, 1057, 6, "custom_name hover entity", "0a08000474657874000553706164610a000b686f7665725f6576656e740a00046e616d65080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000080006616374696f6e000b73686f775f656e74697479080002696400106d696e6563726166743a7a6f6d6269650b00047575696400000004069a79f444e94726a5befca90e38aaf50000"},
        {776, 1057, 6, "custom_name wire hover minecraft:sulfur_cube", "0a08000474657874000950657267616d656e610a000b686f7665725f6576656e74080006616374696f6e000b73686f775f656e74697479080002696400156d696e6563726166743a73756c6675725f637562650b00047575696400000004000000010000000200000003000000040000"},
        {776, 1057, 6, "custom_name wire hover minecraft:slime", "0a08000474657874000950657267616d656e610a000b686f7665725f6576656e74080006616374696f6e000b73686f775f656e746974790800026964000f6d696e6563726166743a736c696d650b00047575696400000004000000010000000200000003000000040000"},
        {776, 1057, 6, "custom_name hover item", "0a08000474657874000553706164610a000b686f7665725f6576656e74080006616374696f6e000973686f775f6974656d0800026964000f6d696e6563726166743a70617065720000"},
        {776, 1057, 6, "custom_name hover item components", "0a08000474657874000553706164610a000b686f7665725f6576656e740a000a636f6d706f6e656e74730a001e216d696e6563726166743a6174747269627574655f6d6f64696669657273000300186d696e6563726166743a6d61785f737461636b5f73697a65000000010a00156d696e6563726166743a637573746f6d5f6e616d6508000474657874000553706164610a000b686f7665725f6576656e740a00046e616d65080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000080006616374696f6e000b73686f775f656e74697479080002696400106d696e6563726166743a7a6f6d6269650b00047575696400000004069a79f444e94726a5befca90e38aaf500000100246d696e6563726166743a656e6368616e746d656e745f676c696e745f6f76657272696465000a00156d696e6563726166743a637573746f6d5f64617461010004666c6167010000030005636f756e7400000003080006616374696f6e000973686f775f6974656d0800026964000f6d696e6563726166743a70617065720000"},
        {776, 1057, 9, "item_name palette", "0a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000"},
        {776, 1057, 11, "lore empty", "00"},
        {776, 1057, 11, "lore lines", "030a08000474657874000553706164610100066974616c696300000a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c696300000800055370616461"},
        {776, 1057, 17, "custom_model_data empty", "00000000"},
        {776, 1057, 17, "custom_model_data floats", "033f80000040200000c0500000000000"},
        {776, 1057, 17, "custom_model_data all", "0141700000020100020670756c6c5f3103626f770200ff00000088c0e8"},
        {776, 1057, 18, "tooltip_display default", "0000"},
        {776, 1057, 18, "tooltip_display hide", "0100"},
        {776, 1057, 18, "tooltip_display hidden components", "0002100d"},
        {776, 1057, 16, "attribute_modifiers empty", "00"},
        {776, 1057, 16, "attribute_modifiers sword", "02031c6d696e6563726166743a626173655f61747461636b5f64616d6167654018000000000000000100051b6d696e6563726166743a626173655f61747461636b5f7370656564c003333340000000000100"},
        {776, 1057, 16, "attribute_modifiers hidden any", "021710656c797a756e653a61726d6f725f31323fd00000000000000200010111656c797a756e653a61726d6f725f31326240080000000000000106020a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000"},
        {776, 1057, 0, "custom_data nested", "0a0c00056c6f6e6773000000020000000000000004fffffffffffffffb0a00125075626c696342756b6b697456616c75657303000c6e6f7374616c653a766e756d0000000f0800096f726178656e3a6964000c6e6f735f73776f72645f313500010004666c616701090007737472696e67730800000002000161000262620b0004696e747300000003000000010000000200000003060006646f75626c65bff400000000000002000573686f7274fffe080007756e69636f6465000d43697474c3a020c3a820e280a2050005666c6f61743f0000000400046c6f6e67000001000000000000"},
        {776, 1057, 0, "custom_data empty", "0a00"},
        {776, 1057, 32, "equippable head", "04470000000101010000a40b"},
        {776, 1057, 32, "equippable chest asset", "034701156e6f7374616c656974656d733a61726d6f725f313200000000000000a40b"},
        {776, 1057, 32, "equippable overlay entities", "044700011a6d696e6563726166743a6d6973632f70756d706b696e626c757201029c010101010100a40b"},
        {776, 1057, 26, "use_cooldown seconds", "3fc0000000"},
        {776, 1057, 26, "use_cooldown group", "3e800000010e656c797a756e653a737570706c79"},
        {776, 1057, 23, "food", "044019999a01"},
        {776, 1057, 23, "food default flag", "010000000000"},
        {776, 1057, 70, "profile name", "0001054e6f746368000000000000"},
        {776, 1057, 70, "profile id", "000001069a79f444e94726a5befca90e38aaf50000000000"},
        {776, 1057, 70, "profile resolved", "01069a79f444e94726a5befca90e38aaf5054e6f746368010874657874757265731465794a305a58683064584a6c63794936653331390000000000"},
        {776, 1057, 6, "custom_name modified UTF-8", "08000f4d757369636120eda0b4edb49ec080"},
        {776, 1057, 0, "custom_data modified UTF-8", "0a08000c636869617665eda0b4edb49e000e76616c6f7265c080eda0b4edb49e00"},
        {776, 1057, 61, "instrument inline variable sound", "00000c656c797a756e653a686f726e0040e0000043800000080005436f726e6f"},
        {776, 1057, 61, "instrument inline fixed sound", "00000c656c797a756e653a686f726e01430000003fc00000420000000a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000"},
        {776, 1057, 62, "provides_trim_material inline", "00076d69746872696c000800074d69746872696c"},
        {776, 1057, 62, "provides_trim_material inline overrides", "00076d69746872696c010e6d696e6563726166743a69726f6e0e6d69746872696c5f6461726b65720a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000"},
        {776, 1057, 56, "trim inline", "00076d69746872696c000800074d69746872696c000d656c797a756e653a7370697265080005537069726500"},
        {776, 1057, 56, "trim inline decal overrides", "00076d69746872696c010e6d696e6563726166743a69726f6e0e6d69746872696c5f6461726b65720a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000000d656c797a756e653a73706972650a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c6963000001"},
        {777, 1145, 6, "custom_name modified UTF-8", "08000f4d757369636120eda0b4edb49ec080"},
        {777, 1145, 0, "custom_data modified UTF-8", "0a08000c636869617665eda0b4edb49e000e76616c6f7265c080eda0b4edb49e00"},
        {777, 1145, 63, "instrument inline variable sound", "00000c656c797a756e653a686f726e0040e000004380000000080005436f726e6f"},
        {777, 1145, 63, "instrument inline fixed sound", "00000c656c797a756e653a686f726e01430000003fc0000042000000000a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000"},
        {777, 1145, 64, "provides_trim_material inline", "00166d696e6563726166743a7472696d2f6d69746872696c0800074d69746872696c"},
        {777, 1145, 64, "provides_trim_material inline overrides", "00166d696e6563726166743a7472696d2f6d69746872696c0a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000"},
        {777, 1145, 58, "trim inline", "00166d696e6563726166743a7472696d2f6d69746872696c0800074d69746872696c000d656c797a756e653a7370697265080005537069726500"},
        {777, 1145, 58, "trim inline decal overrides", "00166d696e6563726166743a7472696d2f6d69746872696c0a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c69630000000d656c797a756e653a73706972650a080005636f6c6f7200072338384330453808000474657874000c53706164612064656c205265010004626f6c64010100066974616c6963000001"},
        {775, 1029, 25, "use_remainder template", "8307020101060800064e657374656415"},
        {775, 1029, 49, "charged_projectiles template", "018307020101060800064e657374656415"},
        {775, 1029, 50, "bundle_contents template", "018307020101060800064e657374656415"},
        {775, 1029, 75, "container optional template", "0200018307020101060800064e657374656415"},
        {775, 1029, 80, "break_sound inline", "000c656c797a756e653a686f726e00"},
        {775, 1029, 84, "wolf collar", "0b"},
        {775, 1029, 107, "cat collar", "0b"},
        {775, 1029, 109, "shulker color", "01"},
        {776, 1057, 25, "use_remainder template", "9e07020101060800064e657374656415"},
        {776, 1057, 49, "charged_projectiles template", "019e07020101060800064e657374656415"},
        {776, 1057, 50, "bundle_contents template", "019e07020101060800064e657374656415"},
        {776, 1057, 75, "container optional template", "0200019e07020101060800064e657374656415"},
        {776, 1057, 81, "break_sound inline", "000c656c797a756e653a686f726e00"},
        {776, 1057, 85, "wolf collar", "0b"},
        {776, 1057, 108, "cat collar", "0b"},
        {776, 1057, 110, "shulker color", "01"},
        {776, 1057, 78, "sulfur nested template", "9e07020101060800064e657374656415"},
        {777, 1145, 25, "use_remainder template", "f407020101060800064e657374656415"},
        {777, 1145, 51, "charged_projectiles template", "01f407020101060800064e657374656415"},
        {777, 1145, 52, "bundle_contents template", "01f407020101060800064e657374656415"},
        {777, 1145, 77, "container optional template", "020001f407020101060800064e657374656415"},
        {777, 1145, 83, "break_sound inline", "000c656c797a756e653a686f726e00"},
        {777, 1145, 91, "wolf collar", "0b"},
        {777, 1145, 114, "cat collar", "0b"},
        {777, 1145, 116, "shulker color", "01"},
        {777, 1145, 80, "sulfur nested template", "f407020101060800064e657374656415"},
    };
    unsigned failures = 0U;
    for (size_t index = 0U; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
        unsigned char storage[4096];
        McPacket packet;
        mc_packet_init(&packet, storage, sizeof(storage));
        assert(mc_packet_varint(&packet, 1));
        assert(mc_packet_varint(&packet, vectors[index].item));
        assert(mc_packet_varint(&packet, 1));
        assert(mc_packet_varint(&packet, 0));
        assert(mc_packet_varint(&packet, vectors[index].component));
        const size_t length = strlen(vectors[index].hex);
        assert(length % 2U == 0U);
        for (size_t byte = 0U; byte < length; byte += 2U) {
            unsigned value = 0U;
            assert(sscanf(vectors[index].hex + byte, "%2x", &value) == 1);
            assert(mc_packet_u8(&packet, (uint8_t)value));
        }
        McReader reader;
        McError error;
        McItemStackView stack;
        mc_reader_init_mode(&reader, packet.data, packet.length, MC_DECODE_STRICT, &error);
        if (!mc_reader_item_stack(&reader, vectors[index].protocol, MC_ITEM_WIRE_FULL, &stack)
            || !mc_reader_finish(&reader)) {
            fprintf(stderr, "official codec mismatch: %d %s component=%d offset=%zu error=%s\n",
                vectors[index].protocol, vectors[index].name, vectors[index].component,
                reader.offset, mc_error_name(error.code));
            failures++;
            continue;
        }
        assert(stack.item_id == vectors[index].item && stack.count == 1);
        /* Every non-empty prefix truncation must be rejected, never accepted
         * as an unchecked component tail. */
        for (size_t cut = 1U; cut < packet.length; ++cut) {
            mc_reader_init_mode(&reader, packet.data, cut, MC_DECODE_STRICT, &error);
            assert(!mc_reader_item_stack(&reader, vectors[index].protocol, MC_ITEM_WIRE_FULL, &stack));
        }
    }
    assert(failures == 0U);
}

int main(void)
{
    official_component_streams_are_fully_validated();
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
