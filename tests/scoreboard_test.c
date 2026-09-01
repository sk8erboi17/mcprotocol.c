#include "api.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static const unsigned char text_component[] = {8U, 0U, 1U, 'x'};

static bool bytes_equal(McBytes value, const char *expected)
{
    const size_t size = strlen(expected);
    return value.size == size && memcmp(value.data, expected, size) == 0;
}

static void packet_component(McPacket *packet)
{
    const McBytes component = {text_component, sizeof(text_component)};
    assert(mc_packet_nbt(packet, false, &component));
}

static void test_protocol(int protocol)
{
    unsigned char storage[512] = {0};
    McPacket body;
    McReader reader;

    mc_packet_init(&body, storage, sizeof(storage));
    assert(mc_packet_string(&body, "objective"));
    if (protocol <= 5) {
        assert(mc_packet_string(&body, "title"));
        assert(mc_packet_u8(&body, 0U));
    } else {
        assert(mc_packet_u8(&body, 0U));
        if (protocol <= 764) assert(mc_packet_string(&body, "title"));
        else packet_component(&body);
        if (protocol <= 340) assert(mc_packet_string(&body, "integer"));
        else assert(mc_packet_varint(&body, 0));
        if (protocol >= 765) {
            assert(mc_packet_bool(&body, true));
            assert(mc_packet_varint(&body, 0));
        }
    }
    McScoreboardObjective objective = {0};
    mc_reader_init(&reader, body.data, body.length);
    assert(mc_reader_scoreboard_objective(&reader, protocol, &objective));
    assert(mc_reader_finish(&reader));
    assert(bytes_equal(objective.objective_name, "objective"));
    assert(objective.action == 0U && objective.has_display_name);
    assert(objective.display_name_is_nbt == (protocol >= 765));
    assert(objective.render_type_is_registry_id == (protocol >= 393));
    assert(objective.has_number_format == (protocol >= 765));
    assert(objective.number_format == (protocol >= 765 ? 0 : -1));

    mc_packet_init(&body, storage, sizeof(storage));
    assert(mc_packet_string(&body, "objective"));
    if (protocol <= 5) assert(mc_packet_string(&body, ""));
    assert(mc_packet_u8(&body, 1U));
    mc_reader_init(&reader, body.data, body.length);
    assert(mc_reader_scoreboard_objective(&reader, protocol, &objective));
    assert(mc_reader_finish(&reader));
    assert(objective.action == 1U);

    mc_packet_init(&body, storage, sizeof(storage));
    if (protocol <= 763) assert(mc_packet_u8(&body, 1U));
    else assert(mc_packet_varint(&body, 1));
    assert(mc_packet_string(&body, "objective"));
    McScoreboardDisplay display = {0};
    mc_reader_init(&reader, body.data, body.length);
    assert(mc_reader_scoreboard_display(&reader, protocol, &display));
    assert(mc_reader_finish(&reader));
    assert(display.slot == 1 && bytes_equal(display.objective_name, "objective"));

    mc_packet_init(&body, storage, sizeof(storage));
    assert(mc_packet_string(&body, "entry"));
    if (protocol <= 5) {
        assert(mc_packet_u8(&body, 0U));
        assert(mc_packet_string(&body, "objective"));
        assert(mc_packet_i32(&body, 9));
    } else if (protocol <= 764) {
        assert(mc_packet_varint(&body, 0));
        assert(mc_packet_string(&body, "objective"));
        assert(mc_packet_varint(&body, 9));
    } else {
        assert(mc_packet_string(&body, "objective"));
        assert(mc_packet_varint(&body, 9));
        assert(mc_packet_bool(&body, true));
        packet_component(&body);
        assert(mc_packet_bool(&body, true));
        assert(mc_packet_varint(&body, 0));
    }
    McScoreboardScore score = {0};
    mc_reader_init(&reader, body.data, body.length);
    assert(mc_reader_scoreboard_score(&reader, protocol, &score));
    assert(mc_reader_finish(&reader));
    assert(score.action == 0U && score.has_objective_name && score.has_value);
    assert(bytes_equal(score.entry_name, "entry"));
    assert(bytes_equal(score.objective_name, "objective"));
    assert(score.value == 9);
    assert(score.has_display_name == (protocol >= 765));
    assert(score.has_number_format == (protocol >= 765));

    mc_packet_init(&body, storage, sizeof(storage));
    assert(mc_packet_string(&body, "entry"));
    if (protocol <= 5) {
        assert(mc_packet_u8(&body, 1U));
        mc_reader_init(&reader, body.data, body.length);
        assert(mc_reader_scoreboard_score(&reader, protocol, &score));
        assert(mc_reader_finish(&reader));
        assert(score.action == 1U && !score.has_objective_name);
    } else if (protocol <= 764) {
        assert(mc_packet_varint(&body, 1));
        assert(mc_packet_string(&body, "objective"));
        mc_reader_init(&reader, body.data, body.length);
        assert(mc_reader_scoreboard_score(&reader, protocol, &score));
        assert(mc_reader_finish(&reader));
        assert(score.action == 1U && score.has_objective_name);
    } else {
        assert(mc_packet_bool(&body, true));
        assert(mc_packet_string(&body, "objective"));
        McScoreboardReset reset = {0};
        mc_reader_init(&reader, body.data, body.length);
        assert(mc_reader_scoreboard_reset(&reader, protocol, &reset));
        assert(mc_reader_finish(&reader));
        assert(reset.has_objective_name);
        assert(bytes_equal(reset.entry_name, "entry"));
        assert(bytes_equal(reset.objective_name, "objective"));
    }
}

static void test_malformed(void)
{
    const unsigned char invalid[] = {1U, 'x', 3U};
    McReader reader;
    McScoreboardObjective objective = {0};
    mc_reader_init(&reader, invalid, sizeof(invalid));
    assert(!mc_reader_scoreboard_objective(&reader, 776, &objective));

    McScoreboardReset reset = {0};
    mc_reader_init(&reader, invalid, sizeof(invalid));
    assert(!mc_reader_scoreboard_reset(&reader, 764, &reset));
}

int main(void)
{
    size_t count = 0U;
    const int *protocols = mc_supported_protocols(&count);
    assert(protocols != NULL && count == 51U);
    for (size_t index = 0U; index < count; ++index) {
        test_protocol(protocols[index]);
    }
    test_malformed();
    puts("PASS scoreboard readers across 51 protocols");
    return 0;
}
