#include "api.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#define CAPACITY 32768U

typedef struct {
    unsigned char data[CAPACITY];
    size_t size;
} Buffer;

static void clear(Buffer *buffer)
{
    buffer->size = 0U;
}

static void append(Buffer *buffer, const void *data, size_t size)
{
    assert(size <= sizeof(buffer->data) - buffer->size);
    if (size != 0U) memcpy(buffer->data + buffer->size, data, size);
    buffer->size += size;
}

static void append_byte(Buffer *buffer, unsigned char value)
{
    append(buffer, &value, 1U);
}

static void append_varint(Buffer *buffer, int32_t value)
{
    uint32_t encoded = (uint32_t)value;
    do {
        unsigned char byte = (unsigned char)(encoded & 0x7fU);
        encoded >>= 7U;
        if (encoded != 0U) byte |= 0x80U;
        append_byte(buffer, byte);
    } while (encoded != 0U);
}

static void packet(Buffer *output, int32_t id,
    const void *payload, size_t payload_size)
{
    clear(output);
    append_varint(output, id);
    append(output, payload, payload_size);
}

static void frame_body(Buffer *wire, const void *body, size_t body_size)
{
    assert(body_size <= (size_t)INT32_MAX);
    clear(wire);
    append_varint(wire, (int32_t)body_size);
    append(wire, body, body_size);
}

static void plain_frame(Buffer *wire, int32_t id,
    const void *payload, size_t payload_size)
{
    Buffer body;
    packet(&body, id, payload, payload_size);
    frame_body(wire, body.data, body.size);
}

static void envelope_frame(Buffer *wire, int32_t id,
    const void *payload, size_t payload_size)
{
    Buffer body;
    Buffer envelope;
    packet(&body, id, payload, payload_size);
    clear(&envelope);
    append_varint(&envelope, 0);
    append(&envelope, body.data, body.size);
    frame_body(wire, envelope.data, envelope.size);
}

static void compressed_frame(Buffer *wire, int32_t id,
    const void *payload, size_t payload_size, int32_t declared_size,
    bool corrupt, size_t trailing_size)
{
    Buffer body;
    Buffer envelope;
    unsigned char compressed[CAPACITY];
    packet(&body, id, payload, payload_size);
    uLongf compressed_size = (uLongf)sizeof(compressed);
    assert(compress2(compressed, &compressed_size, body.data,
        (uLong)body.size, Z_DEFAULT_COMPRESSION) == Z_OK);
    if (corrupt) compressed[0] ^= 0xffU;
    clear(&envelope);
    append_varint(&envelope, declared_size);
    append(&envelope, compressed, (size_t)compressed_size);
    for (size_t index = 0U; index < trailing_size; ++index) {
        append_byte(&envelope, (unsigned char)(0xa0U + index));
    }
    frame_body(wire, envelope.data, envelope.size);
}

static McStreamDecoder *decoder_with_config(McDecodeMode mode,
    size_t max_frame, size_t max_decompressed, size_t max_buffered,
    size_t max_output)
{
    McStreamDecoderConfig config;
    McError error;
    mc_stream_decoder_config_init(&config);
    config.mode = mode;
    config.max_frame_size = max_frame;
    config.max_decompressed_size = max_decompressed;
    config.max_buffered_size = max_buffered;
    config.max_output_size = max_output;
    McStreamDecoder *decoder = mc_stream_decoder_create(&config, &error);
    assert(decoder != NULL);
    assert(error.code == MC_ERROR_NONE);
    return decoder;
}

static McStreamDecoder *decoder(McDecodeMode mode)
{
    return decoder_with_config(mode,
        MC_DEFAULT_MAX_FRAME_SIZE,
        MC_DEFAULT_MAX_DECOMPRESSED_SIZE,
        MC_DEFAULT_MAX_STREAM_BUFFERED_SIZE,
        MC_DEFAULT_MAX_STREAM_OUTPUT_SIZE);
}

static void check_frame(const McDecodedFrame *frame, int32_t id,
    const void *payload, size_t payload_size, bool compressed)
{
    assert(frame->packet_id == id);
    assert(frame->payload.size == payload_size);
    assert(frame->compressed == compressed);
    if (payload_size != 0U) {
        assert(frame->payload.data != NULL);
        assert(memcmp(frame->payload.data, payload, payload_size) == 0);
    }
}

static void check_every_split(const Buffer *wire, int threshold,
    int32_t id, const void *payload, size_t payload_size, bool compressed)
{
    for (size_t split = 0U; split <= wire->size; ++split) {
        McStreamDecoder *stream = decoder(MC_DECODE_STRICT);
        McError error;
        if (threshold >= 0) {
            assert(mc_stream_decoder_set_compression(
                stream, threshold, &error) == 0);
        }
        McDecodedFrame decoded;
        size_t count = 0U;
        size_t total = 0U;
        assert(mc_stream_decoder_feed(stream,
            split == 0U ? NULL : wire->data, split,
            &decoded, 1U, &count, &error) == 0);
        if (count == 1U) {
            check_frame(&decoded, id, payload, payload_size, compressed);
            ++total;
        }
        size_t remaining = wire->size - split;
        assert(mc_stream_decoder_feed(stream,
            remaining == 0U ? NULL : wire->data + split, remaining,
            &decoded, 1U, &count, &error) == 0);
        if (count == 1U) {
            check_frame(&decoded, id, payload, payload_size, compressed);
            ++total;
        }
        assert(total == 1U);
        assert(mc_stream_decoder_finish(stream, &error) == 0);
        mc_stream_decoder_destroy(stream);
    }
}

static void check_every_truncated_prefix(const Buffer *wire, int threshold)
{
    for (size_t prefix = 1U; prefix < wire->size; ++prefix) {
        McStreamDecoder *stream = decoder(MC_DECODE_STRICT);
        McError error;
        if (threshold >= 0) {
            assert(mc_stream_decoder_set_compression(
                stream, threshold, &error) == 0);
        }
        McDecodedFrame decoded;
        size_t count = 99U;
        assert(mc_stream_decoder_feed(stream, wire->data, prefix,
            &decoded, 1U, &count, &error) == 0);
        assert(count == 0U);
        assert(mc_stream_decoder_finish(stream, &error) == -1);
        assert(error.code == MC_ERROR_PARTIAL_INPUT);
        assert(error.offset == prefix);
        mc_stream_decoder_destroy(stream);
    }
}

static McErrorCode feed_failure(McStreamDecoder *stream,
    const void *data, size_t size, size_t *frame_count)
{
    McDecodedFrame frames[4];
    McError error;
    size_t count = 0U;
    assert(mc_stream_decoder_feed(stream, data, size,
        frames, 4U, &count, &error) == -1);
    if (frame_count != NULL) *frame_count = count;
    return error.code;
}

static void fragmentation_matrix(void)
{
    static const unsigned char payload[] = {
        0x10U, 0x20U, 0x30U, 0x40U, 0x50U, 0x60U,
    };
    Buffer plain;
    plain_frame(&plain, 42, payload, sizeof(payload));
    check_every_split(&plain, -1, 42, payload, sizeof(payload), false);
    check_every_truncated_prefix(&plain, -1);

    McStreamDecoder *stream = decoder(MC_DECODE_STRICT);
    for (size_t index = 0U; index < plain.size; ++index) {
        McDecodedFrame decoded;
        McError error;
        size_t count = 0U;
        assert(mc_stream_decoder_feed(stream, plain.data + index, 1U,
            &decoded, 1U, &count, &error) == 0);
        assert(count == (index + 1U == plain.size ? 1U : 0U));
        if (count == 1U) {
            check_frame(&decoded, 42, payload, sizeof(payload), false);
        }
    }
    mc_stream_decoder_destroy(stream);

    static const unsigned char compressed_payload[] = {
        1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U, 9U,
    };
    Buffer body;
    Buffer compressed;
    packet(&body, 12, compressed_payload, sizeof(compressed_payload));
    compressed_frame(&compressed, 12, compressed_payload,
        sizeof(compressed_payload), (int32_t)body.size, false, 0U);
    check_every_split(&compressed, 8, 12, compressed_payload,
        sizeof(compressed_payload), true);
    check_every_truncated_prefix(&compressed, 8);
}

static void coalescing_drain_and_buffer_reuse(void)
{
    static const unsigned char one[] = {1U, 2U};
    static const unsigned char two[] = {3U, 4U, 5U};
    static const unsigned char three[] = {6U};
    Buffer first;
    Buffer second;
    Buffer third;
    Buffer all;
    plain_frame(&first, 1, one, sizeof(one));
    plain_frame(&second, 2, two, sizeof(two));
    plain_frame(&third, 3, three, sizeof(three));
    clear(&all);
    append(&all, first.data, first.size);
    append(&all, second.data, second.size);
    append(&all, third.data, third.size);

    McStreamDecoder *stream = decoder(MC_DECODE_STRICT);
    McDecodedFrame frames[2];
    McError error;
    size_t count = 0U;
    assert(mc_stream_decoder_feed(stream, all.data, all.size,
        frames, 2U, &count, &error) == 0);
    assert(count == 2U);
    check_frame(&frames[0], 1, one, sizeof(one), false);
    check_frame(&frames[1], 2, two, sizeof(two), false);
    assert(mc_stream_decoder_feed(stream, NULL, 0U,
        frames, 2U, &count, &error) == 0);
    assert(count == 1U);
    check_frame(&frames[0], 3, three, sizeof(three), false);
    mc_stream_decoder_destroy(stream);

    /* A complete frame followed by a prefix must emit the complete frame and
     * retain only the prefix for the next feed. */
    clear(&all);
    append(&all, first.data, first.size);
    size_t prefix = second.size / 2U;
    append(&all, second.data, prefix);
    stream = decoder(MC_DECODE_STRICT);
    assert(mc_stream_decoder_feed(stream, all.data, all.size,
        frames, 2U, &count, &error) == 0);
    assert(count == 1U);
    check_frame(&frames[0], 1, one, sizeof(one), false);
    assert(mc_stream_decoder_feed(stream, second.data + prefix,
        second.size - prefix, frames, 2U, &count, &error) == 0);
    assert(count == 1U);
    check_frame(&frames[0], 2, two, sizeof(two), false);
    mc_stream_decoder_destroy(stream);

    /* Ten retained payloads force output arena growth after early frame views
     * have already been published into the caller-owned frame array. */
    Buffer burst;
    clear(&burst);
    unsigned char large[1000];
    for (size_t index = 0U; index < 10U; ++index) {
        memset(large, (int)index, sizeof(large));
        Buffer current;
        plain_frame(&current, (int32_t)index, large, sizeof(large));
        append(&burst, current.data, current.size);
    }
    stream = decoder(MC_DECODE_STRICT);
    McDecodedFrame retained[10];
    assert(mc_stream_decoder_feed(stream, burst.data, burst.size,
        retained, 10U, &count, &error) == 0);
    assert(count == 10U);
    for (size_t index = 0U; index < count; ++index) {
        assert(retained[index].packet_id == (int32_t)index);
        assert(retained[index].payload.size == sizeof(large));
        assert(retained[index].payload.data[0] == (unsigned char)index);
        assert(retained[index].payload.data[sizeof(large) - 1U]
            == (unsigned char)index);
    }
    mc_stream_decoder_destroy(stream);
}

static void partial_eof_reset_and_state_transition(void)
{
    static const unsigned char payload[] = {9U, 8U, 7U, 6U};
    Buffer wire;
    plain_frame(&wire, 7, payload, sizeof(payload));
    size_t split = wire.size / 2U;
    McStreamDecoder *stream = decoder(MC_DECODE_STRICT);
    McDecodedFrame decoded;
    McError error;
    size_t count = 0U;
    assert(mc_stream_decoder_feed(stream, wire.data, split,
        &decoded, 1U, &count, &error) == 0);
    assert(count == 0U);
    assert(mc_stream_decoder_finish(stream, &error) == -1);
    assert(error.code == MC_ERROR_PARTIAL_INPUT);
    assert(error.offset == split);
    assert(feed_failure(stream, NULL, 0U, NULL) == MC_ERROR_PARTIAL_INPUT);

    mc_stream_decoder_reset(stream);
    assert(mc_stream_decoder_feed(stream, wire.data, split,
        &decoded, 1U, &count, &error) == 0);
    assert(mc_stream_decoder_set_compression(stream, 8, &error) == -1);
    assert(error.code == MC_ERROR_INVALID_STATE);
    assert(mc_stream_decoder_feed(stream, wire.data + split, wire.size - split,
        &decoded, 1U, &count, &error) == 0);
    assert(count == 1U);
    check_frame(&decoded, 7, payload, sizeof(payload), false);

    assert(mc_stream_decoder_set_compression(stream, 8, &error) == 0);
    mc_stream_decoder_reset(stream);
    assert(mc_stream_decoder_feed(stream, wire.data, wire.size,
        &decoded, 1U, &count, &error) == 0);
    assert(count == 1U); /* reset restores the no-compression wire mode */
    mc_stream_decoder_destroy(stream);
}

static void malformed_framing_and_limits(void)
{
    static const unsigned char noncanonical_outer[] = {
        0x82U, 0x00U, 0x00U, 0xabU,
    };
    McStreamDecoder *stream = decoder(MC_DECODE_STRICT);
    assert(feed_failure(stream, noncanonical_outer,
        sizeof(noncanonical_outer), NULL) == MC_ERROR_VARINT_NON_CANONICAL);
    mc_stream_decoder_destroy(stream);

    stream = decoder(MC_DECODE_VANILLA_COMPAT);
    McDecodedFrame decoded;
    McError error;
    size_t count = 0U;
    assert(mc_stream_decoder_feed(stream, noncanonical_outer,
        sizeof(noncanonical_outer), &decoded, 1U, &count, &error) == 0);
    static const unsigned char compat_payload[] = {0xabU};
    check_frame(&decoded, 0, compat_payload, sizeof(compat_payload), false);
    mc_stream_decoder_destroy(stream);

    static const unsigned char noncanonical_id[] = {2U, 0x80U, 0x00U};
    stream = decoder(MC_DECODE_STRICT);
    assert(feed_failure(stream, noncanonical_id, sizeof(noncanonical_id), NULL)
        == MC_ERROR_VARINT_NON_CANONICAL);
    mc_stream_decoder_destroy(stream);

    static const unsigned char overflow[] = {
        0xffU, 0xffU, 0xffU, 0xffU, 0x1fU,
    };
    stream = decoder(MC_DECODE_STRICT);
    assert(feed_failure(stream, overflow, sizeof(overflow), NULL)
        == MC_ERROR_VARINT_OVERFLOW);
    mc_stream_decoder_destroy(stream);

    static const unsigned char empty[] = {0U};
    stream = decoder(MC_DECODE_STRICT);
    assert(feed_failure(stream, empty, sizeof(empty), NULL)
        == MC_ERROR_INVALID_LENGTH);
    mc_stream_decoder_destroy(stream);

    stream = decoder_with_config(MC_DECODE_STRICT, 4U, 4U, 64U, 64U);
    static const unsigned char too_large[] = {5U};
    assert(feed_failure(stream, too_large, sizeof(too_large), NULL)
        == MC_ERROR_FRAME_TOO_LARGE);
    mc_stream_decoder_destroy(stream);

    stream = decoder_with_config(MC_DECODE_STRICT, 4U, 4U, 64U, 64U);
    unsigned char excessive[65] = {0};
    assert(feed_failure(stream, excessive, sizeof(excessive), NULL)
        == MC_ERROR_BUFFER_LIMIT);
    mc_stream_decoder_destroy(stream);

    McStreamDecoderConfig invalid;
    mc_stream_decoder_config_init(&invalid);
    invalid.max_frame_size = 100U;
    invalid.max_buffered_size = 100U;
    stream = mc_stream_decoder_create(&invalid, &error);
    assert(stream == NULL);
    assert(error.code == MC_ERROR_INVALID_ARGUMENT);
}

static void valid_frames_before_an_error_remain_observable(void)
{
    static const unsigned char payload[] = {0x55U};
    Buffer valid;
    Buffer input;
    plain_frame(&valid, 3, payload, sizeof(payload));
    clear(&input);
    append(&input, valid.data, valid.size);
    static const unsigned char malformed[] = {
        0x80U, 0x80U, 0x80U, 0x80U, 0x80U,
    };
    append(&input, malformed, sizeof(malformed));
    McStreamDecoder *stream = decoder(MC_DECODE_STRICT);
    McDecodedFrame frames[2];
    McError error;
    size_t count = 0U;
    assert(mc_stream_decoder_feed(stream, input.data, input.size,
        frames, 2U, &count, &error) == -1);
    assert(count == 1U);
    check_frame(&frames[0], 3, payload, sizeof(payload), false);
    assert(error.code == MC_ERROR_VARINT_OVERFLOW);
    assert(error.offset == valid.size + 4U);
    mc_stream_decoder_reset(stream);
    assert(mc_stream_decoder_feed(stream, valid.data, valid.size,
        frames, 1U, &count, &error) == 0);
    assert(count == 1U);
    mc_stream_decoder_destroy(stream);
}

static void compression_matrix(void)
{
    static const unsigned char below[6] = {1U, 2U, 3U, 4U, 5U, 6U};
    static const unsigned char exact[7] = {1U, 2U, 3U, 4U, 5U, 6U, 7U};
    Buffer wire;
    Buffer encoded;
    McDecodedFrame decoded;
    McError error;
    size_t count = 0U;

    McStreamDecoder *stream = decoder(MC_DECODE_STRICT);
    assert(mc_stream_decoder_set_compression(stream, -2, &error) == -1);
    assert(error.code == MC_ERROR_INVALID_ARGUMENT);
    assert(mc_stream_decoder_set_compression(stream, 8, &error) == 0);
    envelope_frame(&wire, 1, below, sizeof(below));
    assert(mc_stream_decoder_feed(stream, wire.data, wire.size,
        &decoded, 1U, &count, &error) == 0);
    check_frame(&decoded, 1, below, sizeof(below), false);
    mc_stream_decoder_destroy(stream);

    packet(&encoded, 2, exact, sizeof(exact));
    assert(encoded.size == 8U);
    compressed_frame(&wire, 2, exact, sizeof(exact),
        (int32_t)encoded.size, false, 0U);
    stream = decoder(MC_DECODE_STRICT);
    assert(mc_stream_decoder_set_compression(stream, 8, &error) == 0);
    assert(mc_stream_decoder_feed(stream, wire.data, wire.size,
        &decoded, 1U, &count, &error) == 0);
    check_frame(&decoded, 2, exact, sizeof(exact), true);
    mc_stream_decoder_destroy(stream);

    envelope_frame(&wire, 2, exact, sizeof(exact));
    stream = decoder(MC_DECODE_STRICT);
    assert(mc_stream_decoder_set_compression(stream, 8, &error) == 0);
    assert(feed_failure(stream, wire.data, wire.size, NULL)
        == MC_ERROR_COMPRESSION_THRESHOLD);
    mc_stream_decoder_destroy(stream);

    packet(&encoded, 1, below, sizeof(below));
    compressed_frame(&wire, 1, below, sizeof(below),
        (int32_t)encoded.size, false, 0U);
    stream = decoder(MC_DECODE_STRICT);
    assert(mc_stream_decoder_set_compression(stream, 8, &error) == 0);
    assert(feed_failure(stream, wire.data, wire.size, NULL)
        == MC_ERROR_COMPRESSION_THRESHOLD);
    mc_stream_decoder_destroy(stream);

    static const unsigned char truncated_header[] = {1U, 0x80U};
    stream = decoder(MC_DECODE_STRICT);
    assert(mc_stream_decoder_set_compression(stream, 8, &error) == 0);
    assert(feed_failure(stream, truncated_header,
        sizeof(truncated_header), NULL) == MC_ERROR_COMPRESSION_HEADER);
    mc_stream_decoder_destroy(stream);

    packet(&encoded, 2, exact, sizeof(exact));
    compressed_frame(&wire, 2, exact, sizeof(exact),
        (int32_t)encoded.size, true, 0U);
    stream = decoder(MC_DECODE_STRICT);
    assert(mc_stream_decoder_set_compression(stream, 8, &error) == 0);
    assert(feed_failure(stream, wire.data, wire.size, NULL) == MC_ERROR_ZLIB);
    mc_stream_decoder_destroy(stream);

    compressed_frame(&wire, 2, exact, sizeof(exact),
        (int32_t)encoded.size + 1, false, 0U);
    stream = decoder(MC_DECODE_STRICT);
    assert(mc_stream_decoder_set_compression(stream, 8, &error) == 0);
    assert(feed_failure(stream, wire.data, wire.size, NULL) == MC_ERROR_ZLIB);
    mc_stream_decoder_destroy(stream);

    compressed_frame(&wire, 2, exact, sizeof(exact),
        (int32_t)encoded.size, false, 2U);
    stream = decoder(MC_DECODE_STRICT);
    assert(mc_stream_decoder_set_compression(stream, 8, &error) == 0);
    assert(feed_failure(stream, wire.data, wire.size, NULL) == MC_ERROR_ZLIB);
    mc_stream_decoder_destroy(stream);
    stream = decoder(MC_DECODE_VANILLA_COMPAT);
    assert(mc_stream_decoder_set_compression(stream, 8, &error) == 0);
    assert(mc_stream_decoder_feed(stream, wire.data, wire.size,
        &decoded, 1U, &count, &error) == 0);
    check_frame(&decoded, 2, exact, sizeof(exact), true);
    mc_stream_decoder_destroy(stream);

    compressed_frame(&wire, 2, exact, sizeof(exact), 65, false, 0U);
    stream = decoder_with_config(MC_DECODE_STRICT, 1024U, 64U, 2048U, 128U);
    assert(mc_stream_decoder_set_compression(stream, 8, &error) == 0);
    assert(feed_failure(stream, wire.data, wire.size, NULL)
        == MC_ERROR_DECOMPRESSED_TOO_LARGE);
    mc_stream_decoder_destroy(stream);
}

int main(void)
{
    fragmentation_matrix();
    coalescing_drain_and_buffer_reuse();
    partial_eof_reset_and_state_transition();
    malformed_framing_and_limits();
    valid_frames_before_an_error_remain_observable();
    compression_matrix();
    puts("PASS incremental stream fragmentation, compression and limits");
    return 0;
}
