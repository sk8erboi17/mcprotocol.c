#include "api.h"
#include "fuzz_common.h"

#include <assert.h>
#include <string.h>

typedef struct {
    int result;
    size_t count;
    McErrorCode code;
    size_t offset;
    int32_t packet_ids[4];
    size_t payload_sizes[4];
    bool compressed[4];
} CompressedResult;

static CompressedResult decode_once(const uint8_t *data, size_t size,
    int threshold)
{
    CompressedResult result = {0};
    McStreamDecoderConfig config;
    mc_stream_decoder_config_init(&config);
    config.max_frame_size = 128U * 1024U;
    config.max_decompressed_size = 128U * 1024U;
    config.max_buffered_size = 256U * 1024U;
    config.max_output_size = 256U * 1024U;
    config.mode = MC_DECODE_STRICT;
    McError error;
    McStreamDecoder *decoder = mc_stream_decoder_create(&config, &error);
    assert(decoder != NULL);
    assert(mc_stream_decoder_set_compression(decoder, threshold, &error) == 0);
    McDecodedFrame frames[4];
    result.result = mc_stream_decoder_feed(decoder, data, size, frames, 4U,
        &result.count, &error);
    if (result.count == 0U && result.result == 0) {
        result.result = mc_stream_decoder_finish(decoder, &error);
    }
    result.code = error.code;
    result.offset = error.offset;
    for (size_t index = 0U; index < result.count; ++index) {
        result.packet_ids[index] = frames[index].packet_id;
        result.payload_sizes[index] = frames[index].payload.size;
        result.compressed[index] = frames[index].compressed;
    }
    mc_stream_decoder_destroy(decoder);
    return result;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    const int threshold = size == 0U ? 0 : (int)(data[0] & UINT8_C(0x7f));
    const CompressedResult first = decode_once(data, size, threshold);
    const CompressedResult second = decode_once(data, size, threshold);
    assert(memcmp(&first, &second, sizeof(first)) == 0);
    return 0;
}

MC_FUZZ_MAIN(LLVMFuzzerTestOneInput)
