#include "api.h"
#include "fuzz_common.h"

#include <assert.h>
#include <string.h>

typedef struct {
    int result;
    size_t count;
    McErrorCode code;
    int32_t ids[8];
    size_t sizes[8];
} FrameResult;

static FrameResult run_once(const uint8_t *data, size_t size, bool compressed)
{
    McStreamDecoderConfig config;
    mc_stream_decoder_config_init(&config);
    config.max_frame_size = 64U * 1024U;
    config.max_decompressed_size = 64U * 1024U;
    config.max_buffered_size = 128U * 1024U;
    config.max_output_size = 128U * 1024U;
    McError error;
    McStreamDecoder *decoder = mc_stream_decoder_create(&config, &error);
    assert(decoder != NULL);
    if (compressed) {
        assert(mc_stream_decoder_set_compression(decoder, 1, &error) == 0);
    }
    McDecodedFrame frames[8];
    FrameResult result = {0};
    result.result = mc_stream_decoder_feed(decoder, data, size, frames, 8U,
        &result.count, &error);
    result.code = error.code;
    if (result.result == 0) {
        for (size_t index = 0U; index < result.count; ++index) {
            result.ids[index] = frames[index].packet_id;
            result.sizes[index] = frames[index].payload.size;
        }
    }
    mc_stream_decoder_destroy(decoder);
    return result;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    for (unsigned int compressed = 0U; compressed < 2U; ++compressed) {
        const FrameResult first = run_once(data, size, compressed != 0U);
        const FrameResult second = run_once(data, size, compressed != 0U);
        assert(memcmp(&first, &second, sizeof(first)) == 0);
    }
    return 0;
}

MC_FUZZ_MAIN(LLVMFuzzerTestOneInput)
