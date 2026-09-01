#include "api.h"
#include "fuzz_common.h"

#include <assert.h>

static void run_once(const uint8_t *data, size_t size, bool named,
    bool *ok, size_t *offset, McErrorCode *code)
{
    McError error;
    McReader reader;
    mc_reader_init_mode(&reader, data, size, MC_DECODE_STRICT, &error);
    *ok = mc_reader_nbt(&reader, named, NULL);
    *offset = reader.offset;
    *code = error.code;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    for (unsigned int named = 0U; named < 2U; ++named) {
        bool first_ok = false;
        bool second_ok = false;
        size_t first_offset = 0U;
        size_t second_offset = 0U;
        McErrorCode first_code = MC_ERROR_NONE;
        McErrorCode second_code = MC_ERROR_NONE;
        run_once(data, size, named != 0U, &first_ok, &first_offset,
            &first_code);
        run_once(data, size, named != 0U, &second_ok, &second_offset,
            &second_code);
        assert(first_ok == second_ok);
        assert(first_offset == second_offset);
        assert(first_code == second_code);
    }
    return 0;
}

MC_FUZZ_MAIN(LLVMFuzzerTestOneInput)
