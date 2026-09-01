#ifndef MC_PROTOCOL_FUZZ_COMMON_H
#define MC_PROTOCOL_FUZZ_COMMON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#ifndef MC_FUZZ_LIBFUZZER
#define MC_FUZZ_MAIN(target) \
    int main(int argc, char **argv) \
    { \
        static const uint8_t empty[] = {0U}; \
        if (argc == 1) (void)target(empty, 0U); \
        for (int index = 1; index < argc; ++index) { \
            FILE *file = fopen(argv[index], "rb"); \
            if (file == NULL) return 2; \
            uint8_t *data = malloc(1024U * 1024U); \
            if (data == NULL) { (void)fclose(file); return 2; } \
            const size_t size = fread(data, 1U, 1024U * 1024U, file); \
            if (ferror(file) != 0) { \
                free(data); (void)fclose(file); return 2; \
            } \
            (void)fclose(file); \
            (void)target(data, size); \
            free(data); \
        } \
        return 0; \
    }
#else
#define MC_FUZZ_MAIN(target)
#endif

#endif
