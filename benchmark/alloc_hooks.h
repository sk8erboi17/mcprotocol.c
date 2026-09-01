#ifndef MCPROTOCOL_BENCHMARK_ALLOC_HOOKS_H
#define MCPROTOCOL_BENCHMARK_ALLOC_HOOKS_H

#include <stddef.h>

void *mc_benchmark_malloc(size_t size);
void *mc_benchmark_calloc(size_t count, size_t size);
void *mc_benchmark_realloc(void *pointer, size_t size);
void mc_benchmark_free(void *pointer);

#endif
