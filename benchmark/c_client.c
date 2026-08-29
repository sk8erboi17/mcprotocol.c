#define _POSIX_C_SOURCE 200809L

#include "../api.h"

#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

typedef enum {
    MODE_LOGIN,
    MODE_STREAM,
    MODE_CONCURRENT
} BenchMode;

typedef struct {
    const char *host;
    uint16_t port;
    size_t messages;
    atomic_bool *failed;
} Worker;

typedef struct {
    size_t keep_alives;
} PacketCounter;

static uint64_t monotonic_ns(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0U;
    return (uint64_t)now.tv_sec * 1000000000ULL + (uint64_t)now.tv_nsec;
}

static void packet_received(void *userdata, McState state, int32_t packet_id,
    const unsigned char *payload, size_t payload_size)
{
    (void)payload;
    (void)payload_size;
    PacketCounter *counter = userdata;
    if (state == MC_STATE_PLAY && packet_id == 0x00) ++counter->keep_alives;
}

static int connect_client(const char *host, uint16_t port,
    PacketCounter *counter, McClient **output, char *error, size_t error_size)
{
    McCallbacks callbacks = {.on_state = NULL, .on_packet = packet_received};
    McClient *client = mc_client_create(47, &callbacks, counter, error, error_size);
    if (client == NULL) return -1;
    if (mc_client_connect(client, host, port, "BenchmarkClient",
            error, error_size) != 0) {
        mc_client_destroy(client);
        return -1;
    }
    *output = client;
    return 0;
}

static void *run_worker(void *opaque)
{
    Worker *worker = opaque;
    PacketCounter counter = {0U};
    char error[256] = "";
    McClient *client = NULL;
    if (connect_client(worker->host, worker->port, &counter, &client,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "C client connect failed: %s\n", error);
        atomic_store(worker->failed, true);
        return NULL;
    }
    while (counter.keep_alives < worker->messages) {
        int result = mc_client_poll(client, 30000U, error, sizeof(error));
        if (result <= 0) {
            fprintf(stderr, "C client poll failed: %s\n", error);
            atomic_store(worker->failed, true);
            break;
        }
    }
    if (!atomic_load(worker->failed)) {
        int result;
        do {
            result = mc_client_poll(client, 30000U, error, sizeof(error));
        } while (result > 0);
        if (result == 0) {
            fprintf(stderr, "C client timed out waiting for validated shutdown\n");
            atomic_store(worker->failed, true);
        }
    }
    mc_client_destroy(client);
    return NULL;
}

static int run_logins(const char *host, uint16_t port, size_t clients)
{
    for (size_t index = 0U; index < clients; ++index) {
        PacketCounter counter = {0U};
        char error[256] = "";
        McClient *client = NULL;
        if (connect_client(host, port, &counter, &client,
                error, sizeof(error)) != 0) {
            fprintf(stderr, "C client connect failed: %s\n", error);
            return -1;
        }
        mc_client_destroy(client);
    }
    return 0;
}

static int run_workers(const char *host, uint16_t port,
    size_t clients, size_t messages)
{
    pthread_t *threads = calloc(clients, sizeof(*threads));
    Worker *workers = calloc(clients, sizeof(*workers));
    if (threads == NULL || workers == NULL) {
        free(threads);
        free(workers);
        return -1;
    }
    atomic_bool failed = false;
    size_t started = 0U;
    for (; started < clients; ++started) {
        workers[started] = (Worker){host, port, messages, &failed};
        if (pthread_create(&threads[started], NULL, run_worker,
                &workers[started]) != 0) break;
    }
    if (started != clients) atomic_store(&failed, true);
    for (size_t index = 0U; index < started; ++index) {
        if (pthread_join(threads[index], NULL) != 0) atomic_store(&failed, true);
    }
    free(threads);
    free(workers);
    return atomic_load(&failed) ? -1 : 0;
}

static int parse_mode(const char *text, BenchMode *mode)
{
    if (strcmp(text, "login") == 0) *mode = MODE_LOGIN;
    else if (strcmp(text, "stream") == 0) *mode = MODE_STREAM;
    else if (strcmp(text, "concurrent") == 0) *mode = MODE_CONCURRENT;
    else return -1;
    return 0;
}

static int parse_size(const char *text, size_t *value)
{
    char *end = NULL;
    errno = 0;
    unsigned long long parsed = strtoull(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || parsed == 0U
        || parsed > SIZE_MAX) return -1;
    *value = (size_t)parsed;
    return 0;
}

static int parse_port(const char *text, uint16_t *port)
{
    size_t parsed = 0U;
    if (parse_size(text, &parsed) != 0 || parsed > UINT16_MAX) return -1;
    *port = (uint16_t)parsed;
    return 0;
}

int main(int argc, char **argv)
{
    BenchMode mode;
    uint16_t port = 0U;
    size_t clients = 0U;
    size_t messages = 0U;
    if (argc != 6 || parse_mode(argv[1], &mode) != 0
        || parse_port(argv[3], &port) != 0
        || parse_size(argv[4], &clients) != 0
        || parse_size(argv[5], &messages) != 0) {
        fprintf(stderr, "usage: %s mode host port clients messages\n", argv[0]);
        return 2;
    }
    if (mode == MODE_STREAM && clients != 1U) return 2;
    uint64_t started = monotonic_ns();
    int result = mode == MODE_LOGIN
        ? run_logins(argv[2], port, clients)
        : run_workers(argv[2], port, clients, messages);
    uint64_t finished = monotonic_ns();
    if (result != 0 || started == 0U || finished < started) return 1;
    size_t operations = mode == MODE_LOGIN ? clients : clients * messages;
    printf("{\"elapsed_ns\":%llu,\"operations\":%zu}\n",
        (unsigned long long)(finished - started), operations);
    return 0;
}
