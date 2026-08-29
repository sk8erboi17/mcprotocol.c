#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define FRAME_LIMIT 4096U

typedef enum {
    MODE_LOGIN,
    MODE_STREAM,
    MODE_CONCURRENT
} BenchMode;

typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    size_t arrived;
    size_t target;
    bool released;
    bool aborted;
} StartGate;

typedef struct {
    int socket_fd;
    size_t messages;
    StartGate *gate;
    int result;
} Session;

static int read_all(int socket_fd, void *output, size_t size)
{
    unsigned char *bytes = output;
    while (size != 0U) {
        ssize_t count = recv(socket_fd, bytes, size, 0);
        if (count == 0) return 1;
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        bytes += (size_t)count;
        size -= (size_t)count;
    }
    return 0;
}

static int write_all(int socket_fd, const void *input, size_t size)
{
    const unsigned char *bytes = input;
    while (size != 0U) {
        ssize_t count = send(socket_fd, bytes, size, 0);
        if (count < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (count == 0) return -1;
        bytes += (size_t)count;
        size -= (size_t)count;
    }
    return 0;
}

static size_t encode_varint(unsigned char output[5], int32_t value)
{
    uint32_t encoded = (uint32_t)value;
    size_t size = 0U;
    do {
        unsigned char byte = (unsigned char)(encoded & 0x7fU);
        encoded >>= 7U;
        if (encoded != 0U) byte |= 0x80U;
        output[size++] = byte;
    } while (encoded != 0U);
    return size;
}

static int decode_varint(const unsigned char *input, size_t size,
    size_t *offset, int32_t *value)
{
    uint32_t decoded = 0U;
    unsigned int shift = 0U;
    for (unsigned int index = 0U; index < 5U; ++index) {
        if (*offset >= size) return -1;
        unsigned char byte = input[(*offset)++];
        decoded |= (uint32_t)(byte & 0x7fU) << shift;
        if ((byte & 0x80U) == 0U) {
            *value = (int32_t)decoded;
            return 0;
        }
        shift += 7U;
    }
    return -1;
}

static int read_frame(int socket_fd, unsigned char *frame, size_t capacity,
    size_t *frame_size)
{
    uint32_t length = 0U;
    unsigned int shift = 0U;
    for (unsigned int index = 0U; index < 5U; ++index) {
        unsigned char byte = 0U;
        int status = read_all(socket_fd, &byte, 1U);
        if (status != 0) return status;
        length |= (uint32_t)(byte & 0x7fU) << shift;
        if ((byte & 0x80U) == 0U) {
            if ((size_t)length > capacity) return -1;
            status = read_all(socket_fd, frame, (size_t)length);
            if (status != 0) return status;
            *frame_size = (size_t)length;
            return 0;
        }
        shift += 7U;
    }
    return -1;
}

static int write_frame(int socket_fd, int32_t packet_id,
    const unsigned char *payload, size_t payload_size)
{
    unsigned char packet[FRAME_LIMIT];
    unsigned char length[5];
    size_t packet_size = encode_varint(packet, packet_id);
    if (payload_size > sizeof(packet) - packet_size) return -1;
    if (payload_size != 0U) memcpy(packet + packet_size, payload, payload_size);
    packet_size += payload_size;
    size_t length_size = encode_varint(length, (int32_t)packet_size);
    return write_all(socket_fd, length, length_size) == 0
            && write_all(socket_fd, packet, packet_size) == 0
        ? 0 : -1;
}

static int string_equals(const unsigned char *frame, size_t frame_size,
    size_t *offset, const char *expected)
{
    int32_t length = -1;
    size_t expected_size = strlen(expected);
    if (decode_varint(frame, frame_size, offset, &length) != 0 || length < 0
        || (size_t)length != expected_size
        || (size_t)length > frame_size - *offset
        || memcmp(frame + *offset, expected, expected_size) != 0) return -1;
    *offset += expected_size;
    return 0;
}

static int expect_handshake(int socket_fd)
{
    unsigned char frame[FRAME_LIMIT];
    size_t frame_size = 0U;
    if (read_frame(socket_fd, frame, sizeof(frame), &frame_size) != 0) return -1;
    size_t offset = 0U;
    int32_t packet_id = -1;
    int32_t protocol = -1;
    if (decode_varint(frame, frame_size, &offset, &packet_id) != 0
        || packet_id != 0x00
        || decode_varint(frame, frame_size, &offset, &protocol) != 0
        || protocol != 47
        || string_equals(frame, frame_size, &offset, "127.0.0.1") != 0
        || frame_size - offset < 2U) return -1;
    uint16_t port = (uint16_t)((uint16_t)frame[offset] << 8U)
        | (uint16_t)frame[offset + 1U];
    offset += 2U;
    int32_t next_state = -1;
    return port != 0U
            && decode_varint(frame, frame_size, &offset, &next_state) == 0
            && next_state == 2 && offset == frame_size
        ? 0 : -1;
}

static int expect_login_start(int socket_fd)
{
    unsigned char frame[FRAME_LIMIT];
    size_t frame_size = 0U;
    if (read_frame(socket_fd, frame, sizeof(frame), &frame_size) != 0) return -1;
    size_t offset = 0U;
    int32_t packet_id = -1;
    return decode_varint(frame, frame_size, &offset, &packet_id) == 0
            && packet_id == 0x00
            && string_equals(frame, frame_size, &offset, "BenchmarkClient") == 0
            && offset == frame_size
        ? 0 : -1;
}

static int send_login_success(int socket_fd)
{
    static const char uuid[] = "00000000-0000-0000-0000-000000000000";
    static const char username[] = "BenchmarkClient";
    unsigned char payload[128];
    size_t offset = 0U;
    offset += encode_varint(payload + offset, (int32_t)(sizeof(uuid) - 1U));
    memcpy(payload + offset, uuid, sizeof(uuid) - 1U);
    offset += sizeof(uuid) - 1U;
    offset += encode_varint(payload + offset, (int32_t)(sizeof(username) - 1U));
    memcpy(payload + offset, username, sizeof(username) - 1U);
    offset += sizeof(username) - 1U;
    return write_frame(socket_fd, 0x02, payload, offset);
}

static int perform_login(int socket_fd)
{
    return expect_handshake(socket_fd) == 0
            && expect_login_start(socket_fd) == 0
            && send_login_success(socket_fd) == 0
        ? 0 : -1;
}

static int wait_for_keep_alive(int socket_fd, int32_t expected_token)
{
    unsigned char frame[FRAME_LIMIT];
    for (;;) {
        size_t frame_size = 0U;
        if (read_frame(socket_fd, frame, sizeof(frame), &frame_size) != 0) return -1;
        size_t offset = 0U;
        int32_t packet_id = -1;
        if (decode_varint(frame, frame_size, &offset, &packet_id) != 0) return -1;
        if (packet_id != 0x00) continue;
        int32_t token = -1;
        return decode_varint(frame, frame_size, &offset, &token) == 0
                && offset == frame_size && token == expected_token
            ? 0 : -1;
    }
}

static int gate_init(StartGate *gate, size_t target)
{
    memset(gate, 0, sizeof(*gate));
    gate->target = target;
    if (pthread_mutex_init(&gate->mutex, NULL) != 0) return -1;
    if (pthread_cond_init(&gate->condition, NULL) != 0) {
        (void)pthread_mutex_destroy(&gate->mutex);
        return -1;
    }
    return 0;
}

static void gate_destroy(StartGate *gate)
{
    (void)pthread_cond_destroy(&gate->condition);
    (void)pthread_mutex_destroy(&gate->mutex);
}

static void gate_abort(StartGate *gate)
{
    if (pthread_mutex_lock(&gate->mutex) != 0) return;
    gate->aborted = true;
    gate->released = true;
    (void)pthread_cond_broadcast(&gate->condition);
    (void)pthread_mutex_unlock(&gate->mutex);
}

static int gate_wait(StartGate *gate)
{
    if (pthread_mutex_lock(&gate->mutex) != 0) return -1;
    ++gate->arrived;
    if (gate->arrived == gate->target) {
        gate->released = true;
        (void)pthread_cond_broadcast(&gate->condition);
    }
    while (!gate->released) {
        if (pthread_cond_wait(&gate->condition, &gate->mutex) != 0) {
            (void)pthread_mutex_unlock(&gate->mutex);
            return -1;
        }
    }
    bool aborted = gate->aborted;
    if (pthread_mutex_unlock(&gate->mutex) != 0) return -1;
    return aborted ? -1 : 0;
}

static void *run_session(void *opaque)
{
    Session *session = opaque;
    session->result = -1;
    if (perform_login(session->socket_fd) != 0) {
        gate_abort(session->gate);
        (void)close(session->socket_fd);
        return NULL;
    }
    if (gate_wait(session->gate) != 0) {
        (void)close(session->socket_fd);
        return NULL;
    }
    for (size_t index = 0U; index < session->messages; ++index) {
        int32_t token = (int32_t)(index & 0x3fffffffU);
        unsigned char payload[5];
        size_t payload_size = encode_varint(payload, token);
        if (write_frame(session->socket_fd, 0x00, payload, payload_size) != 0
            || wait_for_keep_alive(session->socket_fd, token) != 0) {
            (void)close(session->socket_fd);
            return NULL;
        }
    }
    session->result = 0;
    (void)shutdown(session->socket_fd, SHUT_RDWR);
    (void)close(session->socket_fd);
    return NULL;
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

static int parse_mode(const char *text, BenchMode *mode)
{
    if (strcmp(text, "login") == 0) *mode = MODE_LOGIN;
    else if (strcmp(text, "stream") == 0) *mode = MODE_STREAM;
    else if (strcmp(text, "concurrent") == 0) *mode = MODE_CONCURRENT;
    else return -1;
    return 0;
}

static int create_listener(uint16_t *port)
{
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return -1;
    int enabled = 1;
    (void)setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1) {
        (void)close(listener);
        return -1;
    }
    address.sin_port = 0;
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0
        || listen(listener, 256) != 0) {
        (void)close(listener);
        return -1;
    }
    socklen_t size = (socklen_t)sizeof(address);
    if (getsockname(listener, (struct sockaddr *)&address, &size) != 0) {
        (void)close(listener);
        return -1;
    }
    *port = ntohs(address.sin_port);
    return listener;
}

static int run_login_benchmark(int listener, size_t clients)
{
    for (size_t index = 0U; index < clients; ++index) {
        int peer = accept(listener, NULL, NULL);
        if (peer < 0 || perform_login(peer) != 0) {
            if (peer >= 0) (void)close(peer);
            return -1;
        }
        (void)shutdown(peer, SHUT_RDWR);
        (void)close(peer);
    }
    return 0;
}

static int run_packet_benchmark(int listener, size_t clients, size_t messages)
{
    StartGate gate;
    if (gate_init(&gate, clients) != 0) return -1;
    Session *sessions = calloc(clients, sizeof(*sessions));
    pthread_t *threads = calloc(clients, sizeof(*threads));
    if (sessions == NULL || threads == NULL) {
        free(sessions);
        free(threads);
        gate_destroy(&gate);
        return -1;
    }
    size_t started = 0U;
    for (; started < clients; ++started) {
        int peer = accept(listener, NULL, NULL);
        if (peer < 0) break;
        sessions[started] = (Session){peer, messages, &gate, -1};
        if (pthread_create(&threads[started], NULL, run_session,
                &sessions[started]) != 0) {
            (void)close(peer);
            break;
        }
    }
    int result = started == clients ? 0 : -1;
    if (started != clients) gate_abort(&gate);
    for (size_t index = 0U; index < started; ++index) {
        if (pthread_join(threads[index], NULL) != 0 || sessions[index].result != 0) {
            result = -1;
        }
    }
    free(sessions);
    free(threads);
    gate_destroy(&gate);
    return result;
}

int main(int argc, char **argv)
{
    BenchMode mode;
    size_t clients = 0U;
    size_t messages = 0U;
    if (argc != 4 || parse_mode(argv[1], &mode) != 0
        || parse_size(argv[2], &clients) != 0
        || parse_size(argv[3], &messages) != 0) {
        fprintf(stderr, "usage: %s login|stream|concurrent clients messages\n", argv[0]);
        return 2;
    }
    if (mode == MODE_STREAM && clients != 1U) return 2;
    uint16_t port = 0U;
    int listener = create_listener(&port);
    if (listener < 0) {
        perror("listener");
        return 1;
    }
    printf("%u\n", (unsigned int)port);
    (void)fflush(stdout);
    int result = mode == MODE_LOGIN
        ? run_login_benchmark(listener, clients)
        : run_packet_benchmark(listener, clients, messages);
    (void)close(listener);
    if (result != 0) fprintf(stderr, "mock server validation failed\n");
    return result == 0 ? 0 : 1;
}
