#define _POSIX_C_SOURCE 200809L

#include "api.h"

#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const McUuid PROFILE_ID = {{
    0x10U, 0x32U, 0x54U, 0x76U, 0x98U, 0xbaU, 0xdcU, 0xfeU,
    0xefU, 0xcdU, 0xabU, 0x89U, 0x67U, 0x45U, 0x23U, 0x01U,
}};

typedef struct ServerObservation {
    int protocol;
    bool login_start;
    bool login_acknowledged;
    bool settings;
    bool configuration_finished;
    bool known_packs_echoed;
    int teleport_confirms;
    double confirmed_x;
    double confirmed_y;
    float confirmed_yaw;
    bool valid;
} ServerObservation;

/* Clientbound select_known_packs body used by the 777 scenario. */
static const unsigned char KNOWN_PACKS[] = {
    0x01U, 0x09U, 'm', 'i', 'n', 'e', 'c', 'r', 'a', 'f', 't',
    0x04U, 'c', 'o', 'r', 'e', 0x04U, '2', '6', '.', '3',
};

typedef struct StatusObservation {
    bool request;
    bool ping;
    bool valid;
    int64_t nonce;
} StatusObservation;

static bool bytes_equal(McBytes bytes, const char *text)
{
    const size_t size = strlen(text);
    return bytes.size == size && memcmp(bytes.data, text, size) == 0;
}

static bool decode_login_start(const unsigned char *payload, size_t payload_size)
{
    McReader reader;
    McBytes username = {0};
    McUuid profile_id = {{0U}};
    mc_reader_init_mode(&reader, payload, payload_size, MC_DECODE_STRICT, NULL);
    return mc_reader_string_bounded(&reader, 16U, &username)
        && bytes_equal(username, "ProfileClient")
        && mc_reader_uuid(&reader, &profile_id)
        && memcmp(profile_id.bytes, PROFILE_ID.bytes, sizeof(PROFILE_ID.bytes)) == 0
        && mc_reader_finish(&reader);
}

static bool decode_settings(const unsigned char *payload, size_t payload_size)
{
    McReader reader;
    McBytes locale = {0};
    int8_t view_distance = 0;
    int32_t chat_mode = -1;
    bool chat_colors = false;
    uint8_t skin_parts = 0U;
    int32_t main_hand = -1;
    bool text_filtering = true;
    bool server_listing = true;
    int32_t particle_status = -1;
    mc_reader_init_mode(&reader, payload, payload_size, MC_DECODE_STRICT, NULL);
    return mc_reader_string_bounded(&reader, 16U, &locale)
        && bytes_equal(locale, "it_it")
        && mc_reader_i8(&reader, &view_distance) && view_distance == 2
        && mc_reader_varint(&reader, &chat_mode) && chat_mode == 0
        && mc_reader_bool(&reader, &chat_colors) && chat_colors
        && mc_reader_u8(&reader, &skin_parts) && skin_parts == UINT8_C(0x7f)
        && mc_reader_varint(&reader, &main_hand) && main_hand == 1
        && mc_reader_bool(&reader, &text_filtering) && !text_filtering
        && mc_reader_bool(&reader, &server_listing) && !server_listing
        && mc_reader_varint(&reader, &particle_status) && particle_status == 0
        && mc_reader_finish(&reader);
}

static void observe_serverbound(void *userdata, McState state, int32_t packet_id,
    const unsigned char *payload, size_t payload_size)
{
    ServerObservation *observation = userdata;
    const char *name = observation == NULL ? NULL : mc_packet_name(
        observation->protocol, state, MC_PACKET_SERVERBOUND, packet_id);
    if (observation == NULL || name == NULL || !observation->valid) return;
    if (state == MC_STATE_LOGIN && strcmp(name, "login_start") == 0) {
        observation->login_start = true;
        observation->valid = decode_login_start(payload, payload_size);
    } else if (state == MC_STATE_LOGIN
            && strcmp(name, "login_acknowledged") == 0) {
        observation->login_acknowledged = payload_size == 0U;
        observation->valid = observation->login_acknowledged;
    } else if (state == MC_STATE_CONFIGURATION
            && strcmp(name, "settings") == 0) {
        observation->settings = true;
        observation->valid = decode_settings(payload, payload_size);
    } else if (state == MC_STATE_CONFIGURATION
            && strcmp(name, "finish_configuration") == 0) {
        observation->configuration_finished = payload_size == 0U;
        observation->valid = observation->configuration_finished;
    } else if (state == MC_STATE_CONFIGURATION
            && strcmp(name, "select_known_packs") == 0) {
        /* 776+ echoes the concrete pack list instead of an empty selection. */
        observation->known_packs_echoed = payload_size == sizeof(KNOWN_PACKS)
            && memcmp(payload, KNOWN_PACKS, sizeof(KNOWN_PACKS)) == 0;
        observation->valid = observation->known_packs_echoed;
    } else if (state == MC_STATE_PLAY
            && strcmp(name, "teleport_confirm") == 0) {
        /* 777 ACCEPT_TELEPORTATION: id, then the accepted absolute pose. */
        McReader reader;
        int32_t id = -1;
        double z = 0.0;
        float pitch = 0.0F;
        mc_reader_init_mode(&reader, payload, payload_size,
            MC_DECODE_STRICT, NULL);
        observation->valid = mc_reader_varint(&reader, &id)
            && id == (observation->teleport_confirms < 2
                ? 7 + observation->teleport_confirms : -9)
            && mc_reader_double(&reader, &observation->confirmed_x)
            && mc_reader_double(&reader, &observation->confirmed_y)
            && mc_reader_double(&reader, &z) && z == -4.0
            && mc_reader_float(&reader, &observation->confirmed_yaw)
            && mc_reader_float(&reader, &pitch) && pitch == 10.0F
            && mc_reader_finish(&reader);
        observation->teleport_confirms++;
    }
}

static void observe_status(void *userdata, McState state, int32_t packet_id,
    const unsigned char *payload, size_t payload_size)
{
    StatusObservation *observation = userdata;
    if (observation == NULL || !observation->valid || state != MC_STATE_STATUS) {
        return;
    }
    if (packet_id == 0x00) {
        observation->request = payload_size == 0U;
        observation->valid = observation->request;
    } else if (packet_id == 0x01) {
        McReader reader;
        mc_reader_init_mode(&reader, payload, payload_size,
            MC_DECODE_STRICT, NULL);
        observation->ping = mc_reader_i64(&reader, &observation->nonce)
            && mc_reader_finish(&reader);
        observation->valid = observation->ping;
    } else {
        observation->valid = false;
    }
}

static int poll_until(McClient *peer, const bool *complete, char *error,
    size_t error_size)
{
    for (unsigned int attempt = 0U; attempt < 4U && !*complete; ++attempt) {
        if (mc_client_poll(peer, 5000U, error, error_size) <= 0) return -1;
    }
    return *complete ? 0 : -1;
}

static int create_bind_listener(uint16_t *port)
{
    const int listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) return -1;
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons(0U);
    if (inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) != 1
        || bind(listener, (const struct sockaddr *)(const void *)&address,
            (socklen_t)sizeof(address)) != 0
        || listen(listener, 1) != 0) {
        (void)close(listener);
        return -1;
    }
    socklen_t address_size = (socklen_t)sizeof(address);
    if (getsockname(listener, (struct sockaddr *)(void *)&address,
            &address_size) != 0) {
        (void)close(listener);
        return -1;
    }
    *port = ntohs(address.sin_port);
    return listener;
}

static int observe_bound_peer(int listener)
{
    struct sockaddr_in peer_address;
    socklen_t peer_size = (socklen_t)sizeof(peer_address);
    const int peer = accept(listener,
        (struct sockaddr *)(void *)&peer_address, &peer_size);
    if (peer < 0) return EXIT_FAILURE;
    struct in_addr expected;
    unsigned char handshake_byte = 0U;
    bool valid = peer_address.sin_family == AF_INET
        && inet_pton(AF_INET, "127.0.0.1", &expected) == 1
        && memcmp(&peer_address.sin_addr, &expected, sizeof(expected)) == 0
        && recv(peer, &handshake_byte, sizeof(handshake_byte), 0) == 1;
    unsigned char buffer[256];
    ssize_t received = 1;
    while (valid && received > 0) {
        received = recv(peer, buffer, sizeof(buffer), 0);
        if (received < 0) valid = false;
    }
    valid = valid && received == 0;
    (void)close(peer);
    return valid ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void check_local_address(void)
{
    uint16_t port = 0U;
    const int listener = create_bind_listener(&port);
    assert(listener >= 0);
    assert(port != 0U);
    const pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        const int result = observe_bound_peer(listener);
        (void)close(listener);
        _exit(result);
    }

    char error[256] = {0};
    McClient *client = mc_client_create(47, NULL, NULL,
        error, sizeof(error));
    assert(client != NULL);
    assert(mc_client_set_local_address(NULL, "127.0.0.1",
        error, sizeof(error)) != 0);
    assert(mc_client_set_local_address(client, "localhost",
        error, sizeof(error)) != 0);
    assert(mc_client_set_local_address(client, "127.0.0.1",
        error, sizeof(error)) == 0);
    const int opened = mc_client_open(client, "127.0.0.1", port,
        MC_STATE_LOGIN, error, sizeof(error));
    if (opened != 0) fprintf(stderr, "local source bind failed: %s\n", error);
    assert(opened == 0);
    assert(mc_client_set_local_address(client, "127.0.0.3",
        error, sizeof(error)) != 0);
    assert(mc_client_shutdown_write(NULL, error, sizeof(error)) != 0);
    assert(mc_client_wait_closed(NULL, 1000U, error, sizeof(error)) != 0);
    assert(mc_client_shutdown_write(client, error, sizeof(error)) == 0);
    assert(mc_client_wait_closed(client, 5000U, error, sizeof(error)) == 1);
    mc_client_destroy(client);
    (void)close(listener);

    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
}

static bool send_position(McClient *peer, int32_t teleport_id, double x,
    float yaw, int32_t flags, char *error, size_t error_size)
{
    unsigned char storage[96];
    McPacket position;
    mc_packet_init(&position, storage, sizeof(storage));
    return mc_packet_varint(&position, teleport_id)
        && mc_packet_double(&position, x)
        && mc_packet_double(&position, 70.0)
        && mc_packet_double(&position, -4.0)
        && mc_packet_double(&position, 0.0)
        && mc_packet_double(&position, 0.0)
        && mc_packet_double(&position, 0.0)
        && mc_packet_float(&position, yaw)
        && mc_packet_float(&position, 10.0F)
        && mc_packet_i32(&position, flags)
        && mc_client_send_named(peer, "position", position.data,
            position.length, error, error_size) == 0;
}

/* 26.3: the clientbound known-packs ID moved (POST_EFFECTS inserted) and
 * teleport_confirm carries the accepted position, with relative axes resolved
 * against the previous absolute position. */
static int run_server_777(McServer *server)
{
    ServerObservation observation = {.protocol = 777, .valid = true};
    const McCallbacks callbacks = {.on_packet = observe_serverbound};
    McClient *peer = NULL;
    McHandshake handshake = {0};
    char error[256] = {0};
    unsigned char storage[128];
    McPacket success;
    mc_packet_init(&success, storage, sizeof(storage));
    if (mc_server_accept(server, 5000U, &callbacks, &observation, &peer,
            &handshake, error, sizeof(error)) != 1
        || handshake.protocol != 777 || handshake.next_state != MC_STATE_LOGIN
        || poll_until(peer, &observation.login_start, error, sizeof(error)) != 0
        || !mc_packet_uuid(&success, &PROFILE_ID)
        || !mc_packet_string(&success, "ProfileClient")
        || !mc_packet_varint(&success, 0)
        || mc_client_send_named(peer, "success", success.data, success.length,
            error, sizeof(error)) != 0
        || poll_until(peer, &observation.login_acknowledged,
            error, sizeof(error)) != 0
        || mc_client_set_state(peer, MC_STATE_CONFIGURATION,
            error, sizeof(error)) != 0
        || mc_packet_id(777, MC_STATE_CONFIGURATION, MC_PACKET_CLIENTBOUND,
            "select_known_packs") != 0x0f
        || mc_client_send_named(peer, "select_known_packs", KNOWN_PACKS,
            sizeof(KNOWN_PACKS), error, sizeof(error)) != 0
        || poll_until(peer, &observation.known_packs_echoed,
            error, sizeof(error)) != 0
        || mc_client_send_named(peer, "finish_configuration", NULL, 0U,
            error, sizeof(error)) != 0
        || poll_until(peer, &observation.configuration_finished,
            error, sizeof(error)) != 0
        || !observation.settings
        || mc_client_set_state(peer, MC_STATE_PLAY, error, sizeof(error)) != 0
        || !send_position(peer, 7, 3.5, 90.0F, 0, error, sizeof(error))) {
        fprintf(stderr, "777 profile server failed: %s\n", error);
        mc_client_destroy(peer);
        return EXIT_FAILURE;
    }
    bool first = false;
    for (int attempt = 0; attempt < 100 && observation.teleport_confirms < 1; ++attempt) {
        if (mc_client_poll(peer, 50, error, sizeof(error)) < 0) break;
    }
    first = observation.valid && observation.teleport_confirms == 1
        && observation.confirmed_x == 3.5 && observation.confirmed_yaw == 90.0F;
    /* Relative X (bit 0) and yaw (bit 3): the client must echo absolutes. */
    if (!first || !send_position(peer, 8, 2.0, 5.0F, 0x01 | 0x08,
            error, sizeof(error))) {
        fprintf(stderr, "777 first teleport failed: %s\n", error);
        mc_client_destroy(peer);
        return EXIT_FAILURE;
    }
    for (int attempt = 0; attempt < 100 && observation.teleport_confirms < 2; ++attempt) {
        if (mc_client_poll(peer, 50, error, sizeof(error)) < 0) break;
    }
    bool ok = observation.valid && observation.teleport_confirms == 2
        && observation.confirmed_x == 5.5 && observation.confirmed_y == 70.0
        && observation.confirmed_yaw == 95.0F;
    /* Plugins send silent client-only corrections with negative IDs; vanilla
     * accepts and echoes them, so the client must not drop the connection. */
    if (ok && !send_position(peer, -9, 1.0, 45.0F, 0, error, sizeof(error))) ok = false;
    for (int attempt = 0; ok && attempt < 100 && observation.teleport_confirms < 3; ++attempt) {
        if (mc_client_poll(peer, 50, error, sizeof(error)) < 0) break;
    }
    ok = ok && observation.valid && observation.teleport_confirms == 3
        && observation.confirmed_x == 1.0 && observation.confirmed_yaw == 45.0F;
    mc_client_destroy(peer);
    if (!ok) fprintf(stderr, "777 relative or negative-ID teleport failed\n");
    return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int run_server(McServer *server)
{
    ServerObservation observation = {.protocol = 776, .valid = true};
    const McCallbacks callbacks = {.on_packet = observe_serverbound};
    McClient *peer = NULL;
    McHandshake handshake = {0};
    char error[256] = {0};
    if (mc_server_accept(server, 5000U, &callbacks, &observation, &peer,
            &handshake, error, sizeof(error)) != 1
        || handshake.protocol != 776 || handshake.next_state != MC_STATE_LOGIN
        || poll_until(peer, &observation.login_start, error, sizeof(error)) != 0
        || !observation.valid) {
        fprintf(stderr, "profile server login failed: %s\n", error);
        mc_client_destroy(peer);
        return EXIT_FAILURE;
    }

    unsigned char storage[128];
    McPacket success;
    mc_packet_init(&success, storage, sizeof(storage));
    if (!mc_packet_uuid(&success, &PROFILE_ID)
        || !mc_packet_string(&success, "ProfileClient")
        || !mc_packet_varint(&success, 0)
        || mc_client_send_named(peer, "success", success.data, success.length,
            error, sizeof(error)) != 0
        || poll_until(peer, &observation.login_acknowledged,
            error, sizeof(error)) != 0
        || mc_client_set_state(peer, MC_STATE_CONFIGURATION,
            error, sizeof(error)) != 0
        || mc_client_send_named(peer, "finish_configuration", NULL, 0U,
            error, sizeof(error)) != 0
        || poll_until(peer, &observation.settings, error, sizeof(error)) != 0
        || poll_until(peer, &observation.configuration_finished,
            error, sizeof(error)) != 0
        || !observation.valid) {
        fprintf(stderr, "profile server configuration failed: %s\n", error);
        mc_client_destroy(peer);
        return EXIT_FAILURE;
    }
    mc_client_destroy(peer);
    return EXIT_SUCCESS;
}

static int run_status_server(McServer *server)
{
    StatusObservation observation = {.valid = true};
    const McCallbacks callbacks = {.on_packet = observe_status};
    McClient *peer = NULL;
    McHandshake handshake = {0};
    char error[256] = {0};
    if (mc_server_accept(server, 5000U, &callbacks, &observation, &peer,
            &handshake, error, sizeof(error)) != 1
        || handshake.protocol != 776 || handshake.next_state != MC_STATE_STATUS
        || poll_until(peer, &observation.request, error, sizeof(error)) != 0
        || !observation.valid) {
        fprintf(stderr, "status server request failed: %s\n", error);
        mc_client_destroy(peer);
        return EXIT_FAILURE;
    }

    static const char response_json[] =
        "{\"version\":{\"name\":\"26.2\",\"protocol\":776},"
        "\"players\":{\"max\":5,\"online\":2,\"sample\":[]},"
        "\"description\":{\"text\":\"mcprotocol status nonce\"}}";
    unsigned char storage[512];
    McPacket response;
    mc_packet_init(&response, storage, sizeof(storage));
    if (!mc_packet_string(&response, response_json)
        || mc_client_send(peer, 0x00, response.data, response.length,
            error, sizeof(error)) != 0
        || poll_until(peer, &observation.ping, error, sizeof(error)) != 0
        || !observation.valid || observation.nonce != INT64_C(42)) {
        fprintf(stderr, "status server ping failed: %s\n", error);
        mc_client_destroy(peer);
        return EXIT_FAILURE;
    }

    McPacket pong;
    mc_packet_init(&pong, storage, sizeof(storage));
    if (!mc_packet_i64(&pong, observation.nonce)
        || mc_client_send(peer, 0x01, pong.data, pong.length,
            error, sizeof(error)) != 0) {
        fprintf(stderr, "status server pong failed: %s\n", error);
        mc_client_destroy(peer);
        return EXIT_FAILURE;
    }
    mc_client_destroy(peer);
    return EXIT_SUCCESS;
}

int main(void)
{
    char error[256] = {0};
    McServer *server = mc_server_create("127.0.0.1", 0U, 1, error, sizeof(error));
    assert(server != NULL);
    const uint16_t port = mc_server_port(server);
    assert(port != 0U);

    const pid_t child = fork();
    assert(child >= 0);
    if (child == 0) {
        const int result = run_server(server);
        mc_server_destroy(server);
        _exit(result);
    }

    const McClientInformation information = {
        .locale = "it_it",
        .view_distance = 2,
        .chat_mode = 0,
        .chat_colors = true,
        .skin_parts = UINT8_C(0x7f),
        .main_hand = 1,
        .text_filtering = false,
        .server_listing = false,
        .particle_status = 0,
    };
    McClient *client = mc_client_create(776, NULL, NULL, error, sizeof(error));
    assert(client != NULL);
    assert(mc_client_connect_profile(client,
        "127.0.0.1", port, "ProfileClient", &PROFILE_ID, &information,
        error, sizeof(error)) == 0);
    assert(mc_client_state(client) == MC_STATE_PLAY);
    mc_client_destroy(client);
    mc_server_destroy(server);

    int status = 0;
    assert(waitpid(child, &status, 0) == child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);
    assert(mc_client_connect_profile(NULL, "127.0.0.1", port,
        "ProfileClient", &PROFILE_ID, &information,
        error, sizeof(error)) != 0);

    server = mc_server_create("127.0.0.1", 0U, 1, error, sizeof(error));
    assert(server != NULL);
    const uint16_t status_port = mc_server_port(server);
    assert(status_port != 0U);
    const pid_t status_child = fork();
    assert(status_child >= 0);
    if (status_child == 0) {
        const int result = run_status_server(server);
        mc_server_destroy(server);
        _exit(result);
    }

    static const char expected_json[] =
        "{\"version\":{\"name\":\"26.2\",\"protocol\":776},"
        "\"players\":{\"max\":5,\"online\":2,\"sample\":[]},"
        "\"description\":{\"text\":\"mcprotocol status nonce\"}}";
    char json[512];
    McStatus ping_status = {0};
    assert(mc_status_ping_nonce(776, "127.0.0.1", status_port, 5000U,
        INT64_C(42), json, sizeof(json), &ping_status,
        error, sizeof(error)) == 0);
    assert(strcmp(json, expected_json) == 0);
    assert(ping_status.json_size == strlen(expected_json));
    mc_server_destroy(server);
    assert(waitpid(status_child, &status, 0) == status_child);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);

    server = mc_server_create("127.0.0.1", 0U, 1, error, sizeof(error));
    assert(server != NULL);
    const uint16_t port_777 = mc_server_port(server);
    const pid_t child_777 = fork();
    assert(child_777 >= 0);
    if (child_777 == 0) {
        const int result = run_server_777(server);
        mc_server_destroy(server);
        _exit(result);
    }
    McClient *client_777 = mc_client_create(777, NULL, NULL, error, sizeof(error));
    assert(client_777 != NULL);
    assert(mc_client_connect_profile(client_777, "127.0.0.1", port_777,
        "ProfileClient", &PROFILE_ID, &information, error, sizeof(error)) == 0);
    assert(mc_client_state(client_777) == MC_STATE_PLAY);
    /* Serve the two Player Position packets until the peer closes. */
    for (int attempt = 0; attempt < 200; ++attempt) {
        if (mc_client_poll(client_777, 25, error, sizeof(error)) < 0) break;
    }
    mc_client_destroy(client_777);
    mc_server_destroy(server);
    assert(waitpid(child_777, &status, 0) == child_777);
    assert(WIFEXITED(status) && WEXITSTATUS(status) == EXIT_SUCCESS);

    check_local_address();

    puts("PASS explicit profile connect (776, 777), status nonce and local source bind");
    return EXIT_SUCCESS;
}
