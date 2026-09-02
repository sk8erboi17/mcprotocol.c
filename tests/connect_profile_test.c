#define _POSIX_C_SOURCE 200809L

#include "api.h"

#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static const McUuid PROFILE_ID = {{
    0x10U, 0x32U, 0x54U, 0x76U, 0x98U, 0xbaU, 0xdcU, 0xfeU,
    0xefU, 0xcdU, 0xabU, 0x89U, 0x67U, 0x45U, 0x23U, 0x01U,
}};

typedef struct ServerObservation {
    bool login_start;
    bool login_acknowledged;
    bool settings;
    bool configuration_finished;
    bool valid;
} ServerObservation;

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
    const char *name = mc_packet_name(
        776, state, MC_PACKET_SERVERBOUND, packet_id);
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

static int run_server(McServer *server)
{
    ServerObservation observation = {.valid = true};
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
    puts("PASS explicit profile UUID and configuration information connect");
    return EXIT_SUCCESS;
}
