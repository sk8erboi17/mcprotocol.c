#if defined(__linux__)
#define _GNU_SOURCE
#else
#define _POSIX_C_SOURCE 200809L
#endif
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE
#endif

#include "api.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <zlib.h>

#if defined(__APPLE__)
#include <sys/event.h>
#elif defined(__linux__)
#include <linux/io_uring.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#endif

/* ============================================================
 * PROTOCOL PROFILES
 * ============================================================ */

#define MC_MAX_PACKET (16U * 1024U * 1024U)
#define MC_LOGIN_PACKETS 16U
#define MC_CONFIG_PACKETS 256U

typedef struct {
    int protocol;
    int join_game;
    int keep_alive;
    int player_position;
    int teleport_confirm;
    int keep_alive_response;
    uint32_t flags;
} McProfile;

/* Packet numbers move independently between Minecraft releases. Keeping the
 * handful needed for connection maintenance in a profile makes the state
 * machine below version-neutral. Flags describe wire-shape changes that cannot
 * be inferred from an ID alone. */
#define C MC_PROTOCOL_FEATURE_COMPRESSION
#define K MC_PROTOCOL_FEATURE_KEEP_ALIVE_I64
#define L MC_PROTOCOL_FEATURE_LOGIN_KEY
#define O MC_PROTOCOL_FEATURE_OPTIONAL_UUID
#define R MC_PROTOCOL_FEATURE_REQUIRED_UUID
#define F MC_PROTOCOL_FEATURE_CONFIGURATION
#define D MC_PROTOCOL_FEATURE_POSITION_DELTA
#define S MC_PROTOCOL_FEATURE_CHAT_LAST_SEEN
#define A MC_PROTOCOL_FEATURE_CHAT_ACKNOWLEDGED
#define P(v,j,k,p,t,r,f) {v,j,k,p,t,r,f}
static const McProfile profiles[] = {
    P(4,   0x01,0x00,0x08,-1,  0x00,0),
    P(5,   0x01,0x00,0x08,-1,  0x00,0),
    P(47,  0x01,0x00,0x08,-1,  0x00,C),
    P(107, 0x23,0x1F,0x2E,0x00,0x0B,C),
    P(108, 0x23,0x1F,0x2E,0x00,0x0B,C),
    P(109, 0x23,0x1F,0x2E,0x00,0x0B,C),
    P(110, 0x23,0x1F,0x2E,0x00,0x0B,C),
    P(210, 0x23,0x1F,0x2E,0x00,0x0B,C),
    P(315, 0x23,0x1F,0x2E,0x00,0x0B,C),
    P(316, 0x23,0x1F,0x2E,0x00,0x0B,C),
    P(335, 0x23,0x1F,0x2E,0x00,0x0C,C),
    P(338, 0x23,0x1F,0x2F,0x00,0x0B,C),
    P(340, 0x23,0x1F,0x2F,0x00,0x0B,C|K),
    P(393, 0x25,0x21,0x32,0x00,0x0E,C|K),
    P(401, 0x25,0x21,0x32,0x00,0x0E,C|K),
    P(404, 0x25,0x21,0x32,0x00,0x0E,C|K),
    P(477, 0x25,0x20,0x35,0x00,0x0F,C|K),
    P(480, 0x25,0x20,0x35,0x00,0x0F,C|K),
    P(485, 0x25,0x20,0x35,0x00,0x0F,C|K),
    P(490, 0x25,0x20,0x35,0x00,0x0F,C|K),
    P(498, 0x25,0x20,0x35,0x00,0x0F,C|K),
    P(573, 0x26,0x21,0x36,0x00,0x0F,C|K),
    P(575, 0x26,0x21,0x36,0x00,0x0F,C|K),
    P(578, 0x26,0x21,0x36,0x00,0x0F,C|K),
    P(735, 0x25,0x20,0x35,0x00,0x10,C|K),
    P(736, 0x25,0x20,0x35,0x00,0x10,C|K),
    P(751, 0x24,0x1F,0x34,0x00,0x10,C|K),
    P(753, 0x24,0x1F,0x34,0x00,0x10,C|K),
    P(754, 0x24,0x1F,0x34,0x00,0x10,C|K),
    P(755, 0x26,0x21,0x38,0x00,0x0F,C|K),
    P(756, 0x26,0x21,0x38,0x00,0x0F,C|K),
    P(757, 0x26,0x21,0x38,0x00,0x0F,C|K),
    P(758, 0x26,0x21,0x38,0x00,0x0F,C|K),
    P(759, 0x23,0x1E,0x36,0x00,0x11,C|K|L),
    P(760, 0x25,0x20,0x39,0x00,0x12,C|K|L|O|S),
    P(761, 0x24,0x1F,0x38,0x00,0x11,C|K|O|A),
    P(762, 0x28,0x23,0x3C,0x00,0x12,C|K|O|A),
    P(763, 0x28,0x23,0x3C,0x00,0x12,C|K|O|A),
    P(764, 0x29,0x24,0x3E,0x00,0x14,C|K|R|F|A),
    P(765, 0x29,0x24,0x3E,0x00,0x15,C|K|R|F|A),
    P(766, 0x2B,0x26,0x40,0x00,0x18,C|K|R|F),
    P(767, 0x2B,0x26,0x40,0x00,0x18,C|K|R|F),
    P(768, 0x2C,0x27,0x42,0x00,0x1A,C|K|R|F|D),
    P(769, 0x2C,0x27,0x42,0x00,0x1A,C|K|R|F|D),
    P(770, 0x2B,0x26,0x41,0x00,0x1A,C|K|R|F|D),
    P(771, 0x2B,0x26,0x41,0x00,0x1B,C|K|R|F|D),
    P(772, 0x2B,0x26,0x41,0x00,0x1B,C|K|R|F|D),
    P(773, 0x30,0x2B,0x46,0x00,0x1B,C|K|R|F|D),
    P(774, 0x30,0x2B,0x46,0x00,0x1B,C|K|R|F|D),
    P(775, 0x31,0x2C,0x48,0x00,0x1C,C|K|R|F|D),
    P(776, 0x31,0x2C,0x48,0x00,0x1C,C|K|R|F|D)
};
#undef P
#undef A
#undef S
#undef D
#undef F
#undef R
#undef O
#undef L
#undef K
#undef C

static const int protocol_ids[] = {
    4,5,47,107,108,109,110,210,315,316,335,338,340,393,401,404,477,
    480,485,490,498,573,575,578,735,736,751,753,754,755,756,757,758,
    759,760,761,762,763,764,765,766,767,768,769,770,771,772,773,774,
    775,776
};

static const char *const protocol_names[] = {
    "1.7.5","1.7.10","1.8.9","1.9","1.9.1","1.9.2","1.9.4",
    "1.10.2","1.11","1.11.2","1.12","1.12.1","1.12.2","1.13",
    "1.13.1","1.13.2","1.14","1.14.1","1.14.2","1.14.3","1.14.4",
    "1.15","1.15.1","1.15.2","1.16","1.16.1","1.16.2","1.16.3",
    "1.16.5","1.17","1.17.1","1.18.1","1.18.2","1.19","1.19.2",
    "1.19.3","1.19.4","1.20.1","1.20.2","1.20.4","1.20.6","1.21.1",
    "1.21.3","1.21.4","1.21.5","1.21.6","1.21.8","1.21.10",
    "1.21.11","26.1.2","26.2"
};

_Static_assert(sizeof(protocol_names) / sizeof(protocol_names[0])
    == sizeof(protocol_ids) / sizeof(protocol_ids[0]),
    "protocol IDs and canonical names must stay aligned");


/* ============================================================
 * GENERATED PACKET CATALOGS
 * ============================================================ */

/* Each name array is indexed directly by its wire packet ID. Empty states use
 * a zero-length map rather than a sentinel, so enumeration and reverse lookup
 * share one representation. Status has one invariant pair of maps shared by
 * every supported release. When a catalog is regenerated, keep its protocol
 * entry and all six release-specific state/direction maps together: mixing
 * releases produces names that look valid while resolving to the wrong packet
 * on the wire. */
typedef struct {
    const char *const *names;
    size_t count;
} McPacketMap;

typedef struct {
    int protocol;
    McPacketMap login_serverbound;
    McPacketMap login_clientbound;
    McPacketMap configuration_serverbound;
    McPacketMap configuration_clientbound;
    McPacketMap play_serverbound;
    McPacketMap play_clientbound;
} McPacketCatalog;

static const char *const packet_names_status_serverbound[] = {
    "ping_start", "ping",
};

static const char *const packet_names_status_clientbound[] = {
    "server_info", "ping",
};

static const McPacketMap packet_map_status_serverbound = {
    packet_names_status_serverbound,
    sizeof(packet_names_status_serverbound) / sizeof(packet_names_status_serverbound[0]),
};

static const McPacketMap packet_map_status_clientbound = {
    packet_names_status_clientbound,
    sizeof(packet_names_status_clientbound) / sizeof(packet_names_status_clientbound[0]),
};

static const char *const packet_names_0_login_serverbound[] = {
    "login_start", "encryption_begin",
};

static const char *const packet_names_0_login_clientbound[] = {
    "disconnect", "encryption_begin", "success",
};

static const char *const packet_names_0_play_serverbound[] = {
    "keep_alive", "chat", "use_entity", "flying",
    "position", "look", "position_look", "block_dig",
    "block_place", "held_item_slot", "arm_animation", "entity_action",
    "steer_vehicle", "close_window", "window_click", "transaction",
    "set_creative_slot", "enchant_item", "update_sign", "abilities",
    "tab_complete", "settings", "client_command", "custom_payload",
};

static const char *const packet_names_0_play_clientbound[] = {
    "keep_alive", "login", "chat", "update_time",
    "entity_equipment", "spawn_position", "update_health", "respawn",
    "position", "held_item_slot", "bed", "animation",
    "named_entity_spawn", "collect", "spawn_entity", "spawn_entity_living",
    "spawn_entity_painting", "spawn_entity_experience_orb", "entity_velocity", "entity_destroy",
    "entity", "rel_entity_move", "entity_look", "entity_move_look",
    "entity_teleport", "entity_head_rotation", "entity_status", "attach_entity",
    "entity_metadata", "entity_effect", "remove_entity_effect", "experience",
    "update_attributes", "map_chunk", "multi_block_change", "block_change",
    "block_action", "block_break_animation", "map_chunk_bulk", "explosion",
    "world_event", "named_sound_effect", "world_particles", "game_state_change",
    "spawn_entity_weather", "open_window", "close_window", "set_slot",
    "window_items", "craft_progress_bar", "transaction", "update_sign",
    "map", "tile_entity_data", "open_sign_entity", "statistics",
    "player_info", "abilities", "tab_complete", "scoreboard_objective",
    "scoreboard_score", "scoreboard_display_objective", "scoreboard_team", "custom_payload",
    "kick_disconnect",
};

static const char *const packet_names_1_login_serverbound[] = {
    "login_start", "encryption_begin",
};

static const char *const packet_names_1_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
};

static const char *const packet_names_1_play_serverbound[] = {
    "keep_alive", "chat", "use_entity", "flying",
    "position", "look", "position_look", "block_dig",
    "block_place", "held_item_slot", "arm_animation", "entity_action",
    "steer_vehicle", "close_window", "window_click", "transaction",
    "set_creative_slot", "enchant_item", "update_sign", "abilities",
    "tab_complete", "settings", "client_command", "custom_payload",
    "spectate", "resource_pack_receive",
};

static const char *const packet_names_1_play_clientbound[] = {
    "keep_alive", "login", "chat", "update_time",
    "entity_equipment", "spawn_position", "update_health", "respawn",
    "position", "held_item_slot", "bed", "animation",
    "named_entity_spawn", "collect", "spawn_entity", "spawn_entity_living",
    "spawn_entity_painting", "spawn_entity_experience_orb", "entity_velocity", "entity_destroy",
    "entity", "rel_entity_move", "entity_look", "entity_move_look",
    "entity_teleport", "entity_head_rotation", "entity_status", "attach_entity",
    "entity_metadata", "entity_effect", "remove_entity_effect", "experience",
    "update_attributes", "map_chunk", "multi_block_change", "block_change",
    "block_action", "block_break_animation", "map_chunk_bulk", "explosion",
    "world_event", "named_sound_effect", "world_particles", "game_state_change",
    "spawn_entity_weather", "open_window", "close_window", "set_slot",
    "window_items", "craft_progress_bar", "transaction", "update_sign",
    "map", "tile_entity_data", "open_sign_entity", "statistics",
    "player_info", "abilities", "tab_complete", "scoreboard_objective",
    "scoreboard_score", "scoreboard_display_objective", "scoreboard_team", "custom_payload",
    "kick_disconnect", "difficulty", "combat_event", "camera",
    "world_border", "title", "set_compression", "playerlist_header",
    "resource_pack_send", "update_entity_nbt",
};

static const char *const packet_names_2_login_serverbound[] = {
    "login_start", "encryption_begin",
};

static const char *const packet_names_2_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
};

static const char *const packet_names_2_play_serverbound[] = {
    "teleport_confirm", "tab_complete", "chat", "client_command",
    "settings", "transaction", "enchant_item", "window_click",
    "close_window", "custom_payload", "use_entity", "keep_alive",
    "position", "position_look", "look", "flying",
    "vehicle_move", "steer_boat", "abilities", "block_dig",
    "entity_action", "steer_vehicle", "resource_pack_receive", "held_item_slot",
    "set_creative_slot", "update_sign", "arm_animation", "spectate",
    "block_place", "use_item",
};

static const char *const packet_names_2_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_weather", "spawn_entity_living",
    "spawn_entity_painting", "named_entity_spawn", "animation", "statistics",
    "block_break_animation", "tile_entity_data", "block_action", "block_change",
    "boss_bar", "difficulty", "tab_complete", "chat",
    "multi_block_change", "transaction", "close_window", "open_window",
    "window_items", "craft_progress_bar", "set_slot", "set_cooldown",
    "custom_payload", "named_sound_effect", "kick_disconnect", "entity_status",
    "explosion", "unload_chunk", "game_state_change", "keep_alive",
    "map_chunk", "world_event", "world_particles", "login",
    "map", "rel_entity_move", "entity_move_look", "entity_look",
    "entity", "vehicle_move", "open_sign_entity", "abilities",
    "combat_event", "player_info", "position", "bed",
    "entity_destroy", "remove_entity_effect", "resource_pack_send", "respawn",
    "entity_head_rotation", "world_border", "camera", "held_item_slot",
    "scoreboard_display_objective", "entity_metadata", "attach_entity", "entity_velocity",
    "entity_equipment", "experience", "update_health", "scoreboard_objective",
    "set_passengers", "teams", "scoreboard_score", "spawn_position",
    "update_time", "title", "update_sign", "sound_effect",
    "playerlist_header", "collect", "entity_teleport", "entity_update_attributes",
    "entity_effect",
};

static const char *const packet_names_3_login_serverbound[] = {
    "login_start", "encryption_begin",
};

static const char *const packet_names_3_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
};

static const char *const packet_names_3_play_serverbound[] = {
    "teleport_confirm", "tab_complete", "chat", "client_command",
    "settings", "transaction", "enchant_item", "window_click",
    "close_window", "custom_payload", "use_entity", "keep_alive",
    "position", "position_look", "look", "flying",
    "vehicle_move", "steer_boat", "abilities", "block_dig",
    "entity_action", "steer_vehicle", "resource_pack_receive", "held_item_slot",
    "set_creative_slot", "update_sign", "arm_animation", "spectate",
    "block_place", "use_item",
};

static const char *const packet_names_3_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_weather", "spawn_entity_living",
    "spawn_entity_painting", "named_entity_spawn", "animation", "statistics",
    "block_break_animation", "tile_entity_data", "block_action", "block_change",
    "boss_bar", "difficulty", "tab_complete", "chat",
    "multi_block_change", "transaction", "close_window", "open_window",
    "window_items", "craft_progress_bar", "set_slot", "set_cooldown",
    "custom_payload", "named_sound_effect", "kick_disconnect", "entity_status",
    "explosion", "unload_chunk", "game_state_change", "keep_alive",
    "map_chunk", "world_event", "world_particles", "login",
    "map", "rel_entity_move", "entity_move_look", "entity_look",
    "entity", "vehicle_move", "open_sign_entity", "abilities",
    "combat_event", "player_info", "position", "bed",
    "entity_destroy", "remove_entity_effect", "resource_pack_send", "respawn",
    "entity_head_rotation", "world_border", "camera", "held_item_slot",
    "scoreboard_display_objective", "entity_metadata", "attach_entity", "entity_velocity",
    "entity_equipment", "experience", "update_health", "scoreboard_objective",
    "set_passengers", "teams", "scoreboard_score", "spawn_position",
    "update_time", "title", "sound_effect", "playerlist_header",
    "collect", "entity_teleport", "entity_update_attributes", "entity_effect",
};

static const char *const packet_names_4_login_serverbound[] = {
    "login_start", "encryption_begin",
};

static const char *const packet_names_4_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
};

static const char *const packet_names_4_play_serverbound[] = {
    "teleport_confirm", "prepare_crafting_grid", "tab_complete", "chat",
    "client_command", "settings", "transaction", "enchant_item",
    "window_click", "close_window", "custom_payload", "use_entity",
    "keep_alive", "flying", "position", "position_look",
    "look", "vehicle_move", "steer_boat", "abilities",
    "block_dig", "entity_action", "steer_vehicle", "crafting_book_data",
    "resource_pack_receive", "advancement_tab", "held_item_slot", "set_creative_slot",
    "update_sign", "arm_animation", "spectate", "block_place",
    "use_item",
};

static const char *const packet_names_4_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_weather", "spawn_entity_living",
    "spawn_entity_painting", "named_entity_spawn", "animation", "statistics",
    "block_break_animation", "tile_entity_data", "block_action", "block_change",
    "boss_bar", "difficulty", "tab_complete", "chat",
    "multi_block_change", "transaction", "close_window", "open_window",
    "window_items", "craft_progress_bar", "set_slot", "set_cooldown",
    "custom_payload", "named_sound_effect", "kick_disconnect", "entity_status",
    "explosion", "unload_chunk", "game_state_change", "keep_alive",
    "map_chunk", "world_event", "world_particles", "login",
    "map", "entity", "rel_entity_move", "entity_move_look",
    "entity_look", "vehicle_move", "open_sign_entity", "abilities",
    "combat_event", "player_info", "position", "bed",
    "unlock_recipes", "entity_destroy", "remove_entity_effect", "resource_pack_send",
    "respawn", "entity_head_rotation", "select_advancement_tab", "world_border",
    "camera", "held_item_slot", "scoreboard_display_objective", "entity_metadata",
    "attach_entity", "entity_velocity", "entity_equipment", "experience",
    "update_health", "scoreboard_objective", "set_passengers", "teams",
    "scoreboard_score", "spawn_position", "update_time", "title",
    "sound_effect", "playerlist_header", "collect", "entity_teleport",
    "advancements", "entity_update_attributes", "entity_effect",
};

static const char *const packet_names_5_login_serverbound[] = {
    "login_start", "encryption_begin",
};

static const char *const packet_names_5_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
};

static const char *const packet_names_5_play_serverbound[] = {
    "teleport_confirm", "tab_complete", "chat", "client_command",
    "settings", "transaction", "enchant_item", "window_click",
    "close_window", "custom_payload", "use_entity", "keep_alive",
    "flying", "position", "position_look", "look",
    "vehicle_move", "steer_boat", "craft_recipe_request", "abilities",
    "block_dig", "entity_action", "steer_vehicle", "crafting_book_data",
    "resource_pack_receive", "advancement_tab", "held_item_slot", "set_creative_slot",
    "update_sign", "arm_animation", "spectate", "block_place",
    "use_item",
};

static const char *const packet_names_5_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_weather", "spawn_entity_living",
    "spawn_entity_painting", "named_entity_spawn", "animation", "statistics",
    "block_break_animation", "tile_entity_data", "block_action", "block_change",
    "boss_bar", "difficulty", "tab_complete", "chat",
    "multi_block_change", "transaction", "close_window", "open_window",
    "window_items", "craft_progress_bar", "set_slot", "set_cooldown",
    "custom_payload", "named_sound_effect", "kick_disconnect", "entity_status",
    "explosion", "unload_chunk", "game_state_change", "keep_alive",
    "map_chunk", "world_event", "world_particles", "login",
    "map", "entity", "rel_entity_move", "entity_move_look",
    "entity_look", "vehicle_move", "open_sign_entity", "craft_recipe_response",
    "abilities", "combat_event", "player_info", "position",
    "bed", "unlock_recipes", "entity_destroy", "remove_entity_effect",
    "resource_pack_send", "respawn", "entity_head_rotation", "select_advancement_tab",
    "world_border", "camera", "held_item_slot", "scoreboard_display_objective",
    "entity_metadata", "attach_entity", "entity_velocity", "entity_equipment",
    "experience", "update_health", "scoreboard_objective", "set_passengers",
    "teams", "scoreboard_score", "spawn_position", "update_time",
    "title", "sound_effect", "playerlist_header", "collect",
    "entity_teleport", "advancements", "entity_update_attributes", "entity_effect",
};

static const char *const packet_names_6_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_6_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_6_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "chat", "client_command",
    "settings", "tab_complete", "transaction", "enchant_item",
    "window_click", "close_window", "custom_payload", "edit_book",
    "query_entity_nbt", "use_entity", "keep_alive", "flying",
    "position", "position_look", "look", "vehicle_move",
    "steer_boat", "pick_item", "craft_recipe_request", "abilities",
    "block_dig", "entity_action", "steer_vehicle", "crafting_book_data",
    "name_item", "resource_pack_receive", "advancement_tab", "select_trade",
    "set_beacon_effect", "held_item_slot", "update_command_block", "update_command_block_minecart",
    "set_creative_slot", "update_structure_block", "update_sign", "arm_animation",
    "spectate", "block_place", "use_item",
};

static const char *const packet_names_6_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_weather", "spawn_entity_living",
    "spawn_entity_painting", "named_entity_spawn", "animation", "statistics",
    "block_break_animation", "tile_entity_data", "block_action", "block_change",
    "boss_bar", "difficulty", "chat", "multi_block_change",
    "tab_complete", "declare_commands", "transaction", "close_window",
    "open_window", "window_items", "craft_progress_bar", "set_slot",
    "set_cooldown", "custom_payload", "named_sound_effect", "kick_disconnect",
    "entity_status", "nbt_query_response", "explosion", "unload_chunk",
    "game_state_change", "keep_alive", "map_chunk", "world_event",
    "world_particles", "login", "map", "entity",
    "rel_entity_move", "entity_move_look", "entity_look", "vehicle_move",
    "open_sign_entity", "craft_recipe_response", "abilities", "combat_event",
    "player_info", "face_player", "position", "bed",
    "unlock_recipes", "entity_destroy", "remove_entity_effect", "resource_pack_send",
    "respawn", "entity_head_rotation", "select_advancement_tab", "world_border",
    "camera", "held_item_slot", "scoreboard_display_objective", "entity_metadata",
    "attach_entity", "entity_velocity", "entity_equipment", "experience",
    "update_health", "scoreboard_objective", "set_passengers", "teams",
    "scoreboard_score", "spawn_position", "update_time", "title",
    "stop_sound", "sound_effect", "playerlist_header", "collect",
    "entity_teleport", "advancements", "entity_update_attributes", "entity_effect",
    "declare_recipes", "tags",
};

static const char *const packet_names_7_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_7_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_7_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "chat",
    "client_command", "settings", "tab_complete", "transaction",
    "enchant_item", "window_click", "close_window", "custom_payload",
    "edit_book", "query_entity_nbt", "use_entity", "keep_alive",
    "lock_difficulty", "position", "position_look", "look",
    "flying", "vehicle_move", "steer_boat", "pick_item",
    "craft_recipe_request", "abilities", "block_dig", "entity_action",
    "steer_vehicle", "crafting_book_data", "name_item", "resource_pack_receive",
    "advancement_tab", "select_trade", "set_beacon_effect", "held_item_slot",
    "update_command_block", "update_command_block_minecart", "set_creative_slot", "update_jigsaw_block",
    "update_structure_block", "update_sign", "arm_animation", "spectate",
    "block_place", "use_item",
};

static const char *const packet_names_7_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_weather", "spawn_entity_living",
    "spawn_entity_painting", "named_entity_spawn", "animation", "statistics",
    "block_break_animation", "tile_entity_data", "block_action", "block_change",
    "boss_bar", "difficulty", "chat", "multi_block_change",
    "tab_complete", "declare_commands", "transaction", "close_window",
    "window_items", "craft_progress_bar", "set_slot", "set_cooldown",
    "custom_payload", "named_sound_effect", "kick_disconnect", "entity_status",
    "explosion", "unload_chunk", "game_state_change", "open_horse_window",
    "keep_alive", "map_chunk", "world_event", "world_particles",
    "update_light", "login", "map", "trade_list",
    "rel_entity_move", "entity_move_look", "entity_look", "entity",
    "vehicle_move", "open_book", "open_window", "open_sign_entity",
    "craft_recipe_response", "abilities", "combat_event", "player_info",
    "face_player", "position", "unlock_recipes", "entity_destroy",
    "remove_entity_effect", "resource_pack_send", "respawn", "entity_head_rotation",
    "select_advancement_tab", "world_border", "camera", "held_item_slot",
    "update_view_position", "update_view_distance", "scoreboard_display_objective", "entity_metadata",
    "attach_entity", "entity_velocity", "entity_equipment", "experience",
    "update_health", "scoreboard_objective", "set_passengers", "teams",
    "scoreboard_score", "spawn_position", "update_time", "title",
    "entity_sound_effect", "sound_effect", "stop_sound", "playerlist_header",
    "nbt_query_response", "collect", "entity_teleport", "advancements",
    "entity_update_attributes", "entity_effect", "declare_recipes", "tags",
};

static const char *const packet_names_8_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_8_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_8_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "chat",
    "client_command", "settings", "tab_complete", "transaction",
    "enchant_item", "window_click", "close_window", "custom_payload",
    "edit_book", "query_entity_nbt", "use_entity", "keep_alive",
    "lock_difficulty", "position", "position_look", "look",
    "flying", "vehicle_move", "steer_boat", "pick_item",
    "craft_recipe_request", "abilities", "block_dig", "entity_action",
    "steer_vehicle", "crafting_book_data", "name_item", "resource_pack_receive",
    "advancement_tab", "select_trade", "set_beacon_effect", "held_item_slot",
    "update_command_block", "update_command_block_minecart", "set_creative_slot", "update_jigsaw_block",
    "update_structure_block", "update_sign", "arm_animation", "spectate",
    "block_place", "use_item",
};

static const char *const packet_names_8_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_weather", "spawn_entity_living",
    "spawn_entity_painting", "named_entity_spawn", "animation", "statistics",
    "block_break_animation", "tile_entity_data", "block_action", "block_change",
    "boss_bar", "difficulty", "chat", "multi_block_change",
    "tab_complete", "declare_commands", "transaction", "close_window",
    "window_items", "craft_progress_bar", "set_slot", "set_cooldown",
    "custom_payload", "named_sound_effect", "kick_disconnect", "entity_status",
    "explosion", "unload_chunk", "game_state_change", "open_horse_window",
    "keep_alive", "map_chunk", "world_event", "world_particles",
    "update_light", "login", "map", "trade_list",
    "rel_entity_move", "entity_move_look", "entity_look", "entity",
    "vehicle_move", "open_book", "open_window", "open_sign_entity",
    "craft_recipe_response", "abilities", "combat_event", "player_info",
    "face_player", "position", "unlock_recipes", "entity_destroy",
    "remove_entity_effect", "resource_pack_send", "respawn", "entity_head_rotation",
    "select_advancement_tab", "world_border", "camera", "held_item_slot",
    "update_view_position", "update_view_distance", "scoreboard_display_objective", "entity_metadata",
    "attach_entity", "entity_velocity", "entity_equipment", "experience",
    "update_health", "scoreboard_objective", "set_passengers", "teams",
    "scoreboard_score", "spawn_position", "update_time", "title",
    "entity_sound_effect", "sound_effect", "stop_sound", "playerlist_header",
    "nbt_query_response", "collect", "entity_teleport", "advancements",
    "entity_update_attributes", "entity_effect", "declare_recipes", "tags",
    "acknowledge_player_digging",
};

static const char *const packet_names_9_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_9_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_9_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "chat",
    "client_command", "settings", "tab_complete", "transaction",
    "enchant_item", "window_click", "close_window", "custom_payload",
    "edit_book", "query_entity_nbt", "use_entity", "keep_alive",
    "lock_difficulty", "position", "position_look", "look",
    "flying", "vehicle_move", "steer_boat", "pick_item",
    "craft_recipe_request", "abilities", "block_dig", "entity_action",
    "steer_vehicle", "crafting_book_data", "name_item", "resource_pack_receive",
    "advancement_tab", "select_trade", "set_beacon_effect", "held_item_slot",
    "update_command_block", "update_command_block_minecart", "set_creative_slot", "update_jigsaw_block",
    "update_structure_block", "update_sign", "arm_animation", "spectate",
    "block_place", "use_item",
};

static const char *const packet_names_9_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_weather", "spawn_entity_living",
    "spawn_entity_painting", "named_entity_spawn", "animation", "statistics",
    "acknowledge_player_digging", "block_break_animation", "tile_entity_data", "block_action",
    "block_change", "boss_bar", "difficulty", "chat",
    "multi_block_change", "tab_complete", "declare_commands", "transaction",
    "close_window", "window_items", "craft_progress_bar", "set_slot",
    "set_cooldown", "custom_payload", "named_sound_effect", "kick_disconnect",
    "entity_status", "explosion", "unload_chunk", "game_state_change",
    "open_horse_window", "keep_alive", "map_chunk", "world_event",
    "world_particles", "update_light", "login", "map",
    "trade_list", "rel_entity_move", "entity_move_look", "entity_look",
    "entity", "vehicle_move", "open_book", "open_window",
    "open_sign_entity", "craft_recipe_response", "abilities", "combat_event",
    "player_info", "face_player", "position", "unlock_recipes",
    "entity_destroy", "remove_entity_effect", "resource_pack_send", "respawn",
    "entity_head_rotation", "select_advancement_tab", "world_border", "camera",
    "held_item_slot", "update_view_position", "update_view_distance", "scoreboard_display_objective",
    "entity_metadata", "attach_entity", "entity_velocity", "entity_equipment",
    "experience", "update_health", "scoreboard_objective", "set_passengers",
    "teams", "scoreboard_score", "spawn_position", "update_time",
    "title", "entity_sound_effect", "sound_effect", "stop_sound",
    "playerlist_header", "nbt_query_response", "collect", "entity_teleport",
    "advancements", "entity_update_attributes", "entity_effect", "declare_recipes",
    "tags",
};

static const char *const packet_names_10_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_10_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_10_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "chat",
    "client_command", "settings", "tab_complete", "transaction",
    "enchant_item", "window_click", "close_window", "custom_payload",
    "edit_book", "query_entity_nbt", "use_entity", "generate_structure",
    "keep_alive", "lock_difficulty", "position", "position_look",
    "look", "flying", "vehicle_move", "steer_boat",
    "pick_item", "craft_recipe_request", "abilities", "block_dig",
    "entity_action", "steer_vehicle", "crafting_book_data", "name_item",
    "resource_pack_receive", "advancement_tab", "select_trade", "set_beacon_effect",
    "held_item_slot", "update_command_block", "update_command_block_minecart", "set_creative_slot",
    "update_jigsaw_block", "update_structure_block", "update_sign", "arm_animation",
    "spectate", "block_place", "use_item",
};

static const char *const packet_names_10_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_living", "spawn_entity_painting",
    "named_entity_spawn", "animation", "statistics", "acknowledge_player_digging",
    "block_break_animation", "tile_entity_data", "block_action", "block_change",
    "boss_bar", "difficulty", "chat", "multi_block_change",
    "tab_complete", "declare_commands", "transaction", "close_window",
    "window_items", "craft_progress_bar", "set_slot", "set_cooldown",
    "custom_payload", "named_sound_effect", "kick_disconnect", "entity_status",
    "explosion", "unload_chunk", "game_state_change", "open_horse_window",
    "keep_alive", "map_chunk", "world_event", "world_particles",
    "update_light", "login", "map", "trade_list",
    "rel_entity_move", "entity_move_look", "entity_look", "entity",
    "vehicle_move", "open_book", "open_window", "open_sign_entity",
    "craft_recipe_response", "abilities", "combat_event", "player_info",
    "face_player", "position", "unlock_recipes", "entity_destroy",
    "remove_entity_effect", "resource_pack_send", "respawn", "entity_head_rotation",
    "select_advancement_tab", "world_border", "camera", "held_item_slot",
    "update_view_position", "update_view_distance", "spawn_position", "scoreboard_display_objective",
    "entity_metadata", "attach_entity", "entity_velocity", "entity_equipment",
    "experience", "update_health", "scoreboard_objective", "set_passengers",
    "teams", "scoreboard_score", "update_time", "title",
    "entity_sound_effect", "sound_effect", "stop_sound", "playerlist_header",
    "nbt_query_response", "collect", "entity_teleport", "advancements",
    "entity_update_attributes", "entity_effect", "declare_recipes", "tags",
};

static const char *const packet_names_11_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_11_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_11_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "chat",
    "client_command", "settings", "tab_complete", "transaction",
    "enchant_item", "window_click", "close_window", "custom_payload",
    "edit_book", "query_entity_nbt", "use_entity", "generate_structure",
    "keep_alive", "lock_difficulty", "position", "position_look",
    "look", "flying", "vehicle_move", "steer_boat",
    "pick_item", "craft_recipe_request", "abilities", "block_dig",
    "entity_action", "steer_vehicle", "recipe_book", "displayed_recipe",
    "name_item", "resource_pack_receive", "advancement_tab", "select_trade",
    "set_beacon_effect", "held_item_slot", "update_command_block", "update_command_block_minecart",
    "set_creative_slot", "update_jigsaw_block", "update_structure_block", "update_sign",
    "arm_animation", "spectate", "block_place", "use_item",
};

static const char *const packet_names_11_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_living", "spawn_entity_painting",
    "named_entity_spawn", "animation", "statistics", "acknowledge_player_digging",
    "block_break_animation", "tile_entity_data", "block_action", "block_change",
    "boss_bar", "difficulty", "chat", "tab_complete",
    "declare_commands", "transaction", "close_window", "window_items",
    "craft_progress_bar", "set_slot", "set_cooldown", "custom_payload",
    "named_sound_effect", "kick_disconnect", "entity_status", "explosion",
    "unload_chunk", "game_state_change", "open_horse_window", "keep_alive",
    "map_chunk", "world_event", "world_particles", "update_light",
    "login", "map", "trade_list", "rel_entity_move",
    "entity_move_look", "entity_look", "entity", "vehicle_move",
    "open_book", "open_window", "open_sign_entity", "craft_recipe_response",
    "abilities", "combat_event", "player_info", "face_player",
    "position", "unlock_recipes", "entity_destroy", "remove_entity_effect",
    "resource_pack_send", "respawn", "entity_head_rotation", "multi_block_change",
    "select_advancement_tab", "world_border", "camera", "held_item_slot",
    "update_view_position", "update_view_distance", "spawn_position", "scoreboard_display_objective",
    "entity_metadata", "attach_entity", "entity_velocity", "entity_equipment",
    "experience", "update_health", "scoreboard_objective", "set_passengers",
    "teams", "scoreboard_score", "update_time", "title",
    "entity_sound_effect", "sound_effect", "stop_sound", "playerlist_header",
    "nbt_query_response", "collect", "entity_teleport", "advancements",
    "entity_update_attributes", "entity_effect", "declare_recipes", "tags",
};

static const char *const packet_names_12_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_12_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_12_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "chat",
    "client_command", "settings", "tab_complete", "enchant_item",
    "window_click", "close_window", "custom_payload", "edit_book",
    "query_entity_nbt", "use_entity", "generate_structure", "keep_alive",
    "lock_difficulty", "position", "position_look", "look",
    "flying", "vehicle_move", "steer_boat", "pick_item",
    "craft_recipe_request", "abilities", "block_dig", "entity_action",
    "steer_vehicle", "pong", "recipe_book", "displayed_recipe",
    "name_item", "resource_pack_receive", "advancement_tab", "select_trade",
    "set_beacon_effect", "held_item_slot", "update_command_block", "update_command_block_minecart",
    "set_creative_slot", "update_jigsaw_block", "update_structure_block", "update_sign",
    "arm_animation", "spectate", "block_place", "use_item",
};

static const char *const packet_names_12_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_living", "spawn_entity_painting",
    "named_entity_spawn", "sculk_vibration_signal", "animation", "statistics",
    "acknowledge_player_digging", "block_break_animation", "tile_entity_data", "block_action",
    "block_change", "boss_bar", "difficulty", "chat",
    "clear_titles", "tab_complete", "declare_commands", "close_window",
    "window_items", "craft_progress_bar", "set_slot", "set_cooldown",
    "custom_payload", "named_sound_effect", "kick_disconnect", "entity_status",
    "explosion", "unload_chunk", "game_state_change", "open_horse_window",
    "initialize_world_border", "keep_alive", "map_chunk", "world_event",
    "world_particles", "update_light", "login", "map",
    "trade_list", "rel_entity_move", "entity_move_look", "entity_look",
    "vehicle_move", "open_book", "open_window", "open_sign_entity",
    "ping", "craft_recipe_response", "abilities", "end_combat_event",
    "enter_combat_event", "death_combat_event", "player_info", "face_player",
    "position", "unlock_recipes", "destroy_entity", "remove_entity_effect",
    "resource_pack_send", "respawn", "entity_head_rotation", "multi_block_change",
    "select_advancement_tab", "action_bar", "world_border_center", "world_border_lerp_size",
    "world_border_size", "world_border_warning_delay", "world_border_warning_reach", "camera",
    "held_item_slot", "update_view_position", "update_view_distance", "spawn_position",
    "scoreboard_display_objective", "entity_metadata", "attach_entity", "entity_velocity",
    "entity_equipment", "experience", "update_health", "scoreboard_objective",
    "set_passengers", "teams", "scoreboard_score", "set_title_subtitle",
    "update_time", "set_title_text", "set_title_time", "entity_sound_effect",
    "sound_effect", "stop_sound", "playerlist_header", "nbt_query_response",
    "collect", "entity_teleport", "advancements", "entity_update_attributes",
    "entity_effect", "declare_recipes", "tags",
};

static const char *const packet_names_13_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_13_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_13_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "chat",
    "client_command", "settings", "tab_complete", "enchant_item",
    "window_click", "close_window", "custom_payload", "edit_book",
    "query_entity_nbt", "use_entity", "generate_structure", "keep_alive",
    "lock_difficulty", "position", "position_look", "look",
    "flying", "vehicle_move", "steer_boat", "pick_item",
    "craft_recipe_request", "abilities", "block_dig", "entity_action",
    "steer_vehicle", "pong", "recipe_book", "displayed_recipe",
    "name_item", "resource_pack_receive", "advancement_tab", "select_trade",
    "set_beacon_effect", "held_item_slot", "update_command_block", "update_command_block_minecart",
    "set_creative_slot", "update_jigsaw_block", "update_structure_block", "update_sign",
    "arm_animation", "spectate", "block_place", "use_item",
};

static const char *const packet_names_13_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_living", "spawn_entity_painting",
    "named_entity_spawn", "sculk_vibration_signal", "animation", "statistics",
    "acknowledge_player_digging", "block_break_animation", "tile_entity_data", "block_action",
    "block_change", "boss_bar", "difficulty", "chat",
    "clear_titles", "tab_complete", "declare_commands", "close_window",
    "window_items", "craft_progress_bar", "set_slot", "set_cooldown",
    "custom_payload", "named_sound_effect", "kick_disconnect", "entity_status",
    "explosion", "unload_chunk", "game_state_change", "open_horse_window",
    "initialize_world_border", "keep_alive", "map_chunk", "world_event",
    "world_particles", "update_light", "login", "map",
    "trade_list", "rel_entity_move", "entity_move_look", "entity_look",
    "vehicle_move", "open_book", "open_window", "open_sign_entity",
    "ping", "craft_recipe_response", "abilities", "end_combat_event",
    "enter_combat_event", "death_combat_event", "player_info", "face_player",
    "position", "unlock_recipes", "entity_destroy", "remove_entity_effect",
    "resource_pack_send", "respawn", "entity_head_rotation", "multi_block_change",
    "select_advancement_tab", "action_bar", "world_border_center", "world_border_lerp_size",
    "world_border_size", "world_border_warning_delay", "world_border_warning_reach", "camera",
    "held_item_slot", "update_view_position", "update_view_distance", "spawn_position",
    "scoreboard_display_objective", "entity_metadata", "attach_entity", "entity_velocity",
    "entity_equipment", "experience", "update_health", "scoreboard_objective",
    "set_passengers", "teams", "scoreboard_score", "set_title_subtitle",
    "update_time", "set_title_text", "set_title_time", "entity_sound_effect",
    "sound_effect", "stop_sound", "playerlist_header", "nbt_query_response",
    "collect", "entity_teleport", "advancements", "entity_update_attributes",
    "entity_effect", "declare_recipes", "tags",
};

static const char *const packet_names_14_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_14_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_14_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "chat",
    "client_command", "settings", "tab_complete", "enchant_item",
    "window_click", "close_window", "custom_payload", "edit_book",
    "query_entity_nbt", "use_entity", "generate_structure", "keep_alive",
    "lock_difficulty", "position", "position_look", "look",
    "flying", "vehicle_move", "steer_boat", "pick_item",
    "craft_recipe_request", "abilities", "block_dig", "entity_action",
    "steer_vehicle", "pong", "recipe_book", "displayed_recipe",
    "name_item", "resource_pack_receive", "advancement_tab", "select_trade",
    "set_beacon_effect", "held_item_slot", "update_command_block", "update_command_block_minecart",
    "set_creative_slot", "update_jigsaw_block", "update_structure_block", "update_sign",
    "arm_animation", "spectate", "block_place", "use_item",
};

static const char *const packet_names_14_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "spawn_entity_living", "spawn_entity_painting",
    "named_entity_spawn", "sculk_vibration_signal", "animation", "statistics",
    "acknowledge_player_digging", "block_break_animation", "tile_entity_data", "block_action",
    "block_change", "boss_bar", "difficulty", "chat",
    "clear_titles", "tab_complete", "declare_commands", "close_window",
    "window_items", "craft_progress_bar", "set_slot", "set_cooldown",
    "custom_payload", "named_sound_effect", "kick_disconnect", "entity_status",
    "explosion", "unload_chunk", "game_state_change", "open_horse_window",
    "initialize_world_border", "keep_alive", "map_chunk", "world_event",
    "world_particles", "update_light", "login", "map",
    "trade_list", "rel_entity_move", "entity_move_look", "entity_look",
    "vehicle_move", "open_book", "open_window", "open_sign_entity",
    "ping", "craft_recipe_response", "abilities", "end_combat_event",
    "enter_combat_event", "death_combat_event", "player_info", "face_player",
    "position", "unlock_recipes", "entity_destroy", "remove_entity_effect",
    "resource_pack_send", "respawn", "entity_head_rotation", "multi_block_change",
    "select_advancement_tab", "action_bar", "world_border_center", "world_border_lerp_size",
    "world_border_size", "world_border_warning_delay", "world_border_warning_reach", "camera",
    "held_item_slot", "update_view_position", "update_view_distance", "spawn_position",
    "scoreboard_display_objective", "entity_metadata", "attach_entity", "entity_velocity",
    "entity_equipment", "experience", "update_health", "scoreboard_objective",
    "set_passengers", "teams", "scoreboard_score", "simulation_distance",
    "set_title_subtitle", "update_time", "set_title_text", "set_title_time",
    "entity_sound_effect", "sound_effect", "stop_sound", "playerlist_header",
    "nbt_query_response", "collect", "entity_teleport", "advancements",
    "entity_update_attributes", "entity_effect", "declare_recipes", "tags",
};

static const char *const packet_names_15_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_15_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_15_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "chat_command",
    "chat_message", "chat_preview", "client_command", "settings",
    "tab_complete", "enchant_item", "window_click", "close_window",
    "custom_payload", "edit_book", "query_entity_nbt", "use_entity",
    "generate_structure", "keep_alive", "lock_difficulty", "position",
    "position_look", "look", "flying", "vehicle_move",
    "steer_boat", "pick_item", "craft_recipe_request", "abilities",
    "block_dig", "entity_action", "steer_vehicle", "pong",
    "recipe_book", "displayed_recipe", "name_item", "resource_pack_receive",
    "advancement_tab", "select_trade", "set_beacon_effect", "held_item_slot",
    "update_command_block", "update_command_block_minecart", "set_creative_slot", "update_jigsaw_block",
    "update_structure_block", "update_sign", "arm_animation", "spectate",
    "block_place", "use_item",
};

static const char *const packet_names_15_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "named_entity_spawn", "animation",
    "statistics", "acknowledge_player_digging", "block_break_animation", "tile_entity_data",
    "block_action", "block_change", "boss_bar", "difficulty",
    "chat_preview", "clear_titles", "tab_complete", "declare_commands",
    "close_window", "window_items", "craft_progress_bar", "set_slot",
    "set_cooldown", "custom_payload", "named_sound_effect", "kick_disconnect",
    "entity_status", "explosion", "unload_chunk", "game_state_change",
    "open_horse_window", "initialize_world_border", "keep_alive", "map_chunk",
    "world_event", "world_particles", "update_light", "login",
    "map", "trade_list", "rel_entity_move", "entity_move_look",
    "entity_look", "vehicle_move", "open_book", "open_window",
    "open_sign_entity", "ping", "craft_recipe_response", "abilities",
    "player_chat", "end_combat_event", "enter_combat_event", "death_combat_event",
    "player_info", "face_player", "position", "unlock_recipes",
    "entity_destroy", "remove_entity_effect", "resource_pack_send", "respawn",
    "entity_head_rotation", "multi_block_change", "select_advancement_tab", "server_data",
    "action_bar", "world_border_center", "world_border_lerp_size", "world_border_size",
    "world_border_warning_delay", "world_border_warning_reach", "camera", "held_item_slot",
    "update_view_position", "update_view_distance", "spawn_position", "should_display_chat_preview",
    "scoreboard_display_objective", "entity_metadata", "attach_entity", "entity_velocity",
    "entity_equipment", "experience", "update_health", "scoreboard_objective",
    "set_passengers", "teams", "scoreboard_score", "simulation_distance",
    "set_title_subtitle", "update_time", "set_title_text", "set_title_time",
    "entity_sound_effect", "sound_effect", "stop_sound", "system_chat",
    "playerlist_header", "nbt_query_response", "collect", "entity_teleport",
    "advancements", "entity_update_attributes", "entity_effect", "declare_recipes",
    "tags",
};

static const char *const packet_names_16_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_16_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_16_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "message_acknowledgement",
    "chat_command", "chat_message", "chat_preview", "client_command",
    "settings", "tab_complete", "enchant_item", "window_click",
    "close_window", "custom_payload", "edit_book", "query_entity_nbt",
    "use_entity", "generate_structure", "keep_alive", "lock_difficulty",
    "position", "position_look", "look", "flying",
    "vehicle_move", "steer_boat", "pick_item", "craft_recipe_request",
    "abilities", "block_dig", "entity_action", "steer_vehicle",
    "pong", "recipe_book", "displayed_recipe", "name_item",
    "resource_pack_receive", "advancement_tab", "select_trade", "set_beacon_effect",
    "held_item_slot", "update_command_block", "update_command_block_minecart", "set_creative_slot",
    "update_jigsaw_block", "update_structure_block", "update_sign", "arm_animation",
    "spectate", "block_place", "use_item",
};

static const char *const packet_names_16_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "named_entity_spawn", "animation",
    "statistics", "acknowledge_player_digging", "block_break_animation", "tile_entity_data",
    "block_action", "block_change", "boss_bar", "difficulty",
    "chat_preview", "clear_titles", "tab_complete", "declare_commands",
    "close_window", "window_items", "craft_progress_bar", "set_slot",
    "set_cooldown", "chat_suggestions", "custom_payload", "named_sound_effect",
    "hide_message", "kick_disconnect", "entity_status", "explosion",
    "unload_chunk", "game_state_change", "open_horse_window", "initialize_world_border",
    "keep_alive", "map_chunk", "world_event", "world_particles",
    "update_light", "login", "map", "trade_list",
    "rel_entity_move", "entity_move_look", "entity_look", "vehicle_move",
    "open_book", "open_window", "open_sign_entity", "ping",
    "craft_recipe_response", "abilities", "message_header", "player_chat",
    "end_combat_event", "enter_combat_event", "death_combat_event", "player_info",
    "face_player", "position", "unlock_recipes", "entity_destroy",
    "remove_entity_effect", "resource_pack_send", "respawn", "entity_head_rotation",
    "multi_block_change", "select_advancement_tab", "server_data", "action_bar",
    "world_border_center", "world_border_lerp_size", "world_border_size", "world_border_warning_delay",
    "world_border_warning_reach", "camera", "held_item_slot", "update_view_position",
    "update_view_distance", "spawn_position", "should_display_chat_preview", "scoreboard_display_objective",
    "entity_metadata", "attach_entity", "entity_velocity", "entity_equipment",
    "experience", "update_health", "scoreboard_objective", "set_passengers",
    "teams", "scoreboard_score", "simulation_distance", "set_title_subtitle",
    "update_time", "set_title_text", "set_title_time", "entity_sound_effect",
    "sound_effect", "stop_sound", "system_chat", "playerlist_header",
    "nbt_query_response", "collect", "entity_teleport", "advancements",
    "entity_update_attributes", "entity_effect", "declare_recipes", "tags",
};

static const char *const packet_names_17_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_17_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_17_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "message_acknowledgement",
    "chat_command", "chat_message", "client_command", "settings",
    "tab_complete", "enchant_item", "window_click", "close_window",
    "custom_payload", "edit_book", "query_entity_nbt", "use_entity",
    "generate_structure", "keep_alive", "lock_difficulty", "position",
    "position_look", "look", "flying", "vehicle_move",
    "steer_boat", "pick_item", "craft_recipe_request", "abilities",
    "block_dig", "entity_action", "steer_vehicle", "pong",
    "chat_session_update", "recipe_book", "displayed_recipe", "name_item",
    "resource_pack_receive", "advancement_tab", "select_trade", "set_beacon_effect",
    "held_item_slot", "update_command_block", "update_command_block_minecart", "set_creative_slot",
    "update_jigsaw_block", "update_structure_block", "update_sign", "arm_animation",
    "spectate", "block_place", "use_item",
};

static const char *const packet_names_17_play_clientbound[] = {
    "spawn_entity", "spawn_entity_experience_orb", "named_entity_spawn", "animation",
    "statistics", "acknowledge_player_digging", "block_break_animation", "tile_entity_data",
    "block_action", "block_change", "boss_bar", "difficulty",
    "clear_titles", "tab_complete", "declare_commands", "close_window",
    "window_items", "craft_progress_bar", "set_slot", "set_cooldown",
    "chat_suggestions", "custom_payload", "hide_message", "kick_disconnect",
    "profileless_chat", "entity_status", "explosion", "unload_chunk",
    "game_state_change", "open_horse_window", "initialize_world_border", "keep_alive",
    "map_chunk", "world_event", "world_particles", "update_light",
    "login", "map", "trade_list", "rel_entity_move",
    "entity_move_look", "entity_look", "vehicle_move", "open_book",
    "open_window", "open_sign_entity", "ping", "craft_recipe_response",
    "abilities", "player_chat", "end_combat_event", "enter_combat_event",
    "death_combat_event", "player_remove", "player_info", "face_player",
    "position", "unlock_recipes", "entity_destroy", "remove_entity_effect",
    "resource_pack_send", "respawn", "entity_head_rotation", "multi_block_change",
    "select_advancement_tab", "server_data", "action_bar", "world_border_center",
    "world_border_lerp_size", "world_border_size", "world_border_warning_delay", "world_border_warning_reach",
    "camera", "held_item_slot", "update_view_position", "update_view_distance",
    "spawn_position", "scoreboard_display_objective", "entity_metadata", "attach_entity",
    "entity_velocity", "entity_equipment", "experience", "update_health",
    "scoreboard_objective", "set_passengers", "teams", "scoreboard_score",
    "simulation_distance", "set_title_subtitle", "update_time", "set_title_text",
    "set_title_time", "entity_sound_effect", "sound_effect", "stop_sound",
    "system_chat", "playerlist_header", "nbt_query_response", "collect",
    "entity_teleport", "advancements", "entity_update_attributes", "feature_flags",
    "entity_effect", "declare_recipes", "tags",
};

static const char *const packet_names_18_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response",
};

static const char *const packet_names_18_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_18_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "message_acknowledgement",
    "chat_command", "chat_message", "chat_session_update", "client_command",
    "settings", "tab_complete", "enchant_item", "window_click",
    "close_window", "custom_payload", "edit_book", "query_entity_nbt",
    "use_entity", "generate_structure", "keep_alive", "lock_difficulty",
    "position", "position_look", "look", "flying",
    "vehicle_move", "steer_boat", "pick_item", "craft_recipe_request",
    "abilities", "block_dig", "entity_action", "steer_vehicle",
    "pong", "recipe_book", "displayed_recipe", "name_item",
    "resource_pack_receive", "advancement_tab", "select_trade", "set_beacon_effect",
    "held_item_slot", "update_command_block", "update_command_block_minecart", "set_creative_slot",
    "update_jigsaw_block", "update_structure_block", "update_sign", "arm_animation",
    "spectate", "block_place", "use_item",
};

static const char *const packet_names_18_play_clientbound[] = {
    "bundle_delimiter", "spawn_entity", "spawn_entity_experience_orb", "named_entity_spawn",
    "animation", "statistics", "acknowledge_player_digging", "block_break_animation",
    "tile_entity_data", "block_action", "block_change", "boss_bar",
    "difficulty", "chunk_biomes", "clear_titles", "tab_complete",
    "declare_commands", "close_window", "window_items", "craft_progress_bar",
    "set_slot", "set_cooldown", "chat_suggestions", "custom_payload",
    "damage_event", "hide_message", "kick_disconnect", "profileless_chat",
    "entity_status", "explosion", "unload_chunk", "game_state_change",
    "open_horse_window", "hurt_animation", "initialize_world_border", "keep_alive",
    "map_chunk", "world_event", "world_particles", "update_light",
    "login", "map", "trade_list", "rel_entity_move",
    "entity_move_look", "entity_look", "vehicle_move", "open_book",
    "open_window", "open_sign_entity", "ping", "craft_recipe_response",
    "abilities", "player_chat", "end_combat_event", "enter_combat_event",
    "death_combat_event", "player_remove", "player_info", "face_player",
    "position", "unlock_recipes", "entity_destroy", "remove_entity_effect",
    "resource_pack_send", "respawn", "entity_head_rotation", "multi_block_change",
    "select_advancement_tab", "server_data", "action_bar", "world_border_center",
    "world_border_lerp_size", "world_border_size", "world_border_warning_delay", "world_border_warning_reach",
    "camera", "held_item_slot", "update_view_position", "update_view_distance",
    "spawn_position", "scoreboard_display_objective", "entity_metadata", "attach_entity",
    "entity_velocity", "entity_equipment", "experience", "update_health",
    "scoreboard_objective", "set_passengers", "teams", "scoreboard_score",
    "simulation_distance", "set_title_subtitle", "update_time", "set_title_text",
    "set_title_time", "entity_sound_effect", "sound_effect", "stop_sound",
    "system_chat", "playerlist_header", "nbt_query_response", "collect",
    "entity_teleport", "advancements", "entity_update_attributes", "feature_flags",
    "entity_effect", "declare_recipes", "tags",
};

static const char *const packet_names_19_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response", "login_acknowledged",
};

static const char *const packet_names_19_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_19_configuration_serverbound[] = {
    "settings", "custom_payload", "finish_configuration", "keep_alive",
    "pong", "resource_pack_receive",
};

static const char *const packet_names_19_configuration_clientbound[] = {
    "custom_payload", "disconnect", "finish_configuration", "keep_alive",
    "ping", "registry_data", "resource_pack_send", "feature_flags",
    "tags",
};

static const char *const packet_names_19_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "message_acknowledgement",
    "chat_command", "chat_message", "chat_session_update", "chunk_batch_received",
    "client_command", "settings", "tab_complete", "configuration_acknowledged",
    "enchant_item", "window_click", "close_window", "custom_payload",
    "edit_book", "query_entity_nbt", "use_entity", "generate_structure",
    "keep_alive", "lock_difficulty", "position", "position_look",
    "look", "flying", "vehicle_move", "steer_boat",
    "pick_item", "ping_request", "craft_recipe_request", "abilities",
    "block_dig", "entity_action", "steer_vehicle", "pong",
    "recipe_book", "displayed_recipe", "name_item", "resource_pack_receive",
    "advancement_tab", "select_trade", "set_beacon_effect", "held_item_slot",
    "update_command_block", "update_command_block_minecart", "set_creative_slot", "update_jigsaw_block",
    "update_structure_block", "update_sign", "arm_animation", "spectate",
    "block_place", "use_item",
};

static const char *const packet_names_19_play_clientbound[] = {
    "bundle_delimiter", "spawn_entity", "spawn_entity_experience_orb", "animation",
    "statistics", "acknowledge_player_digging", "block_break_animation", "tile_entity_data",
    "block_action", "block_change", "boss_bar", "difficulty",
    "chunk_batch_finished", "chunk_batch_start", "chunk_biomes", "clear_titles",
    "tab_complete", "declare_commands", "close_window", "window_items",
    "craft_progress_bar", "set_slot", "set_cooldown", "chat_suggestions",
    "custom_payload", "damage_event", "hide_message", "kick_disconnect",
    "profileless_chat", "entity_status", "explosion", "unload_chunk",
    "game_state_change", "open_horse_window", "hurt_animation", "initialize_world_border",
    "keep_alive", "map_chunk", "world_event", "world_particles",
    "update_light", "login", "map", "trade_list",
    "rel_entity_move", "entity_move_look", "entity_look", "vehicle_move",
    "open_book", "open_window", "open_sign_entity", "ping",
    "ping_response", "craft_recipe_response", "abilities", "player_chat",
    "end_combat_event", "enter_combat_event", "death_combat_event", "player_remove",
    "player_info", "face_player", "position", "unlock_recipes",
    "entity_destroy", "remove_entity_effect", "resource_pack_send", "respawn",
    "entity_head_rotation", "multi_block_change", "select_advancement_tab", "server_data",
    "action_bar", "world_border_center", "world_border_lerp_size", "world_border_size",
    "world_border_warning_delay", "world_border_warning_reach", "camera", "held_item_slot",
    "update_view_position", "update_view_distance", "spawn_position", "scoreboard_display_objective",
    "entity_metadata", "attach_entity", "entity_velocity", "entity_equipment",
    "experience", "update_health", "scoreboard_objective", "set_passengers",
    "teams", "scoreboard_score", "simulation_distance", "set_title_subtitle",
    "update_time", "set_title_text", "set_title_time", "entity_sound_effect",
    "sound_effect", "start_configuration", "stop_sound", "system_chat",
    "playerlist_header", "nbt_query_response", "collect", "entity_teleport",
    "advancements", "entity_update_attributes", "entity_effect", "declare_recipes",
    "tags",
};

static const char *const packet_names_20_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response", "login_acknowledged",
};

static const char *const packet_names_20_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request",
};

static const char *const packet_names_20_configuration_serverbound[] = {
    "settings", "custom_payload", "finish_configuration", "keep_alive",
    "pong", "resource_pack_receive",
};

static const char *const packet_names_20_configuration_clientbound[] = {
    "custom_payload", "disconnect", "finish_configuration", "keep_alive",
    "ping", "registry_data", "remove_resource_pack", "add_resource_pack",
    "feature_flags", "tags",
};

static const char *const packet_names_20_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "message_acknowledgement",
    "chat_command", "chat_message", "chat_session_update", "chunk_batch_received",
    "client_command", "settings", "tab_complete", "configuration_acknowledged",
    "enchant_item", "window_click", "close_window", "set_slot_state",
    "custom_payload", "edit_book", "query_entity_nbt", "use_entity",
    "generate_structure", "keep_alive", "lock_difficulty", "position",
    "position_look", "look", "flying", "vehicle_move",
    "steer_boat", "pick_item", "ping_request", "craft_recipe_request",
    "abilities", "block_dig", "entity_action", "steer_vehicle",
    "pong", "recipe_book", "displayed_recipe", "name_item",
    "resource_pack_receive", "advancement_tab", "select_trade", "set_beacon_effect",
    "held_item_slot", "update_command_block", "update_command_block_minecart", "set_creative_slot",
    "update_jigsaw_block", "update_structure_block", "update_sign", "arm_animation",
    "spectate", "block_place", "use_item",
};

static const char *const packet_names_20_play_clientbound[] = {
    "bundle_delimiter", "spawn_entity", "spawn_entity_experience_orb", "animation",
    "statistics", "acknowledge_player_digging", "block_break_animation", "tile_entity_data",
    "block_action", "block_change", "boss_bar", "difficulty",
    "chunk_batch_finished", "chunk_batch_start", "chunk_biomes", "clear_titles",
    "tab_complete", "declare_commands", "close_window", "window_items",
    "craft_progress_bar", "set_slot", "set_cooldown", "chat_suggestions",
    "custom_payload", "damage_event", "hide_message", "kick_disconnect",
    "profileless_chat", "entity_status", "explosion", "unload_chunk",
    "game_state_change", "open_horse_window", "hurt_animation", "initialize_world_border",
    "keep_alive", "map_chunk", "world_event", "world_particles",
    "update_light", "login", "map", "trade_list",
    "rel_entity_move", "entity_move_look", "entity_look", "vehicle_move",
    "open_book", "open_window", "open_sign_entity", "ping",
    "ping_response", "craft_recipe_response", "abilities", "player_chat",
    "end_combat_event", "enter_combat_event", "death_combat_event", "player_remove",
    "player_info", "face_player", "position", "unlock_recipes",
    "entity_destroy", "remove_entity_effect", "reset_score", "remove_resource_pack",
    "add_resource_pack", "respawn", "entity_head_rotation", "multi_block_change",
    "select_advancement_tab", "server_data", "action_bar", "world_border_center",
    "world_border_lerp_size", "world_border_size", "world_border_warning_delay", "world_border_warning_reach",
    "camera", "held_item_slot", "update_view_position", "update_view_distance",
    "spawn_position", "scoreboard_display_objective", "entity_metadata", "attach_entity",
    "entity_velocity", "entity_equipment", "experience", "update_health",
    "scoreboard_objective", "set_passengers", "teams", "scoreboard_score",
    "simulation_distance", "set_title_subtitle", "update_time", "set_title_text",
    "set_title_time", "entity_sound_effect", "sound_effect", "start_configuration",
    "stop_sound", "system_chat", "playerlist_header", "nbt_query_response",
    "collect", "entity_teleport", "set_ticking_state", "step_tick",
    "advancements", "entity_update_attributes", "entity_effect", "declare_recipes",
    "tags",
};

static const char *const packet_names_21_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response", "login_acknowledged",
    "cookie_response",
};

static const char *const packet_names_21_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request", "cookie_request",
};

static const char *const packet_names_21_configuration_serverbound[] = {
    "settings", "cookie_response", "custom_payload", "finish_configuration",
    "keep_alive", "pong", "resource_pack_receive", "select_known_packs",
};

static const char *const packet_names_21_configuration_clientbound[] = {
    "cookie_request", "custom_payload", "disconnect", "finish_configuration",
    "keep_alive", "ping", "reset_chat", "registry_data",
    "remove_resource_pack", "add_resource_pack", "store_cookie", "transfer",
    "feature_flags", "tags", "select_known_packs",
};

static const char *const packet_names_21_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "message_acknowledgement",
    "chat_command", "chat_command_signed", "chat_message", "chat_session_update",
    "chunk_batch_received", "client_command", "settings", "tab_complete",
    "configuration_acknowledged", "enchant_item", "window_click", "close_window",
    "set_slot_state", "cookie_response", "custom_payload", "debug_sample_subscription",
    "edit_book", "query_entity_nbt", "use_entity", "generate_structure",
    "keep_alive", "lock_difficulty", "position", "position_look",
    "look", "flying", "vehicle_move", "steer_boat",
    "pick_item", "ping_request", "craft_recipe_request", "abilities",
    "block_dig", "entity_action", "steer_vehicle", "pong",
    "recipe_book", "displayed_recipe", "name_item", "resource_pack_receive",
    "advancement_tab", "select_trade", "set_beacon_effect", "held_item_slot",
    "update_command_block", "update_command_block_minecart", "set_creative_slot", "update_jigsaw_block",
    "update_structure_block", "update_sign", "arm_animation", "spectate",
    "block_place", "use_item",
};

static const char *const packet_names_21_play_clientbound[] = {
    "bundle_delimiter", "spawn_entity", "spawn_entity_experience_orb", "animation",
    "statistics", "acknowledge_player_digging", "block_break_animation", "tile_entity_data",
    "block_action", "block_change", "boss_bar", "difficulty",
    "chunk_batch_finished", "chunk_batch_start", "chunk_biomes", "clear_titles",
    "tab_complete", "declare_commands", "close_window", "window_items",
    "craft_progress_bar", "set_slot", "cookie_request", "set_cooldown",
    "chat_suggestions", "custom_payload", "damage_event", "debug_sample",
    "hide_message", "kick_disconnect", "profileless_chat", "entity_status",
    "explosion", "unload_chunk", "game_state_change", "open_horse_window",
    "hurt_animation", "initialize_world_border", "keep_alive", "map_chunk",
    "world_event", "world_particles", "update_light", "login",
    "map", "trade_list", "rel_entity_move", "entity_move_look",
    "entity_look", "vehicle_move", "open_book", "open_window",
    "open_sign_entity", "ping", "ping_response", "craft_recipe_response",
    "abilities", "player_chat", "end_combat_event", "enter_combat_event",
    "death_combat_event", "player_remove", "player_info", "face_player",
    "position", "unlock_recipes", "entity_destroy", "remove_entity_effect",
    "reset_score", "remove_resource_pack", "add_resource_pack", "respawn",
    "entity_head_rotation", "multi_block_change", "select_advancement_tab", "server_data",
    "action_bar", "world_border_center", "world_border_lerp_size", "world_border_size",
    "world_border_warning_delay", "world_border_warning_reach", "camera", "held_item_slot",
    "update_view_position", "update_view_distance", "spawn_position", "scoreboard_display_objective",
    "entity_metadata", "attach_entity", "entity_velocity", "entity_equipment",
    "experience", "update_health", "scoreboard_objective", "set_passengers",
    "teams", "scoreboard_score", "simulation_distance", "set_title_subtitle",
    "update_time", "set_title_text", "set_title_time", "entity_sound_effect",
    "sound_effect", "start_configuration", "stop_sound", "store_cookie",
    "system_chat", "playerlist_header", "nbt_query_response", "collect",
    "entity_teleport", "set_ticking_state", "step_tick", "transfer",
    "advancements", "entity_update_attributes", "entity_effect", "declare_recipes",
    "tags", "set_projectile_power",
};

static const char *const packet_names_22_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response", "login_acknowledged",
    "cookie_response",
};

static const char *const packet_names_22_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request", "cookie_request",
};

static const char *const packet_names_22_configuration_serverbound[] = {
    "settings", "cookie_response", "custom_payload", "finish_configuration",
    "keep_alive", "pong", "resource_pack_receive", "select_known_packs",
    "custom_report_details", "server_links",
};

static const char *const packet_names_22_configuration_clientbound[] = {
    "cookie_request", "custom_payload", "disconnect", "finish_configuration",
    "keep_alive", "ping", "reset_chat", "registry_data",
    "remove_resource_pack", "add_resource_pack", "store_cookie", "transfer",
    "feature_flags", "tags", "select_known_packs", "custom_report_details",
    "server_links",
};

static const char *const packet_names_22_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "set_difficulty", "message_acknowledgement",
    "chat_command", "chat_command_signed", "chat_message", "chat_session_update",
    "chunk_batch_received", "client_command", "settings", "tab_complete",
    "configuration_acknowledged", "enchant_item", "window_click", "close_window",
    "set_slot_state", "cookie_response", "custom_payload", "debug_sample_subscription",
    "edit_book", "query_entity_nbt", "use_entity", "generate_structure",
    "keep_alive", "lock_difficulty", "position", "position_look",
    "look", "flying", "vehicle_move", "steer_boat",
    "pick_item", "ping_request", "craft_recipe_request", "abilities",
    "block_dig", "entity_action", "steer_vehicle", "pong",
    "recipe_book", "displayed_recipe", "name_item", "resource_pack_receive",
    "advancement_tab", "select_trade", "set_beacon_effect", "held_item_slot",
    "update_command_block", "update_command_block_minecart", "set_creative_slot", "update_jigsaw_block",
    "update_structure_block", "update_sign", "arm_animation", "spectate",
    "block_place", "use_item",
};

static const char *const packet_names_22_play_clientbound[] = {
    "bundle_delimiter", "spawn_entity", "spawn_entity_experience_orb", "animation",
    "statistics", "acknowledge_player_digging", "block_break_animation", "tile_entity_data",
    "block_action", "block_change", "boss_bar", "difficulty",
    "chunk_batch_finished", "chunk_batch_start", "chunk_biomes", "clear_titles",
    "tab_complete", "declare_commands", "close_window", "window_items",
    "craft_progress_bar", "set_slot", "cookie_request", "set_cooldown",
    "chat_suggestions", "custom_payload", "damage_event", "debug_sample",
    "hide_message", "kick_disconnect", "profileless_chat", "entity_status",
    "explosion", "unload_chunk", "game_state_change", "open_horse_window",
    "hurt_animation", "initialize_world_border", "keep_alive", "map_chunk",
    "world_event", "world_particles", "update_light", "login",
    "map", "trade_list", "rel_entity_move", "entity_move_look",
    "entity_look", "vehicle_move", "open_book", "open_window",
    "open_sign_entity", "ping", "ping_response", "craft_recipe_response",
    "abilities", "player_chat", "end_combat_event", "enter_combat_event",
    "death_combat_event", "player_remove", "player_info", "face_player",
    "position", "unlock_recipes", "entity_destroy", "remove_entity_effect",
    "reset_score", "remove_resource_pack", "add_resource_pack", "respawn",
    "entity_head_rotation", "multi_block_change", "select_advancement_tab", "server_data",
    "action_bar", "world_border_center", "world_border_lerp_size", "world_border_size",
    "world_border_warning_delay", "world_border_warning_reach", "camera", "held_item_slot",
    "update_view_position", "update_view_distance", "spawn_position", "scoreboard_display_objective",
    "entity_metadata", "attach_entity", "entity_velocity", "entity_equipment",
    "experience", "update_health", "scoreboard_objective", "set_passengers",
    "teams", "scoreboard_score", "simulation_distance", "set_title_subtitle",
    "update_time", "set_title_text", "set_title_time", "entity_sound_effect",
    "sound_effect", "start_configuration", "stop_sound", "store_cookie",
    "system_chat", "playerlist_header", "nbt_query_response", "collect",
    "entity_teleport", "set_ticking_state", "step_tick", "transfer",
    "advancements", "entity_update_attributes", "entity_effect", "declare_recipes",
    "tags", "set_projectile_power", "custom_report_details", "server_links",
};

static const char *const packet_names_23_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response", "login_acknowledged",
    "cookie_response",
};

static const char *const packet_names_23_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request", "cookie_request",
};

static const char *const packet_names_23_configuration_serverbound[] = {
    "settings", "cookie_response", "custom_payload", "finish_configuration",
    "keep_alive", "pong", "resource_pack_receive", "select_known_packs",
    "custom_report_details", "server_links",
};

static const char *const packet_names_23_configuration_clientbound[] = {
    "cookie_request", "custom_payload", "disconnect", "finish_configuration",
    "keep_alive", "ping", "reset_chat", "registry_data",
    "remove_resource_pack", "add_resource_pack", "store_cookie", "transfer",
    "feature_flags", "tags", "select_known_packs", "custom_report_details",
    "server_links",
};

static const char *const packet_names_23_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "select_bundle_item", "set_difficulty",
    "message_acknowledgement", "chat_command", "chat_command_signed", "chat_message",
    "chat_session_update", "chunk_batch_received", "client_command", "tick_end",
    "settings", "tab_complete", "configuration_acknowledged", "enchant_item",
    "window_click", "close_window", "set_slot_state", "cookie_response",
    "custom_payload", "debug_sample_subscription", "edit_book", "query_entity_nbt",
    "use_entity", "generate_structure", "keep_alive", "lock_difficulty",
    "position", "position_look", "look", "flying",
    "vehicle_move", "steer_boat", "pick_item", "ping_request",
    "craft_recipe_request", "abilities", "block_dig", "entity_action",
    "player_input", "pong", "recipe_book", "displayed_recipe",
    "name_item", "resource_pack_receive", "advancement_tab", "select_trade",
    "set_beacon_effect", "held_item_slot", "update_command_block", "update_command_block_minecart",
    "set_creative_slot", "update_jigsaw_block", "update_structure_block", "update_sign",
    "arm_animation", "spectate", "block_place", "use_item",
};

static const char *const packet_names_23_play_clientbound[] = {
    "bundle_delimiter", "spawn_entity", "spawn_entity_experience_orb", "animation",
    "statistics", "acknowledge_player_digging", "block_break_animation", "tile_entity_data",
    "block_action", "block_change", "boss_bar", "difficulty",
    "chunk_batch_finished", "chunk_batch_start", "chunk_biomes", "clear_titles",
    "tab_complete", "declare_commands", "close_window", "window_items",
    "craft_progress_bar", "set_slot", "cookie_request", "set_cooldown",
    "chat_suggestions", "custom_payload", "damage_event", "debug_sample",
    "hide_message", "kick_disconnect", "profileless_chat", "entity_status",
    "sync_entity_position", "explosion", "unload_chunk", "game_state_change",
    "open_horse_window", "hurt_animation", "initialize_world_border", "keep_alive",
    "map_chunk", "world_event", "world_particles", "update_light",
    "login", "map", "trade_list", "rel_entity_move",
    "entity_move_look", "move_minecart", "entity_look", "vehicle_move",
    "open_book", "open_window", "open_sign_entity", "ping",
    "ping_response", "craft_recipe_response", "abilities", "player_chat",
    "end_combat_event", "enter_combat_event", "death_combat_event", "player_remove",
    "player_info", "face_player", "position", "player_rotation",
    "recipe_book_add", "recipe_book_remove", "recipe_book_settings", "entity_destroy",
    "remove_entity_effect", "reset_score", "remove_resource_pack", "add_resource_pack",
    "respawn", "entity_head_rotation", "multi_block_change", "select_advancement_tab",
    "server_data", "action_bar", "world_border_center", "world_border_lerp_size",
    "world_border_size", "world_border_warning_delay", "world_border_warning_reach", "camera",
    "update_view_position", "update_view_distance", "set_cursor_item", "spawn_position",
    "scoreboard_display_objective", "entity_metadata", "attach_entity", "entity_velocity",
    "entity_equipment", "experience", "update_health", "held_item_slot",
    "scoreboard_objective", "set_passengers", "set_player_inventory", "teams",
    "scoreboard_score", "simulation_distance", "set_title_subtitle", "update_time",
    "set_title_text", "set_title_time", "entity_sound_effect", "sound_effect",
    "start_configuration", "stop_sound", "store_cookie", "system_chat",
    "playerlist_header", "nbt_query_response", "collect", "entity_teleport",
    "set_ticking_state", "step_tick", "transfer", "advancements",
    "entity_update_attributes", "entity_effect", "declare_recipes", "tags",
    "set_projectile_power", "custom_report_details", "server_links",
};

static const char *const packet_names_24_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response", "login_acknowledged",
    "cookie_response",
};

static const char *const packet_names_24_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request", "cookie_request",
};

static const char *const packet_names_24_configuration_serverbound[] = {
    "settings", "cookie_response", "custom_payload", "finish_configuration",
    "keep_alive", "pong", "resource_pack_receive", "select_known_packs",
    "custom_report_details", "server_links",
};

static const char *const packet_names_24_configuration_clientbound[] = {
    "cookie_request", "custom_payload", "disconnect", "finish_configuration",
    "keep_alive", "ping", "reset_chat", "registry_data",
    "remove_resource_pack", "add_resource_pack", "store_cookie", "transfer",
    "feature_flags", "tags", "select_known_packs", "custom_report_details",
    "server_links",
};

static const char *const packet_names_24_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "select_bundle_item", "set_difficulty",
    "message_acknowledgement", "chat_command", "chat_command_signed", "chat_message",
    "chat_session_update", "chunk_batch_received", "client_command", "tick_end",
    "settings", "tab_complete", "configuration_acknowledged", "enchant_item",
    "window_click", "close_window", "set_slot_state", "cookie_response",
    "custom_payload", "debug_sample_subscription", "edit_book", "query_entity_nbt",
    "use_entity", "generate_structure", "keep_alive", "lock_difficulty",
    "position", "position_look", "look", "flying",
    "vehicle_move", "steer_boat", "pick_item_from_block", "pick_item_from_entity",
    "ping_request", "craft_recipe_request", "abilities", "block_dig",
    "entity_action", "player_input", "player_loaded", "pong",
    "recipe_book", "displayed_recipe", "name_item", "resource_pack_receive",
    "advancement_tab", "select_trade", "set_beacon_effect", "held_item_slot",
    "update_command_block", "update_command_block_minecart", "set_creative_slot", "update_jigsaw_block",
    "update_structure_block", "update_sign", "arm_animation", "spectate",
    "block_place", "use_item",
};

static const char *const packet_names_24_play_clientbound[] = {
    "bundle_delimiter", "spawn_entity", "spawn_entity_experience_orb", "animation",
    "statistics", "acknowledge_player_digging", "block_break_animation", "tile_entity_data",
    "block_action", "block_change", "boss_bar", "difficulty",
    "chunk_batch_finished", "chunk_batch_start", "chunk_biomes", "clear_titles",
    "tab_complete", "declare_commands", "close_window", "window_items",
    "craft_progress_bar", "set_slot", "cookie_request", "set_cooldown",
    "chat_suggestions", "custom_payload", "damage_event", "debug_sample",
    "hide_message", "kick_disconnect", "profileless_chat", "entity_status",
    "sync_entity_position", "explosion", "unload_chunk", "game_state_change",
    "open_horse_window", "hurt_animation", "initialize_world_border", "keep_alive",
    "map_chunk", "world_event", "world_particles", "update_light",
    "login", "map", "trade_list", "rel_entity_move",
    "entity_move_look", "move_minecart", "entity_look", "vehicle_move",
    "open_book", "open_window", "open_sign_entity", "ping",
    "ping_response", "craft_recipe_response", "abilities", "player_chat",
    "end_combat_event", "enter_combat_event", "death_combat_event", "player_remove",
    "player_info", "face_player", "position", "player_rotation",
    "recipe_book_add", "recipe_book_remove", "recipe_book_settings", "entity_destroy",
    "remove_entity_effect", "reset_score", "remove_resource_pack", "add_resource_pack",
    "respawn", "entity_head_rotation", "multi_block_change", "select_advancement_tab",
    "server_data", "action_bar", "world_border_center", "world_border_lerp_size",
    "world_border_size", "world_border_warning_delay", "world_border_warning_reach", "camera",
    "update_view_position", "update_view_distance", "set_cursor_item", "spawn_position",
    "scoreboard_display_objective", "entity_metadata", "attach_entity", "entity_velocity",
    "entity_equipment", "experience", "update_health", "held_item_slot",
    "scoreboard_objective", "set_passengers", "set_player_inventory", "teams",
    "scoreboard_score", "simulation_distance", "set_title_subtitle", "update_time",
    "set_title_text", "set_title_time", "entity_sound_effect", "sound_effect",
    "start_configuration", "stop_sound", "store_cookie", "system_chat",
    "playerlist_header", "nbt_query_response", "collect", "entity_teleport",
    "set_ticking_state", "step_tick", "transfer", "advancements",
    "entity_update_attributes", "entity_effect", "declare_recipes", "tags",
    "set_projectile_power", "custom_report_details", "server_links",
};

static const char *const packet_names_25_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response", "login_acknowledged",
    "cookie_response",
};

static const char *const packet_names_25_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request", "cookie_request",
};

static const char *const packet_names_25_configuration_serverbound[] = {
    "settings", "cookie_response", "custom_payload", "finish_configuration",
    "keep_alive", "pong", "resource_pack_receive", "select_known_packs",
    "custom_report_details", "server_links",
};

static const char *const packet_names_25_configuration_clientbound[] = {
    "cookie_request", "custom_payload", "disconnect", "finish_configuration",
    "keep_alive", "ping", "reset_chat", "registry_data",
    "remove_resource_pack", "add_resource_pack", "store_cookie", "transfer",
    "feature_flags", "tags", "select_known_packs", "custom_report_details",
    "server_links",
};

static const char *const packet_names_25_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "select_bundle_item", "set_difficulty",
    "message_acknowledgement", "chat_command", "chat_command_signed", "chat_message",
    "chat_session_update", "chunk_batch_received", "client_command", "tick_end",
    "settings", "tab_complete", "configuration_acknowledged", "enchant_item",
    "window_click", "close_window", "set_slot_state", "cookie_response",
    "custom_payload", "debug_sample_subscription", "edit_book", "query_entity_nbt",
    "use_entity", "generate_structure", "keep_alive", "lock_difficulty",
    "position", "position_look", "look", "flying",
    "vehicle_move", "steer_boat", "pick_item_from_block", "pick_item_from_entity",
    "ping_request", "craft_recipe_request", "abilities", "block_dig",
    "entity_action", "player_input", "player_loaded", "pong",
    "recipe_book", "displayed_recipe", "name_item", "resource_pack_receive",
    "advancement_tab", "select_trade", "set_beacon_effect", "held_item_slot",
    "update_command_block", "update_command_block_minecart", "set_creative_slot", "update_jigsaw_block",
    "update_structure_block", "set_test_block", "update_sign", "arm_animation",
    "test_instance_block_action", "spectate", "block_place", "use_item",
};

static const char *const packet_names_25_play_clientbound[] = {
    "bundle_delimiter", "spawn_entity", "animation", "statistics",
    "acknowledge_player_digging", "block_break_animation", "tile_entity_data", "block_action",
    "block_change", "boss_bar", "difficulty", "chunk_batch_finished",
    "chunk_batch_start", "chunk_biomes", "clear_titles", "tab_complete",
    "declare_commands", "close_window", "window_items", "craft_progress_bar",
    "set_slot", "cookie_request", "set_cooldown", "chat_suggestions",
    "custom_payload", "damage_event", "debug_sample", "hide_message",
    "kick_disconnect", "profileless_chat", "entity_status", "sync_entity_position",
    "explosion", "unload_chunk", "game_state_change", "open_horse_window",
    "hurt_animation", "initialize_world_border", "keep_alive", "map_chunk",
    "world_event", "world_particles", "update_light", "login",
    "map", "trade_list", "rel_entity_move", "entity_move_look",
    "move_minecart", "entity_look", "vehicle_move", "open_book",
    "open_window", "open_sign_entity", "ping", "ping_response",
    "craft_recipe_response", "abilities", "player_chat", "end_combat_event",
    "enter_combat_event", "death_combat_event", "player_remove", "player_info",
    "face_player", "position", "player_rotation", "recipe_book_add",
    "recipe_book_remove", "recipe_book_settings", "entity_destroy", "remove_entity_effect",
    "reset_score", "remove_resource_pack", "add_resource_pack", "respawn",
    "entity_head_rotation", "multi_block_change", "select_advancement_tab", "server_data",
    "action_bar", "world_border_center", "world_border_lerp_size", "world_border_size",
    "world_border_warning_delay", "world_border_warning_reach", "camera", "update_view_position",
    "update_view_distance", "set_cursor_item", "spawn_position", "scoreboard_display_objective",
    "entity_metadata", "attach_entity", "entity_velocity", "entity_equipment",
    "experience", "update_health", "held_item_slot", "scoreboard_objective",
    "set_passengers", "set_player_inventory", "teams", "scoreboard_score",
    "simulation_distance", "set_title_subtitle", "update_time", "set_title_text",
    "set_title_time", "entity_sound_effect", "sound_effect", "start_configuration",
    "stop_sound", "store_cookie", "system_chat", "playerlist_header",
    "nbt_query_response", "collect", "entity_teleport", "test_instance_block_status",
    "set_ticking_state", "step_tick", "transfer", "advancements",
    "entity_update_attributes", "entity_effect", "declare_recipes", "tags",
    "set_projectile_power", "custom_report_details", "server_links",
};

static const char *const packet_names_26_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response", "login_acknowledged",
    "cookie_response",
};

static const char *const packet_names_26_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request", "cookie_request",
};

static const char *const packet_names_26_configuration_serverbound[] = {
    "settings", "cookie_response", "custom_payload", "finish_configuration",
    "keep_alive", "pong", "resource_pack_receive", "select_known_packs",
    "custom_click_action",
};

static const char *const packet_names_26_configuration_clientbound[] = {
    "cookie_request", "custom_payload", "disconnect", "finish_configuration",
    "keep_alive", "ping", "reset_chat", "registry_data",
    "remove_resource_pack", "add_resource_pack", "store_cookie", "transfer",
    "feature_flags", "tags", "select_known_packs", "custom_report_details",
    "server_links", "clear_dialog", "show_dialog",
};

static const char *const packet_names_26_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "select_bundle_item", "set_difficulty",
    "change_gamemode", "message_acknowledgement", "chat_command", "chat_command_signed",
    "chat_message", "chat_session_update", "chunk_batch_received", "client_command",
    "tick_end", "settings", "tab_complete", "configuration_acknowledged",
    "enchant_item", "window_click", "close_window", "set_slot_state",
    "cookie_response", "custom_payload", "debug_sample_subscription", "edit_book",
    "query_entity_nbt", "use_entity", "generate_structure", "keep_alive",
    "lock_difficulty", "position", "position_look", "look",
    "flying", "vehicle_move", "steer_boat", "pick_item_from_block",
    "pick_item_from_entity", "ping_request", "craft_recipe_request", "abilities",
    "block_dig", "entity_action", "player_input", "player_loaded",
    "pong", "recipe_book", "displayed_recipe", "name_item",
    "resource_pack_receive", "advancement_tab", "select_trade", "set_beacon_effect",
    "held_item_slot", "update_command_block", "update_command_block_minecart", "set_creative_slot",
    "update_jigsaw_block", "update_structure_block", "set_test_block", "update_sign",
    "arm_animation", "spectate", "test_instance_block_action", "block_place",
    "use_item", "custom_click_action",
};

static const char *const packet_names_26_play_clientbound[] = {
    "bundle_delimiter", "spawn_entity", "animation", "statistics",
    "acknowledge_player_digging", "block_break_animation", "tile_entity_data", "block_action",
    "block_change", "boss_bar", "difficulty", "chunk_batch_finished",
    "chunk_batch_start", "chunk_biomes", "clear_titles", "tab_complete",
    "declare_commands", "close_window", "window_items", "craft_progress_bar",
    "set_slot", "cookie_request", "set_cooldown", "chat_suggestions",
    "custom_payload", "damage_event", "debug_sample", "hide_message",
    "kick_disconnect", "profileless_chat", "entity_status", "sync_entity_position",
    "explosion", "unload_chunk", "game_state_change", "open_horse_window",
    "hurt_animation", "initialize_world_border", "keep_alive", "map_chunk",
    "world_event", "world_particles", "update_light", "login",
    "map", "trade_list", "rel_entity_move", "entity_move_look",
    "move_minecart", "entity_look", "vehicle_move", "open_book",
    "open_window", "open_sign_entity", "ping", "ping_response",
    "craft_recipe_response", "abilities", "player_chat", "end_combat_event",
    "enter_combat_event", "death_combat_event", "player_remove", "player_info",
    "face_player", "position", "player_rotation", "recipe_book_add",
    "recipe_book_remove", "recipe_book_settings", "entity_destroy", "remove_entity_effect",
    "reset_score", "remove_resource_pack", "add_resource_pack", "respawn",
    "entity_head_rotation", "multi_block_change", "select_advancement_tab", "server_data",
    "action_bar", "world_border_center", "world_border_lerp_size", "world_border_size",
    "world_border_warning_delay", "world_border_warning_reach", "camera", "update_view_position",
    "update_view_distance", "set_cursor_item", "spawn_position", "scoreboard_display_objective",
    "entity_metadata", "attach_entity", "entity_velocity", "entity_equipment",
    "experience", "update_health", "held_item_slot", "scoreboard_objective",
    "set_passengers", "set_player_inventory", "teams", "scoreboard_score",
    "simulation_distance", "set_title_subtitle", "update_time", "set_title_text",
    "set_title_time", "entity_sound_effect", "sound_effect", "start_configuration",
    "stop_sound", "store_cookie", "system_chat", "playerlist_header",
    "nbt_query_response", "collect", "entity_teleport", "test_instance_block_status",
    "set_ticking_state", "step_tick", "transfer", "advancements",
    "entity_update_attributes", "entity_effect", "declare_recipes", "tags",
    "set_projectile_power", "custom_report_details", "server_links", "tracked_waypoint",
    "clear_dialog", "show_dialog",
};

static const char *const packet_names_27_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response", "login_acknowledged",
    "cookie_response",
};

static const char *const packet_names_27_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request", "cookie_request",
};

static const char *const packet_names_27_configuration_serverbound[] = {
    "settings", "cookie_response", "custom_payload", "finish_configuration",
    "keep_alive", "pong", "resource_pack_receive", "select_known_packs",
    "custom_click_action", "accept_code_of_conduct",
};

static const char *const packet_names_27_configuration_clientbound[] = {
    "cookie_request", "custom_payload", "disconnect", "finish_configuration",
    "keep_alive", "ping", "reset_chat", "registry_data",
    "remove_resource_pack", "add_resource_pack", "store_cookie", "transfer",
    "feature_flags", "tags", "select_known_packs", "custom_report_details",
    "server_links", "clear_dialog", "show_dialog", "code_of_conduct",
};

static const char *const packet_names_27_play_serverbound[] = {
    "teleport_confirm", "query_block_nbt", "select_bundle_item", "set_difficulty",
    "change_gamemode", "message_acknowledgement", "chat_command", "chat_command_signed",
    "chat_message", "chat_session_update", "chunk_batch_received", "client_command",
    "tick_end", "settings", "tab_complete", "configuration_acknowledged",
    "enchant_item", "window_click", "close_window", "set_slot_state",
    "cookie_response", "custom_payload", "debug_subscription_request", "edit_book",
    "query_entity_nbt", "use_entity", "generate_structure", "keep_alive",
    "lock_difficulty", "position", "position_look", "look",
    "flying", "vehicle_move", "steer_boat", "pick_item_from_block",
    "pick_item_from_entity", "ping_request", "craft_recipe_request", "abilities",
    "block_dig", "entity_action", "player_input", "player_loaded",
    "pong", "recipe_book", "displayed_recipe", "name_item",
    "resource_pack_receive", "advancement_tab", "select_trade", "set_beacon_effect",
    "held_item_slot", "update_command_block", "update_command_block_minecart", "set_creative_slot",
    "update_jigsaw_block", "update_structure_block", "set_test_block", "update_sign",
    "arm_animation", "spectate", "test_instance_block_action", "block_place",
    "use_item", "custom_click_action",
};

static const char *const packet_names_27_play_clientbound[] = {
    "bundle_delimiter", "spawn_entity", "animation", "statistics",
    "acknowledge_player_digging", "block_break_animation", "tile_entity_data", "block_action",
    "block_change", "boss_bar", "difficulty", "chunk_batch_finished",
    "chunk_batch_start", "chunk_biomes", "clear_titles", "tab_complete",
    "declare_commands", "close_window", "window_items", "craft_progress_bar",
    "set_slot", "cookie_request", "set_cooldown", "chat_suggestions",
    "custom_payload", "damage_event", "debug_block_value", "debug_chunk_value",
    "debug_entity_value", "debug_event", "debug_sample", "hide_message",
    "kick_disconnect", "profileless_chat", "entity_status", "sync_entity_position",
    "explosion", "unload_chunk", "game_state_change", "game_test_highlight_pos",
    "open_horse_window", "hurt_animation", "initialize_world_border", "keep_alive",
    "map_chunk", "world_event", "world_particles", "update_light",
    "login", "map", "trade_list", "rel_entity_move",
    "entity_move_look", "move_minecart", "entity_look", "vehicle_move",
    "open_book", "open_window", "open_sign_entity", "ping",
    "ping_response", "craft_recipe_response", "abilities", "player_chat",
    "end_combat_event", "enter_combat_event", "death_combat_event", "player_remove",
    "player_info", "face_player", "position", "player_rotation",
    "recipe_book_add", "recipe_book_remove", "recipe_book_settings", "entity_destroy",
    "remove_entity_effect", "reset_score", "remove_resource_pack", "add_resource_pack",
    "respawn", "entity_head_rotation", "multi_block_change", "select_advancement_tab",
    "server_data", "action_bar", "world_border_center", "world_border_lerp_size",
    "world_border_size", "world_border_warning_delay", "world_border_warning_reach", "camera",
    "update_view_position", "update_view_distance", "set_cursor_item", "spawn_position",
    "scoreboard_display_objective", "entity_metadata", "attach_entity", "entity_velocity",
    "entity_equipment", "experience", "update_health", "held_item_slot",
    "scoreboard_objective", "set_passengers", "set_player_inventory", "teams",
    "scoreboard_score", "simulation_distance", "set_title_subtitle", "update_time",
    "set_title_text", "set_title_time", "entity_sound_effect", "sound_effect",
    "start_configuration", "stop_sound", "store_cookie", "system_chat",
    "playerlist_header", "nbt_query_response", "collect", "entity_teleport",
    "test_instance_block_status", "set_ticking_state", "step_tick", "transfer",
    "advancements", "entity_update_attributes", "entity_effect", "declare_recipes",
    "tags", "set_projectile_power", "custom_report_details", "server_links",
    "tracked_waypoint", "clear_dialog", "show_dialog",
};

static const char *const packet_names_28_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response", "login_acknowledged",
    "cookie_response",
};

static const char *const packet_names_28_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request", "cookie_request",
};

static const char *const packet_names_28_configuration_serverbound[] = {
    "settings", "cookie_response", "custom_payload", "finish_configuration",
    "keep_alive", "pong", "resource_pack_receive", "select_known_packs",
    "custom_click_action", "accept_code_of_conduct",
};

static const char *const packet_names_28_configuration_clientbound[] = {
    "cookie_request", "custom_payload", "disconnect", "finish_configuration",
    "keep_alive", "ping", "reset_chat", "registry_data",
    "remove_resource_pack", "add_resource_pack", "store_cookie", "transfer",
    "feature_flags", "tags", "select_known_packs", "custom_report_details",
    "server_links", "clear_dialog", "show_dialog", "code_of_conduct",
};

static const char *const packet_names_28_play_serverbound[] = {
    "teleport_confirm", "attack", "query_block_nbt", "select_bundle_item",
    "set_difficulty", "change_gamemode", "message_acknowledgement", "chat_command",
    "chat_command_signed", "chat_message", "chat_session_update", "chunk_batch_received",
    "client_command", "tick_end", "settings", "tab_complete",
    "configuration_acknowledged", "enchant_item", "window_click", "close_window",
    "set_slot_state", "cookie_response", "custom_payload", "debug_subscription_request",
    "edit_book", "query_entity_nbt", "use_entity", "generate_structure",
    "keep_alive", "lock_difficulty", "position", "position_look",
    "look", "flying", "vehicle_move", "steer_boat",
    "pick_item_from_block", "pick_item_from_entity", "ping_request", "craft_recipe_request",
    "abilities", "block_dig", "entity_action", "player_input",
    "player_loaded", "pong", "recipe_book", "displayed_recipe",
    "name_item", "resource_pack_receive", "advancement_tab", "select_trade",
    "set_beacon_effect", "held_item_slot", "update_command_block", "update_command_block_minecart",
    "set_creative_slot", "set_game_rule", "update_jigsaw_block", "update_structure_block",
    "set_test_block", "update_sign", "spectate_entity", "arm_animation",
    "spectate", "test_instance_block_action", "block_place", "use_item",
    "custom_click_action",
};

static const char *const packet_names_28_play_clientbound[] = {
    "bundle_delimiter", "spawn_entity", "animation", "statistics",
    "acknowledge_player_digging", "block_break_animation", "tile_entity_data", "block_action",
    "block_change", "boss_bar", "difficulty", "chunk_batch_finished",
    "chunk_batch_start", "chunk_biomes", "clear_titles", "tab_complete",
    "declare_commands", "close_window", "window_items", "craft_progress_bar",
    "set_slot", "cookie_request", "set_cooldown", "chat_suggestions",
    "custom_payload", "damage_event", "debug_block_value", "debug_chunk_value",
    "debug_entity_value", "debug_event", "debug_sample", "hide_message",
    "kick_disconnect", "profileless_chat", "entity_status", "sync_entity_position",
    "explosion", "unload_chunk", "game_state_change", "game_rule_values",
    "game_test_highlight_pos", "open_horse_window", "hurt_animation", "initialize_world_border",
    "keep_alive", "map_chunk", "world_event", "world_particles",
    "update_light", "login", "low_disk_space_warning", "map",
    "trade_list", "rel_entity_move", "entity_move_look", "move_minecart",
    "entity_look", "vehicle_move", "open_book", "open_window",
    "open_sign_entity", "ping", "ping_response", "craft_recipe_response",
    "abilities", "player_chat", "end_combat_event", "enter_combat_event",
    "death_combat_event", "player_remove", "player_info", "face_player",
    "position", "player_rotation", "recipe_book_add", "recipe_book_remove",
    "recipe_book_settings", "entity_destroy", "remove_entity_effect", "reset_score",
    "remove_resource_pack", "add_resource_pack", "respawn", "entity_head_rotation",
    "multi_block_change", "select_advancement_tab", "server_data", "action_bar",
    "world_border_center", "world_border_lerp_size", "world_border_size", "world_border_warning_delay",
    "world_border_warning_reach", "camera", "update_view_position", "update_view_distance",
    "set_cursor_item", "spawn_position", "scoreboard_display_objective", "entity_metadata",
    "attach_entity", "entity_velocity", "entity_equipment", "experience",
    "update_health", "held_item_slot", "scoreboard_objective", "set_passengers",
    "set_player_inventory", "teams", "scoreboard_score", "simulation_distance",
    "set_title_subtitle", "update_time", "set_title_text", "set_title_time",
    "entity_sound_effect", "sound_effect", "start_configuration", "stop_sound",
    "store_cookie", "system_chat", "playerlist_header", "nbt_query_response",
    "collect", "entity_teleport", "test_instance_block_status", "set_ticking_state",
    "step_tick", "transfer", "advancements", "entity_update_attributes",
    "entity_effect", "declare_recipes", "tags", "set_projectile_power",
    "custom_report_details", "server_links", "tracked_waypoint", "clear_dialog",
    "show_dialog",
};

static const char *const packet_names_29_login_serverbound[] = {
    "login_start", "encryption_begin", "login_plugin_response", "login_acknowledged",
    "cookie_response",
};

static const char *const packet_names_29_login_clientbound[] = {
    "disconnect", "encryption_begin", "success", "compress",
    "login_plugin_request", "cookie_request",
};

static const char *const packet_names_29_configuration_serverbound[] = {
    "settings", "cookie_response", "custom_payload", "finish_configuration",
    "keep_alive", "pong", "resource_pack_receive", "select_known_packs",
    "custom_click_action", "accept_code_of_conduct",
};

static const char *const packet_names_29_configuration_clientbound[] = {
    "cookie_request", "custom_payload", "disconnect", "finish_configuration",
    "keep_alive", "ping", "reset_chat", "registry_data",
    "remove_resource_pack", "add_resource_pack", "store_cookie", "transfer",
    "feature_flags", "tags", "select_known_packs", "custom_report_details",
    "server_links", "clear_dialog", "show_dialog", "code_of_conduct",
};

static const char *const packet_names_29_play_serverbound[] = {
    "teleport_confirm", "attack", "query_block_nbt", "select_bundle_item",
    "set_difficulty", "change_gamemode", "message_acknowledgement", "chat_command",
    "chat_command_signed", "chat_message", "chat_session_update", "chunk_batch_received",
    "client_command", "tick_end", "settings", "tab_complete",
    "configuration_acknowledged", "enchant_item", "window_click", "close_window",
    "set_slot_state", "cookie_response", "custom_payload", "debug_subscription_request",
    "edit_book", "query_entity_nbt", "use_entity", "generate_structure",
    "keep_alive", "lock_difficulty", "position", "position_look",
    "look", "flying", "vehicle_move", "steer_boat",
    "pick_item_from_block", "pick_item_from_entity", "ping_request", "craft_recipe_request",
    "abilities", "block_dig", "entity_action", "player_input",
    "player_loaded", "pong", "recipe_book", "displayed_recipe",
    "name_item", "resource_pack_receive", "advancement_tab", "select_trade",
    "set_beacon_effect", "held_item_slot", "update_command_block", "update_command_block_minecart",
    "set_creative_slot", "set_game_rule", "update_jigsaw_block", "update_structure_block",
    "set_test_block", "update_sign", "spectator_action", "arm_animation",
    "spectate", "test_instance_block_action", "block_place", "use_item",
    "custom_click_action",
};

static const char *const packet_names_29_play_clientbound[] = {
    "bundle_delimiter", "spawn_entity", "animation", "statistics",
    "acknowledge_player_digging", "block_break_animation", "tile_entity_data", "block_action",
    "block_change", "boss_bar", "difficulty", "chunk_batch_finished",
    "chunk_batch_start", "chunk_biomes", "clear_titles", "tab_complete",
    "declare_commands", "close_window", "window_items", "craft_progress_bar",
    "set_slot", "cookie_request", "set_cooldown", "chat_suggestions",
    "custom_payload", "damage_event", "debug_block_value", "debug_chunk_value",
    "debug_entity_value", "debug_event", "debug_sample", "hide_message",
    "kick_disconnect", "profileless_chat", "entity_status", "sync_entity_position",
    "explosion", "unload_chunk", "game_state_change", "game_rule_values",
    "game_test_highlight_pos", "open_horse_window", "hurt_animation", "initialize_world_border",
    "keep_alive", "map_chunk", "world_event", "world_particles",
    "update_light", "login", "low_disk_space_warning", "map",
    "trade_list", "rel_entity_move", "entity_move_look", "move_minecart",
    "entity_look", "vehicle_move", "open_book", "open_window",
    "open_sign_entity", "ping", "ping_response", "craft_recipe_response",
    "abilities", "player_chat", "end_combat_event", "enter_combat_event",
    "death_combat_event", "player_remove", "player_info", "face_player",
    "position", "player_rotation", "recipe_book_add", "recipe_book_remove",
    "recipe_book_settings", "entity_destroy", "remove_entity_effect", "reset_score",
    "remove_resource_pack", "add_resource_pack", "respawn", "entity_head_rotation",
    "multi_block_change", "select_advancement_tab", "server_data", "action_bar",
    "world_border_center", "world_border_lerp_size", "world_border_size", "world_border_warning_delay",
    "world_border_warning_reach", "camera", "update_view_position", "update_view_distance",
    "set_cursor_item", "spawn_position", "scoreboard_display_objective", "entity_metadata",
    "attach_entity", "entity_velocity", "entity_equipment", "experience",
    "update_health", "held_item_slot", "scoreboard_objective", "set_passengers",
    "set_player_inventory", "teams", "scoreboard_score", "simulation_distance",
    "set_title_subtitle", "update_time", "set_title_text", "set_title_time",
    "entity_sound_effect", "sound_effect", "start_configuration", "stop_sound",
    "store_cookie", "system_chat", "playerlist_header", "nbt_query_response",
    "collect", "entity_teleport", "test_instance_block_status", "set_ticking_state",
    "step_tick", "transfer", "advancements", "entity_update_attributes",
    "entity_effect", "declare_recipes", "tags", "set_projectile_power",
    "custom_report_details", "server_links", "tracked_waypoint", "clear_dialog",
    "show_dialog",
};

#define PACKET_MAP(a) {a, sizeof(a) / sizeof((a)[0])}
#define PACKET_MAP_NONE {NULL, 0U}
static const McPacketCatalog packet_catalogs[] = {
    {4,
        PACKET_MAP(packet_names_0_login_serverbound), PACKET_MAP(packet_names_0_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_0_play_serverbound), PACKET_MAP(packet_names_0_play_clientbound)},
    {5,
        PACKET_MAP(packet_names_0_login_serverbound), PACKET_MAP(packet_names_0_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_0_play_serverbound), PACKET_MAP(packet_names_0_play_clientbound)},
    {47,
        PACKET_MAP(packet_names_1_login_serverbound), PACKET_MAP(packet_names_1_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_1_play_serverbound), PACKET_MAP(packet_names_1_play_clientbound)},
    {107,
        PACKET_MAP(packet_names_2_login_serverbound), PACKET_MAP(packet_names_2_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_2_play_serverbound), PACKET_MAP(packet_names_2_play_clientbound)},
    {108,
        PACKET_MAP(packet_names_2_login_serverbound), PACKET_MAP(packet_names_2_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_2_play_serverbound), PACKET_MAP(packet_names_2_play_clientbound)},
    {109,
        PACKET_MAP(packet_names_2_login_serverbound), PACKET_MAP(packet_names_2_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_2_play_serverbound), PACKET_MAP(packet_names_2_play_clientbound)},
    {110,
        PACKET_MAP(packet_names_3_login_serverbound), PACKET_MAP(packet_names_3_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_3_play_serverbound), PACKET_MAP(packet_names_3_play_clientbound)},
    {210,
        PACKET_MAP(packet_names_3_login_serverbound), PACKET_MAP(packet_names_3_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_3_play_serverbound), PACKET_MAP(packet_names_3_play_clientbound)},
    {315,
        PACKET_MAP(packet_names_3_login_serverbound), PACKET_MAP(packet_names_3_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_3_play_serverbound), PACKET_MAP(packet_names_3_play_clientbound)},
    {316,
        PACKET_MAP(packet_names_3_login_serverbound), PACKET_MAP(packet_names_3_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_3_play_serverbound), PACKET_MAP(packet_names_3_play_clientbound)},
    {335,
        PACKET_MAP(packet_names_4_login_serverbound), PACKET_MAP(packet_names_4_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_4_play_serverbound), PACKET_MAP(packet_names_4_play_clientbound)},
    {338,
        PACKET_MAP(packet_names_5_login_serverbound), PACKET_MAP(packet_names_5_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_5_play_serverbound), PACKET_MAP(packet_names_5_play_clientbound)},
    {340,
        PACKET_MAP(packet_names_5_login_serverbound), PACKET_MAP(packet_names_5_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_5_play_serverbound), PACKET_MAP(packet_names_5_play_clientbound)},
    {393,
        PACKET_MAP(packet_names_6_login_serverbound), PACKET_MAP(packet_names_6_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_6_play_serverbound), PACKET_MAP(packet_names_6_play_clientbound)},
    {401,
        PACKET_MAP(packet_names_6_login_serverbound), PACKET_MAP(packet_names_6_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_6_play_serverbound), PACKET_MAP(packet_names_6_play_clientbound)},
    {404,
        PACKET_MAP(packet_names_6_login_serverbound), PACKET_MAP(packet_names_6_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_6_play_serverbound), PACKET_MAP(packet_names_6_play_clientbound)},
    {477,
        PACKET_MAP(packet_names_7_login_serverbound), PACKET_MAP(packet_names_7_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_7_play_serverbound), PACKET_MAP(packet_names_7_play_clientbound)},
    {480,
        PACKET_MAP(packet_names_7_login_serverbound), PACKET_MAP(packet_names_7_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_7_play_serverbound), PACKET_MAP(packet_names_7_play_clientbound)},
    {485,
        PACKET_MAP(packet_names_7_login_serverbound), PACKET_MAP(packet_names_7_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_7_play_serverbound), PACKET_MAP(packet_names_7_play_clientbound)},
    {490,
        PACKET_MAP(packet_names_7_login_serverbound), PACKET_MAP(packet_names_7_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_7_play_serverbound), PACKET_MAP(packet_names_7_play_clientbound)},
    {498,
        PACKET_MAP(packet_names_8_login_serverbound), PACKET_MAP(packet_names_8_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_8_play_serverbound), PACKET_MAP(packet_names_8_play_clientbound)},
    {573,
        PACKET_MAP(packet_names_9_login_serverbound), PACKET_MAP(packet_names_9_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_9_play_serverbound), PACKET_MAP(packet_names_9_play_clientbound)},
    {575,
        PACKET_MAP(packet_names_9_login_serverbound), PACKET_MAP(packet_names_9_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_9_play_serverbound), PACKET_MAP(packet_names_9_play_clientbound)},
    {578,
        PACKET_MAP(packet_names_9_login_serverbound), PACKET_MAP(packet_names_9_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_9_play_serverbound), PACKET_MAP(packet_names_9_play_clientbound)},
    {735,
        PACKET_MAP(packet_names_10_login_serverbound), PACKET_MAP(packet_names_10_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_10_play_serverbound), PACKET_MAP(packet_names_10_play_clientbound)},
    {736,
        PACKET_MAP(packet_names_10_login_serverbound), PACKET_MAP(packet_names_10_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_10_play_serverbound), PACKET_MAP(packet_names_10_play_clientbound)},
    {751,
        PACKET_MAP(packet_names_11_login_serverbound), PACKET_MAP(packet_names_11_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_11_play_serverbound), PACKET_MAP(packet_names_11_play_clientbound)},
    {753,
        PACKET_MAP(packet_names_11_login_serverbound), PACKET_MAP(packet_names_11_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_11_play_serverbound), PACKET_MAP(packet_names_11_play_clientbound)},
    {754,
        PACKET_MAP(packet_names_11_login_serverbound), PACKET_MAP(packet_names_11_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_11_play_serverbound), PACKET_MAP(packet_names_11_play_clientbound)},
    {755,
        PACKET_MAP(packet_names_12_login_serverbound), PACKET_MAP(packet_names_12_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_12_play_serverbound), PACKET_MAP(packet_names_12_play_clientbound)},
    {756,
        PACKET_MAP(packet_names_13_login_serverbound), PACKET_MAP(packet_names_13_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_13_play_serverbound), PACKET_MAP(packet_names_13_play_clientbound)},
    {757,
        PACKET_MAP(packet_names_14_login_serverbound), PACKET_MAP(packet_names_14_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_14_play_serverbound), PACKET_MAP(packet_names_14_play_clientbound)},
    {758,
        PACKET_MAP(packet_names_14_login_serverbound), PACKET_MAP(packet_names_14_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_14_play_serverbound), PACKET_MAP(packet_names_14_play_clientbound)},
    {759,
        PACKET_MAP(packet_names_15_login_serverbound), PACKET_MAP(packet_names_15_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_15_play_serverbound), PACKET_MAP(packet_names_15_play_clientbound)},
    {760,
        PACKET_MAP(packet_names_16_login_serverbound), PACKET_MAP(packet_names_16_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_16_play_serverbound), PACKET_MAP(packet_names_16_play_clientbound)},
    {761,
        PACKET_MAP(packet_names_17_login_serverbound), PACKET_MAP(packet_names_17_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_17_play_serverbound), PACKET_MAP(packet_names_17_play_clientbound)},
    {762,
        PACKET_MAP(packet_names_18_login_serverbound), PACKET_MAP(packet_names_18_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_18_play_serverbound), PACKET_MAP(packet_names_18_play_clientbound)},
    {763,
        PACKET_MAP(packet_names_18_login_serverbound), PACKET_MAP(packet_names_18_login_clientbound),
        PACKET_MAP_NONE, PACKET_MAP_NONE,
        PACKET_MAP(packet_names_18_play_serverbound), PACKET_MAP(packet_names_18_play_clientbound)},
    {764,
        PACKET_MAP(packet_names_19_login_serverbound), PACKET_MAP(packet_names_19_login_clientbound),
        PACKET_MAP(packet_names_19_configuration_serverbound), PACKET_MAP(packet_names_19_configuration_clientbound),
        PACKET_MAP(packet_names_19_play_serverbound), PACKET_MAP(packet_names_19_play_clientbound)},
    {765,
        PACKET_MAP(packet_names_20_login_serverbound), PACKET_MAP(packet_names_20_login_clientbound),
        PACKET_MAP(packet_names_20_configuration_serverbound), PACKET_MAP(packet_names_20_configuration_clientbound),
        PACKET_MAP(packet_names_20_play_serverbound), PACKET_MAP(packet_names_20_play_clientbound)},
    {766,
        PACKET_MAP(packet_names_21_login_serverbound), PACKET_MAP(packet_names_21_login_clientbound),
        PACKET_MAP(packet_names_21_configuration_serverbound), PACKET_MAP(packet_names_21_configuration_clientbound),
        PACKET_MAP(packet_names_21_play_serverbound), PACKET_MAP(packet_names_21_play_clientbound)},
    {767,
        PACKET_MAP(packet_names_22_login_serverbound), PACKET_MAP(packet_names_22_login_clientbound),
        PACKET_MAP(packet_names_22_configuration_serverbound), PACKET_MAP(packet_names_22_configuration_clientbound),
        PACKET_MAP(packet_names_22_play_serverbound), PACKET_MAP(packet_names_22_play_clientbound)},
    {768,
        PACKET_MAP(packet_names_23_login_serverbound), PACKET_MAP(packet_names_23_login_clientbound),
        PACKET_MAP(packet_names_23_configuration_serverbound), PACKET_MAP(packet_names_23_configuration_clientbound),
        PACKET_MAP(packet_names_23_play_serverbound), PACKET_MAP(packet_names_23_play_clientbound)},
    {769,
        PACKET_MAP(packet_names_24_login_serverbound), PACKET_MAP(packet_names_24_login_clientbound),
        PACKET_MAP(packet_names_24_configuration_serverbound), PACKET_MAP(packet_names_24_configuration_clientbound),
        PACKET_MAP(packet_names_24_play_serverbound), PACKET_MAP(packet_names_24_play_clientbound)},
    {770,
        PACKET_MAP(packet_names_25_login_serverbound), PACKET_MAP(packet_names_25_login_clientbound),
        PACKET_MAP(packet_names_25_configuration_serverbound), PACKET_MAP(packet_names_25_configuration_clientbound),
        PACKET_MAP(packet_names_25_play_serverbound), PACKET_MAP(packet_names_25_play_clientbound)},
    {771,
        PACKET_MAP(packet_names_26_login_serverbound), PACKET_MAP(packet_names_26_login_clientbound),
        PACKET_MAP(packet_names_26_configuration_serverbound), PACKET_MAP(packet_names_26_configuration_clientbound),
        PACKET_MAP(packet_names_26_play_serverbound), PACKET_MAP(packet_names_26_play_clientbound)},
    {772,
        PACKET_MAP(packet_names_26_login_serverbound), PACKET_MAP(packet_names_26_login_clientbound),
        PACKET_MAP(packet_names_26_configuration_serverbound), PACKET_MAP(packet_names_26_configuration_clientbound),
        PACKET_MAP(packet_names_26_play_serverbound), PACKET_MAP(packet_names_26_play_clientbound)},
    {773,
        PACKET_MAP(packet_names_27_login_serverbound), PACKET_MAP(packet_names_27_login_clientbound),
        PACKET_MAP(packet_names_27_configuration_serverbound), PACKET_MAP(packet_names_27_configuration_clientbound),
        PACKET_MAP(packet_names_27_play_serverbound), PACKET_MAP(packet_names_27_play_clientbound)},
    {774,
        PACKET_MAP(packet_names_27_login_serverbound), PACKET_MAP(packet_names_27_login_clientbound),
        PACKET_MAP(packet_names_27_configuration_serverbound), PACKET_MAP(packet_names_27_configuration_clientbound),
        PACKET_MAP(packet_names_27_play_serverbound), PACKET_MAP(packet_names_27_play_clientbound)},
    {775,
        PACKET_MAP(packet_names_28_login_serverbound), PACKET_MAP(packet_names_28_login_clientbound),
        PACKET_MAP(packet_names_28_configuration_serverbound), PACKET_MAP(packet_names_28_configuration_clientbound),
        PACKET_MAP(packet_names_28_play_serverbound), PACKET_MAP(packet_names_28_play_clientbound)},
    {776,
        PACKET_MAP(packet_names_29_login_serverbound), PACKET_MAP(packet_names_29_login_clientbound),
        PACKET_MAP(packet_names_29_configuration_serverbound), PACKET_MAP(packet_names_29_configuration_clientbound),
        PACKET_MAP(packet_names_29_play_serverbound), PACKET_MAP(packet_names_29_play_clientbound)},
};
#undef PACKET_MAP_NONE
#undef PACKET_MAP

static const McPacketCatalog *find_packet_catalog(int protocol)
{
    size_t count = sizeof(packet_catalogs) / sizeof(packet_catalogs[0]);
    for (size_t index = 0U; index < count; ++index) {
        if (packet_catalogs[index].protocol == protocol) return &packet_catalogs[index];
    }
    return NULL;
}

static const McPacketMap *packet_map(const McPacketCatalog *catalog,
    McState state, McPacketDirection direction)
{
    if (catalog == NULL
        || (direction != MC_PACKET_SERVERBOUND
            && direction != MC_PACKET_CLIENTBOUND)) return NULL;
    bool serverbound = direction == MC_PACKET_SERVERBOUND;
    switch (state) {
    case MC_STATE_LOGIN:
        return serverbound ? &catalog->login_serverbound : &catalog->login_clientbound;
    case MC_STATE_CONFIGURATION:
        return serverbound ? &catalog->configuration_serverbound
                           : &catalog->configuration_clientbound;
    case MC_STATE_PLAY:
        return serverbound ? &catalog->play_serverbound : &catalog->play_clientbound;
    case MC_STATE_STATUS:
        return serverbound ? &packet_map_status_serverbound
                           : &packet_map_status_clientbound;
    default:
        return NULL;
    }
}


/* ============================================================
 * INTERNAL TYPES
 * ============================================================ */

/* The public reader is also the internal packet cursor. Keeping one bounded
 * implementation prevents login, compression and application codecs from
 * disagreeing about malformed VarInts or buffer limits. */
typedef McReader McCursor;

typedef struct {
    unsigned char *data;
    size_t size;
} McFrame;

#if defined(__linux__)
typedef struct {
    int fd;
    void *sq_map;
    void *cq_map;
    struct io_uring_sqe *sqes;
    size_t sq_map_size;
    size_t cq_map_size;
    size_t sqes_size;
    unsigned int *sq_head;
    unsigned int *sq_tail;
    unsigned int *sq_mask;
    unsigned int *sq_array;
    unsigned int *cq_head;
    unsigned int *cq_tail;
    unsigned int *cq_mask;
    struct io_uring_cqe *cqes;
    bool single_map;
} McRing;
#endif

struct McClient {
    atomic_int socket_fd;
    atomic_bool stop;
    const McProfile *profile;
    McCallbacks callbacks;
    void *userdata;
    McState state;
    McBackend backend;
    McBackend preferred_backend;
    int event_fd;
    int compression_threshold;
    uint64_t sent_bytes;
    uint64_t received_bytes;
    uint32_t automatic_replies;
    unsigned int read_timeout_ms;
    McStreamTransforms transforms;
    bool player_loaded_sent;
    bool server_side;
#if defined(__linux__)
    McRing ring;
#endif
};

struct McServer {
    int socket_fd;
    uint16_t port;
};

/* Error buffers belong to the caller. Treating a missing buffer as a valid
 * choice lets applications ignore diagnostic text without separate APIs. */
static void set_error(char *error, size_t size, const char *format, ...)
{
    if (error == NULL || size == 0U) return;
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(error, size, format, arguments);
    va_end(arguments);
}

static const McProfile *find_profile(int protocol)
{
    size_t count = sizeof(profiles) / sizeof(profiles[0]);
    for (size_t index = 0U; index < count; ++index) {
        if (profiles[index].protocol == protocol) return &profiles[index];
    }
    return NULL;
}


/* ============================================================
 * PACKET REGISTRY
 * ============================================================ */

/* Registry objects are static and immutable. Returning their pointers avoids
 * allocation while giving callers stable names suitable for dispatch tables. */
const int *mc_supported_protocols(size_t *count)
{
    if (count != NULL) *count = sizeof(protocol_ids) / sizeof(protocol_ids[0]);
    return protocol_ids;
}

bool mc_protocol_supported(int protocol)
{
    return find_profile(protocol) != NULL;
}

const char *mc_protocol_name(int protocol)
{
    size_t count = sizeof(protocol_ids) / sizeof(protocol_ids[0]);
    for (size_t index = 0U; index < count; ++index) {
        if (protocol_ids[index] == protocol) return protocol_names[index];
    }
    return NULL;
}

int mc_protocol_by_name(const char *release_name)
{
    if (release_name == NULL) return -1;
    size_t count = sizeof(protocol_names) / sizeof(protocol_names[0]);
    for (size_t index = 0U; index < count; ++index) {
        if (strcmp(protocol_names[index], release_name) == 0) {
            return protocol_ids[index];
        }
    }
    return -1;
}

uint32_t mc_protocol_features(int protocol)
{
    const McProfile *profile = find_profile(protocol);
    return profile != NULL ? profile->flags : 0U;
}

size_t mc_packet_count(int protocol)
{
    const McPacketCatalog *catalog = find_packet_catalog(protocol);
    if (catalog == NULL) return 0U;
    return catalog->login_serverbound.count + catalog->login_clientbound.count
        + catalog->configuration_serverbound.count
        + catalog->configuration_clientbound.count
        + catalog->play_serverbound.count + catalog->play_clientbound.count
        + sizeof(packet_names_status_serverbound)
            / sizeof(packet_names_status_serverbound[0])
        + sizeof(packet_names_status_clientbound)
            / sizeof(packet_names_status_clientbound[0]);
}

bool mc_packet_at(int protocol, size_t index, McPacketInfo *packet)
{
    const McPacketCatalog *catalog = find_packet_catalog(protocol);
    if (catalog == NULL || packet == NULL) return false;
    const McPacketMap *maps[] = {
        &catalog->login_serverbound, &catalog->login_clientbound,
        &catalog->configuration_serverbound, &catalog->configuration_clientbound,
        &catalog->play_serverbound, &catalog->play_clientbound,
        &packet_map_status_serverbound, &packet_map_status_clientbound
    };
    const McState states[] = {
        MC_STATE_LOGIN, MC_STATE_LOGIN,
        MC_STATE_CONFIGURATION, MC_STATE_CONFIGURATION,
        MC_STATE_PLAY, MC_STATE_PLAY,
        MC_STATE_STATUS, MC_STATE_STATUS
    };
    const McPacketDirection directions[] = {
        MC_PACKET_SERVERBOUND, MC_PACKET_CLIENTBOUND,
        MC_PACKET_SERVERBOUND, MC_PACKET_CLIENTBOUND,
        MC_PACKET_SERVERBOUND, MC_PACKET_CLIENTBOUND,
        MC_PACKET_SERVERBOUND, MC_PACKET_CLIENTBOUND
    };
    for (size_t map_index = 0U; map_index < sizeof(maps) / sizeof(maps[0]);
            ++map_index) {
        if (index < maps[map_index]->count) {
            packet->state = states[map_index];
            packet->direction = directions[map_index];
            packet->id = (int32_t)index;
            packet->name = maps[map_index]->names[index];
            return true;
        }
        index -= maps[map_index]->count;
    }
    return false;
}

const char *mc_packet_name(int protocol, McState state,
    McPacketDirection direction, int32_t id)
{
    const McPacketMap *map = packet_map(find_packet_catalog(protocol), state, direction);
    if (map == NULL || id < 0 || (size_t)id >= map->count) return NULL;
    return map->names[id];
}

int32_t mc_packet_id(int protocol, McState state,
    McPacketDirection direction, const char *name)
{
    const McPacketMap *map = packet_map(find_packet_catalog(protocol), state, direction);
    if (map == NULL || name == NULL) return -1;
    for (size_t index = 0U; index < map->count; ++index) {
        if (strcmp(map->names[index], name) == 0) return (int32_t)index;
    }
    return -1;
}


/* ============================================================
 * READER / WRITER CODEC
 * ============================================================ */

/* The writer deliberately has a sticky failure bit. A caller can append a
 * sequence of fields without branching after each one and check the complete
 * body once at send time; overflow can never become a truncated valid packet. */
void mc_packet_init(McPacket *packet, void *storage, size_t capacity)
{
    if (packet == NULL) return;
    packet->data = storage;
    packet->length = 0U;
    packet->capacity = capacity;
    packet->failed = storage == NULL && capacity != 0U;
}

bool mc_packet_bytes(McPacket *packet, const void *data, size_t size)
{
    if (packet == NULL || packet->failed || packet->length > packet->capacity
        || size > packet->capacity - packet->length
        || (size != 0U && data == NULL)) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (size != 0U) memcpy(packet->data + packet->length, data, size);
    packet->length += size;
    return true;
}

bool mc_packet_nbt(McPacket *packet, bool named_root, const McBytes *encoded)
{
    if (packet == NULL || packet->failed || encoded == NULL
        || (encoded->size != 0U && encoded->data == NULL)) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    McReader reader;
    mc_reader_init(&reader, encoded->data, encoded->size);
    if (!mc_reader_nbt(&reader, named_root, NULL)
        || mc_reader_remaining(&reader) != 0U) {
        packet->failed = true;
        return false;
    }
    return mc_packet_bytes(packet, encoded->data, encoded->size);
}

bool mc_packet_bool(McPacket *packet, bool value)
{
    return mc_packet_u8(packet, value ? 1U : 0U);
}

bool mc_packet_i8(McPacket *packet, int8_t value)
{
    return mc_packet_u8(packet, (uint8_t)value);
}

bool mc_packet_u8(McPacket *packet, uint8_t value)
{
    return mc_packet_bytes(packet, &value, 1U);
}

bool mc_packet_i16(McPacket *packet, int16_t value)
{
    return mc_packet_u16(packet, (uint16_t)value);
}

bool mc_packet_u16(McPacket *packet, uint16_t value)
{
    unsigned char bytes[2] = {
        (unsigned char)(value >> 8U), (unsigned char)value
    };
    return mc_packet_bytes(packet, bytes, sizeof(bytes));
}

bool mc_packet_i32(McPacket *packet, int32_t value)
{
    return mc_packet_u32(packet, (uint32_t)value);
}

bool mc_packet_u32(McPacket *packet, uint32_t value)
{
    unsigned char bytes[4];
    for (size_t index = 0U; index < 4U; ++index) {
        bytes[index] = (unsigned char)(value >> ((3U - index) * 8U));
    }
    return mc_packet_bytes(packet, bytes, sizeof(bytes));
}

bool mc_packet_i64(McPacket *packet, int64_t value)
{
    return mc_packet_u64(packet, (uint64_t)value);
}

bool mc_packet_u64(McPacket *packet, uint64_t value)
{
    unsigned char bytes[8];
    for (size_t index = 0U; index < 8U; ++index) {
        bytes[index] = (unsigned char)(value >> ((7U - index) * 8U));
    }
    return mc_packet_bytes(packet, bytes, sizeof(bytes));
}

bool mc_packet_float(McPacket *packet, float value)
{
    uint32_t bits = 0U;
    memcpy(&bits, &value, sizeof(bits));
    return mc_packet_u32(packet, bits);
}

bool mc_packet_double(McPacket *packet, double value)
{
    uint64_t bits = 0U;
    memcpy(&bits, &value, sizeof(bits));
    return mc_packet_u64(packet, bits);
}

bool mc_packet_varint(McPacket *packet, int32_t value)
{
    uint32_t encoded = (uint32_t)value;
    do {
        unsigned char byte = (unsigned char)(encoded & 0x7fU);
        encoded >>= 7U;
        if (encoded != 0U) byte |= 0x80U;
        if (!mc_packet_u8(packet, byte)) return false;
    } while (encoded != 0U);
    return true;
}

bool mc_packet_varlong(McPacket *packet, int64_t value)
{
    uint64_t encoded = (uint64_t)value;
    do {
        unsigned char byte = (unsigned char)(encoded & 0x7fU);
        encoded >>= 7U;
        if (encoded != 0U) byte |= 0x80U;
        if (!mc_packet_u8(packet, byte)) return false;
    } while (encoded != 0U);
    return true;
}

bool mc_packet_buffer_i32(McPacket *packet, const McBytes *value)
{
    if (packet == NULL || value == NULL || value->size > (size_t)INT32_MAX) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    return mc_packet_i32(packet, (int32_t)value->size)
        && mc_packet_bytes(packet, value->data, value->size);
}

bool mc_packet_buffer_varint(McPacket *packet, const McBytes *value)
{
    if (packet == NULL || value == NULL || value->size > (size_t)INT32_MAX) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    return mc_packet_varint(packet, (int32_t)value->size)
        && mc_packet_bytes(packet, value->data, value->size);
}

bool mc_packet_string_n(McPacket *packet, const char *value, size_t size)
{
    if (value == NULL) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (size > INT32_MAX || !mc_packet_varint(packet, (int32_t)size)) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    return mc_packet_bytes(packet, value, size);
}

bool mc_packet_string(McPacket *packet, const char *value)
{
    if (value == NULL) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    return mc_packet_string_n(packet, value, strlen(value));
}

void mc_reader_init(McReader *reader, const void *data, size_t size)
{
    if (reader == NULL) return;
    reader->data = data;
    reader->size = size;
    reader->offset = 0U;
    reader->failed = data == NULL && size != 0U;
}

size_t mc_reader_remaining(const McReader *reader)
{
    if (reader == NULL || reader->failed || reader->offset > reader->size) return 0U;
    return reader->size - reader->offset;
}

bool mc_reader_bytes(McReader *reader, size_t size, McBytes *value)
{
    if (reader == NULL || value == NULL || reader->failed
        || reader->offset > reader->size
        || size > reader->size - reader->offset) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    value->data = size == 0U ? reader->data : reader->data + reader->offset;
    value->size = size;
    reader->offset += size;
    return true;
}

bool mc_reader_skip(McReader *reader, size_t size)
{
    McBytes ignored;
    return mc_reader_bytes(reader, size, &ignored);
}

bool mc_reader_u8(McReader *reader, uint8_t *value)
{
    McBytes bytes;
    if (value == NULL || !mc_reader_bytes(reader, 1U, &bytes)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    *value = bytes.data[0];
    return true;
}

bool mc_reader_bool(McReader *reader, bool *value)
{
    uint8_t encoded = 0U;
    if (value == NULL || !mc_reader_u8(reader, &encoded)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    *value = encoded != 0U;
    return true;
}

bool mc_reader_i8(McReader *reader, int8_t *value)
{
    uint8_t encoded = 0U;
    if (value == NULL || !mc_reader_u8(reader, &encoded)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    *value = (int8_t)encoded;
    return true;
}

bool mc_reader_u16(McReader *reader, uint16_t *value)
{
    McBytes bytes;
    if (value == NULL || !mc_reader_bytes(reader, 2U, &bytes)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    *value = (uint16_t)((uint16_t)bytes.data[0] << 8U)
        | (uint16_t)bytes.data[1];
    return true;
}

bool mc_reader_i16(McReader *reader, int16_t *value)
{
    uint16_t encoded = 0U;
    if (value == NULL || !mc_reader_u16(reader, &encoded)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    *value = (int16_t)encoded;
    return true;
}

bool mc_reader_u32(McReader *reader, uint32_t *value)
{
    McBytes bytes;
    if (value == NULL || !mc_reader_bytes(reader, 4U, &bytes)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    uint32_t decoded = 0U;
    for (size_t index = 0U; index < 4U; ++index) {
        decoded = (decoded << 8U) | bytes.data[index];
    }
    *value = decoded;
    return true;
}

bool mc_reader_i32(McReader *reader, int32_t *value)
{
    uint32_t encoded = 0U;
    if (value == NULL || !mc_reader_u32(reader, &encoded)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    *value = (int32_t)encoded;
    return true;
}

bool mc_reader_u64(McReader *reader, uint64_t *value)
{
    McBytes bytes;
    if (value == NULL || !mc_reader_bytes(reader, 8U, &bytes)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    uint64_t decoded = 0U;
    for (size_t index = 0U; index < 8U; ++index) {
        decoded = (decoded << 8U) | bytes.data[index];
    }
    *value = decoded;
    return true;
}

bool mc_reader_i64(McReader *reader, int64_t *value)
{
    uint64_t encoded = 0U;
    if (value == NULL || !mc_reader_u64(reader, &encoded)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    *value = (int64_t)encoded;
    return true;
}

bool mc_reader_float(McReader *reader, float *value)
{
    uint32_t bits = 0U;
    if (value == NULL || !mc_reader_u32(reader, &bits)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    memcpy(value, &bits, sizeof(bits));
    return true;
}

bool mc_reader_double(McReader *reader, double *value)
{
    uint64_t bits = 0U;
    if (value == NULL || !mc_reader_u64(reader, &bits)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    memcpy(value, &bits, sizeof(bits));
    return true;
}

bool mc_reader_varint(McReader *reader, int32_t *value)
{
    uint32_t result = 0U;
    for (unsigned int index = 0U; index < 5U; ++index) {
        uint8_t byte = 0U;
        if (value == NULL || !mc_reader_u8(reader, &byte)
            || (index == 4U && (byte & 0xf0U) != 0U)) {
            if (reader != NULL) reader->failed = true;
            return false;
        }
        result |= (uint32_t)(byte & 0x7fU) << (index * 7U);
        if ((byte & 0x80U) == 0U) {
            *value = (int32_t)result;
            return true;
        }
    }
    if (reader != NULL) reader->failed = true;
    return false;
}

bool mc_reader_varlong(McReader *reader, int64_t *value)
{
    uint64_t result = 0U;
    for (unsigned int index = 0U; index < 10U; ++index) {
        uint8_t byte = 0U;
        if (value == NULL || !mc_reader_u8(reader, &byte)
            || (index == 9U && (byte & 0xfeU) != 0U)) {
            if (reader != NULL) reader->failed = true;
            return false;
        }
        result |= (uint64_t)(byte & 0x7fU) << (index * 7U);
        if ((byte & 0x80U) == 0U) {
            *value = (int64_t)result;
            return true;
        }
    }
    if (reader != NULL) reader->failed = true;
    return false;
}

bool mc_reader_buffer_i32(McReader *reader, McBytes *value)
{
    int32_t size = -1;
    if (value == NULL || !mc_reader_i32(reader, &size) || size < 0) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    return mc_reader_bytes(reader, (size_t)size, value);
}

bool mc_reader_buffer_varint(McReader *reader, McBytes *value)
{
    int32_t size = -1;
    if (value == NULL || !mc_reader_varint(reader, &size) || size < 0) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    return mc_reader_bytes(reader, (size_t)size, value);
}

bool mc_reader_string(McReader *reader, McBytes *value)
{
    int32_t size = -1;
    if (value == NULL || !mc_reader_varint(reader, &size) || size < 0) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    return mc_reader_bytes(reader, (size_t)size, value);
}

bool mc_packet_position(McPacket *packet, int protocol, McPosition value)
{
    if (!mc_protocol_supported(protocol)
        || value.x < -33554432 || value.x > 33554431
        || value.y < -2048 || value.y > 2047
        || value.z < -33554432 || value.z > 33554431) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    uint64_t x = (uint64_t)(uint32_t)value.x & UINT64_C(0x3ffffff);
    uint64_t y = (uint64_t)(uint32_t)value.y & UINT64_C(0xfff);
    uint64_t z = (uint64_t)(uint32_t)value.z & UINT64_C(0x3ffffff);
    uint64_t packed = protocol >= 477
        ? (x << 38U) | (z << 12U) | y
        : (x << 38U) | (y << 26U) | z;
    return mc_packet_u64(packet, packed);
}

bool mc_packet_uuid(McPacket *packet, const McUuid *value)
{
    if (value == NULL) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    return mc_packet_bytes(packet, value->bytes, sizeof(value->bytes));
}

bool mc_packet_plain_item(McPacket *packet, int protocol,
    int32_t item_id, int32_t count)
{
    if (!mc_protocol_supported(protocol) || count < 0 || count > 127
        || (count != 0 && item_id <= 0)
        || (protocol <= 401 && item_id > (int32_t)UINT16_MAX)) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (protocol <= 340) {
        if (!mc_packet_u16(packet, count == 0 ? UINT16_MAX : (uint16_t)item_id)) {
            return false;
        }
        if (count == 0) return true;
        return mc_packet_u8(packet, (uint8_t)count)
            && mc_packet_u16(packet, 0U)
            && (protocol <= 5
                ? mc_packet_i16(packet, -1)
                : mc_packet_u8(packet, (uint8_t)MC_NBT_END));
    }
    if (protocol == 393 || protocol == 401) {
        if (!mc_packet_u16(packet, count == 0 ? UINT16_MAX : (uint16_t)item_id)) {
            return false;
        }
        return count == 0 || (mc_packet_u8(packet, (uint8_t)count)
            && mc_packet_u8(packet, (uint8_t)MC_NBT_END));
    }
    if (protocol < 766) {
        if (!mc_packet_bool(packet, count != 0)) return false;
        return count == 0 || (mc_packet_varint(packet, item_id)
            && mc_packet_u8(packet, (uint8_t)count)
            && mc_packet_u8(packet, (uint8_t)MC_NBT_END));
    }
    if (!mc_packet_varint(packet, count)) return false;
    return count == 0 || (mc_packet_varint(packet, item_id)
        && mc_packet_varint(packet, 0) && mc_packet_varint(packet, 0));
}

bool mc_packet_set_creative_slot(McPacket *packet, int protocol,
    int16_t slot, int32_t item_id, int32_t count)
{
    return mc_packet_i16(packet, slot)
        && mc_packet_plain_item(packet, protocol, item_id, count);
}

bool mc_packet_held_item_slot(McPacket *packet, int protocol, int16_t slot)
{
    if (packet == NULL || !mc_protocol_supported(protocol)
        || slot < 0 || slot > 8) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    return mc_packet_i16(packet, slot);
}

bool mc_packet_window_click(McPacket *packet, int protocol,
    const McWindowClick *value)
{
    if (packet == NULL || value == NULL || !mc_protocol_supported(protocol)
        || value->state_id < 0 || value->mode < 0 || value->mode > 6
        || value->clicked_item_count < 0 || value->clicked_item_count > 127
        || (value->clicked_item_count != 0 && value->clicked_item_id <= 0)
        || (protocol >= 755 && value->clicked_item_count != 0)
        || (protocol <= 5
            && (value->window_id < INT8_MIN || value->window_id > INT8_MAX))
        || (protocol >= 47 && protocol <= 767
            && (value->window_id < 0
                || value->window_id > (int32_t)UINT8_MAX))
        || (protocol >= 768 && value->window_id < 0)) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (protocol <= 5) {
        if (!mc_packet_i8(packet, (int8_t)value->window_id)) return false;
    } else if (protocol <= 767) {
        if (!mc_packet_u8(packet, (uint8_t)value->window_id)) return false;
    } else if (!mc_packet_varint(packet, value->window_id)) {
        return false;
    }
    if (protocol >= 756 && !mc_packet_varint(packet, value->state_id)) {
        return false;
    }
    if (!mc_packet_i16(packet, value->slot)
        || !mc_packet_i8(packet, value->mouse_button)) {
        return false;
    }
    if (protocol <= 754) {
        return mc_packet_i16(packet, value->action_number)
            && mc_packet_i8(packet, (int8_t)value->mode)
            && mc_packet_plain_item(packet, protocol,
                value->clicked_item_id, value->clicked_item_count);
    }
    if (!(protocol == 755
            ? mc_packet_i8(packet, (int8_t)value->mode)
            : mc_packet_varint(packet, value->mode))
        || !mc_packet_varint(packet, 0)) {
        return false;
    }
    return protocol < 770
        ? mc_packet_plain_item(packet, protocol, 0, 0)
        : mc_packet_bool(packet, false);
}

bool mc_packet_close_window(McPacket *packet, int protocol, int32_t window_id)
{
    if (packet == NULL || !mc_protocol_supported(protocol) || window_id < 0
        || (protocol <= 767 && window_id > (int32_t)UINT8_MAX)) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    return protocol <= 767
        ? mc_packet_u8(packet, (uint8_t)window_id)
        : mc_packet_varint(packet, window_id);
}

bool mc_packet_empty_window_click(McPacket *packet, int protocol,
    const McEmptyWindowClick *value)
{
    if (value == NULL) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    const McWindowClick click = {
        .window_id = value->window_id,
        .state_id = value->state_id,
        .slot = value->slot,
        .mouse_button = value->mouse_button,
        .action_number = value->action_number,
        .mode = value->mode,
        .clicked_item_id = 0,
        .clicked_item_count = 0
    };
    return mc_packet_window_click(packet, protocol, &click);
}

bool mc_packet_container_button(McPacket *packet, int protocol,
    int32_t window_id, int32_t button_id)
{
    if (packet == NULL || !mc_protocol_supported(protocol)
        || window_id < 0 || button_id < 0
        || (protocol <= 766
            && (window_id > INT8_MAX || button_id > INT8_MAX))
        || (protocol == 767 && window_id > (int32_t)UINT8_MAX)) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (protocol <= 766) {
        return mc_packet_i8(packet, (int8_t)window_id)
            && mc_packet_i8(packet, (int8_t)button_id);
    }
    return (protocol == 767
            ? mc_packet_u8(packet, (uint8_t)window_id)
            : mc_packet_varint(packet, window_id))
        && mc_packet_varint(packet, button_id);
}

bool mc_packet_untrusted_component_item(McPacket *packet, int protocol,
    int32_t item_id, int32_t count,
    const McItemComponentPatch *added, size_t added_count,
    const int32_t *removed, size_t removed_count)
{
    if (packet == NULL || !mc_protocol_supported(protocol) || protocol < 766
        || count < 0 || count > 127 || (count != 0 && item_id <= 0)
        || added_count > (size_t)INT32_MAX || removed_count > (size_t)INT32_MAX
        || (added_count != 0U && added == NULL)
        || (removed_count != 0U && removed == NULL)) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (!mc_packet_varint(packet, count) || count == 0) {
        return count == 0 && !packet->failed;
    }
    if (!mc_packet_varint(packet, item_id)
        || !mc_packet_varint(packet, (int32_t)added_count)
        || !mc_packet_varint(packet, (int32_t)removed_count)) {
        return false;
    }
    for (size_t index = 0U; index < added_count; ++index) {
        if (added[index].type_id < 0
            || added[index].data.size > (size_t)INT32_MAX
            || (added[index].data.size != 0U
                && added[index].data.data == NULL)
            || !mc_packet_varint(packet, added[index].type_id)
            || !mc_packet_buffer_varint(packet, &added[index].data)) {
            packet->failed = true;
            return false;
        }
    }
    for (size_t index = 0U; index < removed_count; ++index) {
        if (removed[index] < 0 || !mc_packet_varint(packet, removed[index])) {
            packet->failed = true;
            return false;
        }
    }
    return true;
}

bool mc_packet_client_information(McPacket *packet, int protocol,
    const McClientInformation *value)
{
    if (packet == NULL || !mc_protocol_supported(protocol) || value == NULL
        || value->locale == NULL) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    size_t locale_size = strlen(value->locale);
    if (locale_size == 0U || locale_size > 16U
        || value->view_distance < 2 || value->view_distance > 32
        || value->chat_mode < 0 || value->chat_mode > 2
        || (protocol <= 5 && value->difficulty > 3U)
        || (protocol >= 107 && (value->main_hand < 0 || value->main_hand > 1))
        || (protocol >= 768
            && (value->particle_status < 0 || value->particle_status > 2))) {
        packet->failed = true;
        return false;
    }
    if (!mc_packet_string_n(packet, value->locale, locale_size)
        || !mc_packet_i8(packet, value->view_distance)
        || !(protocol <= 47
            ? mc_packet_i8(packet, (int8_t)value->chat_mode)
            : mc_packet_varint(packet, value->chat_mode))
        || !mc_packet_bool(packet, value->chat_colors)) {
        return false;
    }
    if (protocol <= 5) {
        return mc_packet_u8(packet, value->difficulty)
            && mc_packet_bool(packet, value->show_cape);
    }
    if (!mc_packet_u8(packet, value->skin_parts)
        || (protocol >= 107 && !mc_packet_varint(packet, value->main_hand))
        || (protocol >= 755
            && !mc_packet_bool(packet, value->text_filtering))
        || (protocol >= 757
            && !mc_packet_bool(packet, value->server_listing))) {
        return false;
    }
    return protocol < 768
        || mc_packet_varint(packet, value->particle_status);
}

static bool entity_action_id(int protocol, McEntityActionKind action,
    int32_t *wire_id)
{
    if (wire_id == NULL) return false;
    switch (action) {
    case MC_ENTITY_ACTION_START_SNEAKING:
        if (protocol >= 771) return false;
        *wire_id = protocol <= 5 ? 1 : 0;
        return true;
    case MC_ENTITY_ACTION_STOP_SNEAKING:
        if (protocol >= 771) return false;
        *wire_id = protocol <= 5 ? 2 : 1;
        return true;
    case MC_ENTITY_ACTION_LEAVE_BED:
        *wire_id = protocol <= 5 ? 3 : protocol >= 771 ? 0 : 2;
        return true;
    case MC_ENTITY_ACTION_START_SPRINTING:
        *wire_id = protocol <= 5 ? 4 : protocol >= 771 ? 1 : 3;
        return true;
    case MC_ENTITY_ACTION_STOP_SPRINTING:
        *wire_id = protocol <= 5 ? 5 : protocol >= 771 ? 2 : 4;
        return true;
    case MC_ENTITY_ACTION_START_HORSE_JUMP:
        *wire_id = protocol <= 5 ? 6 : protocol >= 771 ? 3 : 5;
        return true;
    case MC_ENTITY_ACTION_STOP_HORSE_JUMP:
        *wire_id = protocol <= 5 ? 7 : protocol >= 771 ? 4 : 6;
        return true;
    case MC_ENTITY_ACTION_OPEN_VEHICLE_INVENTORY:
        *wire_id = protocol <= 5 ? 8 : protocol >= 771 ? 5 : 7;
        return true;
    case MC_ENTITY_ACTION_START_ELYTRA_FLYING:
        if (protocol < 107) return false;
        *wire_id = protocol >= 771 ? 6 : 8;
        return true;
    }
    return false;
}

bool mc_packet_entity_action(McPacket *packet, int protocol,
    const McEntityAction *value)
{
    int32_t action_id = -1;
    if (packet == NULL || !mc_protocol_supported(protocol) || value == NULL
        || value->entity_id < 0 || value->jump_boost < 0
        || !entity_action_id(protocol, value->action, &action_id)) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    return protocol <= 5
        ? mc_packet_i32(packet, value->entity_id)
            && mc_packet_i8(packet, (int8_t)action_id)
            && mc_packet_i32(packet, value->jump_boost)
        : mc_packet_varint(packet, value->entity_id)
            && mc_packet_varint(packet, action_id)
            && mc_packet_varint(packet, value->jump_boost);
}

bool mc_packet_player_input(McPacket *packet, int protocol, uint8_t flags)
{
    if (packet == NULL || !mc_protocol_supported(protocol) || protocol < 768
        || (flags & UINT8_C(0x80)) != 0U) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    return mc_packet_u8(packet, flags);
}

bool mc_packet_arm_animation(McPacket *packet, int protocol,
    int32_t entity_id, int32_t hand)
{
    if (packet == NULL || !mc_protocol_supported(protocol)
        || (protocol <= 5 && entity_id < 0)
        || (protocol >= 107 && (hand < 0 || hand > 1))) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (protocol <= 5) {
        return mc_packet_i32(packet, entity_id) && mc_packet_i8(packet, 1);
    }
    return protocol == 47 || mc_packet_varint(packet, hand);
}

bool mc_packet_player_position(McPacket *packet, int protocol,
    const McPlayerPosition *value)
{
    if (packet == NULL || !mc_protocol_supported(protocol) || value == NULL
        || !isfinite(value->x) || !isfinite(value->y)
        || !isfinite(value->z) || !isfinite(value->yaw)
        || !isfinite(value->pitch)
        || (protocol <= 5 && !isfinite(value->y + 1.62))) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    return mc_packet_double(packet, value->x)
        && mc_packet_double(packet, value->y)
        && (protocol > 5 || mc_packet_double(packet, value->y + 1.62))
        && mc_packet_double(packet, value->z)
        && mc_packet_float(packet, value->yaw)
        && mc_packet_float(packet, value->pitch)
        && mc_packet_bool(packet, value->on_ground);
}

bool mc_packet_player_abilities(McPacket *packet, int protocol,
    const McPlayerAbilities *value)
{
    if (packet == NULL || value == NULL || !mc_protocol_supported(protocol)) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (!mc_packet_u8(packet, value->flags)) return false;
    return protocol >= 735
        || (mc_packet_float(packet, value->flying_speed)
            && mc_packet_float(packet, value->walking_speed));
}

bool mc_packet_block_dig(McPacket *packet, int protocol,
    const McBlockDig *value)
{
    if (packet == NULL || value == NULL || !mc_protocol_supported(protocol)
        || value->status < 0 || value->status > 6
        || value->face < 0 || value->face > 5 || value->sequence < 0) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (protocol <= 5) {
        if (value->location.y < 0 || value->location.y > (int32_t)UINT8_MAX) {
            packet->failed = true;
            return false;
        }
        return mc_packet_i8(packet, (int8_t)value->status)
            && mc_packet_i32(packet, value->location.x)
            && mc_packet_u8(packet, (uint8_t)value->location.y)
            && mc_packet_i32(packet, value->location.z)
            && mc_packet_i8(packet, value->face);
    }
    return mc_packet_varint(packet, value->status)
        && mc_packet_position(packet, protocol, value->location)
        && mc_packet_i8(packet, value->face)
        && (protocol < 759 || mc_packet_varint(packet, value->sequence));
}

static bool packet_block_place_cursor(McPacket *packet, int protocol,
    float x, float y, float z)
{
    if (!isfinite(x) || !isfinite(y) || !isfinite(z)
        || x < 0.0F || x > 1.0F || y < 0.0F || y > 1.0F
        || z < 0.0F || z > 1.0F) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (protocol <= 210) {
        const float scaled_x = x * 16.0F;
        const float scaled_y = y * 16.0F;
        const float scaled_z = z * 16.0F;
        if (floorf(scaled_x) != scaled_x || floorf(scaled_y) != scaled_y
            || floorf(scaled_z) != scaled_z) {
            packet->failed = true;
            return false;
        }
        return mc_packet_i8(packet, (int8_t)scaled_x)
            && mc_packet_i8(packet, (int8_t)scaled_y)
            && mc_packet_i8(packet, (int8_t)scaled_z);
    }
    return mc_packet_float(packet, x) && mc_packet_float(packet, y)
        && mc_packet_float(packet, z);
}

static bool packet_legacy_reported_item(McPacket *packet, int protocol,
    const McBlockPlace *value)
{
    if (value->held_item_count == 0) {
        if (value->held_item_id != 0 || value->held_item_damage != 0
            || value->held_item_nbt.size != 0U) {
            packet->failed = true;
            return false;
        }
        return mc_packet_u16(packet, UINT16_MAX);
    }
    if (value->held_item_id <= 0 || value->held_item_id > (int32_t)INT16_MAX
        || value->held_item_count < 0 || value->held_item_count > 127
        || value->held_item_damage < 0
        || value->held_item_damage > (int32_t)UINT16_MAX
        || (value->held_item_nbt.size != 0U
            && value->held_item_nbt.data == NULL)) {
        packet->failed = true;
        return false;
    }
    if (!mc_packet_u16(packet, (uint16_t)value->held_item_id)
        || !mc_packet_u8(packet, (uint8_t)value->held_item_count)
        || !mc_packet_u16(packet, (uint16_t)value->held_item_damage)) {
        return false;
    }
    if (value->held_item_nbt.size == 0U) {
        return protocol <= 5
            ? mc_packet_i16(packet, -1)
            : mc_packet_u8(packet, (uint8_t)MC_NBT_END);
    }
    McReader reader;
    McBytes encoded = {0};
    mc_reader_init(&reader,
        value->held_item_nbt.data, value->held_item_nbt.size);
    if (!mc_reader_nbt(&reader, true, &encoded)
        || mc_reader_remaining(&reader) != 0U) {
        packet->failed = true;
        return false;
    }
    if (protocol > 5) {
        return mc_packet_bytes(packet,
            value->held_item_nbt.data, value->held_item_nbt.size);
    }

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    const uLong bound = compressBound((uLong)value->held_item_nbt.size) + 32U;
    if (bound > (uLong)INT16_MAX) {
        packet->failed = true;
        return false;
    }
    unsigned char *compressed = malloc((size_t)bound);
    if (compressed == NULL) {
        packet->failed = true;
        return false;
    }
    stream.next_in = (Bytef *)(uintptr_t)value->held_item_nbt.data;
    stream.avail_in = (uInt)value->held_item_nbt.size;
    stream.next_out = compressed;
    stream.avail_out = (uInt)bound;
    int status = deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
        15 + 16, 8, Z_DEFAULT_STRATEGY);
    if (status == Z_OK) status = deflate(&stream, Z_FINISH);
    const size_t compressed_size = (size_t)stream.total_out;
    if (stream.state != NULL) (void)deflateEnd(&stream);
    const bool ok = status == Z_STREAM_END
        && compressed_size <= (size_t)INT16_MAX
        && mc_packet_i16(packet, (int16_t)compressed_size)
        && mc_packet_bytes(packet, compressed, compressed_size);
    free(compressed);
    if (!ok) packet->failed = true;
    return ok;
}

bool mc_packet_block_place(McPacket *packet, int protocol,
    const McBlockPlace *value)
{
    if (packet == NULL || value == NULL || !mc_protocol_supported(protocol)
        || value->direction < 0 || value->direction > 5
        || value->hand < 0 || value->hand > 1 || value->sequence < 0) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (protocol <= 5) {
        if (value->location.y < 0 || value->location.y > (int32_t)UINT8_MAX
            || !mc_packet_i32(packet, value->location.x)
            || !mc_packet_u8(packet, (uint8_t)value->location.y)
            || !mc_packet_i32(packet, value->location.z)) {
            packet->failed = true;
            return false;
        }
    } else if (protocol <= 404
        && !mc_packet_position(packet, protocol, value->location)) {
        return false;
    }
    if (protocol <= 47) {
        return mc_packet_i8(packet, (int8_t)value->direction)
            && packet_legacy_reported_item(packet, protocol, value)
            && packet_block_place_cursor(packet, protocol,
                value->cursor_x, value->cursor_y, value->cursor_z);
    }
    if (protocol <= 404) {
        return mc_packet_varint(packet, value->direction)
            && mc_packet_varint(packet, value->hand)
            && packet_block_place_cursor(packet, protocol,
                value->cursor_x, value->cursor_y, value->cursor_z);
    }
    return mc_packet_varint(packet, value->hand)
        && mc_packet_position(packet, protocol, value->location)
        && mc_packet_varint(packet, value->direction)
        && packet_block_place_cursor(packet, protocol,
            value->cursor_x, value->cursor_y, value->cursor_z)
        && mc_packet_bool(packet, value->inside_block)
        && (protocol < 768
            || mc_packet_bool(packet, value->world_border_hit))
        && (protocol < 759 || mc_packet_varint(packet, value->sequence));
}

bool mc_packet_use_item(McPacket *packet, int protocol,
    const McUseItem *value)
{
    if (packet == NULL || value == NULL || !mc_protocol_supported(protocol)
        || value->hand < 0 || value->hand > 1 || value->sequence < 0
        || !isfinite(value->yaw) || !isfinite(value->pitch)) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (protocol <= 47) {
        const McBlockPlace legacy = {
            .held_item_id = value->held_item_id,
            .held_item_count = value->held_item_count,
            .held_item_damage = value->held_item_damage,
            .held_item_nbt = value->held_item_nbt,
        };
        if (protocol <= 5) {
            if (!mc_packet_i32(packet, -1)
                || !mc_packet_u8(packet, UINT8_MAX)
                || !mc_packet_i32(packet, -1)) {
                return false;
            }
        } else if (!mc_packet_position(packet, protocol,
                (McPosition){-1, -1, -1})) {
            return false;
        }
        return mc_packet_i8(packet, -1)
            && packet_legacy_reported_item(packet, protocol, &legacy)
            && packet_block_place_cursor(packet, protocol, 0.0F, 0.0F, 0.0F);
    }
    return mc_packet_varint(packet, value->hand)
        && (protocol < 759 || mc_packet_varint(packet, value->sequence))
        && (protocol < 767 || (mc_packet_float(packet, value->yaw)
            && mc_packet_float(packet, value->pitch)));
}

bool mc_packet_attack_entity(McPacket *packet, int protocol, int32_t entity_id)
{
    if (packet == NULL || !mc_protocol_supported(protocol) || entity_id <= 0) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    if (protocol >= 775) return mc_packet_varint(packet, entity_id);
    if (protocol <= 5) {
        return mc_packet_i32(packet, entity_id) && mc_packet_i8(packet, 1);
    }
    return mc_packet_varint(packet, entity_id)
        && mc_packet_varint(packet, 1)
        && (protocol < 735 || mc_packet_bool(packet, false));
}

bool mc_packet_respawn_request(McPacket *packet, int protocol)
{
    if (packet == NULL || !mc_protocol_supported(protocol)) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    return protocol <= 5
        ? mc_packet_i8(packet, 0)
        : mc_packet_varint(packet, 0);
}

bool mc_packet_command(McPacket *packet, int protocol, const char *command,
    int64_t timestamp_ms, int64_t salt)
{
    if (packet == NULL || !mc_protocol_supported(protocol) || command == NULL) {
        if (packet != NULL) packet->failed = true;
        return false;
    }
    const char *bare = command[0] == '/' ? command + 1 : command;
    size_t bare_size = strlen(bare);
    if (bare_size == 0U || bare_size > 256U) {
        packet->failed = true;
        return false;
    }
    if (protocol <= 758) {
        return mc_packet_varint(packet, (int32_t)(bare_size + 1U))
            && mc_packet_u8(packet, (uint8_t)'/')
            && mc_packet_bytes(packet, bare, bare_size);
    }
    if (!mc_packet_string_n(packet, bare, bare_size)) return false;
    if (protocol >= 766) return true;
    if (!mc_packet_i64(packet, timestamp_ms)
        || !mc_packet_i64(packet, salt)
        || !mc_packet_varint(packet, 0)) {
        return false;
    }
    if (protocol == 759) {
        return mc_packet_bool(packet, false);
    }
    if (protocol == 760) {
        return mc_packet_bool(packet, false)
            && mc_packet_varint(packet, 0)
            && mc_packet_bool(packet, false);
    }
    static const unsigned char acknowledged[3] = {0U, 0U, 0U};
    return mc_packet_varint(packet, 0)
        && mc_packet_bytes(packet, acknowledged, sizeof(acknowledged));
}

static int32_t position_signed(uint64_t value, unsigned int bits)
{
    uint64_t sign = UINT64_C(1) << (bits - 1U);
    if ((value & sign) != 0U) {
        return (int32_t)((int64_t)value - (INT64_C(1) << bits));
    }
    return (int32_t)value;
}

bool mc_reader_position(McReader *reader, int protocol, McPosition *value)
{
    uint64_t packed = 0U;
    if (value == NULL || !mc_protocol_supported(protocol)
        || !mc_reader_u64(reader, &packed)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    value->x = position_signed(
        (packed >> 38U) & UINT64_C(0x3ffffff), 26U);
    if (protocol >= 477) {
        value->y = position_signed(packed & UINT64_C(0xfff), 12U);
        value->z = position_signed(
            (packed >> 12U) & UINT64_C(0x3ffffff), 26U);
    } else {
        value->y = position_signed(
            (packed >> 26U) & UINT64_C(0xfff), 12U);
        value->z = position_signed(packed & UINT64_C(0x3ffffff), 26U);
    }
    return true;
}

bool mc_reader_clientbound_player_position(McReader *reader, int protocol,
    McClientboundPlayerPosition *value)
{
    McClientboundPlayerPosition decoded = {0};
    if (reader == NULL || value == NULL || !mc_protocol_supported(protocol)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }

    int32_t flags = 0;
    int32_t teleport_id = 0;
    const bool has_delta =
        (mc_protocol_features(protocol) & MC_PROTOCOL_FEATURE_POSITION_DELTA) != 0U;
    if (has_delta) {
        if (!mc_reader_varint(reader, &teleport_id) || teleport_id < 0
            || !mc_reader_double(reader, &decoded.position.x)
            || !mc_reader_double(reader, &decoded.position.y)
            || !mc_reader_double(reader, &decoded.position.z)
            || !mc_reader_double(reader, &decoded.delta_x)
            || !mc_reader_double(reader, &decoded.delta_y)
            || !mc_reader_double(reader, &decoded.delta_z)
            || !mc_reader_float(reader, &decoded.position.yaw)
            || !mc_reader_float(reader, &decoded.position.pitch)
            || !mc_reader_i32(reader, &flags) || flags < 0
            || (flags & ~0x1ff) != 0) {
            reader->failed = true;
            return false;
        }
        decoded.has_velocity_delta = true;
        decoded.has_teleport_id = true;
        decoded.teleport_id = teleport_id;
    } else {
        uint8_t legacy_flags = 0U;
        if (!mc_reader_double(reader, &decoded.position.x)
            || !mc_reader_double(reader, &decoded.position.y)
            || !mc_reader_double(reader, &decoded.position.z)
            || !mc_reader_float(reader, &decoded.position.yaw)
            || !mc_reader_float(reader, &decoded.position.pitch)
            || !mc_reader_u8(reader, &legacy_flags)
            || (legacy_flags & UINT8_C(0xe0)) != 0U) {
            reader->failed = true;
            return false;
        }
        flags = (int32_t)legacy_flags;
        if (protocol <= 5) {
            /* EntityPlayerSP applies the historical eye/stance coordinate;
             * serverbound Position then requires feet followed by stance. */
            decoded.position.y -= 1.6200000047683716;
        }
        if (protocol >= 107) {
            if (!mc_reader_varint(reader, &teleport_id) || teleport_id < 0) {
                reader->failed = true;
                return false;
            }
            decoded.has_teleport_id = true;
            decoded.teleport_id = teleport_id;
        }
        if (protocol >= 755 && protocol <= 762) {
            uint8_t dismount = 0U;
            if (!mc_reader_u8(reader, &dismount) || dismount > 1U) {
                reader->failed = true;
                return false;
            }
            decoded.dismount_vehicle = dismount != 0U;
        }
    }
    if (!isfinite(decoded.position.x) || !isfinite(decoded.position.y)
        || !isfinite(decoded.position.z) || !isfinite(decoded.position.yaw)
        || !isfinite(decoded.position.pitch) || !isfinite(decoded.delta_x)
        || !isfinite(decoded.delta_y) || !isfinite(decoded.delta_z)) {
        reader->failed = true;
        return false;
    }
    decoded.relative_flags = (uint32_t)flags;
    *value = decoded;
    return true;
}

static bool mc_reader_respawn_bool(McReader *reader, bool *value)
{
    uint8_t encoded = 0U;
    if (value == NULL || !mc_reader_u8(reader, &encoded) || encoded > 1U) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    *value = encoded != 0U;
    return true;
}

static bool mc_reader_respawn_keep_data(McReader *reader, int protocol,
    uint8_t *mask)
{
    uint8_t encoded = 0U;
    if (mask == NULL || !mc_reader_u8(reader, &encoded)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    if (protocol >= 761) {
        if ((encoded & ~UINT8_C(3)) != 0U) {
            reader->failed = true;
            return false;
        }
        *mask = encoded;
        return true;
    }
    if (encoded > 1U) {
        reader->failed = true;
        return false;
    }
    *mask = encoded != 0U ? 3U : 0U;
    return true;
}

static bool mc_reader_respawn_last_death(McReader *reader, int protocol,
    McClientboundRespawn *decoded)
{
    bool present = false;
    if (!mc_reader_respawn_bool(reader, &present)) return false;
    decoded->has_last_death_location = present;
    return !present
        || (mc_reader_string(reader, &decoded->last_death_dimension)
            && mc_reader_position(reader, protocol,
                &decoded->last_death_position));
}

static bool mc_reader_respawn_identity_tail(McReader *reader,
    McClientboundRespawn *decoded)
{
    return mc_reader_i64(reader, &decoded->hashed_seed)
        && mc_reader_u8(reader, &decoded->game_mode)
        && mc_reader_i8(reader, &decoded->previous_game_mode)
        && mc_reader_respawn_bool(reader, &decoded->debug)
        && mc_reader_respawn_bool(reader, &decoded->flat);
}

bool mc_reader_clientbound_respawn(McReader *reader, int protocol,
    McClientboundRespawn *value)
{
    McClientboundRespawn decoded = {0};
    if (reader == NULL || value == NULL || !mc_protocol_supported(protocol)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }

    int32_t variable = 0;
    if (protocol <= 404) {
        if (!mc_reader_i32(reader, &decoded.legacy_dimension)
            || !mc_reader_u8(reader, &decoded.difficulty)
            || !mc_reader_u8(reader, &decoded.game_mode)
            || !mc_reader_string(reader, &decoded.level_type)) {
            reader->failed = true;
            return false;
        }
        decoded.has_legacy_dimension = true;
        decoded.has_difficulty = true;
        decoded.has_level_type = true;
    } else if (protocol <= 498) {
        if (!mc_reader_i32(reader, &decoded.legacy_dimension)
            || !mc_reader_u8(reader, &decoded.game_mode)
            || !mc_reader_string(reader, &decoded.level_type)) {
            reader->failed = true;
            return false;
        }
        decoded.has_legacy_dimension = true;
        decoded.has_level_type = true;
    } else if (protocol <= 578) {
        if (!mc_reader_i32(reader, &decoded.legacy_dimension)
            || !mc_reader_i64(reader, &decoded.hashed_seed)
            || !mc_reader_u8(reader, &decoded.game_mode)
            || !mc_reader_string(reader, &decoded.level_type)) {
            reader->failed = true;
            return false;
        }
        decoded.has_legacy_dimension = true;
        decoded.has_hashed_seed = true;
        decoded.has_level_type = true;
    } else if (protocol <= 736) {
        if (!mc_reader_string(reader, &decoded.dimension_identifier)
            || !mc_reader_string(reader, &decoded.world_name)
            || !mc_reader_respawn_identity_tail(reader, &decoded)
            || !mc_reader_respawn_keep_data(reader, protocol,
                &decoded.keep_data_mask)) {
            reader->failed = true;
            return false;
        }
        decoded.has_dimension_identifier = true;
        decoded.has_world_name = true;
        decoded.has_hashed_seed = true;
        decoded.has_previous_game_mode = true;
    } else if (protocol <= 758) {
        if (!mc_reader_nbt(reader, true, &decoded.dimension_nbt)
            || !mc_reader_string(reader, &decoded.world_name)
            || !mc_reader_respawn_identity_tail(reader, &decoded)
            || !mc_reader_respawn_keep_data(reader, protocol,
                &decoded.keep_data_mask)) {
            reader->failed = true;
            return false;
        }
        decoded.has_dimension_nbt = true;
        decoded.has_world_name = true;
        decoded.has_hashed_seed = true;
        decoded.has_previous_game_mode = true;
    } else if (protocol <= 765) {
        if (!mc_reader_string(reader, &decoded.dimension_identifier)
            || !mc_reader_string(reader, &decoded.world_name)
            || !mc_reader_respawn_identity_tail(reader, &decoded)) {
            reader->failed = true;
            return false;
        }
        decoded.has_dimension_identifier = true;
        decoded.has_world_name = true;
        decoded.has_hashed_seed = true;
        decoded.has_previous_game_mode = true;
        if (protocol <= 763
            && !mc_reader_respawn_keep_data(reader, protocol,
                &decoded.keep_data_mask)) {
            reader->failed = true;
            return false;
        }
        if (!mc_reader_respawn_last_death(reader, protocol, &decoded)) {
            reader->failed = true;
            return false;
        }
        if (protocol >= 763) {
            if (!mc_reader_varint(reader, &variable) || variable < 0) {
                reader->failed = true;
                return false;
            }
            decoded.portal_cooldown = variable;
            decoded.has_portal_cooldown = true;
        }
        if (protocol >= 764
            && !mc_reader_respawn_keep_data(reader, protocol,
                &decoded.keep_data_mask)) {
            reader->failed = true;
            return false;
        }
    } else {
        if (!mc_reader_varint(reader, &decoded.dimension_type_id)
            || decoded.dimension_type_id < 0
            || !mc_reader_string(reader, &decoded.world_name)
            || !mc_reader_respawn_identity_tail(reader, &decoded)
            || !mc_reader_respawn_last_death(reader, protocol, &decoded)
            || !mc_reader_varint(reader, &variable) || variable < 0) {
            reader->failed = true;
            return false;
        }
        decoded.has_dimension_type_id = true;
        decoded.has_world_name = true;
        decoded.has_hashed_seed = true;
        decoded.has_previous_game_mode = true;
        decoded.portal_cooldown = variable;
        decoded.has_portal_cooldown = true;
        if (protocol >= 768) {
            if (!mc_reader_varint(reader, &decoded.sea_level)) {
                reader->failed = true;
                return false;
            }
            decoded.has_sea_level = true;
        }
        if (!mc_reader_u8(reader, &decoded.keep_data_mask)
            || (decoded.keep_data_mask & ~UINT8_C(3)) != 0U) {
            reader->failed = true;
            return false;
        }
    }

    if (decoded.game_mode > 3U
        || (decoded.has_previous_game_mode
            && (decoded.previous_game_mode < -1
                || decoded.previous_game_mode > 3))) {
        reader->failed = true;
        return false;
    }
    *value = decoded;
    return true;
}

bool mc_reader_block_change(McReader *reader, int protocol,
    McPosition *position, int32_t *state_id)
{
    McPosition decoded = {0};
    int32_t decoded_state = -1;
    if (reader == NULL || position == NULL || state_id == NULL
        || !mc_protocol_supported(protocol)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    if (protocol <= 5) {
        uint8_t y = 0U;
        uint8_t metadata = 0U;
        int32_t block_id = -1;
        if (!mc_reader_i32(reader, &decoded.x)
            || !mc_reader_u8(reader, &y)
            || !mc_reader_i32(reader, &decoded.z)
            || !mc_reader_varint(reader, &block_id)
            || !mc_reader_u8(reader, &metadata)
            || block_id < 0 || block_id > (INT32_MAX >> 4U)
            || metadata > 15U) {
            reader->failed = true;
            return false;
        }
        decoded.y = (int32_t)y;
        decoded_state = (block_id << 4U) | (int32_t)metadata;
    } else if (!mc_reader_position(reader, protocol, &decoded)) {
        return false;
    } else if (!mc_reader_varint(reader, &decoded_state) || decoded_state < 0) {
        reader->failed = true;
        return false;
    }
    *position = decoded;
    *state_id = decoded_state;
    return true;
}

bool mc_reader_uuid(McReader *reader, McUuid *value)
{
    McBytes bytes;
    if (value == NULL || !mc_reader_bytes(reader, sizeof(value->bytes), &bytes)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    memcpy(value->bytes, bytes.data, sizeof(value->bytes));
    return true;
}

static bool plain_item_failure(McReader *reader)
{
    if (reader != NULL) reader->failed = true;
    return false;
}

bool mc_reader_plain_item(McReader *reader, int protocol,
    int32_t *item_id, int32_t *count)
{
    if (reader == NULL || item_id == NULL || count == NULL
        || !mc_protocol_supported(protocol)) {
        return plain_item_failure(reader);
    }
    *item_id = 0;
    *count = 0;
    if (protocol <= 401) {
        uint16_t encoded_item = 0U;
        if (!mc_reader_u16(reader, &encoded_item)) return false;
        if (encoded_item == UINT16_MAX) return true;
        uint8_t encoded_count = 0U;
        if (!mc_reader_u8(reader, &encoded_count)
            || encoded_item == 0U || encoded_count == 0U
            || encoded_count > 127U) return plain_item_failure(reader);
        if (protocol <= 340) {
            uint16_t damage = 0U;
            if (!mc_reader_u16(reader, &damage) || damage != 0U) {
                return plain_item_failure(reader);
            }
        }
        if (protocol <= 5) {
            int16_t compressed_nbt_size = 0;
            if (!mc_reader_i16(reader, &compressed_nbt_size)
                || compressed_nbt_size != -1) return plain_item_failure(reader);
        } else {
            uint8_t root = UINT8_MAX;
            if (!mc_reader_u8(reader, &root)
                || root != (uint8_t)MC_NBT_END) return plain_item_failure(reader);
        }
        *item_id = encoded_item;
        *count = encoded_count;
        return true;
    }
    if (protocol < 766) {
        uint8_t present = 0U;
        if (!mc_reader_u8(reader, &present) || present > 1U) {
            return plain_item_failure(reader);
        }
        if (present == 0U) return true;
        int32_t encoded_item = 0;
        uint8_t encoded_count = 0U;
        uint8_t root = UINT8_MAX;
        if (!mc_reader_varint(reader, &encoded_item) || encoded_item <= 0
            || !mc_reader_u8(reader, &encoded_count) || encoded_count == 0U
            || encoded_count > 127U || !mc_reader_u8(reader, &root)
            || root != (uint8_t)MC_NBT_END) return plain_item_failure(reader);
        *item_id = encoded_item;
        *count = encoded_count;
        return true;
    }
    int32_t encoded_count = -1;
    if (!mc_reader_varint(reader, &encoded_count)
        || encoded_count < 0 || encoded_count > 127) {
        return plain_item_failure(reader);
    }
    if (encoded_count == 0) return true;
    int32_t encoded_item = 0;
    int32_t added = -1;
    int32_t removed = -1;
    if (!mc_reader_varint(reader, &encoded_item) || encoded_item <= 0
        || !mc_reader_varint(reader, &added) || added != 0
        || !mc_reader_varint(reader, &removed) || removed != 0) {
        return plain_item_failure(reader);
    }
    *item_id = encoded_item;
    *count = encoded_count;
    return true;
}

bool mc_entity_equipment_slot_supported(int protocol, McEquipmentSlot slot)
{
    if (!mc_protocol_supported(protocol) || slot < MC_EQUIPMENT_MAIN_HAND
        || slot >= MC_EQUIPMENT_SLOT_COUNT) {
        return false;
    }
    if (slot == MC_EQUIPMENT_OFF_HAND) return protocol >= 107;
    if (slot == MC_EQUIPMENT_BODY) return protocol >= 766;
    if (slot == MC_EQUIPMENT_SADDLE) return protocol >= 770;
    return true;
}

static bool equipment_slot_normalize(int protocol, int32_t wire_slot,
    McEquipmentSlot *slot)
{
    if (slot == NULL || wire_slot < 0) return false;
    if (protocol <= 47) {
        switch (wire_slot) {
        case 0: *slot = MC_EQUIPMENT_MAIN_HAND; return true;
        case 1: *slot = MC_EQUIPMENT_FEET; return true;
        case 2: *slot = MC_EQUIPMENT_LEGS; return true;
        case 3: *slot = MC_EQUIPMENT_CHEST; return true;
        case 4: *slot = MC_EQUIPMENT_HEAD; return true;
        default: return false;
        }
    }
    if (wire_slot >= (int32_t)MC_EQUIPMENT_SLOT_COUNT) return false;
    *slot = (McEquipmentSlot)wire_slot;
    return mc_entity_equipment_slot_supported(protocol, *slot);
}

static bool reader_entity_equipment_entry(McReader *reader, int protocol,
    int32_t wire_slot, McEntityEquipment *decoded, uint32_t *seen)
{
    McEquipmentSlot slot = MC_EQUIPMENT_MAIN_HAND;
    McEntityEquipmentEntry entry = {0};
    if (!equipment_slot_normalize(protocol, wire_slot, &slot)
        || decoded->entry_count >= MC_ENTITY_EQUIPMENT_MAX_ENTRIES
        || (*seen & (UINT32_C(1) << (uint32_t)slot)) != 0U
        || !mc_reader_plain_item(reader, protocol,
            &entry.item_id, &entry.count)) {
        reader->failed = true;
        return false;
    }
    entry.slot = slot;
    *seen |= UINT32_C(1) << (uint32_t)slot;
    decoded->entries[decoded->entry_count++] = entry;
    return true;
}

bool mc_reader_entity_equipment(McReader *reader, int protocol,
    McEntityEquipment *value)
{
    McEntityEquipment decoded = {0};
    if (reader == NULL || value == NULL || !mc_protocol_supported(protocol)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    if (protocol <= 5) {
        if (!mc_reader_i32(reader, &decoded.entity_id)) return false;
    } else if (!mc_reader_varint(reader, &decoded.entity_id)) {
        return false;
    }
    if (decoded.entity_id < 0) {
        reader->failed = true;
        return false;
    }

    uint32_t seen = 0U;
    if (protocol <= 47) {
        uint16_t wire_slot = 0U;
        if (!mc_reader_u16(reader, &wire_slot)
            || !reader_entity_equipment_entry(reader, protocol,
                (int32_t)wire_slot, &decoded, &seen)) {
            return false;
        }
    } else if (protocol < 735) {
        int32_t wire_slot = -1;
        if (!mc_reader_varint(reader, &wire_slot)
            || !reader_entity_equipment_entry(reader, protocol,
                wire_slot, &decoded, &seen)) {
            return false;
        }
    } else {
        bool more = false;
        do {
            uint8_t encoded_slot = 0U;
            if (!mc_reader_u8(reader, &encoded_slot)
                || !reader_entity_equipment_entry(reader, protocol,
                    (int32_t)(encoded_slot & UINT8_C(0x7f)),
                    &decoded, &seen)) {
                return false;
            }
            more = (encoded_slot & UINT8_C(0x80)) != 0U;
        } while (more);
    }
    *value = decoded;
    return true;
}

static uint8_t entity_hand_use_metadata_index(int protocol)
{
    if (protocol < 107) return 0U;
    if (protocol <= 110) return 5U;
    if (protocol <= 404) return 6U;
    if (protocol <= 754) return 7U;
    return 8U;
}

bool mc_reader_entity_hand_use_metadata(McReader *reader, int protocol,
    McEntityHandUseMetadata *value)
{
    McEntityHandUseMetadata decoded = {0};
    if (reader == NULL || value == NULL || !mc_protocol_supported(protocol)) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    if (protocol <= 5) {
        if (!mc_reader_i32(reader, &decoded.entity_id)) return false;
    } else if (!mc_reader_varint(reader, &decoded.entity_id)) {
        return false;
    }
    if (decoded.entity_id < 0) {
        reader->failed = true;
        return false;
    }

    decoded.metadata_index = entity_hand_use_metadata_index(protocol);
    if (protocol <= 47) {
        uint8_t packed_header = UINT8_MAX;
        if (!mc_reader_u8(reader, &packed_header)
            || packed_header != decoded.metadata_index) {
            reader->failed = true;
            return false;
        }
    } else {
        uint8_t index = UINT8_MAX;
        int32_t serializer = -1;
        uint8_t legacy_serializer = UINT8_MAX;
        if (!mc_reader_u8(reader, &index) || index != decoded.metadata_index) {
            reader->failed = true;
            return false;
        }
        const bool serializer_ok =
            protocol <= 340
                ? (mc_reader_u8(reader, &legacy_serializer)
                    && legacy_serializer == 0U)
                : (mc_reader_varint(reader, &serializer) && serializer == 0);
        if (!serializer_ok) {
            reader->failed = true;
            return false;
        }
    }
    uint8_t terminator = 0U;
    if (!mc_reader_u8(reader, &decoded.raw_flags)
        || !mc_reader_u8(reader, &terminator)
        || terminator != (protocol <= 47 ? UINT8_C(0x7f) : UINT8_C(0xff))) {
        reader->failed = true;
        return false;
    }
    decoded.uses_living_flags = protocol >= 107;
    decoded.active = (decoded.raw_flags
        & (decoded.uses_living_flags ? UINT8_C(0x01) : UINT8_C(0x10))) != 0U;
    decoded.off_hand = decoded.uses_living_flags && decoded.active
        && (decoded.raw_flags & UINT8_C(0x02)) != 0U;
    *value = decoded;
    return true;
}

bool mc_reader_nbt_name(McReader *reader, McBytes *name)
{
    uint16_t size = 0U;
    return name != NULL && mc_reader_u16(reader, &size)
        && mc_reader_bytes(reader, (size_t)size, name);
}

#define MC_NBT_MAX_DEPTH 64U

/* A length from the wire must be checked before multiplication. This matters
 * on 32-bit builds where a valid signed NBT count can still overflow size_t
 * when converted into an int or long array byte length. */
static bool nbt_skip_array(McReader *reader, size_t width)
{
    int32_t count = -1;
    if (!mc_reader_i32(reader, &count) || count < 0
        || (size_t)count > SIZE_MAX / width) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    return mc_reader_skip(reader, (size_t)count * width);
}

static bool nbt_skip_value(McReader *reader, McNbtType type,
    unsigned int depth)
{
    if (reader == NULL || reader->failed || depth > MC_NBT_MAX_DEPTH) {
        if (reader != NULL) reader->failed = true;
        return false;
    }
    switch (type) {
    case MC_NBT_BYTE:
        return mc_reader_skip(reader, 1U);
    case MC_NBT_SHORT:
        return mc_reader_skip(reader, 2U);
    case MC_NBT_INT:
    case MC_NBT_FLOAT:
        return mc_reader_skip(reader, 4U);
    case MC_NBT_LONG:
    case MC_NBT_DOUBLE:
        return mc_reader_skip(reader, 8U);
    case MC_NBT_BYTE_ARRAY:
        return nbt_skip_array(reader, 1U);
    case MC_NBT_STRING: {
        McBytes ignored;
        return mc_reader_nbt_name(reader, &ignored);
    }
    case MC_NBT_LIST: {
        uint8_t element = 0U;
        int32_t count = -1;
        if (!mc_reader_u8(reader, &element)
            || !mc_reader_i32(reader, &count) || count < 0
            || element > (uint8_t)MC_NBT_LONG_ARRAY
            || (element == (uint8_t)MC_NBT_END && count != 0)) {
            reader->failed = true;
            return false;
        }
        for (int32_t index = 0; index < count; ++index) {
            if (!nbt_skip_value(reader, (McNbtType)element, depth + 1U)) {
                return false;
            }
        }
        return true;
    }
    case MC_NBT_COMPOUND:
        for (;;) {
            uint8_t child = 0U;
            if (!mc_reader_u8(reader, &child)) return false;
            if (child == (uint8_t)MC_NBT_END) return true;
            McBytes ignored;
            if (child > (uint8_t)MC_NBT_LONG_ARRAY
                || !mc_reader_nbt_name(reader, &ignored)
                || !nbt_skip_value(reader, (McNbtType)child, depth + 1U)) {
                reader->failed = true;
                return false;
            }
        }
    case MC_NBT_INT_ARRAY:
        return nbt_skip_array(reader, 4U);
    case MC_NBT_LONG_ARRAY:
        return nbt_skip_array(reader, 8U);
    default:
        reader->failed = true;
        return false;
    }
}

bool mc_reader_nbt_value(McReader *reader, McNbtType type, McBytes *encoded)
{
    if (reader == NULL || reader->failed) return false;
    size_t start = reader->offset;
    if (!nbt_skip_value(reader, type, 0U)) return false;
    if (encoded != NULL) {
        encoded->data = reader->data + start;
        encoded->size = reader->offset - start;
    }
    return true;
}

bool mc_reader_nbt(McReader *reader, bool named_root, McBytes *encoded)
{
    if (reader == NULL || reader->failed) return false;
    size_t start = reader->offset;
    uint8_t root = 0U;
    if (!mc_reader_u8(reader, &root)
        || root > (uint8_t)MC_NBT_LONG_ARRAY) {
        reader->failed = true;
        return false;
    }
    if (root != (uint8_t)MC_NBT_END) {
        McBytes ignored;
        if ((named_root && !mc_reader_nbt_name(reader, &ignored))
            || !nbt_skip_value(reader, (McNbtType)root, 0U)) {
            reader->failed = true;
            return false;
        }
    }
    if (encoded != NULL) {
        encoded->data = reader->data + start;
        encoded->size = reader->offset - start;
    }
    return true;
}
#undef MC_NBT_MAX_DEPTH

/* State and packet callbacks are synchronous. This keeps the body lifetime
 * obvious and prevents hidden worker threads from serializing application
 * callbacks behind the caller's back. */
static void change_state(McClient *client, McState state)
{
    if (client->state == state) return;
    McState previous = client->state;
    client->state = state;
    if (client->callbacks.on_state != NULL) {
        client->callbacks.on_state(client->userdata, previous, state);
    }
}

static void emit_packet(McClient *client, McState state, int32_t packet_id,
    const McCursor *cursor)
{
    if (client->callbacks.on_packet == NULL) return;
    client->callbacks.on_packet(client->userdata, state, packet_id,
        cursor->data + cursor->offset, cursor->size - cursor->offset);
}


/* ============================================================
 * NETWORK BACKENDS
 * ============================================================ */

#if defined(__linux__)
/* The kernel owns the io_uring head/tail fields concurrently with this
 * process. Acquire/release accesses are required even though this library
 * submits only one readiness operation at a time. */
static unsigned int load_u32(const unsigned int *value)
{
    return __atomic_load_n(value, __ATOMIC_ACQUIRE);
}

static void store_u32(unsigned int *target, unsigned int value)
{
    __atomic_store_n(target, value, __ATOMIC_RELEASE);
}

static void ring_close(McRing *ring)
{
    if (ring->sqes != NULL) (void)munmap(ring->sqes, ring->sqes_size);
    if (ring->sq_map != NULL) (void)munmap(ring->sq_map, ring->sq_map_size);
    if (!ring->single_map && ring->cq_map != NULL) {
        (void)munmap(ring->cq_map, ring->cq_map_size);
    }
    if (ring->fd >= 0) (void)close(ring->fd);
    memset(ring, 0, sizeof(*ring));
    ring->fd = -1;
}

static int ring_init(McRing *ring)
{
    memset(ring, 0, sizeof(*ring));
    ring->fd = -1;
    struct io_uring_params parameters;
    memset(&parameters, 0, sizeof(parameters));
    int fd = (int)syscall(__NR_io_uring_setup, 8U, &parameters);
    if (fd < 0) return -1;
    ring->fd = fd;
    ring->sq_map_size = parameters.sq_off.array
        + parameters.sq_entries * sizeof(unsigned int);
    ring->cq_map_size = parameters.cq_off.cqes
        + parameters.cq_entries * sizeof(struct io_uring_cqe);
    ring->single_map = (parameters.features & IORING_FEAT_SINGLE_MMAP) != 0U;
    if (ring->single_map && ring->cq_map_size > ring->sq_map_size) {
        ring->sq_map_size = ring->cq_map_size;
    }
    ring->sq_map = mmap(NULL, ring->sq_map_size, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQ_RING);
    if (ring->sq_map == MAP_FAILED) {
        ring->sq_map = NULL;
        ring_close(ring);
        return -1;
    }
    if (ring->single_map) {
        ring->cq_map = ring->sq_map;
        ring->cq_map_size = ring->sq_map_size;
    } else {
        ring->cq_map = mmap(NULL, ring->cq_map_size, PROT_READ | PROT_WRITE,
            MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_CQ_RING);
        if (ring->cq_map == MAP_FAILED) {
            ring->cq_map = NULL;
            ring_close(ring);
            return -1;
        }
    }
    ring->sqes_size = parameters.sq_entries * sizeof(struct io_uring_sqe);
    ring->sqes = mmap(NULL, ring->sqes_size, PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_POPULATE, fd, IORING_OFF_SQES);
    if (ring->sqes == MAP_FAILED) {
        ring->sqes = NULL;
        ring_close(ring);
        return -1;
    }
    unsigned char *sq = ring->sq_map;
    unsigned char *cq = ring->cq_map;
    ring->sq_head = (unsigned int *)(void *)(sq + parameters.sq_off.head);
    ring->sq_tail = (unsigned int *)(void *)(sq + parameters.sq_off.tail);
    ring->sq_mask = (unsigned int *)(void *)(sq + parameters.sq_off.ring_mask);
    ring->sq_array = (unsigned int *)(void *)(sq + parameters.sq_off.array);
    ring->cq_head = (unsigned int *)(void *)(cq + parameters.cq_off.head);
    ring->cq_tail = (unsigned int *)(void *)(cq + parameters.cq_off.tail);
    ring->cq_mask = (unsigned int *)(void *)(cq + parameters.cq_off.ring_mask);
    ring->cqes = (struct io_uring_cqe *)(void *)(cq + parameters.cq_off.cqes);
    return 0;
}

/* Read readiness and its timeout are linked, so exactly one decides the public
 * result while both completion entries are consumed before the stack-allocated
 * timeout leaves scope. -2 is deliberately internal: it asks backend_wait()
 * to preserve the connection and replace io_uring with epoll. */
static int ring_wait(McRing *ring, int socket_fd, unsigned int timeout_ms)
{
    unsigned int head = load_u32(ring->sq_head);
    unsigned int tail = load_u32(ring->sq_tail);
    if (tail - head + 2U > 8U) return -2;
    unsigned int mask = *ring->sq_mask;
    struct io_uring_sqe *poll_sqe = &ring->sqes[tail & mask];
    struct io_uring_sqe *timeout_sqe = &ring->sqes[(tail + 1U) & mask];
    memset(poll_sqe, 0, sizeof(*poll_sqe));
    memset(timeout_sqe, 0, sizeof(*timeout_sqe));
    struct __kernel_timespec timeout = {
        .tv_sec = (int64_t)(timeout_ms / 1000U),
        .tv_nsec = (long long)(timeout_ms % 1000U) * 1000000LL
    };
    poll_sqe->opcode = IORING_OP_POLL_ADD;
    poll_sqe->fd = socket_fd;
    poll_sqe->poll_events = POLLIN;
    poll_sqe->flags = IOSQE_IO_LINK;
    poll_sqe->user_data = 1U;
    timeout_sqe->opcode = IORING_OP_LINK_TIMEOUT;
    timeout_sqe->addr = (uint64_t)(uintptr_t)&timeout;
    timeout_sqe->len = 1U;
    timeout_sqe->user_data = 2U;
    ring->sq_array[tail & mask] = tail & mask;
    ring->sq_array[(tail + 1U) & mask] = (tail + 1U) & mask;
    store_u32(ring->sq_tail, tail + 2U);

    int entered;
    do {
        entered = (int)syscall(__NR_io_uring_enter, ring->fd, 2U, 1U,
            IORING_ENTER_GETEVENTS, NULL, 0U);
    } while (entered < 0 && errno == EINTR);
    if (entered < 0) return -2;

    int poll_result = -ECANCELED;
    unsigned int completed = 0U;
    while (completed < 2U) {
        unsigned int cq_head = load_u32(ring->cq_head);
        unsigned int cq_tail = load_u32(ring->cq_tail);
        while (cq_head != cq_tail && completed < 2U) {
            struct io_uring_cqe *cqe = &ring->cqes[cq_head & *ring->cq_mask];
            if (cqe->user_data == 1U) poll_result = cqe->res;
            ++cq_head;
            ++completed;
        }
        store_u32(ring->cq_head, cq_head);
        if (completed < 2U) {
            do {
                entered = (int)syscall(__NR_io_uring_enter, ring->fd, 0U, 1U,
                    IORING_ENTER_GETEVENTS, NULL, 0U);
            } while (entered < 0 && errno == EINTR);
            if (entered < 0) return -2;
        }
    }
    if (poll_result >= 0) return (poll_result & POLLIN) != 0 ? 1 : 0;
    if (poll_result == -ECANCELED) return 0;
    return -2;
}
#endif

static void backend_close(McClient *client)
{
#if defined(__linux__)
    if (client->backend == MC_BACKEND_IO_URING) ring_close(&client->ring);
#endif
    if (client->event_fd >= 0) (void)close(client->event_fd);
    client->event_fd = -1;
    client->backend = MC_BACKEND_NONE;
}

#if defined(__linux__)
static int backend_epoll(McClient *client, int socket_fd)
{
    int epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0) return -1;
    struct epoll_event event;
    memset(&event, 0, sizeof(event));
    event.events = EPOLLIN;
    event.data.fd = socket_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, socket_fd, &event) != 0) {
        (void)close(epoll_fd);
        return -1;
    }
    client->event_fd = epoll_fd;
    client->backend = MC_BACKEND_EPOLL;
    return 0;
}
#endif

static int backend_init(McClient *client, int socket_fd)
{
    /* Prefer the native scalable interface, but retain poll as the portability
     * floor. Automatic fallback is safe here because all backends implement the
     * same one-socket readiness contract and no application state is lost. */
    backend_close(client);
    if (client->preferred_backend == MC_BACKEND_POLL) {
        client->backend = MC_BACKEND_POLL;
        return 0;
    }
#if defined(__APPLE__)
    int queue = client->preferred_backend == MC_BACKEND_NONE
            || client->preferred_backend == MC_BACKEND_KQUEUE
        ? kqueue() : -1;
    if (queue >= 0) {
        struct kevent change;
        EV_SET(&change, (uintptr_t)socket_fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
        if (kevent(queue, &change, 1, NULL, 0, NULL) == 0) {
            client->event_fd = queue;
            client->backend = MC_BACKEND_KQUEUE;
            return 0;
        }
        (void)close(queue);
    }
    if (client->preferred_backend == MC_BACKEND_KQUEUE) return -1;
#elif defined(__linux__)
    if (client->preferred_backend != MC_BACKEND_EPOLL
        && ring_init(&client->ring) == 0) {
        client->backend = MC_BACKEND_IO_URING;
        return 0;
    }
    if (client->preferred_backend == MC_BACKEND_IO_URING) return -1;
    if (backend_epoll(client, socket_fd) == 0) return 0;
    if (client->preferred_backend == MC_BACKEND_EPOLL) return -1;
#endif
    client->backend = MC_BACKEND_POLL;
    return 0;
}

static int backend_wait(McClient *client, unsigned int timeout_ms)
{
    int socket_fd = atomic_load(&client->socket_fd);
#if defined(__APPLE__)
    if (client->backend == MC_BACKEND_KQUEUE) {
        struct kevent event;
        struct timespec timeout = {
            .tv_sec = (time_t)(timeout_ms / 1000U),
            .tv_nsec = (long)(timeout_ms % 1000U) * 1000000L
        };
        int result;
        do {
            result = kevent(client->event_fd, NULL, 0, &event, 1, &timeout);
        } while (result < 0 && errno == EINTR);
        return result;
    }
#elif defined(__linux__)
    if (client->backend == MC_BACKEND_IO_URING) {
        int result = ring_wait(&client->ring, socket_fd, timeout_ms);
        if (result != -2) return result;
        ring_close(&client->ring);
        if (client->preferred_backend == MC_BACKEND_IO_URING) {
            errno = EIO;
            return -1;
        }
        if (backend_epoll(client, socket_fd) != 0) {
            client->backend = MC_BACKEND_POLL;
        }
    }
    if (client->backend == MC_BACKEND_EPOLL) {
        struct epoll_event event;
        int result;
        do {
            result = epoll_wait(client->event_fd, &event, 1, (int)timeout_ms);
        } while (result < 0 && errno == EINTR);
        return result;
    }
#endif
    struct pollfd descriptor = {.fd = socket_fd, .events = POLLIN, .revents = 0};
    int result;
    do {
        result = poll(&descriptor, 1U, (int)timeout_ms);
    } while (result < 0 && errno == EINTR);
    return result;
}

const char *mc_backend_name(McBackend backend)
{
    switch (backend) {
    case MC_BACKEND_IO_URING: return "io_uring";
    case MC_BACKEND_KQUEUE: return "kqueue";
    case MC_BACKEND_EPOLL: return "epoll";
    case MC_BACKEND_POLL: return "poll";
    default: return "none";
    }
}

McBackend mc_client_backend(const McClient *client)
{
    return client != NULL ? client->backend : MC_BACKEND_NONE;
}

int mc_client_set_backend(McClient *client, McBackend backend,
    char *error, size_t error_size)
{
    if (client == NULL || atomic_load(&client->socket_fd) >= 0) {
        set_error(error, error_size,
            "Il backend puo essere scelto soltanto prima della connessione");
        return -1;
    }
    if (backend < MC_BACKEND_NONE || backend > MC_BACKEND_POLL) {
        set_error(error, error_size, "Backend non valido");
        return -1;
    }
#if defined(__APPLE__)
    if (backend == MC_BACKEND_IO_URING || backend == MC_BACKEND_EPOLL) {
        set_error(error, error_size, "Backend non disponibile su macOS");
        return -1;
    }
#elif defined(__linux__)
    if (backend == MC_BACKEND_KQUEUE) {
        set_error(error, error_size, "Backend non disponibile su Linux");
        return -1;
    }
#else
    if (backend != MC_BACKEND_NONE && backend != MC_BACKEND_POLL) {
        set_error(error, error_size, "Backend non disponibile su questa piattaforma");
        return -1;
    }
#endif
    client->preferred_backend = backend;
    return 0;
}

int mc_client_set_automatic_replies(McClient *client, uint32_t replies,
    char *error, size_t error_size)
{
    if (client == NULL || atomic_load(&client->socket_fd) >= 0) {
        set_error(error, error_size,
            "Le risposte automatiche vanno configurate prima della connessione");
        return -1;
    }
    if ((replies & ~(uint32_t)MC_AUTOMATIC_ALL) != 0U) {
        set_error(error, error_size, "Maschera risposte automatiche non valida");
        return -1;
    }
    client->automatic_replies = replies;
    return 0;
}

int mc_client_wait(McClient *client, unsigned int timeout_ms,
    char *error, size_t error_size)
{
    if (client == NULL || atomic_load(&client->socket_fd) < 0) {
        set_error(error, error_size, "Client non connesso");
        return -1;
    }
    int result = backend_wait(client, timeout_ms);
    if (result < 0) {
        set_error(error, error_size, "Attesa socket fallita: %s", strerror(errno));
        return -1;
    }
    return result > 0 ? 1 : 0;
}


/* ============================================================
 * TRANSPORT / TCP
 * ============================================================ */

/* Try every resolved address because localhost and real servers commonly
 * publish both IPv6 and IPv4. A failure in one address family must not prevent
 * a valid address later in the getaddrinfo() list from connecting. */
static int connect_tcp(const char *host, uint16_t port, char *error, size_t size)
{
    char service[6];
    (void)snprintf(service, sizeof(service), "%u", (unsigned int)port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    struct addrinfo *addresses = NULL;
    int resolved = getaddrinfo(host, service, &hints, &addresses);
    if (resolved != 0) {
        set_error(error, size, "DNS: %s", gai_strerror(resolved));
        return -1;
    }
    int connected = -1;
    for (const struct addrinfo *address = addresses; address != NULL;
         address = address->ai_next) {
        int socket_fd = socket(address->ai_family, address->ai_socktype,
            address->ai_protocol);
        if (socket_fd < 0) continue;
#if defined(__APPLE__) && defined(SO_NOSIGPIPE)
        int enabled = 1;
        (void)setsockopt(socket_fd, SOL_SOCKET, SO_NOSIGPIPE,
            &enabled, sizeof(enabled));
#endif
        if (connect(socket_fd, address->ai_addr, address->ai_addrlen) == 0) {
            int no_delay = 1;
            (void)setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY,
                &no_delay, (socklen_t)sizeof(no_delay));
            connected = socket_fd;
            break;
        }
        (void)close(socket_fd);
    }
    freeaddrinfo(addresses);
    if (connected < 0) set_error(error, size, "Connessione TCP fallita: %s", strerror(errno));
    return connected;
}

static int bind_tcp(const char *host, uint16_t port, int backlog,
    uint16_t *bound_port, char *error, size_t error_size)
{
    char service[6];
    (void)snprintf(service, sizeof(service), "%u", (unsigned int)port);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;
    struct addrinfo *addresses = NULL;
    int resolved = getaddrinfo(
        host != NULL && host[0] != '\0' ? host : NULL,
        service, &hints, &addresses);
    if (resolved != 0) {
        set_error(error, error_size, "Bind DNS: %s", gai_strerror(resolved));
        return -1;
    }
    int listener = -1;
    for (const struct addrinfo *address = addresses; address != NULL;
         address = address->ai_next) {
        int candidate = socket(address->ai_family, address->ai_socktype,
            address->ai_protocol);
        if (candidate < 0) continue;
        int enabled = 1;
        (void)setsockopt(candidate, SOL_SOCKET, SO_REUSEADDR,
            &enabled, (socklen_t)sizeof(enabled));
        if (bind(candidate, address->ai_addr, address->ai_addrlen) == 0
            && listen(candidate, backlog) == 0) {
            listener = candidate;
            break;
        }
        (void)close(candidate);
    }
    freeaddrinfo(addresses);
    if (listener < 0) {
        set_error(error, error_size, "Bind/listen TCP fallito: %s",
            strerror(errno));
        return -1;
    }
    struct sockaddr_storage address;
    socklen_t address_size = (socklen_t)sizeof(address);
    if (getsockname(listener, (struct sockaddr *)(void *)&address,
            &address_size) != 0) {
        set_error(error, error_size, "getsockname fallita: %s", strerror(errno));
        (void)close(listener);
        return -1;
    }
    if (address.ss_family == AF_INET) {
        const struct sockaddr_in *ipv4 = (const struct sockaddr_in *)(const void *)&address;
        *bound_port = ntohs(ipv4->sin_port);
    } else if (address.ss_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6 = (const struct sockaddr_in6 *)(const void *)&address;
        *bound_port = ntohs(ipv6->sin6_port);
    } else {
        set_error(error, error_size, "Famiglia socket listener non valida");
        (void)close(listener);
        return -1;
    }
    return listener;
}

static int send_all(McClient *client, const unsigned char *data, size_t size,
    char *error, size_t error_size)
{
    unsigned char *transformed = NULL;
    const unsigned char *wire = data;
    if (client->transforms.encrypt != NULL && size != 0U) {
        transformed = malloc(size);
        if (transformed == NULL) {
            set_error(error, error_size,
                "Memoria insufficiente per la cifratura stream");
            return -1;
        }
        memcpy(transformed, data, size);
        if (client->transforms.encrypt(client->transforms.userdata,
                transformed, size) != 0) {
            free(transformed);
            set_error(error, error_size, "Cifratura stream fallita");
            return -1;
        }
        wire = transformed;
    }
    int socket_fd = atomic_load(&client->socket_fd);
    size_t sent = 0U;
    while (sent < size) {
#ifdef MSG_NOSIGNAL
        ssize_t result = send(socket_fd, wire + sent, size - sent, MSG_NOSIGNAL);
#else
        ssize_t result = send(socket_fd, wire + sent, size - sent, 0);
#endif
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) {
            set_error(error, error_size, "Invio socket fallito: %s", strerror(errno));
            free(transformed);
            return -1;
        }
        sent += (size_t)result;
        client->sent_bytes += (uint64_t)result;
    }
    free(transformed);
    return 0;
}

/* Framing code needs exact byte counts: a short TCP read is progress, not a
 * short Minecraft packet. These loops also keep traffic counters at the only
 * layer that observes every on-wire byte. */
static int receive_all(McClient *client, unsigned char *data, size_t size,
    char *error, size_t error_size)
{
    int socket_fd = atomic_load(&client->socket_fd);
    size_t received = 0U;
    while (received < size) {
        ssize_t result = recv(socket_fd, data + received, size - received,
#ifdef MSG_DONTWAIT
            MSG_DONTWAIT
#else
            0
#endif
        );
        if (result < 0 && errno == EINTR) continue;
        if (result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            int ready = backend_wait(client, client->read_timeout_ms);
            if (ready > 0) continue;
            set_error(error, error_size, ready == 0
                ? "Timeout durante la ricezione del frame"
                : "Attesa frame fallita: %s", strerror(errno));
            return -1;
        }
        if (result <= 0) {
            set_error(error, error_size, result == 0
                ? "Connessione chiusa dal server" : "Lettura socket fallita: %s",
                strerror(errno));
            return -1;
        }
        received += (size_t)result;
        client->received_bytes += (uint64_t)result;
        if (client->transforms.decrypt != NULL
            && client->transforms.decrypt(client->transforms.userdata,
                data + received - (size_t)result, (size_t)result) != 0) {
            set_error(error, error_size, "Decifratura stream fallita");
            return -1;
        }
    }
    return 0;
}


/* ============================================================
 * FRAMING / COMPRESSION
 * ============================================================ */

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

static int encode_frame(const McClient *client, int32_t packet_id,
    const void *payload, size_t payload_size, unsigned char **encoded,
    size_t *encoded_size, char *error, size_t error_size)
{
    if (client == NULL || encoded == NULL || encoded_size == NULL
        || packet_id < 0 || payload_size > MC_MAX_PACKET
        || (payload_size != 0U && payload == NULL)) {
        set_error(error, error_size, "Packet ID o payload non valido");
        return -1;
    }
    *encoded = NULL;
    *encoded_size = 0U;
    unsigned char id_bytes[5];
    size_t id_size = encode_varint(id_bytes, packet_id);
    size_t plain_size = id_size + payload_size;
    unsigned char *plain = malloc(plain_size == 0U ? 1U : plain_size);
    if (plain == NULL) {
        set_error(error, error_size, "Memoria insufficiente");
        return -1;
    }
    memcpy(plain, id_bytes, id_size);
    if (payload_size != 0U) memcpy(plain + id_size, payload, payload_size);

    unsigned char data_length[5];
    size_t data_length_size = 0U;
    unsigned char *inner = plain;
    size_t inner_size = plain_size;
    unsigned char *compressed = NULL;
    if (client->compression_threshold >= 0) {
        if (plain_size >= (size_t)client->compression_threshold) {
            uLongf capacity = compressBound((uLong)plain_size);
            compressed = malloc((size_t)capacity);
            if (compressed == NULL
                || compress2(compressed, &capacity, plain, (uLong)plain_size,
                    Z_DEFAULT_COMPRESSION) != Z_OK) {
                free(compressed);
                free(plain);
                set_error(error, error_size, "Compressione zlib fallita");
                return -1;
            }
            data_length_size = encode_varint(data_length, (int32_t)plain_size);
            inner = compressed;
            inner_size = (size_t)capacity;
        } else {
            data_length[0] = 0U;
            data_length_size = 1U;
        }
    }
    size_t framed_size = data_length_size + inner_size;
    if (framed_size > INT32_MAX) {
        free(compressed);
        free(plain);
        set_error(error, error_size, "Frame troppo grande");
        return -1;
    }
    unsigned char frame_length[5];
    size_t frame_length_size = encode_varint(frame_length, (int32_t)framed_size);
    size_t wire_size = frame_length_size + framed_size;
    unsigned char *wire = malloc(wire_size);
    if (wire == NULL) {
        free(compressed);
        free(plain);
        set_error(error, error_size, "Memoria insufficiente");
        return -1;
    }
    size_t offset = 0U;
    memcpy(wire + offset, frame_length, frame_length_size);
    offset += frame_length_size;
    if (data_length_size != 0U) {
        memcpy(wire + offset, data_length, data_length_size);
        offset += data_length_size;
    }
    memcpy(wire + offset, inner, inner_size);
    free(compressed);
    free(plain);
    *encoded = wire;
    *encoded_size = wire_size;
    return 0;
}

static int send_frame(McClient *client, int32_t packet_id,
    const void *payload, size_t payload_size, char *error, size_t error_size)
{
    unsigned char *wire = NULL;
    size_t wire_size = 0U;
    if (encode_frame(client, packet_id, payload, payload_size,
            &wire, &wire_size, error, error_size) != 0) return -1;
    int result = send_all(client, wire, wire_size, error, error_size);
    free(wire);
    return result;
}

static int read_socket_varint(McClient *client, int32_t *value,
    char *error, size_t error_size)
{
    uint32_t result = 0U;
    for (unsigned int index = 0U; index < 5U; ++index) {
        unsigned char byte = 0U;
        if (receive_all(client, &byte, 1U, error, error_size) != 0) return -1;
        result |= (uint32_t)(byte & 0x7fU) << (index * 7U);
        if ((byte & 0x80U) == 0U) {
            *value = (int32_t)result;
            return 0;
        }
    }
    set_error(error, error_size, "VarInt frame non valido");
    return -1;
}

static int read_frame(McClient *client, McFrame *packet,
    char *error, size_t error_size)
{
    packet->data = NULL;
    packet->size = 0U;
    int32_t encoded_size = 0;
    if (read_socket_varint(client, &encoded_size, error, error_size) != 0) return -1;
    /* Validate advertised sizes before allocating or entering zlib. Apart from
     * bounding memory use, this prevents a tiny hostile frame from claiming an
     * arbitrarily large decompressed destination. */
    if (encoded_size <= 0 || (uint32_t)encoded_size > MC_MAX_PACKET) {
        set_error(error, error_size, "Lunghezza frame non valida: %d", encoded_size);
        return -1;
    }
    size_t frame_size = (size_t)encoded_size;
    unsigned char *frame = malloc(frame_size);
    if (frame == NULL || receive_all(client, frame, frame_size,
            error, error_size) != 0) {
        free(frame);
        if (frame == NULL) set_error(error, error_size, "Memoria insufficiente");
        return -1;
    }
    if (client->compression_threshold < 0) {
        packet->data = frame;
        packet->size = frame_size;
        return 0;
    }
    McCursor cursor;
    mc_reader_init(&cursor, frame, frame_size);
    int32_t uncompressed_size = 0;
    if (!mc_reader_varint(&cursor, &uncompressed_size) || uncompressed_size < 0
        || (uint32_t)uncompressed_size > MC_MAX_PACKET) {
        free(frame);
        set_error(error, error_size, "Header compressione non valido");
        return -1;
    }
    size_t body_size = frame_size - cursor.offset;
    if (uncompressed_size == 0) {
        memmove(frame, frame + cursor.offset, body_size);
        packet->data = frame;
        packet->size = body_size;
        return 0;
    }
    unsigned char *plain = malloc((size_t)uncompressed_size);
    if (plain == NULL) {
        free(frame);
        set_error(error, error_size, "Memoria insufficiente");
        return -1;
    }
    uLongf destination = (uLongf)uncompressed_size;
    int zresult = uncompress(plain, &destination, frame + cursor.offset,
        (uLong)body_size);
    free(frame);
    if (zresult != Z_OK || destination != (uLongf)uncompressed_size) {
        free(plain);
        set_error(error, error_size, "Frame zlib non valido");
        return -1;
    }
    packet->data = plain;
    packet->size = (size_t)destination;
    return 0;
}


/* ============================================================
 * AUTH / UUID / LOGIN HELPERS
 * ============================================================ */

/* Offline UUIDs are specified as the version-3 UUID of
 * "OfflinePlayer:<name>". MD5 is implemented locally only for that protocol
 * identity rule; it is not exposed or used as a security primitive. The input
 * is at most 30 bytes, therefore exactly one MD5 block is sufficient. */
static int uuid_hex_value(unsigned char value)
{
    if (value >= '0' && value <= '9') return (int)(value - '0');
    if (value >= 'a' && value <= 'f') return (int)(value - 'a') + 10;
    if (value >= 'A' && value <= 'F') return (int)(value - 'A') + 10;
    return -1;
}

bool mc_uuid_parse(const char *text, McUuid *uuid)
{
    if (text == NULL || uuid == NULL) return false;
    size_t length = strlen(text);
    if (length != 32U && length != 36U) return false;
    McUuid parsed = {{0}};
    size_t input = 0U;
    for (size_t output = 0U; output < sizeof(parsed.bytes); ++output) {
        if (length == 36U
            && (input == 8U || input == 13U || input == 18U || input == 23U)) {
            if (text[input] != '-') return false;
            ++input;
        }
        int high = uuid_hex_value((unsigned char)text[input++]);
        int low = uuid_hex_value((unsigned char)text[input++]);
        if (high < 0 || low < 0) return false;
        parsed.bytes[output] = (unsigned char)((unsigned int)high << 4U
            | (unsigned int)low);
    }
    if (input != length) return false;
    *uuid = parsed;
    return true;
}

void mc_uuid_format(const McUuid *uuid, char text[MC_UUID_STRING_SIZE])
{
    static const char hexadecimal[] = "0123456789abcdef";
    if (text == NULL) return;
    if (uuid == NULL) {
        text[0] = '\0';
        return;
    }
    size_t output = 0U;
    for (size_t input = 0U; input < sizeof(uuid->bytes); ++input) {
        if (input == 4U || input == 6U || input == 8U || input == 10U) {
            text[output++] = '-';
        }
        text[output++] = hexadecimal[uuid->bytes[input] >> 4U];
        text[output++] = hexadecimal[uuid->bytes[input] & 0x0fU];
    }
    text[output] = '\0';
}

static uint32_t rotate_left(uint32_t value, unsigned int shift)
{
    return (value << shift) | (value >> (32U - shift));
}

static void md5_single_block(const unsigned char *input, size_t input_size,
    unsigned char digest[16])
{
    static const unsigned char shifts[64] = {
        7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
        5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
        4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
        6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
    };
    static const uint32_t constants[64] = {
        0xd76aa478U,0xe8c7b756U,0x242070dbU,0xc1bdceeeU,0xf57c0fafU,0x4787c62aU,0xa8304613U,0xfd469501U,
        0x698098d8U,0x8b44f7afU,0xffff5bb1U,0x895cd7beU,0x6b901122U,0xfd987193U,0xa679438eU,0x49b40821U,
        0xf61e2562U,0xc040b340U,0x265e5a51U,0xe9b6c7aaU,0xd62f105dU,0x02441453U,0xd8a1e681U,0xe7d3fbc8U,
        0x21e1cde6U,0xc33707d6U,0xf4d50d87U,0x455a14edU,0xa9e3e905U,0xfcefa3f8U,0x676f02d9U,0x8d2a4c8aU,
        0xfffa3942U,0x8771f681U,0x6d9d6122U,0xfde5380cU,0xa4beea44U,0x4bdecfa9U,0xf6bb4b60U,0xbebfbc70U,
        0x289b7ec6U,0xeaa127faU,0xd4ef3085U,0x04881d05U,0xd9d4d039U,0xe6db99e5U,0x1fa27cf8U,0xc4ac5665U,
        0xf4292244U,0x432aff97U,0xab9423a7U,0xfc93a039U,0x655b59c3U,0x8f0ccc92U,0xffeff47dU,0x85845dd1U,
        0x6fa87e4fU,0xfe2ce6e0U,0xa3014314U,0x4e0811a1U,0xf7537e82U,0xbd3af235U,0x2ad7d2bbU,0xeb86d391U
    };
    unsigned char block[64] = {0};
    memcpy(block, input, input_size);
    block[input_size] = 0x80U;
    uint64_t bits = (uint64_t)input_size * 8U;
    for (size_t index = 0U; index < 8U; ++index) {
        block[56U + index] = (unsigned char)(bits >> (index * 8U));
    }
    uint32_t words[16];
    for (size_t index = 0U; index < 16U; ++index) {
        size_t offset = index * 4U;
        words[index] = (uint32_t)block[offset]
            | (uint32_t)block[offset + 1U] << 8U
            | (uint32_t)block[offset + 2U] << 16U
            | (uint32_t)block[offset + 3U] << 24U;
    }
    uint32_t a=0x67452301U,b=0xefcdab89U,c=0x98badcfeU,d=0x10325476U;
    const uint32_t initial[4] = {a,b,c,d};
    for (uint32_t index = 0U; index < 64U; ++index) {
        uint32_t mixed, word;
        if (index < 16U) { mixed=(b&c)|((~b)&d); word=index; }
        else if (index < 32U) { mixed=(d&b)|((~d)&c); word=(5U*index+1U)&15U; }
        else if (index < 48U) { mixed=b^c^d; word=(3U*index+5U)&15U; }
        else { mixed=c^(b|(~d)); word=(7U*index)&15U; }
        uint32_t previous=d; d=c; c=b;
        b += rotate_left(a + mixed + constants[index] + words[word], shifts[index]);
        a=previous;
    }
    const uint32_t state[4] = {initial[0]+a,initial[1]+b,initial[2]+c,initial[3]+d};
    for (size_t index = 0U; index < 4U; ++index) {
        digest[index*4U]=(unsigned char)state[index];
        digest[index*4U+1U]=(unsigned char)(state[index]>>8U);
        digest[index*4U+2U]=(unsigned char)(state[index]>>16U);
        digest[index*4U+3U]=(unsigned char)(state[index]>>24U);
    }
}

static bool valid_username(const char *username);

bool mc_offline_uuid(const char *username, McUuid *uuid)
{
    if (!valid_username(username) || uuid == NULL) return false;
    char name[40];
    int length = snprintf(name, sizeof(name), "OfflinePlayer:%s", username);
    md5_single_block((const unsigned char *)name, (size_t)length, uuid->bytes);
    uuid->bytes[6] = (unsigned char)((uuid->bytes[6] & 0x0fU) | 0x30U);
    uuid->bytes[8] = (unsigned char)((uuid->bytes[8] & 0x3fU) | 0x80U);
    return true;
}

static bool valid_username(const char *username)
{
    if (username == NULL) return false;
    size_t length = strlen(username);
    if (length == 0U || length > 16U) return false;
    for (size_t index = 0U; index < length; ++index) {
        unsigned char value = (unsigned char)username[index];
        if (!((value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z')
                || (value >= '0' && value <= '9') || value == '_')) return false;
    }
    return true;
}


/* ============================================================
 * CLIENT LIFECYCLE
 * ============================================================ */

McServer *mc_server_create(const char *bind_host, uint16_t port, int backlog,
    char *error, size_t error_size)
{
    if (backlog <= 0) {
        set_error(error, error_size, "Backlog server non valido");
        return NULL;
    }
    McServer *server = calloc(1U, sizeof(*server));
    if (server == NULL) {
        set_error(error, error_size, "Memoria insufficiente");
        return NULL;
    }
    server->socket_fd = -1;
    server->socket_fd = bind_tcp(bind_host, port, backlog, &server->port,
        error, error_size);
    if (server->socket_fd < 0) {
        free(server);
        return NULL;
    }
    return server;
}

void mc_server_destroy(McServer *server)
{
    if (server == NULL) return;
    if (server->socket_fd >= 0) (void)close(server->socket_fd);
    free(server);
}

uint16_t mc_server_port(const McServer *server)
{
    return server != NULL ? server->port : 0U;
}

static int accepted_receive(int socket_fd, unsigned char *data, size_t size,
    unsigned int timeout_ms, uint64_t *wire_size,
    char *error, size_t error_size)
{
    size_t offset = 0U;
    while (offset < size) {
        struct pollfd descriptor = {
            .fd = socket_fd,
            .events = POLLIN,
            .revents = 0
        };
        int ready;
        do {
            ready = poll(&descriptor, 1U, (int)timeout_ms);
        } while (ready < 0 && errno == EINTR);
        if (ready <= 0) {
            set_error(error, error_size, ready == 0
                ? "Timeout handshake client" : "Attesa handshake fallita: %s",
                strerror(errno));
            return -1;
        }
        ssize_t received = recv(socket_fd, data + offset, size - offset, 0);
        if (received < 0 && errno == EINTR) continue;
        if (received <= 0) {
            set_error(error, error_size, received == 0
                ? "Client chiuso durante handshake"
                : "Lettura handshake fallita: %s", strerror(errno));
            return -1;
        }
        offset += (size_t)received;
        *wire_size += (uint64_t)received;
    }
    return 0;
}

static int accepted_varint(int socket_fd, int32_t *value,
    unsigned int timeout_ms, uint64_t *wire_size,
    char *error, size_t error_size)
{
    uint32_t result = 0U;
    for (unsigned int index = 0U; index < 5U; ++index) {
        unsigned char byte = 0U;
        if (accepted_receive(socket_fd, &byte, 1U, timeout_ms, wire_size,
                error, error_size) != 0) return -1;
        result |= (uint32_t)(byte & 0x7fU) << (index * 7U);
        if ((byte & 0x80U) == 0U) {
            if (index == 4U && (byte & 0xf0U) != 0U) {
                set_error(error, error_size, "VarInt handshake fuori range");
                return -1;
            }
            *value = (int32_t)result;
            return 0;
        }
    }
    set_error(error, error_size, "VarInt handshake non valido");
    return -1;
}

int mc_server_accept(McServer *server, unsigned int timeout_ms,
    const McCallbacks *callbacks, void *userdata, McClient **accepted,
    McHandshake *handshake, char *error, size_t error_size)
{
    if (server == NULL || server->socket_fd < 0
        || accepted == NULL || handshake == NULL) {
        set_error(error, error_size, "Parametri accept non validi");
        return -1;
    }
    *accepted = NULL;
    *handshake = (McHandshake){0};
    struct pollfd descriptor = {
        .fd = server->socket_fd,
        .events = POLLIN,
        .revents = 0
    };
    int ready;
    do {
        ready = poll(&descriptor, 1U, (int)timeout_ms);
    } while (ready < 0 && errno == EINTR);
    if (ready == 0) return 0;
    if (ready < 0) {
        set_error(error, error_size, "Attesa accept fallita: %s", strerror(errno));
        return -1;
    }
    int socket_fd = accept(server->socket_fd, NULL, NULL);
    if (socket_fd < 0) {
        set_error(error, error_size, "Accept fallita: %s", strerror(errno));
        return -1;
    }
#if defined(__APPLE__) && defined(SO_NOSIGPIPE)
    int no_sigpipe = 1;
    (void)setsockopt(socket_fd, SOL_SOCKET, SO_NOSIGPIPE,
        &no_sigpipe, (socklen_t)sizeof(no_sigpipe));
#endif
    int no_delay = 1;
    (void)setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY,
        &no_delay, (socklen_t)sizeof(no_delay));

    uint64_t received_bytes = 0U;
    unsigned int handshake_timeout = timeout_ms == 0U ? 10000U : timeout_ms;
    int32_t frame_size = -1;
    unsigned char frame[512];
    if (accepted_varint(socket_fd, &frame_size, handshake_timeout, &received_bytes,
            error, error_size) != 0
        || frame_size <= 0 || frame_size > (int32_t)sizeof(frame)
        || accepted_receive(socket_fd, frame, (size_t)frame_size, handshake_timeout,
            &received_bytes, error, error_size) != 0) {
        if (frame_size <= 0 || frame_size > (int32_t)sizeof(frame)) {
            set_error(error, error_size, "Dimensione handshake client non valida");
        }
        (void)close(socket_fd);
        return -1;
    }
    McReader reader;
    int32_t packet_id = -1;
    int32_t protocol = -1;
    int32_t next_state = -1;
    McBytes host;
    uint16_t requested_port = 0U;
    mc_reader_init(&reader, frame, (size_t)frame_size);
    if (!mc_reader_varint(&reader, &packet_id) || packet_id != 0
        || !mc_reader_varint(&reader, &protocol)
        || !mc_reader_string(&reader, &host)
        || host.size == 0U || host.size >= MC_HANDSHAKE_HOST_SIZE
        || !mc_reader_u16(&reader, &requested_port)
        || !mc_reader_varint(&reader, &next_state)
        || (next_state != 1 && next_state != 2)
        || mc_reader_remaining(&reader) != 0U) {
        set_error(error, error_size, "Handshake Minecraft non valido");
        (void)close(socket_fd);
        return -1;
    }
    McClient *client = mc_client_create(protocol, callbacks, userdata,
        error, error_size);
    if (client == NULL) {
        (void)close(socket_fd);
        return -1;
    }
    client->server_side = true;
    client->automatic_replies = 0U;
    client->received_bytes = received_bytes;
    atomic_store(&client->socket_fd, socket_fd);
    if (backend_init(client, socket_fd) != 0) {
        set_error(error, error_size, "Backend client accettato non inizializzabile: %s",
            strerror(errno));
        mc_client_destroy(client);
        return -1;
    }
    handshake->protocol = protocol;
    memcpy(handshake->host, host.data, host.size);
    handshake->host[host.size] = '\0';
    handshake->host_size = host.size;
    handshake->port = requested_port;
    handshake->next_state = next_state == 1
        ? MC_STATE_STATUS : MC_STATE_LOGIN;
    change_state(client, handshake->next_state);
    *accepted = client;
    return 1;
}

McClient *mc_client_create(int protocol, const McCallbacks *callbacks,
    void *userdata, char *error, size_t error_size)
{
    const McProfile *profile = find_profile(protocol);
    if (profile == NULL) {
        set_error(error, error_size, "Protocollo Minecraft %d non supportato", protocol);
        return NULL;
    }
    McClient *client = calloc(1U, sizeof(*client));
    if (client == NULL) {
        set_error(error, error_size, "Memoria insufficiente");
        return NULL;
    }
    atomic_init(&client->socket_fd, -1);
    atomic_init(&client->stop, false);
    client->profile = profile;
    client->state = MC_STATE_DISCONNECTED;
    client->backend = MC_BACKEND_NONE;
    client->event_fd = -1;
    client->compression_threshold = -1;
    client->automatic_replies = MC_AUTOMATIC_ALL;
    client->read_timeout_ms = 30000U;
    if (callbacks != NULL) client->callbacks = *callbacks;
    client->userdata = userdata;
#if defined(__linux__)
    client->ring.fd = -1;
#endif
    return client;
}

int mc_client_protocol(const McClient *client)
{
    return client != NULL ? client->profile->protocol : -1;
}

McState mc_client_state(const McClient *client)
{
    return client != NULL ? client->state : MC_STATE_DISCONNECTED;
}

void mc_client_traffic(const McClient *client, McTraffic *traffic)
{
    if (traffic == NULL) return;
    traffic->sent_bytes = client != NULL ? client->sent_bytes : 0U;
    traffic->received_bytes = client != NULL ? client->received_bytes : 0U;
}

void mc_client_disconnect(McClient *client)
{
    if (client == NULL) return;
    /* Exchange the descriptor before close so a concurrent disconnect cannot
     * close a descriptor number that the operating system has already reused.
     * shutdown wakes a thread blocked in receive_all(). */
    atomic_store(&client->stop, true);
    int socket_fd = atomic_exchange(&client->socket_fd, -1);
    if (socket_fd >= 0) {
        (void)shutdown(socket_fd, SHUT_RDWR);
        (void)close(socket_fd);
    }
    backend_close(client);
    change_state(client, MC_STATE_DISCONNECTED);
}

void mc_client_destroy(McClient *client)
{
    if (client == NULL) return;
    mc_client_disconnect(client);
    free(client);
}

int mc_client_set_state(McClient *client, McState state,
    char *error, size_t error_size)
{
    if (client == NULL || atomic_load(&client->socket_fd) < 0) {
        set_error(error, error_size, "Client non connesso");
        return -1;
    }
    if (state != MC_STATE_LOGIN && state != MC_STATE_CONFIGURATION
        && state != MC_STATE_PLAY && state != MC_STATE_STATUS) {
        set_error(error, error_size, "Stato protocollo non valido");
        return -1;
    }
    change_state(client, state);
    return 0;
}

int mc_client_set_compression(McClient *client, int threshold,
    char *error, size_t error_size)
{
    if (client == NULL || atomic_load(&client->socket_fd) < 0) {
        set_error(error, error_size, "Client non connesso");
        return -1;
    }
    if (threshold < -1) {
        set_error(error, error_size, "Soglia compressione non valida");
        return -1;
    }
    client->compression_threshold = threshold;
    return 0;
}

int mc_client_set_read_timeout(McClient *client, unsigned int timeout_ms,
    char *error, size_t error_size)
{
    if (client == NULL || timeout_ms == 0U) {
        set_error(error, error_size, "Timeout lettura non valido");
        return -1;
    }
    client->read_timeout_ms = timeout_ms;
    return 0;
}

int mc_client_set_stream_transforms(McClient *client,
    const McStreamTransforms *transforms, char *error, size_t error_size)
{
    if (client == NULL || atomic_load(&client->socket_fd) < 0) {
        set_error(error, error_size, "Client non connesso");
        return -1;
    }
    if (transforms == NULL) {
        client->transforms = (McStreamTransforms){0};
        return 0;
    }
    if (transforms->encrypt == NULL || transforms->decrypt == NULL) {
        set_error(error, error_size,
            "Le trasformazioni stream richiedono encrypt e decrypt");
        return -1;
    }
    client->transforms = *transforms;
    return 0;
}

int mc_client_send(McClient *client, int32_t packet_id,
    const void *payload, size_t payload_size, char *error, size_t error_size)
{
    if (client == NULL || atomic_load(&client->socket_fd) < 0
        || client->state == MC_STATE_DISCONNECTED) {
        set_error(error, error_size, "Client non connesso");
        return -1;
    }
    return send_frame(client, packet_id, payload, payload_size, error, error_size);
}

int mc_client_send_named(McClient *client, const char *packet_name,
    const void *payload, size_t payload_size, char *error, size_t error_size)
{
    if (client == NULL || atomic_load(&client->socket_fd) < 0
        || client->state == MC_STATE_DISCONNECTED) {
        set_error(error, error_size, "Client non connesso");
        return -1;
    }
    int32_t packet_id = mc_packet_id(client->profile->protocol, client->state,
        client->server_side ? MC_PACKET_CLIENTBOUND : MC_PACKET_SERVERBOUND,
        packet_name);
    if (packet_id < 0) {
        set_error(error, error_size, "Pacchetto %s sconosciuto: %s",
            client->server_side ? "clientbound" : "serverbound",
            packet_name != NULL ? packet_name : "(null)");
        return -1;
    }
    return mc_client_send(client, packet_id, payload, payload_size,
        error, error_size);
}

int mc_client_send_command(McClient *client, const char *command,
    char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    struct timespec now;
    if (clock_gettime(CLOCK_REALTIME, &now) != 0
        || now.tv_sec > INT64_MAX / 1000) {
        set_error(error, error_size, "Orologio comando non disponibile");
        return -1;
    }
    int64_t timestamp_ms = (int64_t)now.tv_sec * INT64_C(1000)
        + (int64_t)now.tv_nsec / INT64_C(1000000);
    unsigned char storage[384];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_command(&body, client->profile->protocol,
            command, timestamp_ms, 0)) {
        set_error(error, error_size, "Comando Minecraft non valido");
        return -1;
    }
    const char *packet_name = client->profile->protocol <= 758
        ? "chat" : "chat_command";
    return mc_client_send_named(client, packet_name,
        body.data, body.length, error, error_size);
}

static McClientInformation default_client_information(void)
{
    const McClientInformation information = {
        .locale = "en_us",
        .view_distance = 2,
        .chat_mode = 0,
        .chat_colors = true,
        .skin_parts = 0x7fU,
        .difficulty = 0U,
        .show_cape = true,
        .main_hand = 1,
        .text_filtering = false,
        .server_listing = true,
        .particle_status = 0,
    };
    return information;
}

int mc_client_send_client_information(McClient *client,
    const McClientInformation *information, char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || (client->state != MC_STATE_PLAY
            && client->state != MC_STATE_CONFIGURATION)) {
        set_error(error, error_size,
            "Client non in stato PLAY o CONFIGURATION");
        return -1;
    }
    unsigned char storage[64];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_client_information(
            &body, client->profile->protocol, information)) {
        set_error(error, error_size, "Client Information Minecraft non valida");
        return -1;
    }
    return mc_client_send_named(client, "settings",
        body.data, body.length, error, error_size);
}

int mc_client_send_entity_action(McClient *client,
    const McEntityAction *action, char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[16];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_entity_action(&body, client->profile->protocol, action)) {
        set_error(error, error_size, "Entity Action Minecraft non valida");
        return -1;
    }
    return mc_client_send_named(client, "entity_action",
        body.data, body.length, error, error_size);
}

int mc_client_send_player_input(McClient *client, uint8_t flags,
    char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[1];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_player_input(&body, client->profile->protocol, flags)) {
        set_error(error, error_size, "Player Input Minecraft non valido");
        return -1;
    }
    return mc_client_send_named(client, "player_input",
        body.data, body.length, error, error_size);
}

int mc_client_swing_arm(McClient *client, int32_t entity_id, int32_t hand,
    char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[5];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_arm_animation(
            &body, client->profile->protocol, entity_id, hand)) {
        set_error(error, error_size, "Arm Animation Minecraft non valida");
        return -1;
    }
    return mc_client_send_named(client, "arm_animation",
        body.data, body.length, error, error_size);
}

int mc_client_send_player_position(McClient *client,
    const McPlayerPosition *position, char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[48];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_player_position(
            &body, client->profile->protocol, position)) {
        set_error(error, error_size, "Posizione Minecraft non valida");
        return -1;
    }
    return mc_client_send_named(client, "position_look",
        body.data, body.length, error, error_size);
}

int mc_client_send_player_abilities(McClient *client,
    const McPlayerAbilities *abilities, char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[9];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_player_abilities(&body, client->profile->protocol, abilities)) {
        set_error(error, error_size, "Abilities Minecraft non valide");
        return -1;
    }
    return mc_client_send_named(client, "abilities",
        body.data, body.length, error, error_size);
}

int mc_client_dig_block(McClient *client, const McBlockDig *dig,
    char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[16];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_block_dig(&body, client->profile->protocol, dig)) {
        set_error(error, error_size, "Azione block_dig Minecraft non valida");
        return -1;
    }
    return mc_client_send_named(client, "block_dig",
        body.data, body.length, error, error_size);
}

int mc_client_place_block(McClient *client, const McBlockPlace *place,
    char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    size_t capacity = 64U;
    if (client->profile->protocol <= 47 && place->held_item_nbt.size != 0U) {
        if (client->profile->protocol <= 5) {
            const uLong bound = compressBound((uLong)place->held_item_nbt.size);
            if (bound > (uLong)MC_MAX_PACKET - 64U) {
                set_error(error, error_size, "NBT block_place troppo grande");
                return -1;
            }
            capacity = (size_t)bound + 64U;
        } else {
            if (place->held_item_nbt.size > (size_t)MC_MAX_PACKET - 64U) {
                set_error(error, error_size, "NBT block_place troppo grande");
                return -1;
            }
            capacity = place->held_item_nbt.size + 64U;
        }
    }
    unsigned char *storage = malloc(capacity);
    if (storage == NULL) {
        set_error(error, error_size, "Allocazione block_place fallita");
        return -1;
    }
    McPacket body;
    mc_packet_init(&body, storage, capacity);
    if (!mc_packet_block_place(&body, client->profile->protocol, place)) {
        free(storage);
        set_error(error, error_size, "Azione block_place Minecraft non valida");
        return -1;
    }
    const int result = mc_client_send_named(client, "block_place",
        body.data, body.length, error, error_size);
    free(storage);
    return result;
}

int mc_client_use_item(McClient *client, const McUseItem *use,
    char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL || use == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    size_t capacity = 64U;
    if (client->profile->protocol <= 47 && use->held_item_nbt.size != 0U) {
        if (client->profile->protocol <= 5) {
            const uLong bound = compressBound((uLong)use->held_item_nbt.size);
            if (bound > (uLong)MC_MAX_PACKET - 64U) {
                set_error(error, error_size, "NBT use_item troppo grande");
                return -1;
            }
            capacity = (size_t)bound + 64U;
        } else {
            if (use->held_item_nbt.size > (size_t)MC_MAX_PACKET - 64U) {
                set_error(error, error_size, "NBT use_item troppo grande");
                return -1;
            }
            capacity = use->held_item_nbt.size + 64U;
        }
    }
    unsigned char *storage = malloc(capacity);
    if (storage == NULL) {
        set_error(error, error_size, "Allocazione use_item fallita");
        return -1;
    }
    McPacket body;
    mc_packet_init(&body, storage, capacity);
    if (!mc_packet_use_item(&body, client->profile->protocol, use)) {
        free(storage);
        set_error(error, error_size, "Azione use_item Minecraft non valida");
        return -1;
    }
    const char *packet_name = client->profile->protocol <= 47
        ? "block_place" : "use_item";
    const int result = mc_client_send_named(client, packet_name,
        body.data, body.length, error, error_size);
    free(storage);
    return result;
}

int mc_client_close_window(McClient *client, int32_t window_id,
    char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[5];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_close_window(
            &body, client->profile->protocol, window_id)) {
        set_error(error, error_size, "Finestra Minecraft non valida");
        return -1;
    }
    return mc_client_send_named(client, "close_window",
        body.data, body.length, error, error_size);
}

int mc_client_set_creative_slot(McClient *client, int16_t slot,
    int32_t item_id, int32_t count, char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[32];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_set_creative_slot(&body, client->profile->protocol,
            slot, item_id, count)) {
        set_error(error, error_size, "Slot creativo Minecraft non valido");
        return -1;
    }
    return mc_client_send_named(client, "set_creative_slot",
        body.data, body.length, error, error_size);
}

int mc_client_select_hotbar_slot(McClient *client, int16_t slot,
    char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[2];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_held_item_slot(&body, client->profile->protocol, slot)) {
        set_error(error, error_size, "Slot hotbar Minecraft non valido");
        return -1;
    }
    return mc_client_send_named(client, "held_item_slot",
        body.data, body.length, error, error_size);
}

int mc_client_click_window(McClient *client, const McWindowClick *click,
    char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[32];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_window_click(&body, client->profile->protocol, click)) {
        set_error(error, error_size, "Click finestra Minecraft non valido");
        return -1;
    }
    return mc_client_send_named(client, "window_click",
        body.data, body.length, error, error_size);
}

int mc_client_click_container_button(McClient *client,
    int32_t window_id, int32_t button_id, char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[10];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_container_button(
            &body, client->profile->protocol, window_id, button_id)) {
        set_error(error, error_size, "Bottone container Minecraft non valido");
        return -1;
    }
    return mc_client_send_named(client, "enchant_item",
        body.data, body.length, error, error_size);
}

int mc_client_attack_entity(McClient *client, int32_t entity_id,
    char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[16];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_attack_entity(
            &body, client->profile->protocol, entity_id)) {
        set_error(error, error_size, "Bersaglio attacco Minecraft non valido");
        return -1;
    }
    const char *packet_name = client->profile->protocol >= 775
        ? "attack" : "use_entity";
    return mc_client_send_named(client, packet_name,
        body.data, body.length, error, error_size);
}

int mc_client_request_respawn(McClient *client,
    char *error, size_t error_size)
{
    if (client == NULL || client->profile == NULL
        || atomic_load(&client->socket_fd) < 0
        || client->state != MC_STATE_PLAY) {
        set_error(error, error_size, "Client non in stato PLAY");
        return -1;
    }
    unsigned char storage[5];
    McPacket body;
    mc_packet_init(&body, storage, sizeof(storage));
    if (!mc_packet_respawn_request(&body, client->profile->protocol)) {
        set_error(error, error_size, "Richiesta respawn Minecraft non valida");
        return -1;
    }
    return mc_client_send_named(client, "client_command",
        body.data, body.length, error, error_size);
}

int mc_client_send_batch(McClient *client, const McOutboundPacket *packets,
    size_t count, char *error, size_t error_size)
{
    if (client == NULL || atomic_load(&client->socket_fd) < 0
        || client->state == MC_STATE_DISCONNECTED) {
        set_error(error, error_size, "Client non connesso");
        return -1;
    }
    if (count != 0U && packets == NULL) {
        set_error(error, error_size, "Batch pacchetti non valido");
        return -1;
    }
    unsigned char *batch = NULL;
    size_t batch_size = 0U;
    size_t capacity = 0U;
    for (size_t index = 0U; index < count; ++index) {
        unsigned char *frame = NULL;
        size_t frame_size = 0U;
        if (encode_frame(client, packets[index].packet_id,
                packets[index].payload, packets[index].payload_size,
                &frame, &frame_size, error, error_size) != 0) {
            free(batch);
            return -1;
        }
        if (frame_size > SIZE_MAX - batch_size) {
            free(frame);
            free(batch);
            set_error(error, error_size, "Batch pacchetti troppo grande");
            return -1;
        }
        size_t needed = batch_size + frame_size;
        if (needed > capacity) {
            size_t grown = capacity == 0U ? 4096U : capacity;
            while (grown < needed && grown <= SIZE_MAX / 2U) grown *= 2U;
            if (grown < needed) grown = needed;
            unsigned char *resized = realloc(batch, grown);
            if (resized == NULL) {
                free(frame);
                free(batch);
                set_error(error, error_size, "Memoria insufficiente per il batch");
                return -1;
            }
            batch = resized;
            capacity = grown;
        }
        memcpy(batch + batch_size, frame, frame_size);
        batch_size = needed;
        free(frame);
    }
    int result = batch_size == 0U ? 0
        : send_all(client, batch, batch_size, error, error_size);
    free(batch);
    return result;
}

static int send_builder(McClient *client, int32_t id, const McPacket *packet,
    char *error, size_t error_size)
{
    if (packet->failed) {
        set_error(error, error_size, "Packet builder pieno");
        return -1;
    }
    return send_frame(client, id, packet->data, packet->length, error, error_size);
}

static int read_protocol_packet(McClient *client, McState state,
    McFrame *frame, int32_t *packet_id, McCursor *body,
    char *error, size_t error_size)
{
    if (read_frame(client, frame, error, error_size) != 0) return -1;
    McCursor cursor;
    mc_reader_init(&cursor, frame->data, frame->size);
    if (!mc_reader_varint(&cursor, packet_id)) {
        free(frame->data);
        frame->data = NULL;
        set_error(error, error_size, "Pacchetto senza ID VarInt");
        return -1;
    }
    *body = cursor;
    emit_packet(client, state, *packet_id, body);
    return 0;
}


/* ============================================================
 * CONFIGURATION STATE
 * ============================================================ */

/* Modern servers interpose CONFIGURATION between login success and PLAY. The
 * exchange is bounded even if a broken peer never sends finish_configuration.
 * Known-pack selection is echoed on protocol 776 because that release sends
 * the concrete registry list; older releases accept an empty selection. */
static int configuration(McClient *client, char *error, size_t error_size)
{
    change_state(client, MC_STATE_CONFIGURATION);
    if (send_frame(client, 0x03, NULL, 0U, error, error_size) != 0) return -1;
    bool information_sent = false;
    int finish_id = client->profile->protocol >= 766 ? 0x03 : 0x02;
    for (unsigned int index = 0U; index < MC_CONFIG_PACKETS; ++index) {
        McFrame frame;
        McCursor body;
        int32_t packet_id = -1;
        if (read_protocol_packet(client, MC_STATE_CONFIGURATION, &frame,
                &packet_id, &body, error, error_size) != 0) return -1;

        if (client->profile->protocol == 776 && !information_sent) {
            unsigned char storage[128];
            McPacket settings;
            McClientInformation information = default_client_information();
            information.server_listing = false;
            mc_packet_init(&settings, storage, sizeof(storage));
            mc_packet_client_information(
                &settings, client->profile->protocol, &information);
            if (send_builder(client, 0x00, &settings, error, error_size) != 0) {
                free(frame.data);
                return -1;
            }
            information_sent = true;
        }
        if (client->profile->protocol >= 766 && packet_id == 0x0e) {
            unsigned char storage[1024];
            McPacket selection;
            mc_packet_init(&selection, storage, sizeof(storage));
            if (client->profile->protocol == 776) {
                mc_packet_bytes(&selection, body.data + body.offset,
                    body.size - body.offset);
            } else {
                mc_packet_varint(&selection, 0);
            }
            if (send_builder(client, 0x07, &selection, error, error_size) != 0) {
                free(frame.data);
                return -1;
            }
        }
        bool finished = packet_id == finish_id;
        free(frame.data);
        if (!finished) continue;

        if (!information_sent) {
            unsigned char storage[128];
            McPacket settings;
            const McClientInformation information = default_client_information();
            mc_packet_init(&settings, storage, sizeof(storage));
            mc_packet_client_information(
                &settings, client->profile->protocol, &information);
            if (send_builder(client, 0x00, &settings, error, error_size) != 0) return -1;
        }
        if (client->profile->protocol >= 765 && client->profile->protocol <= 775) {
            unsigned char storage[20] = {0};
            const unsigned char uuid[16] = {0};
            McPacket pack;
            mc_packet_init(&pack, storage, sizeof(storage));
            mc_packet_bytes(&pack, uuid, sizeof(uuid));
            mc_packet_varint(&pack, 0);
            int response = client->profile->protocol == 765 ? 0x05 : 0x06;
            if (send_builder(client, response, &pack, error, error_size) != 0) return -1;
        }
        int result = send_frame(client, client->profile->protocol >= 766 ? 0x03 : 0x02,
            NULL, 0U, error, error_size);
        if (result == 0) change_state(client, MC_STATE_PLAY);
        return result;
    }
    set_error(error, error_size, "Configuration non terminata");
    return -1;
}

int mc_client_open(McClient *client, const char *host, uint16_t port,
    McState next_state, char *error, size_t error_size)
{
    if (client == NULL || host == NULL || host[0] == '\0'
        || (next_state != MC_STATE_LOGIN && next_state != MC_STATE_STATUS)) {
        set_error(error, error_size, "Host o stato handshake non valido");
        return -1;
    }
    if (atomic_load(&client->socket_fd) >= 0) {
        set_error(error, error_size, "Client gia connesso");
        return -1;
    }
    atomic_store(&client->stop, false);
    client->compression_threshold = -1;
    client->player_loaded_sent = false;
    client->transforms = (McStreamTransforms){0};
    client->server_side = false;
    uint16_t effective_port = port == 0U ? MC_DEFAULT_PORT : port;
    int socket_fd = connect_tcp(host, effective_port, error, error_size);
    if (socket_fd < 0) return -1;
    atomic_store(&client->socket_fd, socket_fd);
    if (backend_init(client, socket_fd) != 0) {
        set_error(error, error_size, "Backend %s non inizializzabile: %s",
            mc_backend_name(client->preferred_backend), strerror(errno));
        goto fail;
    }

    unsigned char storage[512];
    McPacket handshake;
    mc_packet_init(&handshake, storage, sizeof(storage));
    mc_packet_varint(&handshake, client->profile->protocol);
    mc_packet_string(&handshake, host);
    mc_packet_u16(&handshake, effective_port);
    mc_packet_varint(&handshake, next_state == MC_STATE_STATUS ? 1 : 2);
    if (send_builder(client, 0x00, &handshake, error, error_size) != 0) {
        goto fail;
    }
    change_state(client, next_state);
    return 0;

fail:
    mc_client_disconnect(client);
    return -1;
}

int mc_client_connect(McClient *client, const char *host, uint16_t port,
    const char *username, char *error, size_t error_size)
{
    if (client == NULL || host == NULL || host[0] == '\0' || !valid_username(username)) {
        set_error(error, error_size, "Host o username non valido");
        return -1;
    }
    if (mc_client_open(client, host, port, MC_STATE_LOGIN,
            error, error_size) != 0) return -1;
    unsigned char storage[512];
    McUuid uuid;
    (void)mc_offline_uuid(username, &uuid);
    McPacket login;
    mc_packet_init(&login, storage, sizeof(storage));
    mc_packet_string(&login, username);
    if ((client->profile->flags & MC_PROTOCOL_FEATURE_LOGIN_KEY) != 0U) {
        mc_packet_u8(&login, 0U);
    }
    if ((client->profile->flags & MC_PROTOCOL_FEATURE_OPTIONAL_UUID) != 0U) {
        mc_packet_u8(&login, 1U);
        mc_packet_uuid(&login, &uuid);
    } else if ((client->profile->flags & MC_PROTOCOL_FEATURE_REQUIRED_UUID) != 0U) {
        mc_packet_uuid(&login, &uuid);
    }
    if (send_builder(client, 0x00, &login, error, error_size) != 0) goto fail;

    for (unsigned int index = 0U; index < MC_LOGIN_PACKETS; ++index) {
        McFrame frame;
        McCursor body;
        int32_t packet_id = -1;
        if (read_protocol_packet(client, MC_STATE_LOGIN, &frame,
                &packet_id, &body, error, error_size) != 0) goto fail;
        if (packet_id == 0x00) {
            free(frame.data);
            set_error(error, error_size, "Login rifiutato dal server");
            goto fail;
        }
        if (packet_id == 0x01) {
            free(frame.data);
            set_error(error, error_size,
                "Online-mode/encryption non supportato da questa build");
            goto fail;
        }
        if (packet_id == 0x03) {
            int32_t threshold = -1;
            if (!mc_reader_varint(&body, &threshold) || threshold < 0) {
                free(frame.data);
                set_error(error, error_size, "Soglia compressione non valida");
                goto fail;
            }
            client->compression_threshold = threshold;
            free(frame.data);
            continue;
        }
        if (packet_id == 0x02) {
            free(frame.data);
            if ((client->profile->flags & MC_PROTOCOL_FEATURE_CONFIGURATION) != 0U) {
                if (configuration(client, error, error_size) != 0) goto fail;
            } else {
                change_state(client, MC_STATE_PLAY);
            }
            return 0;
        }
        free(frame.data);
    }
    set_error(error, error_size, "Login Success non ricevuto");

fail:
    mc_client_disconnect(client);
    return -1;
}


/* ============================================================
 * STATUS
 * ============================================================ */

static uint64_t monotonic_milliseconds(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return 0U;
    return (uint64_t)value.tv_sec * UINT64_C(1000)
        + (uint64_t)value.tv_nsec / UINT64_C(1000000);
}

static int status_read_packet(McClient *client, unsigned int timeout_ms,
    McFrame *frame, int32_t *packet_id, McReader *body,
    char *error, size_t error_size)
{
    int ready = backend_wait(client, timeout_ms);
    if (ready <= 0) {
        set_error(error, error_size, ready == 0
            ? "Timeout status Minecraft" : "Attesa status fallita: %s",
            strerror(errno));
        return -1;
    }
    if (read_frame(client, frame, error, error_size) != 0) return -1;
    mc_reader_init(body, frame->data, frame->size);
    if (!mc_reader_varint(body, packet_id)) {
        free(frame->data);
        frame->data = NULL;
        set_error(error, error_size, "Packet ID status non valido");
        return -1;
    }
    return 0;
}

int mc_status_ping(int protocol, const char *host, uint16_t port,
    unsigned int timeout_ms, char *json, size_t json_capacity,
    McStatus *status, char *error, size_t error_size)
{
    if (!mc_protocol_supported(protocol) || host == NULL || host[0] == '\0'
        || timeout_ms == 0U || json == NULL || json_capacity == 0U
        || status == NULL) {
        set_error(error, error_size, "Parametri status non validi");
        return -1;
    }
    json[0] = '\0';
    *status = (McStatus){0};
    McClient *client = mc_client_create(protocol, NULL, NULL,
        error, error_size);
    if (client == NULL) return -1;
    client->read_timeout_ms = timeout_ms;
    uint16_t effective_port = port == 0U ? MC_DEFAULT_PORT : port;
    int socket_fd = connect_tcp(host, effective_port, error, error_size);
    if (socket_fd < 0) {
        mc_client_destroy(client);
        return -1;
    }
    atomic_store(&client->socket_fd, socket_fd);
    if (backend_init(client, socket_fd) != 0) {
        set_error(error, error_size, "Backend status non inizializzabile: %s",
            strerror(errno));
        mc_client_destroy(client);
        return -1;
    }

    unsigned char storage[512];
    McPacket handshake;
    mc_packet_init(&handshake, storage, sizeof(storage));
    mc_packet_varint(&handshake, protocol);
    mc_packet_string(&handshake, host);
    mc_packet_u16(&handshake, effective_port);
    mc_packet_varint(&handshake, 1);
    if (send_builder(client, 0x00, &handshake, error, error_size) != 0
        || send_frame(client, 0x00, NULL, 0U, error, error_size) != 0) {
        mc_client_destroy(client);
        return -1;
    }

    McFrame frame = {0};
    McReader body;
    int32_t packet_id = -1;
    if (status_read_packet(client, timeout_ms, &frame, &packet_id, &body,
            error, error_size) != 0) {
        mc_client_destroy(client);
        return -1;
    }
    McBytes response = {0};
    if (packet_id != 0x00 || !mc_reader_string(&body, &response)
        || mc_reader_remaining(&body) != 0U
        || response.size >= json_capacity) {
        free(frame.data);
        set_error(error, error_size, response.size >= json_capacity
            ? "Buffer JSON status troppo piccolo" : "Risposta status non valida");
        mc_client_destroy(client);
        return -1;
    }
    memcpy(json, response.data, response.size);
    json[response.size] = '\0';
    status->json_size = response.size;
    free(frame.data);

    uint64_t started = monotonic_milliseconds();
    McPacket ping;
    mc_packet_init(&ping, storage, sizeof(storage));
    mc_packet_i64(&ping, (int64_t)started);
    if (send_builder(client, 0x01, &ping, error, error_size) != 0
        || status_read_packet(client, timeout_ms, &frame, &packet_id, &body,
            error, error_size) != 0) {
        mc_client_destroy(client);
        return -1;
    }
    int64_t echoed = -1;
    if (packet_id != 0x01 || !mc_reader_i64(&body, &echoed)
        || echoed != (int64_t)started || mc_reader_remaining(&body) != 0U) {
        free(frame.data);
        set_error(error, error_size, "Pong status non valido");
        mc_client_destroy(client);
        return -1;
    }
    free(frame.data);
    uint64_t finished = monotonic_milliseconds();
    status->latency_ms = finished >= started ? finished - started : 0U;
    mc_client_destroy(client);
    return 0;
}


/* ============================================================
 * PLAY STATE
 * ============================================================ */

/* These IDs are kept separate from the generated catalog because they are the
 * mandatory replies emitted by the client itself, not merely names presented
 * to the application. They are intentionally grouped here with handle_play()
 * so a new protocol profile cannot hide the maintenance behavior it needs. */
static int movement_packet(int protocol)
{
    if (protocol <= 47) return 0x06;
    if (protocol <= 316) return 0x0d;
    if (protocol == 335) return 0x0f;
    if (protocol <= 340) return 0x0e;
    if (protocol <= 404) return 0x11;
    if (protocol <= 734) return 0x12;
    if (protocol <= 754) return 0x13;
    if (protocol <= 758) return 0x12;
    if (protocol == 759) return 0x14;
    if (protocol == 760) return 0x15;
    if (protocol == 761) return 0x14;
    if (protocol <= 763) return 0x15;
    if (protocol == 764) return 0x17;
    if (protocol == 765) return 0x18;
    if (protocol <= 767) return 0x1b;
    if (protocol <= 770) return 0x1d;
    if (protocol <= 774) return 0x1e;
    return 0x1f;
}

static int player_loaded_packet(int protocol)
{
    if (protocol >= 775) return 0x2c;
    if (protocol >= 771) return 0x2b;
    if (protocol >= 769) return 0x2a;
    return -1;
}

static int batch_response_packet(int protocol)
{
    if (protocol >= 775) return 0x0b;
    if (protocol >= 771) return 0x0a;
    if (protocol >= 768) return 0x09;
    if (protocol >= 766) return 0x08;
    if (protocol >= 764) return 0x07;
    return -1;
}

static int handle_play(McClient *client, int32_t packet_id, McCursor body,
    char *error, size_t error_size)
{
    /* Applications receive the packet before this function runs. Automatic
     * replies cover only server liveness and state acknowledgements: keepalive,
     * teleport acceptance, player-loaded and chunk-batch flow control. Game
     * actions remain under application control. */
    if (packet_id == client->profile->keep_alive
        && (client->automatic_replies & MC_AUTOMATIC_KEEP_ALIVE) != 0U) {
        return send_frame(client, client->profile->keep_alive_response,
            body.data + body.offset, body.size - body.offset, error, error_size);
    }
    if (packet_id == client->profile->player_position
        && (client->automatic_replies
            & (MC_AUTOMATIC_TELEPORT | MC_AUTOMATIC_PLAYER_LOADED)) != 0U) {
        McClientboundPlayerPosition decoded = {0};
        if (!mc_reader_clientbound_player_position(
                &body, client->profile->protocol, &decoded)
            || mc_reader_remaining(&body) != 0U) {
            set_error(error, error_size, "Player Position non valido");
            return -1;
        }
        const int32_t teleport_id =
            decoded.has_teleport_id ? decoded.teleport_id : -1;
        if (client->profile->protocol < 107) {
            unsigned char storage[48];
            McPacket movement;
            mc_packet_init(&movement, storage, sizeof(storage));
            McPlayerPosition response = {
                .x = decoded.position.x,
                .y = decoded.position.y,
                .z = decoded.position.z,
                .yaw = decoded.position.yaw,
                .pitch = decoded.position.pitch,
                .on_ground = true
            };
            mc_packet_player_position(&movement,
                client->profile->protocol, &response);
            if (send_builder(client, movement_packet(client->profile->protocol),
                    &movement, error, error_size) != 0) return -1;
        }
        if (teleport_id >= 0
            && (client->automatic_replies & MC_AUTOMATIC_TELEPORT) != 0U) {
            unsigned char storage[5];
            McPacket confirmation;
            mc_packet_init(&confirmation, storage, sizeof(storage));
            mc_packet_varint(&confirmation, teleport_id);
            if (send_builder(client, client->profile->teleport_confirm,
                    &confirmation, error, error_size) != 0) return -1;
        }
        int loaded = player_loaded_packet(client->profile->protocol);
        if (loaded >= 0 && !client->player_loaded_sent
            && (client->automatic_replies & MC_AUTOMATIC_PLAYER_LOADED) != 0U) {
            if (send_frame(client, loaded, NULL, 0U, error, error_size) != 0) return -1;
            client->player_loaded_sent = true;
        }
    }
    int batch_finished = client->profile->protocol >= 770 ? 0x0b
        : client->profile->protocol >= 764 ? 0x0c : -1;
    if (packet_id == batch_finished
        && (client->automatic_replies & MC_AUTOMATIC_CHUNK_BATCH) != 0U) {
        unsigned char storage[4];
        McPacket response;
        mc_packet_init(&response, storage, sizeof(storage));
        mc_packet_float(&response, 64.0F);
        return send_builder(client, batch_response_packet(client->profile->protocol),
            &response, error, error_size);
    }
    return 0;
}

int mc_client_poll(McClient *client, unsigned int timeout_ms,
    char *error, size_t error_size)
{
    if (client == NULL || atomic_load(&client->socket_fd) < 0
        || client->state == MC_STATE_DISCONNECTED) {
        set_error(error, error_size, "Client non connesso");
        return -1;
    }
    if (atomic_load(&client->stop)) return 0;
    int ready = backend_wait(client, timeout_ms);
    if (ready == 0) return 0;
    if (ready < 0) {
        set_error(error, error_size, "Attesa socket fallita: %s", strerror(errno));
        mc_client_disconnect(client);
        return -1;
    }
    McFrame frame;
    McCursor body;
    int32_t packet_id = -1;
    McState state = client->state;
    unsigned int saved_timeout = client->read_timeout_ms;
    client->read_timeout_ms = timeout_ms;
    if (read_protocol_packet(client, state, &frame,
            &packet_id, &body, error, error_size) != 0) {
        client->read_timeout_ms = saved_timeout;
        mc_client_disconnect(client);
        return -1;
    }
    client->read_timeout_ms = saved_timeout;
    /* A callback may deliberately transition state or disconnect. Do not emit
     * a PLAY acknowledgement for a packet after the application has moved the
     * connection elsewhere. */
    int result = state == MC_STATE_PLAY && client->state == MC_STATE_PLAY
            && atomic_load(&client->socket_fd) >= 0
        ? handle_play(client, packet_id, body, error, error_size) : 0;
    free(frame.data);
    if (result != 0) {
        mc_client_disconnect(client);
        return -1;
    }
    return 1;
}

int mc_client_run(McClient *client, char *error, size_t error_size)
{
    while (client != NULL && !atomic_load(&client->stop)) {
        if (mc_client_poll(client, 1000U, error, error_size) < 0) return -1;
    }
    return 0;
}
