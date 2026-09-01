#ifndef MC_PROTOCOL_API_H
#define MC_PROTOCOL_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MC_PROTOCOL_API_VERSION 1
#define MC_DEFAULT_PORT 25565U
#define MC_UUID_STRING_SIZE 37U
#define MC_HANDSHAKE_HOST_SIZE 256U

/* mcprotocol.c deliberately exposes the protocol rather than a game bot. The
 * client takes care of connection state, framing and mandatory protocol
 * replies; application packets remain visible to the caller through the raw
 * callback and can be built without allocations with McPacket.
 *
 * A client is driven by the thread calling mc_client_connect(),
 * mc_client_poll() or mc_client_run(). Callbacks run synchronously on that same
 * thread. mc_client_disconnect() is the sole operation intended to interrupt a
 * running client from another thread. */

/* ============================================================
 * PUBLIC TYPES
 * ============================================================ */

typedef struct McClient McClient;
typedef struct McServer McServer;

typedef enum {
    MC_STATE_DISCONNECTED = 0,
    MC_STATE_LOGIN,
    MC_STATE_CONFIGURATION,
    MC_STATE_PLAY,
    MC_STATE_STATUS
} McState;

typedef enum {
    MC_BACKEND_NONE = 0,
    MC_BACKEND_IO_URING,
    MC_BACKEND_KQUEUE,
    MC_BACKEND_EPOLL,
    MC_BACKEND_POLL
} McBackend;

typedef enum {
    MC_PACKET_SERVERBOUND = 0,
    MC_PACKET_CLIENTBOUND
} McPacketDirection;

typedef struct {
    McState state;
    McPacketDirection direction;
    int32_t id;
    const char *name;
} McPacketInfo;

typedef struct {
    void (*on_state)(void *userdata, McState previous, McState current);
    /* Payload excludes the VarInt packet ID. It becomes invalid as soon as the
     * callback returns, so copy it when it must outlive the call. */
    void (*on_packet)(void *userdata, McState state, int32_t packet_id,
        const unsigned char *payload, size_t payload_size);
} McCallbacks;

/* Minecraft online-mode encrypts the entire framed TCP stream. A transform is
 * stateful and operates in place; return zero on success. Supplying callbacks
 * lets applications use their preferred crypto provider without making it a
 * mandatory dependency of this two-file library. */
typedef int (*McStreamTransform)(void *userdata, unsigned char *data,
    size_t size);

typedef struct {
    McStreamTransform encrypt;
    McStreamTransform decrypt;
    void *userdata;
} McStreamTransforms;

typedef struct {
    uint64_t sent_bytes;
    uint64_t received_bytes;
} McTraffic;

typedef struct {
    int32_t packet_id;
    const void *payload;
    size_t payload_size;
} McOutboundPacket;

typedef struct {
    size_t json_size;
    uint64_t latency_ms;
} McStatus;

typedef struct {
    int protocol;
    unsigned char host[MC_HANDSHAKE_HOST_SIZE];
    size_t host_size;
    uint16_t port;
    McState next_state;
} McHandshake;


/* ============================================================
 * PROTOCOL PROFILES / PACKET REGISTRY
 * ============================================================ */

/* The returned protocol array and all catalog names are immutable and live for
 * the lifetime of the process. McPacketInfo itself is copied into caller-owned
 * storage. Unknown protocols, states, directions, IDs and names fail without
 * modifying library state. */
typedef enum {
    MC_PROTOCOL_FEATURE_COMPRESSION = 1U << 0,
    MC_PROTOCOL_FEATURE_LOGIN_KEY = 1U << 1,
    MC_PROTOCOL_FEATURE_OPTIONAL_UUID = 1U << 2,
    MC_PROTOCOL_FEATURE_REQUIRED_UUID = 1U << 3,
    MC_PROTOCOL_FEATURE_CONFIGURATION = 1U << 4,
    MC_PROTOCOL_FEATURE_POSITION_DELTA = 1U << 5,
    MC_PROTOCOL_FEATURE_KEEP_ALIVE_I64 = 1U << 6,
    MC_PROTOCOL_FEATURE_CHAT_LAST_SEEN = 1U << 7,
    MC_PROTOCOL_FEATURE_CHAT_ACKNOWLEDGED = 1U << 8
} McProtocolFeature;

typedef enum {
    MC_AUTOMATIC_KEEP_ALIVE = 1U << 0,
    MC_AUTOMATIC_TELEPORT = 1U << 1,
    MC_AUTOMATIC_PLAYER_LOADED = 1U << 2,
    MC_AUTOMATIC_CHUNK_BATCH = 1U << 3,
    MC_AUTOMATIC_ALL = (1U << 4) - 1U
} McAutomaticReply;

const int *mc_supported_protocols(size_t *count);
bool mc_protocol_supported(int protocol);
/* Canonical names select the newest stable release sharing a protocol number,
 * for example 47 -> "1.8.9" and 776 -> "26.2". */
const char *mc_protocol_name(int protocol);
int mc_protocol_by_name(const char *release_name);
/* Feature bits describe wire-shape changes shared by several packets. For
 * example, KEEP_ALIVE_I64 selects an i64 rather than VarInt payload and the
 * UUID bits select the Login Start suffix. A supported old protocol can
 * legitimately return zero; use mc_protocol_supported() to detect unknowns. */
uint32_t mc_protocol_features(int protocol);
size_t mc_packet_count(int protocol);
bool mc_packet_at(int protocol, size_t index, McPacketInfo *packet);
const char *mc_packet_name(int protocol, McState state,
    McPacketDirection direction, int32_t id);
int32_t mc_packet_id(int protocol, McState state,
    McPacketDirection direction, const char *name);


/* ============================================================
 * READER / WRITER CODEC
 * ============================================================ */

/* McPacket writes a packet body into storage supplied by the caller. Writers
 * use Minecraft network byte order and VarInt/String encodings. Failure is
 * sticky: once capacity or input validation fails, every later write fails and
 * the packet cannot accidentally be sent as a valid truncated body. */
typedef struct {
    unsigned char *data;
    size_t length;
    size_t capacity;
    bool failed;
} McPacket;

/* McBytes is a borrowed, non-NUL-terminated view into an input packet. */
typedef struct {
    const unsigned char *data;
    size_t size;
} McBytes;

/* McReader decodes one packet body without allocation. Like McPacket, failure
 * is sticky so a complete schema can be read linearly and checked once. Views
 * returned by mc_reader_bytes() and mc_reader_string() borrow input storage. */
typedef struct {
    const unsigned char *data;
    size_t size;
    size_t offset;
    bool failed;
} McReader;

typedef enum {
    MC_NBT_END = 0,
    MC_NBT_BYTE = 1,
    MC_NBT_SHORT = 2,
    MC_NBT_INT = 3,
    MC_NBT_LONG = 4,
    MC_NBT_FLOAT = 5,
    MC_NBT_DOUBLE = 6,
    MC_NBT_BYTE_ARRAY = 7,
    MC_NBT_STRING = 8,
    MC_NBT_LIST = 9,
    MC_NBT_COMPOUND = 10,
    MC_NBT_INT_ARRAY = 11,
    MC_NBT_LONG_ARRAY = 12
} McNbtType;

typedef struct {
    int32_t x;
    int32_t y;
    int32_t z;
} McPosition;

typedef struct {
    double x;
    double y;
    double z;
    float yaw;
    float pitch;
    bool on_ground;
} McPlayerPosition;

/* Decoded clientbound position/correction. `position.y` is normalized to
 * feet Y for 1.7 even though that wire family carries stance/eye Y. The
 * velocity delta fields and 9-bit relative flags are present only from
 * 1.21.2; older families leave them zero. Teleport IDs start in 1.9 and the
 * dismount flag exists only from 1.17 through 1.19.4. */
typedef struct {
    McPlayerPosition position;
    double delta_x;
    double delta_y;
    double delta_z;
    uint32_t relative_flags;
    int32_t teleport_id;
    bool has_velocity_delta;
    bool has_teleport_id;
    bool dismount_vehicle;
} McClientboundPlayerPosition;

/* Normalized clientbound Respawn body. String/NBT fields are borrowed from
 * the reader input and become invalid with that packet buffer. Legacy
 * dimensions expose legacy_dimension; 1.16--1.18 expose dimension_nbt;
 * registry-based modern layouts expose dimension_type_id. */
typedef struct {
    int32_t legacy_dimension;
    int32_t dimension_type_id;
    McBytes dimension_identifier;
    McBytes dimension_nbt;
    McBytes world_name;
    McBytes level_type;
    McBytes last_death_dimension;
    McPosition last_death_position;
    int64_t hashed_seed;
    int32_t portal_cooldown;
    int32_t sea_level;
    uint8_t difficulty;
    uint8_t game_mode;
    int8_t previous_game_mode;
    /* 1.19.3+ exposes the two KEEP_* bits directly. Older copy-data
     * booleans are normalized to either zero or both bits set. */
    uint8_t keep_data_mask;
    bool has_legacy_dimension;
    bool has_dimension_type_id;
    bool has_dimension_identifier;
    bool has_dimension_nbt;
    bool has_world_name;
    bool has_level_type;
    bool has_hashed_seed;
    bool has_difficulty;
    bool has_previous_game_mode;
    bool debug;
    bool flat;
    bool has_last_death_location;
    bool has_portal_cooldown;
    bool has_sea_level;
} McClientboundRespawn;

typedef struct {
    const char *locale;
    int8_t view_distance;
    int32_t chat_mode;
    bool chat_colors;
    uint8_t skin_parts;
    uint8_t difficulty;
    bool show_cape;
    int32_t main_hand;
    /* This is the raw wire boolean. Mojang renamed it from
     * disableTextFiltering to enableTextFiltering at the 1.18 boundary. */
    bool text_filtering;
    bool server_listing;
    int32_t particle_status;
} McClientInformation;

typedef enum {
    MC_ENTITY_ACTION_START_SNEAKING = 0,
    MC_ENTITY_ACTION_STOP_SNEAKING,
    MC_ENTITY_ACTION_LEAVE_BED,
    MC_ENTITY_ACTION_START_SPRINTING,
    MC_ENTITY_ACTION_STOP_SPRINTING,
    MC_ENTITY_ACTION_START_HORSE_JUMP,
    MC_ENTITY_ACTION_STOP_HORSE_JUMP,
    MC_ENTITY_ACTION_OPEN_VEHICLE_INVENTORY,
    MC_ENTITY_ACTION_START_ELYTRA_FLYING
} McEntityActionKind;

typedef struct {
    int32_t entity_id;
    McEntityActionKind action;
    int32_t jump_boost;
} McEntityAction;

typedef enum {
    MC_PLAYER_INPUT_FORWARD = 1U << 0,
    MC_PLAYER_INPUT_BACKWARD = 1U << 1,
    MC_PLAYER_INPUT_LEFT = 1U << 2,
    MC_PLAYER_INPUT_RIGHT = 1U << 3,
    MC_PLAYER_INPUT_JUMP = 1U << 4,
    MC_PLAYER_INPUT_SHIFT = 1U << 5,
    MC_PLAYER_INPUT_SPRINT = 1U << 6
} McPlayerInputFlag;

typedef struct {
    uint8_t flags;
    float flying_speed;
    float walking_speed;
} McPlayerAbilities;

typedef struct {
    int32_t status;
    McPosition location;
    int8_t face;
    int32_t sequence;
} McBlockDig;

typedef struct {
    McPosition location;
    int32_t direction;
    int32_t hand;
    int32_t held_item_id;
    int32_t held_item_count;
    int32_t held_item_damage;
    /* Optional complete, uncompressed named-root NBT for the client-reported
     * held stack embedded by 1.7/1.8 block_place packets. It is gzip-compressed
     * for 1.7 and written directly for 1.8. */
    McBytes held_item_nbt;
    float cursor_x;
    float cursor_y;
    float cursor_z;
    bool inside_block;
    bool world_border_hit;
    int32_t sequence;
} McBlockPlace;

typedef struct {
    int32_t hand;
    int32_t held_item_id;
    int32_t held_item_count;
    int32_t held_item_damage;
    /* Used only by the legacy block_place sentinel representation. */
    McBytes held_item_nbt;
    int32_t sequence;
    float yaw;
    float pitch;
} McUseItem;

typedef struct {
    int32_t window_id;
    int32_t state_id;
    int16_t slot;
    int8_t mouse_button;
    int16_t action_number;
    int32_t mode;
} McEmptyWindowClick;

typedef struct {
    int32_t window_id;
    int32_t state_id;
    int16_t slot;
    int8_t mouse_button;
    int16_t action_number;
    int32_t mode;
    /* Client-predicted clicked stack used through 1.16.5. Modern changed-slot
     * claims remain deliberately empty and require clicked_item_count == 0. */
    int32_t clicked_item_id;
    int32_t clicked_item_count;
} McWindowClick;

typedef struct {
    unsigned char bytes[16];
} McUuid;

typedef struct {
    int32_t type_id;
    McBytes data;
} McItemComponentPatch;

/* Canonical equipment slots. Legacy wire slots are normalized into this
 * ordering: their slot 1 (boots) becomes MC_EQUIPMENT_FEET rather than being
 * confused with the off hand introduced in 1.9. */
typedef enum {
    MC_EQUIPMENT_MAIN_HAND = 0,
    MC_EQUIPMENT_OFF_HAND,
    MC_EQUIPMENT_FEET,
    MC_EQUIPMENT_LEGS,
    MC_EQUIPMENT_CHEST,
    MC_EQUIPMENT_HEAD,
    MC_EQUIPMENT_BODY,
    MC_EQUIPMENT_SADDLE,
    MC_EQUIPMENT_SLOT_COUNT
} McEquipmentSlot;

#define MC_ENTITY_EQUIPMENT_MAX_ENTRIES 8U

typedef struct {
    McEquipmentSlot slot;
    int32_t item_id;
    int32_t count;
} McEntityEquipmentEntry;

typedef struct {
    int32_t entity_id;
    size_t entry_count;
    McEntityEquipmentEntry entries[MC_ENTITY_EQUIPMENT_MAX_ENTRIES];
} McEntityEquipment;

/* Normalized clientbound inventory-slot update. Releases through 1.21.1 use
 * ContainerSetSlot (window/state/menu slot); 1.21.2+ may instead address the
 * player's logical inventory directly. */
typedef struct {
    int32_t window_id;
    int32_t state_id;
    int32_t slot;
    int32_t item_id;
    int32_t count;
    bool direct_player_inventory;
} McInventorySlotUpdate;

/* Normalized result of the one-entry metadata projection used to publish
 * player hand-use state. Pre-1.9 stores active use in shared entity flag 0x10
 * and cannot represent the off hand; newer releases use LivingEntity bits
 * 0x01/0x02 at a release-specific metadata index. */
typedef struct {
    int32_t entity_id;
    uint8_t metadata_index;
    uint8_t raw_flags;
    bool active;
    bool off_hand;
    bool uses_living_flags;
} McEntityHandUseMetadata;

void mc_packet_init(McPacket *packet, void *storage, size_t capacity);
bool mc_packet_bytes(McPacket *packet, const void *data, size_t size);
bool mc_packet_bool(McPacket *packet, bool value);
bool mc_packet_i8(McPacket *packet, int8_t value);
bool mc_packet_u8(McPacket *packet, uint8_t value);
bool mc_packet_i16(McPacket *packet, int16_t value);
bool mc_packet_u16(McPacket *packet, uint16_t value);
bool mc_packet_i32(McPacket *packet, int32_t value);
bool mc_packet_u32(McPacket *packet, uint32_t value);
bool mc_packet_i64(McPacket *packet, int64_t value);
bool mc_packet_u64(McPacket *packet, uint64_t value);
bool mc_packet_float(McPacket *packet, float value);
bool mc_packet_double(McPacket *packet, double value);
bool mc_packet_varint(McPacket *packet, int32_t value);
bool mc_packet_varlong(McPacket *packet, int64_t value);
bool mc_packet_buffer_i32(McPacket *packet, const McBytes *value);
bool mc_packet_buffer_varint(McPacket *packet, const McBytes *value);
bool mc_packet_string_n(McPacket *packet, const char *value, size_t size);
bool mc_packet_string(McPacket *packet, const char *value);
bool mc_packet_position(McPacket *packet, int protocol, McPosition value);
bool mc_packet_uuid(McPacket *packet, const McUuid *value);
/* Validates and appends one complete encoded NBT value. named_root selects
 * the legacy named-root network form; modern components use false. */
bool mc_packet_nbt(McPacket *packet, bool named_root, const McBytes *encoded);
/* Encodes a metadata-free Slot/ItemStack value. count=0 writes the empty-item
 * sentinel for the selected release; non-empty stacks require item_id > 0. */
bool mc_packet_plain_item(McPacket *packet, int protocol,
    int32_t item_id, int32_t count);
/* Builds a release-aware creative inventory mutation. The slot is the
 * canonical player-inventory slot and the item is metadata-free. */
bool mc_packet_set_creative_slot(McPacket *packet, int protocol,
    int16_t slot, int32_t item_id, int32_t count);
/* Selects one hotbar slot. The body is a signed big-endian short in every
 * supported release; Vanilla accepts only indices 0 through 8. */
bool mc_packet_held_item_slot(McPacket *packet, int protocol, int16_t slot);
/* Builds a release-aware inventory click with no changed-slot claims and an
 * empty carried/clicked item. state_id is used from 1.17.1 onward;
 * action_number is used through 1.16.5. */
bool mc_packet_empty_window_click(McPacket *packet, int protocol,
    const McEmptyWindowClick *value);
/* Builds a release-aware inventory click whose legacy client-predicted stack
 * may be non-empty. From 1.17 onward the changed-slot and carried-item claims
 * are deliberately empty, so clicked_item_count must be zero. */
bool mc_packet_window_click(McPacket *packet, int protocol,
    const McWindowClick *value);
/* Builds one container-menu button click. Window IDs become unsigned in
 * 1.21.1 and VarInt in 1.21.3; button IDs become VarInt in 1.21.1. */
bool mc_packet_container_button(McPacket *packet, int protocol,
    int32_t window_id, int32_t button_id);
/* Builds a release-aware close-window body. Container IDs use one unsigned
 * byte through 1.21.1 and VarInt from 1.21.3 onward. */
bool mc_packet_close_window(McPacket *packet, int protocol, int32_t window_id);
/* Encodes a serverbound UntrustedSlot item with raw, length-prefixed added
 * component payloads and removed component type IDs (1.20.5+). */
bool mc_packet_untrusted_component_item(McPacket *packet, int protocol,
    int32_t item_id, int32_t count,
    const McItemComponentPatch *added, size_t added_count,
    const int32_t *removed, size_t removed_count);
/* Builds the release-aware Client Information/Settings body. The packet is
 * sent in PLAY through 1.20.1 and in CONFIGURATION from 1.20.2 onward. */
bool mc_packet_client_information(McPacket *packet, int protocol,
    const McClientInformation *value);
/* Builds the canonical player-command action and translates the 1.7 offset
 * and 1.21.6 removal of sneak actions from entity_action. */
bool mc_packet_entity_action(McPacket *packet, int protocol,
    const McEntityAction *value);
/* Builds the bitset-based Player Input packet introduced in 1.21.2. */
bool mc_packet_player_input(McPacket *packet, int protocol, uint8_t flags);
/* Builds one main/off-hand swing. entity_id is used only by 1.7; 1.8 has an
 * empty body and 1.9+ encodes hand as a VarInt. */
bool mc_packet_arm_animation(McPacket *packet, int protocol,
    int32_t entity_id, int32_t hand);
/* Builds the body of the serverbound position_look packet, including the
 * stance field used only by 1.7. Packet ID/framing remain mc_client_send's job. */
bool mc_packet_player_position(McPacket *packet, int protocol,
    const McPlayerPosition *value);
/* Builds the release-aware serverbound abilities body. Through 1.15.2 it
 * contains flags plus both speed floats; 1.16+ contains flags only. */
bool mc_packet_player_abilities(McPacket *packet, int protocol,
    const McPlayerAbilities *value);
/* Builds the release-aware serverbound block_dig body. The sequence is
 * encoded from 1.19 onward and ignored by older releases. */
bool mc_packet_block_dig(McPacket *packet, int protocol,
    const McBlockDig *value);
/* Builds block_place/use_item_on bodies across the legacy embedded-stack,
 * byte-cursor, hand-first, sequence and world-border-hit boundaries. The
 * legacy held stack may include damage and named-root NBT; modern protocols
 * ignore those client-reported fields. */
bool mc_packet_block_place(McPacket *packet, int protocol,
    const McBlockPlace *value);
/* Builds a use-item action. 1.7/1.8 use the block_place sentinel and its
 * reported held stack; newer releases add sequence and then rotation. */
bool mc_packet_use_item(McPacket *packet, int protocol,
    const McUseItem *value);
/* Builds a primary attack against one entity. Legacy use_entity packets use
 * action 1 and add the sneaking flag from 1.16; 26.1+ has a dedicated body. */
bool mc_packet_attack_entity(McPacket *packet, int protocol, int32_t entity_id);
/* Builds client_command's perform-respawn action for the selected release. */
bool mc_packet_respawn_request(McPacket *packet, int protocol);
/* Builds the body used to execute a command for the selected release. The
 * command may include one leading slash. timestamp_ms and salt are used only
 * by signed-chat-era protocols; offline callers may pass salt zero. */
bool mc_packet_command(McPacket *packet, int protocol, const char *command,
    int64_t timestamp_ms, int64_t salt);

void mc_reader_init(McReader *reader, const void *data, size_t size);
size_t mc_reader_remaining(const McReader *reader);
bool mc_reader_bytes(McReader *reader, size_t size, McBytes *value);
bool mc_reader_skip(McReader *reader, size_t size);
bool mc_reader_bool(McReader *reader, bool *value);
bool mc_reader_i8(McReader *reader, int8_t *value);
bool mc_reader_u8(McReader *reader, uint8_t *value);
bool mc_reader_i16(McReader *reader, int16_t *value);
bool mc_reader_u16(McReader *reader, uint16_t *value);
bool mc_reader_i32(McReader *reader, int32_t *value);
bool mc_reader_u32(McReader *reader, uint32_t *value);
bool mc_reader_i64(McReader *reader, int64_t *value);
bool mc_reader_u64(McReader *reader, uint64_t *value);
bool mc_reader_float(McReader *reader, float *value);
bool mc_reader_double(McReader *reader, double *value);
bool mc_reader_varint(McReader *reader, int32_t *value);
bool mc_reader_varlong(McReader *reader, int64_t *value);
bool mc_reader_buffer_i32(McReader *reader, McBytes *value);
bool mc_reader_buffer_varint(McReader *reader, McBytes *value);
bool mc_reader_string(McReader *reader, McBytes *value);
bool mc_reader_position(McReader *reader, int protocol, McPosition *value);
/* Decodes the release-aware clientbound position packet body (without packet
 * ID). The caller may require mc_reader_remaining(reader) == 0 to reject a
 * body with trailing fields. */
bool mc_reader_clientbound_player_position(McReader *reader, int protocol,
    McClientboundPlayerPosition *value);
/* Decodes and validates one complete release-aware Respawn body (without its
 * packet ID). The caller may require mc_reader_remaining(reader) == 0. */
bool mc_reader_clientbound_respawn(McReader *reader, int protocol,
    McClientboundRespawn *value);
/* Decodes one complete clientbound block_change body. Protocols 1.7.x use
 * x:i32/y:u8/z:i32 plus separate block-id/metadata fields; their returned
 * state_id is (block_id << 4) | metadata. 1.8+ returns the wire state ID. */
bool mc_reader_block_change(McReader *reader, int protocol,
    McPosition *position, int32_t *state_id);
bool mc_reader_uuid(McReader *reader, McUuid *value);
bool mc_reader_plain_item(McReader *reader, int protocol,
    int32_t *item_id, int32_t *count);
/* Decodes either clientbound set_slot/container_set_slot or the dedicated
 * set_player_inventory body used from 1.21.2. Packet IDs are excluded. */
bool mc_reader_inventory_slot_update(McReader *reader, int protocol,
    bool direct_player_inventory, McInventorySlotUpdate *value);
/* Reports whether the canonical equipment slot exists in the selected
 * release. Off hand starts in 1.9, body armor in 1.20.5 and saddle in 1.21.5. */
bool mc_entity_equipment_slot_supported(int protocol, McEquipmentSlot slot);
/* Decodes one clientbound entity_equipment/set_equipment body without packet
 * ID. The 1.16+ continuation-bit list is bounded, rejects duplicate slots and
 * is normalized to the canonical slot enum above. Items must be metadata-free;
 * richer item components deliberately remain visible as a decode failure. */
bool mc_reader_entity_equipment(McReader *reader, int protocol,
    McEntityEquipment *value);
/* Decodes the one-entry clientbound entity_metadata body used for player
 * hand-use projection. The packet ID is excluded; unexpected index,
 * serializer, missing terminator or a second entry before the terminator is
 * rejected. The caller may require mc_reader_remaining(reader) == 0 to reject
 * bytes following the complete metadata list. */
bool mc_reader_entity_hand_use_metadata(McReader *reader, int protocol,
    McEntityHandUseMetadata *value);

/* NBT functions validate the complete encoded value and optionally return a
 * borrowed slice (encoded may be NULL when only validation/skipping matters).
 * Network NBT before 1.20.2 normally has a named root; newer packet schemas
 * often use an anonymous root. mc_reader_nbt_value() starts after the tag type
 * and is useful while walking selected fields in a compound. */
bool mc_reader_nbt_name(McReader *reader, McBytes *name);
bool mc_reader_nbt_value(McReader *reader, McNbtType type, McBytes *encoded);
bool mc_reader_nbt(McReader *reader, bool named_root, McBytes *encoded);


/* ============================================================
 * AUTH / UUID HELPERS
 * ============================================================ */

/* Parse accepts canonical dashed UUIDs and compact 32-hex-digit UUIDs. Format
 * writes lowercase canonical text and always needs MC_UUID_STRING_SIZE bytes. */
bool mc_uuid_parse(const char *text, McUuid *uuid);
void mc_uuid_format(const McUuid *uuid, char text[MC_UUID_STRING_SIZE]);
bool mc_offline_uuid(const char *username, McUuid *uuid);


/* ============================================================
 * CLIENT LIFECYCLE
 * ============================================================ */

/* Creation validates the protocol but opens no socket. The callbacks and
 * userdata pointer are borrowed until destroy; their targets must therefore
 * outlive the client. Errors are written only when error is non-NULL and
 * error_size is non-zero. */
McClient *mc_client_create(int protocol, const McCallbacks *callbacks,
    void *userdata, char *error, size_t error_size);
void mc_client_destroy(McClient *client);

/* A raw server validates the initial handshake and returns a normal McClient
 * representing the accepted peer. Named sends on that object resolve the
 * clientbound catalog; received callbacks contain serverbound packet IDs. */
McServer *mc_server_create(const char *bind_host, uint16_t port, int backlog,
    char *error, size_t error_size);
void mc_server_destroy(McServer *server);
uint16_t mc_server_port(const McServer *server);
int mc_server_accept(McServer *server, unsigned int timeout_ms,
    const McCallbacks *callbacks, void *userdata, McClient **accepted,
    McHandshake *handshake, char *error, size_t error_size);

/* Opens TCP, sends the handshake and stops in LOGIN or STATUS without sending
 * a Login Start/Status Request. This is the entry point for custom login,
 * authentication and protocol probing. */
int mc_client_open(McClient *client, const char *host, uint16_t port,
    McState next_state, char *error, size_t error_size);

/* Performs an offline-mode login and returns only after PLAY is reached,
 * including the CONFIGURATION exchange required by modern versions. */
int mc_client_connect(McClient *client, const char *host, uint16_t port,
    const char *username, char *error, size_t error_size);

/* Performs the server-list status handshake, copies the response JSON with a
 * terminating NUL and verifies a ping/pong nonce. timeout_ms applies to each
 * response packet; port=0 selects MC_DEFAULT_PORT. */
int mc_status_ping(int protocol, const char *host, uint16_t port,
    unsigned int timeout_ms, char *json, size_t json_capacity,
    McStatus *status, char *error, size_t error_size);

/* Sends one serverbound body. The library adds the packet ID, framing and the
 * negotiated compression envelope. The numeric form is useful for generated
 * or application-specific packets; the named form resolves the ID in the
 * client's current protocol state. */
int mc_client_send(McClient *client, int32_t packet_id,
    const void *payload, size_t payload_size, char *error, size_t error_size);
int mc_client_send_named(McClient *client, const char *packet_name,
    const void *payload, size_t payload_size, char *error, size_t error_size);
/* Sends one offline command using the correct legacy, signed-chat-era or
 * modern unsigned command packet. The command may include one leading slash. */
int mc_client_send_command(McClient *client, const char *command,
    char *error, size_t error_size);
/* Sends Client Information in the client's current PLAY or CONFIGURATION
 * state. mc_client_connect() already sends a conservative default while
 * completing modern CONFIGURATION. */
int mc_client_send_client_information(McClient *client,
    const McClientInformation *information, char *error, size_t error_size);
/* Sends one release-aware player command while in PLAY. */
int mc_client_send_entity_action(McClient *client,
    const McEntityAction *action, char *error, size_t error_size);
/* Sends one 1.21.2+ Player Input bitset while in PLAY. */
int mc_client_send_player_input(McClient *client, uint8_t flags,
    char *error, size_t error_size);
/* Sends one release-aware arm swing while in PLAY. */
int mc_client_swing_arm(McClient *client, int32_t entity_id, int32_t hand,
    char *error, size_t error_size);
/* Sends one release-aware player position/look update while in PLAY. */
int mc_client_send_player_position(McClient *client,
    const McPlayerPosition *position, char *error, size_t error_size);
/* Sends the serverbound abilities state while the client is in PLAY. */
int mc_client_send_player_abilities(McClient *client,
    const McPlayerAbilities *abilities, char *error, size_t error_size);
/* Sends one release-aware block_dig action while the client is in PLAY. */
int mc_client_dig_block(McClient *client, const McBlockDig *dig,
    char *error, size_t error_size);
/* Sends one release-aware block placement while the client is in PLAY. */
int mc_client_place_block(McClient *client, const McBlockPlace *place,
    char *error, size_t error_size);
/* Uses the held item without targeting a block while in PLAY. */
int mc_client_use_item(McClient *client, const McUseItem *use,
    char *error, size_t error_size);
/* Closes one inventory menu while the client is in PLAY. */
int mc_client_close_window(McClient *client, int32_t window_id,
    char *error, size_t error_size);
/* Writes one metadata-free stack into a creative player-inventory slot. */
int mc_client_set_creative_slot(McClient *client, int16_t slot,
    int32_t item_id, int32_t count, char *error, size_t error_size);
/* Selects one of the nine player hotbar slots while in PLAY. */
int mc_client_select_hotbar_slot(McClient *client, int16_t slot,
    char *error, size_t error_size);
/* Sends a release-aware inventory click while in PLAY. */
int mc_client_click_window(McClient *client, const McWindowClick *click,
    char *error, size_t error_size);
/* Activates one button/recipe in the current container menu. */
int mc_client_click_container_button(McClient *client,
    int32_t window_id, int32_t button_id, char *error, size_t error_size);
/* Sends one primary entity attack while the client is in PLAY. */
int mc_client_attack_entity(McClient *client, int32_t entity_id,
    char *error, size_t error_size);
/* Requests respawn through the release-aware client_command packet. */
int mc_client_request_respawn(McClient *client,
    char *error, size_t error_size);
/* Encodes every packet with the current compression settings and writes the
 * resulting frames contiguously. This preserves packet order while avoiding a
 * send syscall per packet. A zero-length batch is a successful no-op. */
int mc_client_send_batch(McClient *client, const McOutboundPacket *packets,
    size_t count, char *error, size_t error_size);

/* Poll processes at most one inbound packet: 1 means a packet was processed,
 * 0 is a timeout or requested stop, and -1 is an error. Run repeats that work
 * until disconnect is requested. */
int mc_client_poll(McClient *client, unsigned int timeout_ms,
    char *error, size_t error_size);
int mc_client_run(McClient *client, char *error, size_t error_size);
/* Wait checks socket readability without consuming a packet. */
int mc_client_wait(McClient *client, unsigned int timeout_ms,
    char *error, size_t error_size);
void mc_client_disconnect(McClient *client);


/* ============================================================
 * NETWORK BACKENDS / CLIENT INSPECTION
 * ============================================================ */

/* Set the backend before connect. MC_BACKEND_NONE preserves automatic native
 * selection; an unavailable explicit backend is rejected instead of silently
 * changing the caller's requested execution model. */
int mc_client_set_backend(McClient *client, McBackend backend,
    char *error, size_t error_size);
/* Automatic replies are enabled by default. Set a subset (or zero for a raw
 * protocol client) before connect when the application owns those packets. */
int mc_client_set_automatic_replies(McClient *client, uint32_t replies,
    char *error, size_t error_size);
/* Raw sessions may update protocol state and compression after the matching
 * server packet. Stream transforms are normally installed immediately after
 * sending Encryption Response. Passing NULL removes both transforms. */
int mc_client_set_state(McClient *client, McState state,
    char *error, size_t error_size);
int mc_client_set_compression(McClient *client, int threshold,
    char *error, size_t error_size);
/* Sets the maximum idle wait while completing one partially received frame.
 * Poll temporarily uses its own timeout for the packet it processes. */
int mc_client_set_read_timeout(McClient *client, unsigned int timeout_ms,
    char *error, size_t error_size);
int mc_client_set_stream_transforms(McClient *client,
    const McStreamTransforms *transforms, char *error, size_t error_size);
const char *mc_backend_name(McBackend backend);

/* Inspection functions do not transfer ownership. Traffic counters include
 * Minecraft framing bytes and are cumulative for the client object. */
int mc_client_protocol(const McClient *client);
McState mc_client_state(const McClient *client);
McBackend mc_client_backend(const McClient *client);
void mc_client_traffic(const McClient *client, McTraffic *traffic);

#ifdef __cplusplus
}
#endif

#endif
