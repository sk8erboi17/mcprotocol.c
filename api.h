#ifndef MC_PROTOCOL_API_H
#define MC_PROTOCOL_API_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MC_PROTOCOL_API_VERSION 3
#define MC_DEFAULT_PORT 25565U
#define MC_UUID_STRING_SIZE 37U
#define MC_HANDSHAKE_HOST_SIZE 256U
#define MC_DEFAULT_MAX_STRING_BYTES (1024U * 1024U)
#define MC_DEFAULT_MAX_FRAME_SIZE (16U * 1024U * 1024U)
#define MC_DEFAULT_MAX_DECOMPRESSED_SIZE (16U * 1024U * 1024U)
#define MC_DEFAULT_MAX_STREAM_BUFFERED_SIZE (64U * 1024U * 1024U)
#define MC_DEFAULT_MAX_STREAM_OUTPUT_SIZE (32U * 1024U * 1024U)
#define MC_MAX_PACKET_ARRAY_COUNT (1024U * 1024U)
#define MC_MAX_NBT_DEPTH 64U
#define MC_MAX_NBT_COLLECTION_COUNT (1024U * 1024U)
#define MC_MAX_ITEM_COMPONENT_COUNT 256U
#define MC_MAX_CONTAINER_SLOTS 4096U
#define MC_MAX_ENTITY_METADATA_ENTRIES 256U
#define MC_MAX_ATTRIBUTE_COUNT 1024U
#define MC_MAX_ATTRIBUTE_MODIFIER_COUNT 1024U
#define MC_MAX_CHUNK_SECTIONS 1024U
#define MC_MAX_CHUNK_BLOCK_ENTITIES 65536U
#define MC_MAX_CHUNK_LIGHT_ARRAYS 1024U
#define MC_ERROR_OFFSET_UNKNOWN SIZE_MAX

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
typedef struct McStreamDecoder McStreamDecoder;

typedef enum {
    MC_STATE_UNKNOWN = -1,
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
    MC_PACKET_DIRECTION_UNKNOWN = -1,
    MC_PACKET_SERVERBOUND = 0,
    MC_PACKET_CLIENTBOUND
} McPacketDirection;


/* ============================================================
 * ERROR MODEL / DECODE POLICY
 * ============================================================ */

/* Error codes are stable machine-readable identifiers. Diagnostic strings may
 * change and must not be used as test or control-flow identifiers. */
typedef enum {
    MC_ERROR_NONE = 0,
    MC_ERROR_INVALID_ARGUMENT,
    MC_ERROR_UNSUPPORTED_PROTOCOL,
    MC_ERROR_INVALID_STATE,
    MC_ERROR_INVALID_DIRECTION,
    MC_ERROR_UNKNOWN_PACKET,
    MC_ERROR_PARTIAL_INPUT,
    MC_ERROR_VARINT_OVERFLOW,
    MC_ERROR_VARINT_NON_CANONICAL,
    MC_ERROR_FRAME_TOO_LARGE,
    MC_ERROR_BUFFER_LIMIT,
    MC_ERROR_DECOMPRESSED_TOO_LARGE,
    MC_ERROR_COMPRESSION_HEADER,
    MC_ERROR_COMPRESSION_THRESHOLD,
    MC_ERROR_ZLIB,
    MC_ERROR_TRAILING_BYTES,
    MC_ERROR_INVALID_BOOLEAN,
    MC_ERROR_STRING_TOO_LARGE,
    MC_ERROR_NBT_DEPTH,
    MC_ERROR_NBT_LENGTH,
    MC_ERROR_INVALID_LENGTH,
    MC_ERROR_INTEGER_OVERFLOW,
    MC_ERROR_INVALID_PACKET_BODY,
    MC_ERROR_OUT_OF_MEMORY,
    MC_ERROR_IO,
    MC_ERROR_TIMEOUT,
    MC_ERROR_INTERNAL
} McErrorCode;

typedef struct {
    McErrorCode code;
    size_t offset;
    int protocol;
    McState state;
    McPacketDirection direction;
    int32_t packet_id;
} McError;

typedef enum {
    MC_DECODE_VANILLA_COMPAT = 0,
    MC_DECODE_STRICT = 1
} McDecodeMode;

void mc_error_clear(McError *error);
const char *mc_error_name(McErrorCode code);

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
    /* Initialized by mc_reader_init()/mc_reader_init_mode(). Direct aggregate
     * initialization is not supported because future additive policy fields
     * may be appended here. */
    McDecodeMode mode;
    McError *error;
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
    /* Decoders preserve the 1.7 gzip member as a borrowed wire slice instead
     * of allocating an inflated copy. Encoders continue to accept uncompressed
     * named-root NBT and therefore require this flag to be false. */
    bool held_item_nbt_compressed;
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
    bool held_item_nbt_compressed;
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

/* A bounded, normalized view of clientbound open_window/open_screen. Legacy
 * protocols expose either a numeric or namespaced menu type plus an explicit
 * top-inventory size; registry-era protocols expose a numeric menu type. The
 * title is returned as a borrowed encoded string/NBT slice so callers do not
 * need to duplicate release-specific framing merely to identify the menu. */
typedef struct {
    int32_t window_id;
    int32_t menu_type;
    int32_t slot_count;
    int32_t entity_id;
    McBytes named_menu_type;
    McBytes encoded_title;
    bool registry_menu_type;
    bool title_is_nbt;
    bool has_entity_id;
} McContainerOpen;

#define MC_CONTAINER_CONTENT_MAX_SLOTS 128U

typedef struct {
    int32_t item_id;
    int32_t count;
} McContainerItem;

/* Normalized clientbound window_items/container_set_content. The fixed bound
 * covers every Vanilla menu while keeping parsing allocation-free and safe for
 * packet callbacks. Items with metadata/components intentionally fail the
 * plain-item decoder instead of being accepted lossily. */
typedef struct {
    int32_t window_id;
    int32_t state_id;
    size_t slot_count;
    McContainerItem slots[MC_CONTAINER_CONTENT_MAX_SLOTS];
    McContainerItem carried;
    bool has_state_id;
    bool has_carried;
} McContainerContent;

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

/* ============================================================
 * TYPED PACKET FAMILIES
 * ============================================================ */

/* Family values are stable across wire packet-ID renumbering. UNKNOWN means
 * catalog-only coverage; it never implies that a packet body was decoded. */
typedef enum {
    MC_FAMILY_UNKNOWN = 0,
    MC_FAMILY_PLAYER_MOVEMENT,
    MC_FAMILY_PLAYER_INPUT,
    MC_FAMILY_ENTITY_ACTION,
    MC_FAMILY_ABILITIES,
    MC_FAMILY_VEHICLE_MOVE,
    MC_FAMILY_STEER_VEHICLE,
    MC_FAMILY_USE_ENTITY,
    MC_FAMILY_ATTACK,
    MC_FAMILY_ARM_ANIMATION,
    MC_FAMILY_BLOCK_DIG,
    MC_FAMILY_BLOCK_PLACE,
    MC_FAMILY_USE_ITEM,
    MC_FAMILY_HELD_ITEM_SLOT,
    MC_FAMILY_TELEPORT_CONFIRM,
    MC_FAMILY_WINDOW_CLICK,
    MC_FAMILY_SET_CREATIVE_SLOT,
    MC_FAMILY_CLIENT_COMMAND,
    MC_FAMILY_CLOSE_WINDOW,
    MC_FAMILY_SERVER_POSITION,
    MC_FAMILY_ENTITY_VELOCITY,
    MC_FAMILY_EXPLOSION,
    MC_FAMILY_ENTITY_EFFECT,
    MC_FAMILY_REMOVE_ENTITY_EFFECT,
    MC_FAMILY_UPDATE_ATTRIBUTES,
    MC_FAMILY_RELATIVE_ENTITY_MOVE,
    MC_FAMILY_ENTITY_MOVE_LOOK,
    MC_FAMILY_ENTITY_TELEPORT,
    MC_FAMILY_ENTITY_HEAD_ROTATION,
    MC_FAMILY_ENTITY_METADATA,
    MC_FAMILY_ATTACH_ENTITY,
    MC_FAMILY_SET_PASSENGERS,
    MC_FAMILY_BLOCK_CHANGE,
    MC_FAMILY_MULTI_BLOCK_CHANGE,
    MC_FAMILY_MAP_CHUNK,
    MC_FAMILY_UNLOAD_CHUNK,
    MC_FAMILY_SET_SLOT,
    MC_FAMILY_WINDOW_ITEMS,
    MC_FAMILY_RESPAWN,
    MC_FAMILY_GAME_STATE_CHANGE
} McPacketFamily;

enum {
    MC_MOVE_HAS_POSITION = 1U << 0,
    MC_MOVE_HAS_ROTATION = 1U << 1,
    MC_MOVE_HAS_ON_GROUND = 1U << 2,
    MC_MOVE_HAS_TELEPORT_ID = 1U << 3,
    MC_MOVE_HAS_DELTA = 1U << 4,
    MC_MOVE_HAS_STANCE_Y = 1U << 5,
    MC_MOVE_HAS_HORIZONTAL_COLLISION = 1U << 6
};

typedef struct {
    double x;
    double y;
    double z;
    double wire_y;
    float yaw;
    float pitch;
    bool on_ground;
    bool horizontal_collision;
    bool wire_y_is_stance;
    uint32_t presence;
    uint32_t raw_flags;
} McPlayerMovementPacket;

typedef struct {
    float sideways;
    float forward;
    uint8_t flags;
    bool bitset;
} McPlayerInputPacket;

typedef struct {
    double x;
    double y;
    double z;
    float yaw;
    float pitch;
    bool on_ground;
    uint32_t presence;
} McVehicleMovePacket;

enum {
    MC_USE_ENTITY_HAS_TARGET = 1U << 0,
    MC_USE_ENTITY_HAS_HAND = 1U << 1,
    MC_USE_ENTITY_HAS_SNEAKING = 1U << 2
};

typedef struct {
    int32_t entity_id;
    int32_t action;
    float target_x;
    float target_y;
    float target_z;
    int32_t hand;
    bool sneaking;
    uint32_t presence;
} McUseEntityPacket;

typedef struct {
    int32_t entity_id;
    int32_t hand;
} McArmAnimationPacket;

typedef struct {
    int32_t slot;
} McHeldItemSlotPacket;

typedef struct {
    int32_t teleport_id;
} McTeleportConfirmPacket;

typedef struct {
    int32_t action;
} McClientCommandPacket;

typedef struct {
    int32_t window_id;
} McCloseWindowPacket;

typedef struct {
    int32_t entity_id;
    int16_t velocity_x_raw;
    int16_t velocity_y_raw;
    int16_t velocity_z_raw;
    double velocity_x;
    double velocity_y;
    double velocity_z;
    /* Protocol 773+ replaces the three signed shorts with Mojang's bounded
     * low-precision vector. These fields preserve that complete wire form. */
    uint64_t velocity_packed;
    uint64_t velocity_scale;
    McBytes velocity_wire;
    bool low_precision_encoding;
} McEntityVelocityPacket;

typedef struct {
    int32_t entity_id;
    int16_t delta_x_raw;
    int16_t delta_y_raw;
    int16_t delta_z_raw;
    double delta_x;
    double delta_y;
    double delta_z;
    uint8_t yaw_raw;
    uint8_t pitch_raw;
    float yaw;
    float pitch;
    bool on_ground;
    uint32_t presence;
} McEntityMovePacket;

typedef struct {
    int32_t entity_id;
    double x;
    double y;
    double z;
    double delta_x;
    double delta_y;
    double delta_z;
    uint8_t yaw_raw;
    uint8_t pitch_raw;
    float yaw;
    float pitch;
    bool on_ground;
    uint32_t presence;
} McEntityTeleportPacket;

typedef struct {
    int32_t entity_id;
    uint8_t yaw_raw;
    float yaw;
} McEntityHeadRotationPacket;

typedef struct {
    McPosition position;
    int32_t state_id;
} McBlockChangePacket;

typedef enum {
    MC_ITEM_WIRE_FULL = 0,
    MC_ITEM_WIRE_UNTRUSTED,
    MC_ITEM_WIRE_HASHED
} McItemWireKind;

/* Borrowed view of one complete ItemStack/Slot. `encoded` contains precisely
 * the bytes consumed for the item. NBT and component sub-views point inside
 * it and remain valid for the lifetime of the packet payload. */
typedef struct {
    bool present;
    bool nbt_compressed;
    bool component_values_length_prefixed;
    McItemWireKind wire_kind;
    int32_t item_id;
    int32_t count;
    int32_t damage;
    uint32_t added_component_count;
    uint32_t removed_component_count;
    McBytes nbt;
    McBytes components;
    McBytes encoded;
} McItemStackView;

typedef struct {
    int32_t window_id;
    int32_t state_id;
    int16_t slot;
    int8_t mouse_button;
    int16_t action_number;
    int32_t mode;
    uint32_t changed_slot_count;
    McBytes changed_slots;
    McItemStackView carried_item;
    bool has_state_id;
    bool has_action_number;
    bool hashed_slots;
} McWindowClickPacket;

typedef struct {
    int16_t slot;
    McItemStackView item;
} McSetCreativeSlotPacket;

typedef struct {
    int32_t window_id;
    int32_t state_id;
    int16_t slot;
    McItemStackView item;
    bool has_state_id;
} McSetSlotPacket;

typedef struct {
    int32_t window_id;
    int32_t state_id;
    uint32_t item_count;
    McBytes items;
    McItemStackView carried_item;
    McItemWireKind item_wire_kind;
    bool has_state_id;
    bool has_carried_item;
} McWindowItemsPacket;

typedef struct {
    McReader reader;
    int protocol;
    McItemWireKind wire_kind;
    uint32_t remaining;
} McItemIterator;

typedef enum {
    MC_MULTI_BLOCK_RECORD_LEGACY_1_7 = 0,
    MC_MULTI_BLOCK_RECORD_CHUNK,
    MC_MULTI_BLOCK_RECORD_SECTION_VARLONG,
    MC_MULTI_BLOCK_RECORD_SECTION_VARINT
} McMultiBlockRecordFormat;

typedef struct {
    int32_t chunk_x;
    int32_t chunk_z;
    int32_t section_y;
    uint32_t record_count;
    McBytes records;
    McMultiBlockRecordFormat format;
    bool suppress_light_updates;
    bool has_light_update_flag;
} McMultiBlockChangePacket;

typedef struct {
    McReader reader;
    McMultiBlockChangePacket packet;
    uint32_t remaining;
} McBlockChangeIterator;

typedef struct {
    McPosition position;
    int32_t state_id;
    uint64_t raw_record;
} McBlockChangeRecord;


/* ============================================================
 * TIER B BOUNDED PACKET ENVELOPES
 * ============================================================ */

typedef struct {
    double x;
    double y;
    double z;
    float radius;
    uint32_t affected_block_count;
    McBytes affected_blocks;
    double motion_x;
    double motion_y;
    double motion_z;
    McBytes effects;
    bool has_motion;
} McExplosionPacket;

typedef struct {
    int32_t entity_id;
    int32_t effect_id;
    int32_t amplifier;
    int32_t duration;
    uint8_t flags;
    McBytes factor_data;
    bool has_factor_data;
} McEntityEffectPacket;

typedef struct {
    int32_t entity_id;
    int32_t effect_id;
} McRemoveEntityEffectPacket;

typedef struct {
    int32_t entity_id;
    uint32_t attribute_count;
    uint32_t modifier_count;
    McBytes attributes;
} McUpdateAttributesPacket;

typedef struct {
    int32_t entity_id;
    uint32_t entry_count;
    McBytes entries;
    bool terminated;
} McEntityMetadataPacket;

typedef struct {
    int32_t entity_id;
    int32_t vehicle_id;
    bool leash;
    bool has_leash;
} McAttachEntityPacket;

typedef struct {
    int32_t entity_id;
    uint32_t passenger_count;
    McBytes passengers;
} McPassengersPacket;

typedef struct {
    int32_t chunk_x;
    int32_t chunk_z;
} McUnloadChunkPacket;

typedef struct {
    int32_t dimension_id;
    McBytes dimension;
    McBytes world_name;
    int64_t hashed_seed;
    int32_t game_mode;
    int32_t previous_game_mode;
    int32_t portal_cooldown;
    int32_t sea_level;
    uint32_t raw_flags;
    McBytes death_location;
    bool has_dimension_id;
    bool has_dimension_data;
    bool has_world_name;
    bool has_hashed_seed;
    bool has_previous_game_mode;
    bool has_death_location;
    bool has_portal_cooldown;
    bool has_sea_level;
} McRespawnPacket;

typedef struct {
    uint8_t reason;
    float value;
} McGameStateChangePacket;

typedef enum {
    MC_CHUNK_HEIGHTMAP_NONE = 0,
    MC_CHUNK_HEIGHTMAP_NAMED_NBT,
    MC_CHUNK_HEIGHTMAP_ANONYMOUS_NBT,
    MC_CHUNK_HEIGHTMAP_REGISTRY
} McChunkHeightmapFormat;

typedef struct {
    int32_t chunk_x;
    int32_t chunk_z;
    uint64_t section_mask;
    uint32_t section_mask_word_count;
    uint32_t biome_count;
    uint32_t block_entity_count;
    uint32_t sky_light_count;
    uint32_t block_light_count;
    McBytes heightmaps;
    McBytes biomes;
    McBytes chunk_data;
    McBytes block_entities;
    McBytes light_data;
    McChunkHeightmapFormat heightmap_format;
    bool ground_up;
    bool ignore_old_data;
    bool trust_edges;
    bool has_trust_edges;
} McChunkEnvelope;

typedef struct {
    uint16_t non_air_block_count;
    uint8_t block_bits_per_entry;
    uint8_t biome_bits_per_entry;
    uint32_t block_palette_count;
    uint32_t biome_palette_count;
    uint32_t block_long_count;
    uint32_t biome_long_count;
    McBytes block_palette;
    McBytes biome_palette;
    McBytes block_data;
    McBytes biome_data;
    McBytes encoded;
} McChunkSectionView;

typedef struct {
    McReader reader;
    int protocol;
    uint32_t remaining;
} McChunkSectionIterator;


/* ============================================================
 * CANONICAL PACKET IR
 * ============================================================ */

/* Canonical values normalize equivalent wire families while raw_payload,
 * packet_id, presence and raw_flags preserve the information required for
 * diagnostics and deterministic replay. No canonical decoder performs game
 * simulation, collision checks or plausibility repair. */
typedef struct {
    int protocol;
    McState state;
    McPacketDirection direction;
    int32_t packet_id;
    McPacketFamily family;
    McBytes raw_payload;
} McCanonicalHeader;

typedef struct {
    int protocol;
    int32_t packet_id;
    McPacketDirection direction;
    McPacketFamily family;
    int32_t entity_id;
    double x;
    double y;
    double z;
    double wire_y;
    float yaw;
    float pitch;
    double delta_x;
    double delta_y;
    double delta_z;
    int32_t teleport_id;
    uint32_t relative_flags;
    uint32_t presence;
    uint32_t raw_flags;
    bool on_ground;
    bool horizontal_collision;
    bool wire_y_is_stance;
} McCanonicalMovement;

enum {
    MC_ACTION_HAS_ENTITY = 1U << 0,
    MC_ACTION_HAS_ACTION = 1U << 1,
    MC_ACTION_HAS_HAND = 1U << 2,
    MC_ACTION_HAS_POSITION = 1U << 3,
    MC_ACTION_HAS_TARGET = 1U << 4,
    MC_ACTION_HAS_SEQUENCE = 1U << 5,
    MC_ACTION_HAS_SLOT = 1U << 6,
    MC_ACTION_HAS_FLAGS = 1U << 7,
    MC_ACTION_HAS_SPEEDS = 1U << 8,
    MC_ACTION_HAS_BOOLEAN = 1U << 9
};

typedef struct {
    int protocol;
    int32_t packet_id;
    McPacketDirection direction;
    McPacketFamily family;
    int32_t entity_id;
    int32_t action;
    int32_t hand;
    int32_t sequence;
    int32_t slot;
    McPosition position;
    float target_x;
    float target_y;
    float target_z;
    float sideways;
    float forward;
    float flying_speed;
    float walking_speed;
    uint32_t presence;
    uint32_t raw_flags;
    bool boolean_value;
} McCanonicalAction;

typedef struct {
    int protocol;
    int32_t packet_id;
    McPacketDirection direction;
    McPacketFamily family;
    int32_t window_id;
    int32_t state_id;
    int16_t slot;
    int8_t mouse_button;
    int16_t action_number;
    int32_t mode;
    uint32_t item_count;
    uint32_t changed_slot_count;
    McItemStackView item;
    McBytes items;
    McBytes changed_slots;
    uint32_t presence;
} McCanonicalInventory;

typedef struct {
    int protocol;
    int32_t packet_id;
    McPacketDirection direction;
    McPacketFamily family;
    McPosition position;
    int32_t state_id;
    uint32_t record_count;
    McBytes records;
    McMultiBlockRecordFormat record_format;
    bool suppress_light_updates;
} McCanonicalBlockChange;


/* ============================================================
 * DETERMINISTIC REPLAY FORMAT
 * ============================================================ */

#define MC_REPLAY_MAGIC_SIZE 4U
#define MC_REPLAY_FORMAT_VERSION 1U

typedef struct {
    McPacketDirection direction;
    McState state;
    uint64_t delta_time_ns;
    int32_t packet_id;
    McBytes payload;
} McReplayRecord;

typedef struct {
    McReader reader;
    int protocol;
    uint32_t record_count;
    uint32_t record_index;
    McError *error;
} McReplayReader;

McPacketFamily mc_packet_family(int protocol, McState state,
    McPacketDirection direction, int32_t packet_id);
const char *mc_packet_family_name(McPacketFamily family);
/* Catalog/family tables are immutable. Readers, writers, typed decoders,
 * canonical decoders and replay readers are thread-safe when each invocation
 * uses separate caller-owned storage; the library has no mutable global
 * decode cache. */
/* Returns the family-specific caller-owned output size, or zero for
 * catalog-only and envelope families without a typed decoder. */
size_t mc_packet_decoded_size(McPacketFamily family);
/* Pure exact-consumption dispatcher. output must be at least
 * mc_packet_decoded_size(*family); no allocation or socket access occurs. */
int mc_decode_packet(int protocol, McState state,
    McPacketDirection direction, int32_t packet_id,
    const void *payload, size_t payload_size, McDecodeMode mode,
    void *output, size_t output_size, McPacketFamily *family,
    McError *error);

/* Standalone item and borrowed iterator APIs use the same bounded codecs as
 * the typed dispatcher. Item/component counts are capped by the public limits
 * above and every accepted item is consumed exactly. */
bool mc_reader_item_stack(McReader *reader, int protocol,
    McItemWireKind wire_kind, McItemStackView *item);
bool mc_window_items_iterator(const McWindowItemsPacket *packet,
    int protocol, McItemIterator *iterator);
bool mc_item_iterator_next(McItemIterator *iterator, McItemStackView *item);
bool mc_multi_block_change_iterator(const McMultiBlockChangePacket *packet,
    McBlockChangeIterator *iterator);
bool mc_block_change_iterator_next(McBlockChangeIterator *iterator,
    McBlockChangeRecord *record);
bool mc_canonical_header_init(McCanonicalHeader *header, int protocol,
    McState state, McPacketDirection direction, int32_t packet_id,
    const void *payload, size_t payload_size, McError *error);
/* Catalog-only packets are valid headers with MC_FAMILY_UNKNOWN and retain
 * their complete raw payload; family-specific canonical decoders reject them. */
bool mc_decode_canonical_movement(const McCanonicalHeader *header,
    McCanonicalMovement *value, McDecodeMode mode, McError *error);
bool mc_decode_canonical_action(const McCanonicalHeader *header,
    McCanonicalAction *value, McDecodeMode mode, McError *error);
bool mc_decode_canonical_inventory(const McCanonicalHeader *header,
    McCanonicalInventory *value, McDecodeMode mode, McError *error);
bool mc_decode_canonical_block_change(const McCanonicalHeader *header,
    McCanonicalBlockChange *value, McDecodeMode mode, McError *error);
/* Trace layout: "MCTR", u16 version, u16 flags, i32 protocol, u32 count,
 * followed by direction:u8, state:u8, delta_ns:u64, packet_id:i32,
 * payload_size:u32 and payload bytes. Integers use network byte order. */
bool mc_replay_reader_init(McReplayReader *reader, const void *data,
    size_t size, McError *error);
bool mc_replay_reader_next(McReplayReader *reader, McReplayRecord *record);
bool mc_replay_reader_finish(McReplayReader *reader);
/* Modern (1.18+) section views are initialized with the dimension section
 * count supplied by the caller/profile. No 4096-entry array is materialized. */
bool mc_chunk_section_iterator_init(const McChunkEnvelope *chunk, int protocol,
    uint32_t section_count, McChunkSectionIterator *iterator);
bool mc_chunk_section_iterator_next(McChunkSectionIterator *iterator,
    McChunkSectionView *section);
bool mc_chunk_section_block_state(const McChunkSectionView *section,
    uint32_t block_index, int32_t *state_id);

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
 * component payloads and removed component type IDs (1.21.5+). */
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
/* The structured error is optional and borrowed for the reader lifetime. It is
 * cleared by initialization. Strict mode additionally requires canonical
 * VarInt/VarLong encodings and boolean bytes 0 or 1. */
void mc_reader_init_mode(McReader *reader, const void *data, size_t size,
    McDecodeMode mode, McError *error);
size_t mc_reader_remaining(const McReader *reader);
/* Succeeds only for a healthy, exactly consumed reader. A remaining byte is a
 * stable MC_ERROR_TRAILING_BYTES failure at the first trailing offset. */
bool mc_reader_finish(McReader *reader);
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
bool mc_reader_string_bounded(McReader *reader, size_t max_size,
    McBytes *value);
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
/* Decodes a complete release-aware open_window/open_screen body. The packet ID
 * is excluded. encoded_title and named_menu_type borrow from reader storage. */
bool mc_reader_container_open(McReader *reader, int protocol,
    McContainerOpen *value);
/* Decodes one bounded release-aware window_items/container_set_content body.
 * The packet ID is excluded; callers may require zero bytes remaining. */
bool mc_reader_container_content(McReader *reader, int protocol,
    McContainerContent *value);
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


/* MC_GENERATED_PUBLIC_BEGIN */
/* Generated by tools/schema_compiler.py from minecraft-data.
 * Protocol 776; protocol.json sha256 c9daf09fbedf465516b4c08c70d374a13ec1c369df70bf945b1817bb181b68fc.
 * Do not edit inside the generated markers. */

#define MC776_HANDSHAKING_SERVERBOUND_SET_PROTOCOL 0
#define MC776_HANDSHAKING_SERVERBOUND_LEGACY_SERVER_LIST_PING 254
#define MC776_STATUS_SERVERBOUND_PING_START 0
#define MC776_STATUS_SERVERBOUND_PING 1
#define MC776_STATUS_CLIENTBOUND_SERVER_INFO 0
#define MC776_STATUS_CLIENTBOUND_PING 1
#define MC776_LOGIN_SERVERBOUND_LOGIN_START 0
#define MC776_LOGIN_SERVERBOUND_ENCRYPTION_BEGIN 1
#define MC776_LOGIN_SERVERBOUND_LOGIN_PLUGIN_RESPONSE 2
#define MC776_LOGIN_SERVERBOUND_LOGIN_ACKNOWLEDGED 3
#define MC776_LOGIN_SERVERBOUND_COOKIE_RESPONSE 4
#define MC776_LOGIN_CLIENTBOUND_DISCONNECT 0
#define MC776_LOGIN_CLIENTBOUND_ENCRYPTION_BEGIN 1
#define MC776_LOGIN_CLIENTBOUND_SUCCESS 2
#define MC776_LOGIN_CLIENTBOUND_COMPRESS 3
#define MC776_LOGIN_CLIENTBOUND_LOGIN_PLUGIN_REQUEST 4
#define MC776_LOGIN_CLIENTBOUND_COOKIE_REQUEST 5
#define MC776_CONFIGURATION_SERVERBOUND_SETTINGS 0
#define MC776_CONFIGURATION_SERVERBOUND_COOKIE_RESPONSE 1
#define MC776_CONFIGURATION_SERVERBOUND_CUSTOM_PAYLOAD 2
#define MC776_CONFIGURATION_SERVERBOUND_FINISH_CONFIGURATION 3
#define MC776_CONFIGURATION_SERVERBOUND_KEEP_ALIVE 4
#define MC776_CONFIGURATION_SERVERBOUND_PONG 5
#define MC776_CONFIGURATION_SERVERBOUND_RESOURCE_PACK_RECEIVE 6
#define MC776_CONFIGURATION_SERVERBOUND_SELECT_KNOWN_PACKS 7
#define MC776_CONFIGURATION_SERVERBOUND_CUSTOM_CLICK_ACTION 8
#define MC776_CONFIGURATION_SERVERBOUND_ACCEPT_CODE_OF_CONDUCT 9
#define MC776_CONFIGURATION_CLIENTBOUND_COOKIE_REQUEST 0
#define MC776_CONFIGURATION_CLIENTBOUND_CUSTOM_PAYLOAD 1
#define MC776_CONFIGURATION_CLIENTBOUND_DISCONNECT 2
#define MC776_CONFIGURATION_CLIENTBOUND_FINISH_CONFIGURATION 3
#define MC776_CONFIGURATION_CLIENTBOUND_KEEP_ALIVE 4
#define MC776_CONFIGURATION_CLIENTBOUND_PING 5
#define MC776_CONFIGURATION_CLIENTBOUND_RESET_CHAT 6
#define MC776_CONFIGURATION_CLIENTBOUND_REGISTRY_DATA 7
#define MC776_CONFIGURATION_CLIENTBOUND_REMOVE_RESOURCE_PACK 8
#define MC776_CONFIGURATION_CLIENTBOUND_ADD_RESOURCE_PACK 9
#define MC776_CONFIGURATION_CLIENTBOUND_STORE_COOKIE 10
#define MC776_CONFIGURATION_CLIENTBOUND_TRANSFER 11
#define MC776_CONFIGURATION_CLIENTBOUND_FEATURE_FLAGS 12
#define MC776_CONFIGURATION_CLIENTBOUND_TAGS 13
#define MC776_CONFIGURATION_CLIENTBOUND_SELECT_KNOWN_PACKS 14
#define MC776_CONFIGURATION_CLIENTBOUND_CUSTOM_REPORT_DETAILS 15
#define MC776_CONFIGURATION_CLIENTBOUND_SERVER_LINKS 16
#define MC776_CONFIGURATION_CLIENTBOUND_CLEAR_DIALOG 17
#define MC776_CONFIGURATION_CLIENTBOUND_SHOW_DIALOG 18
#define MC776_CONFIGURATION_CLIENTBOUND_CODE_OF_CONDUCT 19
#define MC776_PLAY_SERVERBOUND_TELEPORT_CONFIRM 0
#define MC776_PLAY_SERVERBOUND_ATTACK 1
#define MC776_PLAY_SERVERBOUND_QUERY_BLOCK_NBT 2
#define MC776_PLAY_SERVERBOUND_SELECT_BUNDLE_ITEM 3
#define MC776_PLAY_SERVERBOUND_SET_DIFFICULTY 4
#define MC776_PLAY_SERVERBOUND_CHANGE_GAMEMODE 5
#define MC776_PLAY_SERVERBOUND_MESSAGE_ACKNOWLEDGEMENT 6
#define MC776_PLAY_SERVERBOUND_CHAT_COMMAND 7
#define MC776_PLAY_SERVERBOUND_CHAT_COMMAND_SIGNED 8
#define MC776_PLAY_SERVERBOUND_CHAT_MESSAGE 9
#define MC776_PLAY_SERVERBOUND_CHAT_SESSION_UPDATE 10
#define MC776_PLAY_SERVERBOUND_CHUNK_BATCH_RECEIVED 11
#define MC776_PLAY_SERVERBOUND_CLIENT_COMMAND 12
#define MC776_PLAY_SERVERBOUND_TICK_END 13
#define MC776_PLAY_SERVERBOUND_SETTINGS 14
#define MC776_PLAY_SERVERBOUND_TAB_COMPLETE 15
#define MC776_PLAY_SERVERBOUND_CONFIGURATION_ACKNOWLEDGED 16
#define MC776_PLAY_SERVERBOUND_ENCHANT_ITEM 17
#define MC776_PLAY_SERVERBOUND_WINDOW_CLICK 18
#define MC776_PLAY_SERVERBOUND_CLOSE_WINDOW 19
#define MC776_PLAY_SERVERBOUND_SET_SLOT_STATE 20
#define MC776_PLAY_SERVERBOUND_COOKIE_RESPONSE 21
#define MC776_PLAY_SERVERBOUND_CUSTOM_PAYLOAD 22
#define MC776_PLAY_SERVERBOUND_DEBUG_SUBSCRIPTION_REQUEST 23
#define MC776_PLAY_SERVERBOUND_EDIT_BOOK 24
#define MC776_PLAY_SERVERBOUND_QUERY_ENTITY_NBT 25
#define MC776_PLAY_SERVERBOUND_USE_ENTITY 26
#define MC776_PLAY_SERVERBOUND_GENERATE_STRUCTURE 27
#define MC776_PLAY_SERVERBOUND_KEEP_ALIVE 28
#define MC776_PLAY_SERVERBOUND_LOCK_DIFFICULTY 29
#define MC776_PLAY_SERVERBOUND_POSITION 30
#define MC776_PLAY_SERVERBOUND_POSITION_LOOK 31
#define MC776_PLAY_SERVERBOUND_LOOK 32
#define MC776_PLAY_SERVERBOUND_FLYING 33
#define MC776_PLAY_SERVERBOUND_VEHICLE_MOVE 34
#define MC776_PLAY_SERVERBOUND_STEER_BOAT 35
#define MC776_PLAY_SERVERBOUND_PICK_ITEM_FROM_BLOCK 36
#define MC776_PLAY_SERVERBOUND_PICK_ITEM_FROM_ENTITY 37
#define MC776_PLAY_SERVERBOUND_PING_REQUEST 38
#define MC776_PLAY_SERVERBOUND_CRAFT_RECIPE_REQUEST 39
#define MC776_PLAY_SERVERBOUND_ABILITIES 40
#define MC776_PLAY_SERVERBOUND_BLOCK_DIG 41
#define MC776_PLAY_SERVERBOUND_ENTITY_ACTION 42
#define MC776_PLAY_SERVERBOUND_PLAYER_INPUT 43
#define MC776_PLAY_SERVERBOUND_PLAYER_LOADED 44
#define MC776_PLAY_SERVERBOUND_PONG 45
#define MC776_PLAY_SERVERBOUND_RECIPE_BOOK 46
#define MC776_PLAY_SERVERBOUND_DISPLAYED_RECIPE 47
#define MC776_PLAY_SERVERBOUND_NAME_ITEM 48
#define MC776_PLAY_SERVERBOUND_RESOURCE_PACK_RECEIVE 49
#define MC776_PLAY_SERVERBOUND_ADVANCEMENT_TAB 50
#define MC776_PLAY_SERVERBOUND_SELECT_TRADE 51
#define MC776_PLAY_SERVERBOUND_SET_BEACON_EFFECT 52
#define MC776_PLAY_SERVERBOUND_HELD_ITEM_SLOT 53
#define MC776_PLAY_SERVERBOUND_UPDATE_COMMAND_BLOCK 54
#define MC776_PLAY_SERVERBOUND_UPDATE_COMMAND_BLOCK_MINECART 55
#define MC776_PLAY_SERVERBOUND_SET_CREATIVE_SLOT 56
#define MC776_PLAY_SERVERBOUND_SET_GAME_RULE 57
#define MC776_PLAY_SERVERBOUND_UPDATE_JIGSAW_BLOCK 58
#define MC776_PLAY_SERVERBOUND_UPDATE_STRUCTURE_BLOCK 59
#define MC776_PLAY_SERVERBOUND_SET_TEST_BLOCK 60
#define MC776_PLAY_SERVERBOUND_UPDATE_SIGN 61
#define MC776_PLAY_SERVERBOUND_SPECTATOR_ACTION 62
#define MC776_PLAY_SERVERBOUND_ARM_ANIMATION 63
#define MC776_PLAY_SERVERBOUND_SPECTATE 64
#define MC776_PLAY_SERVERBOUND_TEST_INSTANCE_BLOCK_ACTION 65
#define MC776_PLAY_SERVERBOUND_BLOCK_PLACE 66
#define MC776_PLAY_SERVERBOUND_USE_ITEM 67
#define MC776_PLAY_SERVERBOUND_CUSTOM_CLICK_ACTION 68
#define MC776_PLAY_CLIENTBOUND_BUNDLE_DELIMITER 0
#define MC776_PLAY_CLIENTBOUND_SPAWN_ENTITY 1
#define MC776_PLAY_CLIENTBOUND_ANIMATION 2
#define MC776_PLAY_CLIENTBOUND_STATISTICS 3
#define MC776_PLAY_CLIENTBOUND_ACKNOWLEDGE_PLAYER_DIGGING 4
#define MC776_PLAY_CLIENTBOUND_BLOCK_BREAK_ANIMATION 5
#define MC776_PLAY_CLIENTBOUND_TILE_ENTITY_DATA 6
#define MC776_PLAY_CLIENTBOUND_BLOCK_ACTION 7
#define MC776_PLAY_CLIENTBOUND_BLOCK_CHANGE 8
#define MC776_PLAY_CLIENTBOUND_BOSS_BAR 9
#define MC776_PLAY_CLIENTBOUND_DIFFICULTY 10
#define MC776_PLAY_CLIENTBOUND_CHUNK_BATCH_FINISHED 11
#define MC776_PLAY_CLIENTBOUND_CHUNK_BATCH_START 12
#define MC776_PLAY_CLIENTBOUND_CHUNK_BIOMES 13
#define MC776_PLAY_CLIENTBOUND_CLEAR_TITLES 14
#define MC776_PLAY_CLIENTBOUND_TAB_COMPLETE 15
#define MC776_PLAY_CLIENTBOUND_DECLARE_COMMANDS 16
#define MC776_PLAY_CLIENTBOUND_CLOSE_WINDOW 17
#define MC776_PLAY_CLIENTBOUND_WINDOW_ITEMS 18
#define MC776_PLAY_CLIENTBOUND_CRAFT_PROGRESS_BAR 19
#define MC776_PLAY_CLIENTBOUND_SET_SLOT 20
#define MC776_PLAY_CLIENTBOUND_COOKIE_REQUEST 21
#define MC776_PLAY_CLIENTBOUND_SET_COOLDOWN 22
#define MC776_PLAY_CLIENTBOUND_CHAT_SUGGESTIONS 23
#define MC776_PLAY_CLIENTBOUND_CUSTOM_PAYLOAD 24
#define MC776_PLAY_CLIENTBOUND_DAMAGE_EVENT 25
#define MC776_PLAY_CLIENTBOUND_DEBUG_BLOCK_VALUE 26
#define MC776_PLAY_CLIENTBOUND_DEBUG_CHUNK_VALUE 27
#define MC776_PLAY_CLIENTBOUND_DEBUG_ENTITY_VALUE 28
#define MC776_PLAY_CLIENTBOUND_DEBUG_EVENT 29
#define MC776_PLAY_CLIENTBOUND_DEBUG_SAMPLE 30
#define MC776_PLAY_CLIENTBOUND_HIDE_MESSAGE 31
#define MC776_PLAY_CLIENTBOUND_KICK_DISCONNECT 32
#define MC776_PLAY_CLIENTBOUND_PROFILELESS_CHAT 33
#define MC776_PLAY_CLIENTBOUND_ENTITY_STATUS 34
#define MC776_PLAY_CLIENTBOUND_SYNC_ENTITY_POSITION 35
#define MC776_PLAY_CLIENTBOUND_EXPLOSION 36
#define MC776_PLAY_CLIENTBOUND_UNLOAD_CHUNK 37
#define MC776_PLAY_CLIENTBOUND_GAME_STATE_CHANGE 38
#define MC776_PLAY_CLIENTBOUND_GAME_RULE_VALUES 39
#define MC776_PLAY_CLIENTBOUND_GAME_TEST_HIGHLIGHT_POS 40
#define MC776_PLAY_CLIENTBOUND_OPEN_HORSE_WINDOW 41
#define MC776_PLAY_CLIENTBOUND_HURT_ANIMATION 42
#define MC776_PLAY_CLIENTBOUND_INITIALIZE_WORLD_BORDER 43
#define MC776_PLAY_CLIENTBOUND_KEEP_ALIVE 44
#define MC776_PLAY_CLIENTBOUND_MAP_CHUNK 45
#define MC776_PLAY_CLIENTBOUND_WORLD_EVENT 46
#define MC776_PLAY_CLIENTBOUND_WORLD_PARTICLES 47
#define MC776_PLAY_CLIENTBOUND_UPDATE_LIGHT 48
#define MC776_PLAY_CLIENTBOUND_LOGIN 49
#define MC776_PLAY_CLIENTBOUND_LOW_DISK_SPACE_WARNING 50
#define MC776_PLAY_CLIENTBOUND_MAP 51
#define MC776_PLAY_CLIENTBOUND_TRADE_LIST 52
#define MC776_PLAY_CLIENTBOUND_REL_ENTITY_MOVE 53
#define MC776_PLAY_CLIENTBOUND_ENTITY_MOVE_LOOK 54
#define MC776_PLAY_CLIENTBOUND_MOVE_MINECART 55
#define MC776_PLAY_CLIENTBOUND_ENTITY_LOOK 56
#define MC776_PLAY_CLIENTBOUND_VEHICLE_MOVE 57
#define MC776_PLAY_CLIENTBOUND_OPEN_BOOK 58
#define MC776_PLAY_CLIENTBOUND_OPEN_WINDOW 59
#define MC776_PLAY_CLIENTBOUND_OPEN_SIGN_ENTITY 60
#define MC776_PLAY_CLIENTBOUND_PING 61
#define MC776_PLAY_CLIENTBOUND_PING_RESPONSE 62
#define MC776_PLAY_CLIENTBOUND_CRAFT_RECIPE_RESPONSE 63
#define MC776_PLAY_CLIENTBOUND_ABILITIES 64
#define MC776_PLAY_CLIENTBOUND_PLAYER_CHAT 65
#define MC776_PLAY_CLIENTBOUND_END_COMBAT_EVENT 66
#define MC776_PLAY_CLIENTBOUND_ENTER_COMBAT_EVENT 67
#define MC776_PLAY_CLIENTBOUND_DEATH_COMBAT_EVENT 68
#define MC776_PLAY_CLIENTBOUND_PLAYER_REMOVE 69
#define MC776_PLAY_CLIENTBOUND_PLAYER_INFO 70
#define MC776_PLAY_CLIENTBOUND_FACE_PLAYER 71
#define MC776_PLAY_CLIENTBOUND_POSITION 72
#define MC776_PLAY_CLIENTBOUND_PLAYER_ROTATION 73
#define MC776_PLAY_CLIENTBOUND_RECIPE_BOOK_ADD 74
#define MC776_PLAY_CLIENTBOUND_RECIPE_BOOK_REMOVE 75
#define MC776_PLAY_CLIENTBOUND_RECIPE_BOOK_SETTINGS 76
#define MC776_PLAY_CLIENTBOUND_ENTITY_DESTROY 77
#define MC776_PLAY_CLIENTBOUND_REMOVE_ENTITY_EFFECT 78
#define MC776_PLAY_CLIENTBOUND_RESET_SCORE 79
#define MC776_PLAY_CLIENTBOUND_REMOVE_RESOURCE_PACK 80
#define MC776_PLAY_CLIENTBOUND_ADD_RESOURCE_PACK 81
#define MC776_PLAY_CLIENTBOUND_RESPAWN 82
#define MC776_PLAY_CLIENTBOUND_ENTITY_HEAD_ROTATION 83
#define MC776_PLAY_CLIENTBOUND_MULTI_BLOCK_CHANGE 84
#define MC776_PLAY_CLIENTBOUND_SELECT_ADVANCEMENT_TAB 85
#define MC776_PLAY_CLIENTBOUND_SERVER_DATA 86
#define MC776_PLAY_CLIENTBOUND_ACTION_BAR 87
#define MC776_PLAY_CLIENTBOUND_WORLD_BORDER_CENTER 88
#define MC776_PLAY_CLIENTBOUND_WORLD_BORDER_LERP_SIZE 89
#define MC776_PLAY_CLIENTBOUND_WORLD_BORDER_SIZE 90
#define MC776_PLAY_CLIENTBOUND_WORLD_BORDER_WARNING_DELAY 91
#define MC776_PLAY_CLIENTBOUND_WORLD_BORDER_WARNING_REACH 92
#define MC776_PLAY_CLIENTBOUND_CAMERA 93
#define MC776_PLAY_CLIENTBOUND_UPDATE_VIEW_POSITION 94
#define MC776_PLAY_CLIENTBOUND_UPDATE_VIEW_DISTANCE 95
#define MC776_PLAY_CLIENTBOUND_SET_CURSOR_ITEM 96
#define MC776_PLAY_CLIENTBOUND_SPAWN_POSITION 97
#define MC776_PLAY_CLIENTBOUND_SCOREBOARD_DISPLAY_OBJECTIVE 98
#define MC776_PLAY_CLIENTBOUND_ENTITY_METADATA 99
#define MC776_PLAY_CLIENTBOUND_ATTACH_ENTITY 100
#define MC776_PLAY_CLIENTBOUND_ENTITY_VELOCITY 101
#define MC776_PLAY_CLIENTBOUND_ENTITY_EQUIPMENT 102
#define MC776_PLAY_CLIENTBOUND_EXPERIENCE 103
#define MC776_PLAY_CLIENTBOUND_UPDATE_HEALTH 104
#define MC776_PLAY_CLIENTBOUND_HELD_ITEM_SLOT 105
#define MC776_PLAY_CLIENTBOUND_SCOREBOARD_OBJECTIVE 106
#define MC776_PLAY_CLIENTBOUND_SET_PASSENGERS 107
#define MC776_PLAY_CLIENTBOUND_SET_PLAYER_INVENTORY 108
#define MC776_PLAY_CLIENTBOUND_TEAMS 109
#define MC776_PLAY_CLIENTBOUND_SCOREBOARD_SCORE 110
#define MC776_PLAY_CLIENTBOUND_SIMULATION_DISTANCE 111
#define MC776_PLAY_CLIENTBOUND_SET_TITLE_SUBTITLE 112
#define MC776_PLAY_CLIENTBOUND_UPDATE_TIME 113
#define MC776_PLAY_CLIENTBOUND_SET_TITLE_TEXT 114
#define MC776_PLAY_CLIENTBOUND_SET_TITLE_TIME 115
#define MC776_PLAY_CLIENTBOUND_ENTITY_SOUND_EFFECT 116
#define MC776_PLAY_CLIENTBOUND_SOUND_EFFECT 117
#define MC776_PLAY_CLIENTBOUND_START_CONFIGURATION 118
#define MC776_PLAY_CLIENTBOUND_STOP_SOUND 119
#define MC776_PLAY_CLIENTBOUND_STORE_COOKIE 120
#define MC776_PLAY_CLIENTBOUND_SYSTEM_CHAT 121
#define MC776_PLAY_CLIENTBOUND_PLAYERLIST_HEADER 122
#define MC776_PLAY_CLIENTBOUND_NBT_QUERY_RESPONSE 123
#define MC776_PLAY_CLIENTBOUND_COLLECT 124
#define MC776_PLAY_CLIENTBOUND_ENTITY_TELEPORT 125
#define MC776_PLAY_CLIENTBOUND_TEST_INSTANCE_BLOCK_STATUS 126
#define MC776_PLAY_CLIENTBOUND_SET_TICKING_STATE 127
#define MC776_PLAY_CLIENTBOUND_STEP_TICK 128
#define MC776_PLAY_CLIENTBOUND_TRANSFER 129
#define MC776_PLAY_CLIENTBOUND_ADVANCEMENTS 130
#define MC776_PLAY_CLIENTBOUND_ENTITY_UPDATE_ATTRIBUTES 131
#define MC776_PLAY_CLIENTBOUND_ENTITY_EFFECT 132
#define MC776_PLAY_CLIENTBOUND_DECLARE_RECIPES 133
#define MC776_PLAY_CLIENTBOUND_TAGS 134
#define MC776_PLAY_CLIENTBOUND_SET_PROJECTILE_POWER 135
#define MC776_PLAY_CLIENTBOUND_CUSTOM_REPORT_DETAILS 136
#define MC776_PLAY_CLIENTBOUND_SERVER_LINKS 137
#define MC776_PLAY_CLIENTBOUND_TRACKED_WAYPOINT 138
#define MC776_PLAY_CLIENTBOUND_CLEAR_DIALOG 139
#define MC776_PLAY_CLIENTBOUND_SHOW_DIALOG 140

typedef struct Mc776PlayServerboundUseItem {
    int32_t hand;
    int32_t sequence;
    struct {
        float x;
        float y;
    } rotation;
} Mc776PlayServerboundUseItem;

bool mc776_play_serverbound_use_item_encode(McPacket *packet, const Mc776PlayServerboundUseItem *value);
bool mc776_play_serverbound_use_item_decode(McReader *reader, Mc776PlayServerboundUseItem *value);

typedef struct Mc776PlayServerboundBlockDig {
    int32_t status;
    McPosition location;
    int8_t face;
    int32_t sequence;
} Mc776PlayServerboundBlockDig;

bool mc776_play_serverbound_block_dig_encode(McPacket *packet, const Mc776PlayServerboundBlockDig *value);
bool mc776_play_serverbound_block_dig_decode(McReader *reader, Mc776PlayServerboundBlockDig *value);
/* MC_GENERATED_PUBLIC_END */


/* ============================================================
 * INCREMENTAL STREAM FRAMING
 * ============================================================ */

typedef struct {
    size_t max_frame_size;
    size_t max_decompressed_size;
    size_t max_buffered_size;
    size_t max_output_size;
    McDecodeMode mode;
} McStreamDecoderConfig;

typedef struct {
    int32_t packet_id;
    McBytes payload;
    bool compressed;
} McDecodedFrame;

/* Static catalogs and pure readers are thread-safe. An McStreamDecoder is
 * single-owner unless the caller provides external synchronization. Frame
 * payloads borrow decoder storage and remain valid only until the next feed,
 * reset or destroy call. */
void mc_stream_decoder_config_init(McStreamDecoderConfig *config);
McStreamDecoder *mc_stream_decoder_create(
    const McStreamDecoderConfig *config, McError *error);
void mc_stream_decoder_destroy(McStreamDecoder *decoder);
/* Reset discards partial input, retained output and the compression setting. */
void mc_stream_decoder_reset(McStreamDecoder *decoder);
/* Compression may change only between frames; -1 disables it and values >= 0
 * enable the Minecraft compression envelope at the supplied threshold. */
int mc_stream_decoder_set_compression(McStreamDecoder *decoder, int threshold,
    McError *error);
/* Appends one arbitrary TCP chunk and extracts up to frame_capacity complete
 * frames. Complete excess frames remain buffered and can be drained by a
 * later zero-size feed. A successful partial feed returns zero frames. */
int mc_stream_decoder_feed(McStreamDecoder *decoder, const void *data,
    size_t size, McDecodedFrame *frames, size_t frame_capacity,
    size_t *frame_count, McError *error);
/* Call at EOF. It fails with MC_ERROR_PARTIAL_INPUT when buffered bytes do not
 * form a complete frame; complete buffered frames must first be drained. */
int mc_stream_decoder_finish(McStreamDecoder *decoder, McError *error);
/* Observability helpers for tests and capacity monitoring. Retained size is
 * buffer capacity plus decompression/output capacity, not live payload size. */
size_t mc_stream_decoder_buffered_size(const McStreamDecoder *decoder);
size_t mc_stream_decoder_retained_size(const McStreamDecoder *decoder);


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
