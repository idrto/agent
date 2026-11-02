/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#ifndef IDR_H
#define IDR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IDR_ABI_VERSION 3

#define IDR_AUTH_BEARER 0
#define IDR_AUTH_DEVICE_TOKEN 1
#define IDR_AUTH_MTLS 2

typedef struct idr_engine idr_engine_t;

typedef struct idr_engine_config {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t use_mock; /* 1 = unit-test mock only; 0 = native libdatachannel */
  const char *source_id;
  const char *source_region;
  const char *auth_token; /* required */
  uint32_t auth_mode;     /* IDR_AUTH_* */
  const char *discovery_url; /* required when use_mock=0 */
  const char *discovery_key; /* optional; empty skips verify (dev) */
  uint32_t insecure_dev;     /* 1 = skip Presence TLS verify (local) */
} idr_engine_config_t;

enum {
  IDR_EVENT_NONE = 0,
  IDR_EVENT_CONNECTED = 1,
  IDR_EVENT_STREAM_OPENED = 2,
  IDR_EVENT_BYTES_AVAILABLE = 3,
  IDR_EVENT_STREAM_CLOSED = 4,
  IDR_EVENT_ERROR = 5
};

typedef struct idr_event {
  uint32_t kind;
  uint64_t session_id;
  uint64_t stream_id;
  uint32_t code;
  uint32_t len;
} idr_event_t;

uint32_t idr_abi_version(void);

idr_engine_t *idr_engine_create(const idr_engine_config_t *config);
void idr_engine_destroy(idr_engine_t *engine);

int idr_connect(idr_engine_t *engine, const char *target_fqhn, uint64_t *out_session);
int idr_disconnect(idr_engine_t *engine, uint64_t session_id);

/** JSON array of Target named services (fetched over DataChannel after connect). */
int idr_session_named_services(idr_engine_t *engine, uint64_t session_id, char *buf,
                               size_t capacity);

/**
 * JSON array of structured service catalog entries:
 * [{"name":"...","kind":"http|tcp","credential_mode":"source|target","require_upstream_tls":bool}, ...]
 */
int idr_session_named_service_catalog(idr_engine_t *engine, uint64_t session_id, char *buf,
                                      size_t capacity);

int idr_open_stream(idr_engine_t *engine, uint64_t session_id, const char *service,
                    uint64_t *out_stream);

int idr_stream_write(idr_engine_t *engine, uint64_t session_id, uint64_t stream_id,
                     const uint8_t *buf, size_t len, size_t *out_written);
int idr_stream_read(idr_engine_t *engine, uint64_t session_id, uint64_t stream_id, uint8_t *buf,
                    size_t len, size_t *out_read);
int idr_stream_half_close(idr_engine_t *engine, uint64_t session_id, uint64_t stream_id);
int idr_stream_reset(idr_engine_t *engine, uint64_t session_id, uint64_t stream_id,
                     uint16_t reason);

int idr_poll_events(idr_engine_t *engine, idr_event_t *out_events, size_t max_events,
                    size_t *out_count);

/* Inject DP DeviceIdentity JSON loaded from flutter_secure_storage (or tests). */
int idr_engine_set_dp_identity(idr_engine_t *engine, const char *identity_json);

/* ---- File transfer (ABI 3) ---------------------------------------------
 *
 * The engine runs the same agent as `source-agent`: per Target a supervisor
 * keeps an identity-bound session (reconnecting, re-authorizing at lease end),
 * and transfers belong to an outbox in `data_dir`, so they resume after
 * reconnects and after the app restarts with the same `data_dir`.
 *
 * Ownership: transfers are named by 16-byte ids (values). A call on an unknown
 * or finished id returns an error; nothing is freed by the caller except the
 * engine (idr_engine_destroy stops transfers resumably first). No callbacks:
 * drain idr_transfer_poll_events (progress coalesced per transfer). Any thread
 * may issue commands; poll from one thread at a time.
 *
 * Return codes: 0 ok; -(IdrErrorKind) for argument/state errors;
 * -(IDR_TRANSFER_ERROR_BASE + IDR_TERR_*) when the transfer layer refuses.
 * idr_last_error_message then holds the stable name (e.g. "unauthorized").
 * Paths and raw OS errors never appear in events or JSON.
 */

#define IDR_TRANSFER_ERROR_BASE 100

/* Stable transfer error kinds (shared with the CLI and Dart). */
enum {
  IDR_TERR_PROTOCOL_VIOLATION = 1,
  IDR_TERR_INCOMPATIBLE_VERSION = 2,
  IDR_TERR_MANIFEST_INVALID = 3,
  IDR_TERR_LIMIT_EXCEEDED = 4,
  IDR_TERR_REJECTED = 5,
  IDR_TERR_CANCELLED = 6,
  IDR_TERR_HASH_MISMATCH = 7,
  IDR_TERR_SIZE_MISMATCH = 8,
  IDR_TERR_CHANGED_DURING_TRANSFER = 9,
  IDR_TERR_NAME_INCOMPATIBLE = 10,
  IDR_TERR_STORAGE_FAILED = 11,
  IDR_TERR_STALLED = 12,
  IDR_TERR_TRANSPORT_CLOSED = 13,
  IDR_TERR_AUTHORIZATION_EXPIRED = 14,
  IDR_TERR_CONFLICTING_MANIFEST = 15,
  IDR_TERR_SOURCE_READ_FAILED = 16,
  IDR_TERR_UNAUTHORIZED = 17,
  IDR_TERR_COMPLETED_WITH_ERRORS = 18,
  IDR_TERR_TIMEOUT = 19
};

typedef struct idr_transfer_config {
  uint32_t abi_version;
  uint32_t struct_size;
  const char *data_dir;        /* required: outbox of agent-owned transfers */
  const char *receive_dir;     /* required: default destination for incoming */
  const char *entity_root_pem; /* optional; default: root at the end of this device's chain */
  uint32_t interactive;        /* 1: offers no rule auto-accepts wait for accept/reject */
  uint32_t any_destination;    /* 1: accept may name any directory (native picker) */
  uint32_t lease_minutes;      /* 0 = 15; minimum 5 */
  uint32_t offer_expiry_seconds; /* 0 = 300 */
} idr_transfer_config_t;

enum {
  IDR_TEV_OFFERED = 1,           /* files_total, bytes_total */
  IDR_TEV_AWAITING_DECISION = 2, /* incoming: call accept or reject */
  IDR_TEV_ACCEPTED = 3,          /* code: 1 user, 2 auto */
  IDR_TEV_PROGRESS = 4,
  IDR_TEV_ENTRY_FAILED = 5,      /* entry, code = IDR_TERR_* */
  IDR_TEV_RENAMED = 6,           /* entry; stored name via idr_transfer_entries */
  IDR_TEV_LEASE_EXPIRING = 7,    /* code = seconds left */
  IDR_TEV_PAUSED = 8,            /* code: 1 by peer */
  IDR_TEV_RESUMED = 9,           /* code: 1 by peer */
  IDR_TEV_FINISHED = 10,         /* code = IDR_OUTCOME_*, entry = IDR_TERR_* or 0 */
  IDR_TEV_INTERRUPTED = 11,      /* code = IDR_TERR_*; resumes automatically */
  IDR_TEV_RESYNC = 12            /* events were dropped: re-read idr_transfer_list */
};

enum {
  IDR_OUTCOME_COMPLETED = 0,
  IDR_OUTCOME_COMPLETED_WITH_ERRORS = 1,
  IDR_OUTCOME_FAILED = 2,
  IDR_OUTCOME_CANCELLED = 3,
  IDR_OUTCOME_REJECTED = 4
};

typedef struct idr_transfer_event { /* 64 bytes */
  uint32_t kind;
  uint32_t code;
  uint8_t transfer_id[16];
  uint32_t entry;
  uint32_t files_done;
  uint32_t files_total;
  uint32_t files_failed;
  uint64_t bytes_done;
  uint64_t bytes_total;
  uint64_t bytes_per_sec;
} idr_transfer_event_t;

/* Requires idr_engine_set_dp_identity first (an enrolled device). */
int idr_transfer_enable(idr_engine_t *engine, const idr_transfer_config_t *config);

/* Files (one or more) or one folder, as absolute paths. */
int idr_transfer_send(idr_engine_t *engine, const char *target_fqhn, const char *const *paths,
                      size_t n_paths, uint8_t out_id[16]);
/* A selection inside `folder`: `/`-separated paths relative to it. */
int idr_transfer_send_selection(idr_engine_t *engine, const char *target_fqhn, const char *folder,
                                const char *const *selected, size_t n_selected,
                                uint8_t out_id[16]);

/* out_dir NULL = receive_dir. */
int idr_transfer_accept(idr_engine_t *engine, const uint8_t id[16], const char *out_dir);
int idr_transfer_reject(idr_engine_t *engine, const uint8_t id[16]);
int idr_transfer_pause(idr_engine_t *engine, const uint8_t id[16]);
int idr_transfer_resume(idr_engine_t *engine, const uint8_t id[16]);
int idr_transfer_cancel(idr_engine_t *engine, const uint8_t id[16]);
int idr_transfer_retry_failed(idr_engine_t *engine, const uint8_t id[16]);

/* JSON into buf (NUL-terminated); returns its length, or -RESOURCE_EXHAUSTED if too small. */
int idr_transfer_list(idr_engine_t *engine, char *buf, size_t capacity);
int idr_transfer_status(idr_engine_t *engine, const uint8_t id[16], char *buf, size_t capacity);
/* {"total","first","entries":[{entry,path,kind,size,failed,stored_as}]}, at most 256 per call. */
int idr_transfer_entries(idr_engine_t *engine, const uint8_t id[16], uint32_t first, uint32_t max,
                         char *buf, size_t capacity);

int idr_transfer_poll_events(idr_engine_t *engine, idr_transfer_event_t *out_events,
                             size_t max_events, size_t *out_count);

uint32_t idr_last_error_code(void);
int idr_last_error_message(char *buf, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif /* IDR_H */
