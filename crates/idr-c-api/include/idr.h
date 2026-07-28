/* SPDX-License-Identifier: MIT OR Apache-2.0 */
#ifndef IDR_H
#define IDR_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IDR_ABI_VERSION 1

typedef struct idr_engine idr_engine_t;

typedef struct idr_engine_config {
  uint32_t abi_version;
  uint32_t struct_size;
  uint32_t use_mock; /* 1 = mock backend (CI / tests); 0 = native (future) */
  const char *source_id;
  const char *source_region;
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

uint32_t idr_last_error_code(void);
int idr_last_error_message(char *buf, size_t capacity);

#ifdef __cplusplus
}
#endif

#endif /* IDR_H */
