#ifndef PE_NETPLAN_H
#define PE_NETPLAN_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#  if defined(NETPLAN_BUILD_DLL)
#    define NETPLAN_API __declspec(dllexport)
#  else
#    define NETPLAN_API __declspec(dllimport)
#  endif
#else
#  define NETPLAN_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct NetplanClient NetplanClient;

enum NetplanStatus {
    NETPLAN_OK = 0,
    NETPLAN_INVALID_ARGUMENT = 1,
    NETPLAN_PROTOCOL_ERROR = 2,
    NETPLAN_IO_ERROR = 3,
    NETPLAN_DAEMON_ERROR = 4, /* reserved for APIs that unwrap daemon errors */
    NETPLAN_INTERNAL_ERROR = 5
};

NETPLAN_API uint32_t netplan_abi_version(void);

/* endpoint may be NULL to select the platform default. */
NETPLAN_API int32_t netplan_client_create(
    const char *endpoint,
    NetplanClient **out_client
);

NETPLAN_API void netplan_client_destroy(NetplanClient *client);

/* Request and response are size-prefixed FlatBuffers with identifier PNET. */
NETPLAN_API int32_t netplan_client_call(
    NetplanClient *client,
    const uint8_t *request,
    size_t request_len,
    uint8_t **out_response,
    size_t *out_response_len
);

NETPLAN_API void netplan_buffer_free(uint8_t *data, size_t len);

/* Returns the required byte count including NUL. */
NETPLAN_API size_t netplan_client_last_error(
    const NetplanClient *client,
    char *buffer,
    size_t capacity
);

#ifdef __cplusplus
}
#endif

#endif
