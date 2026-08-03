# SDK and native integration

## Rust

The `netplan` crate owns the configuration model, planner, verified protocol codec, and
async daemon client:

```rust,no_run
use netplan::Client;
use netplan::protocol::{Request, Response};

# async fn example() -> netplan::Result<()> {
let client = Client::default();
let response = client.call(&Request::Ping).await?;
assert!(matches!(response, Response::Pong { .. }));
# Ok(())
# }
```

`Client::call` assigns and verifies correlation identifiers. `Client::call_frame` is
the lower-level entry point for already encoded size-prefixed frames.

The default endpoint is `\\.\pipe\pe-netplan-netpland-v1` on Windows. Tests and Unix
development use `/tmp/pe-netplan-netpland-v1.sock`. `NETPLAN_ENDPOINT` overrides the
default for either client.

## C ABI

Include `include/netplan.h`, load `netplan.dll`, and follow this ownership sequence:

1. Call `netplan_client_create`; pass `NULL` to select the default endpoint.
2. Build a size-prefixed `Envelope` from `schemas/ipc.fbs` with file identifier `PNET`.
3. Call `netplan_client_call`.
4. Decode the verified response envelope and correlate `request_id`.
5. Release the returned allocation exactly once with `netplan_buffer_free`.
6. Destroy the client exactly once with `netplan_client_destroy`.

`netplan_client_call` returning `NETPLAN_OK` means a verified response frame was
received. The frame may contain a typed `ErrorResponse`; daemon application errors are
data in the protocol rather than transport failures. Use `netplan_client_last_error`
after a nonzero C status.

The ABI version is returned by `netplan_abi_version`. All pointers and lengths are
validated at the Rust boundary, but ownership violations by a C caller remain undefined
behavior as documented in the header.

## Daemon protocol

- Local transport only: Windows named pipe or Unix-domain development socket.
- Little-endian, size-prefixed FlatBuffers envelope.
- File identifier: `PNET`.
- Protocol version: `1`.
- Maximum frame body: 16 MiB.
- One request and one correlated response per connection.

The checked-in Rust bindings were generated with `flatc` 25.12.19:

```console
flatc --rust --gen-object-api -o crates/netplan/src/protocol schemas/ipc.fbs
```

The generated module intentionally carries lint exemptions. Regeneration must preserve
the module-level generated-code lint header and pass both native and Windows-target
Clippy checks.
