# rmcp 3.11.0 terminal HTTP ownership

The published `rmcp` 3.11.0 archive has SHA-256
`391f153431ab68664d946513ea0cb3edbca78eaf99c5a983036cacab6220d85b`.
Its `.cargo_vcs_info.json` names upstream revision
`165f8fd514afb8f6d1be3e86260ee9abfce58541` and path `crates/rmcp`.
The published archive includes its Apache-2.0 license and lockfile. The manifest
records every file, including the changes to the HTTP transport, peer request handling and the additional
terminal custody regression module.

## Reviewed ownership problem

The published stateless HTTP path calls `serve_directly_with_ct`, then spawns a
waiter that discards `RunningService::waiting()`'s outcome. `serve_inner` spawns
the service loop, which discards handler and notification `JoinHandle`s. The
service loop also owns response-send and peer-send `JoinSet`s. Its cancellation
and EOF cleanup wait only two/five seconds for response channels, not the actual
handler handles; send and close errors are logged. A handler panic can therefore
be lost, and completed service waiters do not prove completed children.

Wrapping the outer HTTP future or only joining `RunningService` cannot close
this ownership gap. Replacing Kasumi's HTTP adapter would duplicate private SDK
protocol, header and negotiation validation.

## Reviewed change

`StreamableHttpService::new_terminal_stateless(factory, config)` is the installed
Kasumi constructor. It requires JSON responses, mandatory stateless metadata,
explicit hosts, a positive request-body bound, disabled sessions and no session
store. An immutable private flag survives cloning. Because upstream exposes
`config` publicly, every HTTP invocation rechecks these conditions before any
dispatch. Misconfiguration fails closed; it cannot activate another execution
mode.

The terminal path preserves the upstream Host/Origin, Accept/Content-Type,
bounded-body, standard-header, protocol-header and protocol-metadata validators.
It preserves JSON-RPC request identity, metadata, original HTTP parts/extensions,
client information, originating request ID and originating protocol version. SDK `Service::handle_request`
still performs protocol/capability checks and method dispatch.

The handler is polled directly inside the HTTP future. This path never constructs
`OneshotTransport`, calls `serve_directly_with_ct`/`serve_inner`, or spawns a
service, waiter, handler, notification or send task. Kasumi's retained TLS
connection/HTTP2-stream inventory therefore owns the actual handler future.
Dropping that future drops the handler and cancels its context. Handler panics
propagate to that same retained owner; there is no detached SDK JoinError.
Engine operations that independently retain committed work continue to use
their existing engine ownership; this patch does not change that contract.

Only one terminal JSON-RPC request/response is supported. Inbound asynchronous
notifications/responses/errors are explicitly rejected. Outbound peer requests
and notifications are observed inline and reject the response; a message queued
in the handler's final poll is checked before terminal publication. The peer also
notifies the terminal owner if upstream protocol enforcement rejects an outbound
request before it can reach the channel. This wakes a pending handler and makes
the refusal visible even when the handler consumes its local error. No action
is silently acknowledged and dropped, and no SSE fallback runs.

Server cancellation and unsupported outbound transport attach the typed
`TerminalTransportFailure` response extension. Kasumi's final middleware
withholds that response and returns `UnknownOutcome` if mutation dispatch has
started. The original credential deadline, final body materialization and
retained database response fence remain in the Kasumi adapter.

## Original 3.2.0 validation

The nine added `terminal_stateless_tests` passed on native macOS ARM64 with
Rust 1.97.1. They execute without a Tokio runtime (an SDK `tokio::spawn` would
panic), check actual handler-drop/cancellation/panic behavior, reject queued
outbound traffic, and exercise inherited validation and post-construction
configuration changes. The six focused upstream suites also passed (60 cases).
No Kasumi workspace build has been run for this branch. A supplementary strict
SDK Clippy attempt failed on 11 existing upstream findings in unchanged code
(`collapsible_if`, `result_large_err`, `type_complexity`, and `question_mark`);
that failure is retained and is not claimed as a passing gate.

## 3.11.0 checks

Run the focused protocol and custody checks on the upgraded candidate:

```sh
cargo test --manifest-path vendor/rmcp-3.11.0/Cargo.toml --locked --features transport-streamable-http-server --lib terminal_stateless_tests
cargo test --manifest-path vendor/rmcp-3.11.0/Cargo.toml --locked --features client,transport-streamable-http-server,reqwest --test test_streamable_http_json_response --test test_streamable_http_standard_headers --test test_streamable_http_protocol_version --test test_stateless_protocol_version --test test_protocol_version_negotiation --test test_server_discover
cargo test --locked -p kasumi-server --lib mcp::credential_tests -- --test-threads=1
python3 scripts/check_dependency_patches.py
```

Installed TLS cancellation/panic/drain tests and exact-final-source release
qualification remain necessary. This patch does not close the full G07 workstream.

## Timestamp dependency

The Kasumi build uses `time` 0.3.55 for UTC timestamps. The fork removes the
direct Chrono dependency and the unused Schemars Chrono feature. MCP resource
annotations and task timestamps still serialize as RFC 3339. The annotation
constructors take a `UtcDateTime` and return a formatting result. Request-state
expiry still uses whole Unix milliseconds, including floor rounding before
the epoch. Timeout diagnostics use the standard duration formatter.

The upstream SDK's optional OAuth client depends on `oauth2` 5.0.0. That
separate crate still selects Chrono in the SDK's own all-features lockfile.
Kasumi implements its own authentication and does not select that SDK feature.

The upstream cancellation and concurrent-response suites both launch a child
server on standard input and output. Their Cargo test targets require the
server and `transport-io` features. The upstream HTTP test case enables that
transport to exercise both child-process suites. The product feature roster
continues to match the workspace lockfile resolution.
