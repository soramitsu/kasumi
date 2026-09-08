# Renewable benchmark credential sources

Live native and MCP requests now load one fresh owner-only credential file
snapshot per request. A missing or malformed replacement fails without reusing
a cached secret. Existing request metadata remains unchanged. The fixture
producer emits private token files, and the current example uses the mandatory
token_file field. Old environment-token configuration is rejected.

Two focused regressions, strict benchmark Clippy across all targets/features and
formatting pass on c53aeb4. This prepares long-running live measurements for an
external credential renewal watcher; it does not claim a live renewal test,
new million-document matrix or endurance result.
