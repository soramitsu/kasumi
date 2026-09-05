# Service compatibility evidence

## OpenBao Transit

The opt-in integration test ran successfully on 2026-09-05 with the official
[OpenBao v2.6.2 release](https://github.com/openbao/openbao/releases/tag/v2.6.2),
Darwin ARM64. The downloaded archive SHA-256 was
`4e495376174accc0e014d31e9901f518a974f966850c839f626347eaac05fd52`.
This verifies the adapter against an actual server. OpenBao's development mode
is used only for the local test, as described in its
[installation documentation](https://openbao.org/docs/install/).

```sh
bao_binary="$(python3 scripts/fetch_openbao.py)"
KASUMI_OPENBAO_BIN="$bao_binary" \
  cargo test -p kasumi-store --test openbao_live -- --ignored
```

The test starts an isolated TLS loopback server, creates ordinary and derived
AES-256 wrapping keys, and issues scoped child tokens. It verifies generation,
fresh decryption, context isolation, KEK rotation, rewrapping retained state,
backup restoration after rotation, historical decryption-version denial and
warm-state sealing after the child token is revoked. The child is terminated
afterward; no token helper or system trust store is changed, and tokens are not
printed. The fetch script installs nothing globally and verifies pinned hashes
before extracting the binary into the warm Cargo target directory.

This does not establish OpenBao service durability, HA behavior, HSM behavior or
Vault interoperability. Production key-service deployment is an independent
operational responsibility. Vault remains covered by wire-compatible fixtures
until a live Vault test is recorded.

## S3-compatible backup storage

The SigV4 implementation matches an AWS published signing vector. Local TLS
tests validate signed PUT/GET, session tokens, create-only object writes,
integrity checks, size limits, and TLS validation.

The opt-in real MinIO test passed on 2026-09-05 using official release
`RELEASE.2025-09-07T16-13-09Z`, with the Docker registry manifest pinned to
`sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e`.
It verifies signed bucket creation, encrypted upload/download/decryption,
create-only overwrite rejection, wrong credentials, untrusted TLS certificates,
missing objects and bounded downloads. The temporary local container is capped
at 512 MiB and one CPU and is removed afterward. Its tmpfs storage establishes
protocol interoperability, not a remote storage service's durability.

Use the explicit local Docker socket/config and pinned-image instructions in
[the storage README](../crates/kasumi-store/README.md#actual-s3-interoperability):

```sh
cargo test -p kasumi-store --lib actual_minio --locked -- --ignored
```

Externally operated S3 services remain untested. Their TLS 1.3 support, SigV4
behavior, consistency and durable-storage configuration need deployment-specific
verification.
