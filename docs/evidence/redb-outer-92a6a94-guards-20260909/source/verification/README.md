# Pinned upstream verification harness

Status: source preparation only. No image, tools, upstream tests or fuzzer have
been built or run using this harness. The existing focused prototype evidence
does not satisfy the complete upstream verification requirement.

This worktree preserves the exact upstream source overlay and its two frozen
lockfiles. Its original justfile, Podman script, workspace/default members,
examples, Python/derive members and fuzzer sources remain unchanged. The new
`justfile.verification` executes the complete upstream `just test` scope inside
an externally supervised offline container. It deliberately adds locked/offline
flags, exact artifact messages, one test thread and strict warnings. Report its
result as a pinned harness variant, never an unchanged upstream invocation.

`verification/Containerfile` pins the Rust 1.97.1 base manifest and Debian snapshot.
Preparation compiles the exact upstream CI versions of just, cargo-deny and
cargo-fuzz; preserves their packaged locks/executable hashes; vendors the complete
root and fuzz graphs together; captures resolved packages, all vendor/index file
hashes and the fetched advisory database commit, checkout contents and timestamp
inputs. Neither verification lock may
change. The build context must be an SHA-256 checked `git archive` from this
committed source, excluding working-tree files and generated targets.
The Dockerfile-specific `verification/Containerfile.dockerignore` intentionally
excludes nothing. It overrides the upstream root whitelist, which otherwise
omits both lockfiles, the fuzzer and this harness. Use
`-f verification/Containerfile`; a Podman builder must additionally pass
`--ignorefile verification/Containerfile.dockerignore`. Preserve the original
upstream ignore files. Preparation does not make an arbitrary checkout a valid
build context.

The sole advisory-config delta redirects its database into the immutable image.
No license or advisory exemptions are added. In cargo-deny 0.20.2, `--frozen`
disables remote advisory fetching as well as dependency changes; the obsolete
`--disable-fetch` flag is not used. The exact tool source is authoritative:
[check](https://raw.githubusercontent.com/EmbarkStudios/cargo-deny/0.20.2/src/cargo-deny/check.rs),
[fetch](https://raw.githubusercontent.com/EmbarkStudios/cargo-deny/0.20.2/src/cargo-deny/fetch.rs).
Offline checking still takes an exclusive writable `db.lock` without a read-only
fallback, so the outer runner must provide the narrow lock-file mount below.
The advisory checkout and its timestamps stay read-only. Its existing freshness
policy can reject an old preparation image; no clock override or staleness
exemption is permitted. See the pinned
[database loader](https://raw.githubusercontent.com/EmbarkStudios/cargo-deny/0.20.2/src/advisories/helpers/db.rs)
and [timestamp reader](https://raw.githubusercontent.com/EmbarkStudios/cargo-deny/0.20.2/src/git.rs).
[Cargo vendor](https://doc.rust-lang.org/cargo/commands/cargo-vendor.html)
supports the second workspace through `--sync` while retaining locked versions.

## Required outer runner

The source-only outer resource/process runner is now in `outer.py`, with its
ownership and execution contract in `OUTER.md`. It has not run on Linux or
Docker and still requires that integration gate before dispatch for acceptance.
Its required contract remains:

- Own a bounded preparation builder: one build job, 8 GiB memory, 30 minutes and
  at most 40 GiB writable storage. Record the platform-specific image ID and
  archive/source/lock hashes. Preserve any preparation failure rather than
  continuing with a partially prepared image.
- Run the resulting image by immutable ID with network disabled, read-only root,
  no capabilities, no-new-privileges and an 8 GiB memory limit. Use separately
  bounded target/scratch mounts; do not share another task's target or corpus.
- Copy only the prepared registry index into a new writable Cargo home, install
  `/opt/verification/vendor-config.toml` there as `config.toml`, and set
  `CARGO_NET_OFFLINE=true`. Preserve the original workspace Cargo configuration.
  Do not repurpose the operator's HOME or copy private operator credentials.
- Bind one privately created writable regular lock file at
  `/opt/verification/advisory-db/db.lock`. Do not make the surrounding advisory
  directory writable. Check every prepared advisory input before execution,
  excluding only this coordination file; preserve the prepared `.git/HEAD` and
  `.git/FETCH_HEAD` timestamps used by cargo-deny.
- Execute `just --justfile justfile.verification test` under the original
  45 minute deadline. Capture Cargo's actual package features, every test executable
  and all test summaries. Any failure blocks acceptance; do not filter away
  default workspace members, doctests or the real 3 GiB large-value regression.
- Separately execute `fuzz-build` under 20 minutes, then `fuzz-smoke` under 90 seconds
  including its declared 60 second libFuzzer duration. Mount private writable
  `/workspace/fuzz/corpus` and `/workspace/fuzz/artifacts`, with an isolated
  `/target-fuzz`. Retain the corpus, seed, crashes and actual executable hash.
- Retain exact container identity, process groups, wall/monotonic times, raw
  cgroup memory/peak/events and writable-storage use. Timeout/cancellation must
  stop and wait for the owned container and its children before reporting drain.
  A stopped Docker client alone is not proof that the container stopped.

Afterward compare every archived source input and both lockfiles to preparation.
The inventory records regular-file hashes, sizes and permission modes as well as
directory entries, including empty directories. It rejects symlinks, special
files, missing roots and incomplete traversals. Compare while the corpus/artifact
mounts are detached, or separately exclude exactly those declared generated
mounts after proving they cannot hide an archived input. File hashes alone do not
prove unchanged executable permissions or complete traversal.
The immutable image and manifests bind dependency/tool input identity. Do not
claim non-overlap or performance isolation without actual shared-host evidence.

The upstream fuzzer uses ordinary transactions. This checks changed allocator
and transaction behavior but does not inject the prototype growth-admission
callback or simulate real host power loss. Those remain separate validation
requirements. The production dependency patch remains uninstalled.

The preparation guard tests can run without installing tools or invoking Cargo:

```sh
python3 -B -m unittest discover -s verification -p test_prepare.py -v
```

These tests exercise input guards only. They do not validate container
construction, tool installation, upstream Rust tests or fuzz execution.
