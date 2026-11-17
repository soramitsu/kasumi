# Deployed-format fixtures

A live deployment (BOI) serves a store that commit `12140939` first wrote and
later builds have served since, `cf9959f1` when these fixtures were made.
Everything that deployment has written must stay readable and writable; see
[deployed persisted formats](../../docs/COMPATIBILITY.md#deployed-persisted-formats).
The files here are the real bytes that requirement is tested against: one
small standalone installation written by those two commits' own `kasumid`.

| File | Content |
| --- | --- |
| `fixtures.kfx` | Three copies of the stopped installation, packed |
| `<copy>.manifest.json` | What the build that wrote the copy answered before it stopped |
| `schedule-<commit>.patch` | The only change to the builds that wrote the copies |
| `support.rs` | Reader for `fixtures.kfx` and the pinned byte layouts, included by the tests |

| Copy | Written by | State |
| --- | --- | --- |
| `12140939-killed` | `12140939` | Killed with `SIGKILL` in the compaction cycle after its first segment was sealed, while a root slot listed garbage files (that segment among them, unless already gone) and a write was in flight. The listed files are left out of the copy, as right after their unlink |
| `12140939-clean` | `12140939` | The same installation after `12140939` recovered from that kill, finished the cycle and stopped cleanly: an embedded (`KASUMID1`) snapshot and a journal tail after it |
| `cf9959f1-clean` | `12140939`, then `cf9959f1` | The same installation after `cf9959f1` served it and stopped cleanly: a by-reference (`KASUMIL1`) snapshot over the archive chain in `tenant-audit-archives` |

## What the installation went through

`scripts/deployed_format_fixture.py` is the whole history. In short, with the
first build: `kasumid init --mode standalone`; four collections (structured,
unique, multikey, decimal and three text indexes; one append-only, one with
strict read audit, one created by schema activation); a changed policy and
changed limits; three more credential families, one of them revoked; inserts,
overwrites, merge patches, deletes, an atomic batch over three collections,
retained rejections, writes by a second principal; a verified full backup to
the local destination; a data-key rotation; large documents overwritten,
deleted and kept; tenant audit records archived into `tenant-audit-archives`;
several snapshots and compaction cycles.

The first 64 MiB segment fills with large writes the collection refuses for a
stale expected version. Each is journaled with its whole body, but leaves no
document version, change image or history body that the cycle after the seal
would have to copy into the next segment. A second backup exports the history
of the large documents first; the copies leave out its objects, since the
tests read only the destination marker. The second build then adds writes, a
by-reference snapshot and its own cycles.

A manifest lists the collections, every document, 22 queries with their rows
and aggregates, retained receipts, the policy and limits readback, the
credential families' status and the backup checkpoints, exactly as
`kasumictl` and `kasumid` of the writing build printed them, just before it
stopped. A string longer than 4096 bytes is replaced by `{"$sha256",
"$bytes"}`. The killed copy's manifest was read just before the kill, and
`in_flight` names the documents its interrupted writer may have changed.
Revisions only move forward from those recorded: audited reads of the
manifest itself commit audit records.

## The tests

| Test | Reads |
| --- | --- |
| `cargo test -p kasumi-kv --test deployed_format` | Root slots, garbage tags, segment and arena headers and Fixed directory pages as bytes; then opens, compacts, writes and reopens each node group |
| `cargo test -p kasumi-store --test deployed_format` | The envelope of every node file, audit archive objects, file keyrings and the backup marker |
| `cargo test -p kasumi-server --lib deployed_format` | Serves each copy with the current runtime and compares its answers with the manifest; then writes, snapshots, compacts, stops, checks the files on disk and reopens |

## Keys

Nothing in a store can be read without its keys, so the copies include the
installation's file keyrings, token signer, CA key and TLS private keys. The
installation was created only to make these fixtures and its keys protect
nothing else. Bearer tokens are left out; they expired an hour after the
copies were made. The packed stream keeps one key's PEM text literal, the
CA key; `.gitleaks.toml` allows exactly that key in `fixtures.kfx`, and the
backup key-lineage digests in the manifests. A regenerated installation has
new keys: review them and replace both entries.

## Size

`fixtures.kfx` is about 27 MiB and the manifests about 0.7 MiB. Most of it is
encrypted, so it does not compress: the segment that follows the sealed
64 MiB one, holding what the builds wrote after the seal (snapshots of about
1.8 MiB each among it), and the directory arenas, which pack to a fraction of
their size. The copies share their common bytes. How many writes a compaction
cycle needs before it finishes varies, and with it the size: earlier runs of
the same generator packed to between 16 and 28 MiB.

## The schedule patch

The deployed builds take a snapshot every 5000 journal entries and start a
compaction cycle after 256 MiB of growth. A store that has done both is
hundreds of megabytes. `schedule-<commit>.patch` makes the two thresholds
readable from `KASUMI_FIXTURE_SNAPSHOT_INTERVAL` and
`KASUMI_FIXTURE_COMPACTION_SLACK_BYTES`; the generator sets them to 96 entries
and 4 MiB. Nothing a snapshot contains or a cycle writes depends on when it
runs, and without the variables a patched build behaves as the deployed one.
The first segment still fills to its deployed 64 MiB before it is sealed.

`KASUMI_DEPLOYED_FORMAT_COPY=<out>/<copy> cargo test -p kasumi-server
--all-features --lib a_named_local_copy` serves one generator copy before it
is packed.

## Regenerating

```sh
for commit in 12140939 cf9959f1; do
  mkdir -p "$WORK/$commit" && git archive "$commit" | tar -x -C "$WORK/$commit"
  (cd "$WORK/$commit" && patch -p1 < "$REPO/tests/deployed-format/schedule-$commit.patch" &&
    CARGO_TARGET_DIR="$WORK/target-$commit" cargo build --locked -p kasumi-server \
      --bin kasumid --bin kasumictl)
done
python3 scripts/deployed_format_fixture.py generate \
  --first-bin-dir "$WORK/target-12140939/debug" \
  --second-bin-dir "$WORK/target-cf9959f1/debug" \
  --work /tmp/kasumi-deployed-format --out "$WORK/copies" --base-port 47410
KASUMI_DEPLOYED_FORMAT_RAW="$WORK/copies" \
  cargo test -p kasumi-kv --test deployed_format -- --ignored pack
```

Give each commit its own target directory. The generator needs about half an
hour and the three loopback ports from `--base-port`. The copies record the
installation's path below `--work`, so keep that path free of user names, as
here. The work directory holds the installation's credentials: delete it
afterwards. Every identifier, key and timestamp is new in a regenerated
installation, so the manifests and `fixtures.kfx` change as a whole.
