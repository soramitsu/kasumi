# Ledger-referenced development evidence manifest

The release ledger cites development evidence (logs, patches, reviews, JSON
receipts and candidate trees) that existed only in the gitignored target/
directory, where a cargo clean or target pruning would destroy it, including
failed-attempt evidence. `scripts/preserve_ledger_evidence.py` copies every
cited path to the same repository-relative path under
`/Users/mtakemiya/dev/kasumi-release-evidence/20260926-master-development`.
`manifest.json` binds each citation to its bytes. This is development evidence
custody. It is not release acceptance, and it does not change what any cited
run proved.

`manifest.json` comes from the sixth run on 2026-09-26 on `master`, started
at 08:00:04Z:

    python3 scripts/preserve_ledger_evidence.py \
        --destination /Users/mtakemiya/dev/kasumi-release-evidence/20260926-master-development

It found 431 distinct references: 408 files and 23 directories, with none
missing, none refused and none cited only in prose. Those references cover
294,908 distinct files. It copied 288,784 of them (17,642,264,308 bytes). It
hashed the other 6,124, all binaries larger than the 1 MiB copy cap
(35,497,490,885 bytes), without copying them. It pruned 21 build caches
tagged with a CACHEDIR.TAG. Under `not_citations` it recorded the build
directory itself (2 mentions) and six prose phrases (9 mentions).

The sixth run's log wrapper failed before it recorded the exit status, so a
seventh run, started at 08:14:30Z, repeated it. The seventh run exited 0
after 454 seconds and wrote a byte-identical manifest (SHA-256
`0b11c2f80bc502eba96f11d801270e2ed2fc473eda1304d73c86e65003a2bc03`). Neither
run copied a file, because the earlier runs had already preserved every
reference. The only new destination entry is the sixth run's stored manifest.
Both main ledger documents had the same SHA-256 before and after both runs. A
separate check, independent of the script, found no mismatch. It rehashed
every file reference (source and copy), every inventory, 5,000 random
inventory rows and the stored manifest copy. It also confirmed that each of
the 470 target/ tokens in the ledger's raw text is a reference or a
`not_citations` entry.

## Earlier runs

The first five runs used the first version of the script, which read
citations only from code spans and from fences indented at most three spaces.
The first run copied the evidence in 504 seconds. Runs two to five reused the
same destination. All five exited 0 with the same 431 references,
dispositions, hashes and summary, and all 23 directory inventories were
byte-identical. Their manifests differ only in the `cited_by` lists and in
the recorded hashes of `docs/first-release-goals.md` and
`docs/production-release.md`, which were being edited during the runs. A
separate check, independent of the script, rehashed every file reference
(source and copy), every inventory, and 5,000 random inventory rows. It found
no mismatches.

Review then showed that a prose citation, an indented code block or a fence
nested in a list item would have been dropped without notice. The sixth run
uses the corrected script, which accounts for every target/ token (see below).
It resolved the same 431 references with the same dispositions and hashes.
The differences from the fifth manifest are the schema, the new sections, one
added absolute citation of target/tmp, and `cited_by` line numbers in
`docs/first-release-goals.md`, which was edited after the fifth run.

## What counts as a citation

- The ledger is `docs/production-release.md`, `docs/first-release-goals.md`
  and every `README.md` under `docs/evidence/`. This directory's README is
  excluded because it describes the preservation rather than citing evidence.
  An unreadable or symlinked directory under `docs/evidence/` is refused
  rather than skipped. `manifest.json` records each ledger document's
  SHA-256, so any later ledger edit, including a new evidence README, needs a
  new run.
- Every token that starts with target/ is accounted for. A token starts at a
  boundary: it is not preceded by a letter, digit, underscore, `.`, `/` or
  `-`. Text such as `kasumi-target/x`, "all-target/all-feature",
  "journal/target/Raft" or `../target/x` therefore names something else.
  `./target/x` and an absolute path into this checkout's target/ are the same
  citation as target/x. The ledger has one absolute path, naming the TMPDIR
  target/tmp.
- Inside Markdown code, every token is a citation. Code means code spans,
  fenced blocks at any indentation (including fences nested in list items)
  and indented code blocks. An indented code block sits four columns past the
  enclosing list item's content, after a blank line or a heading. `{a,b}`
  brace lists expand, so the three
  `serving-expiry-after-election-freeze-focused-{1,2,3}.log` runs count as
  three files.
- A token in prose, without its trailing sentence punctuation, is resolved in
  this order:
  - If its path exists, it is preserved, and the entry lists those citations
    in `prose_cited_by`.
  - If it looks like a file path, it is listed as missing. That means two or
    more components after target/, or a leaf containing a dot.
  - If it is one of six known prose phrases, it is recorded under
    `not_citations`. The phrases are target/archive, target/issuer,
    target/local, target/scratch, target/signing and target/source/custody.
  - Otherwise it is refused.

  A prose mention is therefore preserved, recorded, or fails the run; it is
  never dropped. The same phrases inside code are citations.
- A bare target/, meaning the build directory itself, is recorded under
  `not_citations` and cites nothing.
- A path with `..`, `.`, an empty component or unusual characters is refused
  as unsafe.
- A cited directory is preserved recursively. Two cited directories are
  umbrella roots and account for most of the volume:
  target/installed-disk-validation (264,820 files) and target/tmp (201
  files).

## Preservation rules

- target/ is only read. Each source is opened component by component without
  following symlinks. A cited symlink, a symlinked parent, a symlink inside a
  cited directory and any non-regular file are refused and not followed.
- An unreadable source is refused with its reason, and the run goes on with
  the other references. That covers a permission error on the path or on any
  parent, or a race that replaces a directory. Only a destination failure
  stops a run.
- A source is hashed while it is copied. If its size or modification time
  changes during the read, it is refused and nothing is published. That makes
  the run safe alongside cargo.
- A copy is staged, fsynced and then hard-linked into place. Linking never
  replaces an existing file, even one that appears while the copy is staged.
  An existing destination with identical bytes is kept unchanged. A
  destination with different bytes, or one that is not a regular file, is
  refused and left untouched.
- On macOS, fsync(2) leaves data in the drive's write cache, so every fsync
  is followed by F_FULLFSYNC. That applies to each staged copy before it is
  linked, to each changed destination directory, and to the repository
  manifest and its directory. The manifest is written only after the copies
  and their directory entries have been flushed. If F_FULLFSYNC fails, the
  run stops without writing a manifest.
- A file is a binary when its first 8000 bytes contain a NUL, which is Git's
  heuristic. A binary larger than `--binary-cap` (default 1 MiB) is recorded
  with its SHA-256, size and modification time and is not copied; its original
  stays in target/. Text is always copied.
- A directory with a valid Cache Directory Tagging `CACHEDIR.TAG`, as Cargo
  writes for every target directory, is a build cache. It is pruned during
  directory expansion and its path is listed. A file cited explicitly is
  preserved even if it lies inside a cache.
- Missing references are listed with the ledger line that cites them. Every
  refusal is listed with its reason. Either one makes the exit nonzero, after
  everything else has been preserved. A destination I/O failure aborts the
  run without writing a manifest. A rerun then resumes idempotently.

## Manifest layout

`manifest.json` (schema `kasumi-ledger-evidence-preservation-v2`) holds the
destination, the copy cap and the hashed ledger inputs. It also has one entry
per reference:

- A file entry has `path`, `cited_by` (ledger `document:line`), `bytes`,
  `sha256`, `mtime_ns` and `disposition` (`copied` or `hash-only`).
- A directory entry has file and byte counts, the pruned caches and a
  content-addressed per-file inventory. That inventory is
  `inventories/<sha256>.json` under the destination; `inventory_sha256` binds
  it here. Each inventory row has `path`, `bytes`, `sha256`, `mtime_ns` and
  `disposition`.
- An entry cited in prose also has `prose_cited_by`, the citations found only
  outside code.

The file ends with the `missing`, `refused`, `not_citations` and `summary`
sections. Each `not_citations` item has the token, the reason and its
citations. Every run also stores a copy of its manifest as
`manifests/<sha256>.json` under the destination. Copies keep their source
modification time.

## Limits

- The destination is on the same APFS volume as the checkout. This protects
  the evidence against target/ cleanup, not against disk loss. The directory's
  capacity and backup remain unverified; archive it separately.
- Hash-only binaries survive only as hashes once target/ is cleaned. By
  volume they are mostly object files, rlibs, rmeta files, test executables,
  dylibs and incremental-compilation caches.
- Eight Cargo target directories under target/installed-disk-validation
  have no CACHEDIR.TAG, for example
  `actual-combined-qualification/cargo-target`. They were expanded like any
  other content: 72,439 build files were copied (about 7.3 GB) and 5,530
  large binaries hashed (about 32.5 GB). That costs space but loses nothing,
  and it records hashes for the test executables those runs retained.
- A drive-cache flush costs about 7.5 ms on this Mac when idle, and about ten
  times that under heavy build load. A run into an empty destination pays it
  once per copied file: about 36 minutes more for the 288,784 copies when
  idle. Reruns pay only for new copies.
- Markdown is classified with a line-based approximation of CommonMark, not a
  full parser. A misclassified line only moves a token between code and
  prose. Either way an existing path is preserved and a missing path-shaped
  one fails the run. The only difference is that a known prose phrase in
  misread code is recorded rather than failing the run.
- A crashed run can leave hidden `.preserve-*.partial` staging files beside
  the copies. They are never published or listed, and they can be deleted.

## Rerun after the 2026-09-26 ledger status update

The W01-4 ledger edits changed both main ledger documents after the seventh
run, so the binding above no longer matched them. An eighth run on
2026-09-27, after those edits and before they were committed, found the same
431 references (408 files, 23 directories), none missing or refused, and
copied nothing new. It rewrote `manifest.json` with SHA-256
`e59689899a59ec38430d6567edd2b7c7114023a3f48abac9b0efea8a4c135cbd`,
binding `docs/production-release.md` at `6b864bb6…df151` and
`docs/first-release-goals.md` at `1d991dc4…9b497`. Its log is
`/Users/mtakemiya/dev/kasumi-release-evidence/claude-20260926/wave-1/manifest-rerun/run.log`.
Any later ledger edit again requires a rerun before the manifest is cited.
