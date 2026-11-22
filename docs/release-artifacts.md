# Candidate artifact assembly

`scripts/package_release.py` assembles three production executables, normalized
binary/source archives, checksums, an SPDX 2.3 Cargo compilation inventory,
original third-party notices and systemd units. It consumes a successful frozen
functional run made with this source's runner and packager:

```sh
python3 scripts/release_gate.py \
  --output /absolute/evidence/final-functional \
  --execution-description 'Describe the actual pinned native host or VM' --jobs 2
mkdir -p /absolute/artifacts
python3 -B -S /absolute/evidence/final-functional/source/scripts/attempt_index.py create \
  --root /absolute/artifacts --journal-id <unique-journal-id> \
  --host <native-host-id> --target <target>
python3 -I -B -S /absolute/evidence/final-functional/source/scripts/run_repeatable_assembly_owned.py \
  --evidence /absolute/evidence/final-functional \
  --native-inputs /absolute/native-inputs/inputs.json \
  --output /absolute/artifacts/repeatable-assembly-001 \
  --attempt-root /absolute/artifacts --attempt-id assembly-001
python3 -B -S /absolute/evidence/final-functional/source/scripts/transport_assembly_evidence.py produce \
  --assembly /absolute/artifacts/repeatable-assembly-001 \
  --evidence /absolute/evidence/final-functional \
  --archive /absolute/artifacts/assembly-<target>-<commit>-<attempt>.tar \
  --producer /absolute/artifacts/assembly-producer-<target>-<commit>-<attempt>.json \
  --receipt /absolute/artifacts/assembly-transport.json \
  --max-bytes <positive-native-assembly-byte-cap> \
  --expected-target <target> --expected-source-commit <commit> \
  --expected-source-tree <tree>
```

Create one journal per native host and target before its first attempt, and
retain its printed head outside the candidate bundle. Reuse that journal for
later attempts and retain each new head with
`attempt_index.py head --root /absolute/artifacts`; an existing journal must
have the same identity.

For final verification, retain each complete host directory under
`native-attempts/<journal-id>/` in the evidence bundle. Preserve the native
relative paths and the original bytes of the journal, outcomes and process
records. The manifest's `attempts` array contains one object per journal with
its `id` and a `journal` file reference to
`native-attempts/<journal-id>/attempts/index.jsonl`. Keep the operator's
anchor file outside the bundle. Its JSON array contains one object per native
journal with the final `head` from `attempt_index.py head` and the absolute
`original_root` on the producing host. The verifier checks that all three
targets are represented and replays every admission, including failures and
interruptions. It reads transported files from the bundle.

When finishing a selected functional or independent build, pass its original
qualification record as the output-relative `build_evidence` argument to
`attempt_index.finish_outcome`. The functional record is `evidence.json`.
The independent build record uses final bundle paths for its binary references.
The verifier compares both records with their admitted native products.
Run the frozen verifier against the exact clean Git revision.

```sh
python3 -I -B -S /frozen/source/scripts/verify_release_acceptance.py \
  /evidence/release-manifest.json --repository /clean/revision \
  --journal-heads /operator/native-journal-heads.json
```

### Producing the independent build

`scripts/run_independent_build.py` produces a candidate's `independent` record.
It makes one fresh native production compilation per target, separately from
the primary functional run, and may use the same physical host. Run it with the
declared native Python from a frozen source that has no `__pycache__`:

```sh
python3 /frozen/source/scripts/release_host.py \
  --output /operator/host-preflight.json --target <target>
python3 -I -S -B /frozen/source/scripts/run_independent_build.py \
  --journal /absolute/artifacts --attempt-id independent-001 \
  --output /absolute/artifacts/independent-001 \
  --identity /operator/release-identity.json \
  --source-archive /evidence/source.tar \
  --native-inputs /absolute/native-inputs/inputs.json \
  --host-preflight /operator/host-preflight.json \
  --host-attestation /operator/host-attestation.txt \
  --host-reservation /operator/host-reservation.json --jobs 2
```

The journal is this host's existing attempt journal, and the output is a fresh
path inside it. The identity file holds exactly the seven source identity
fields of [the acceptance manifest](release-acceptance-manifest.md), with the
values the final manifest will compute, including `configurations_sha256`.
A later configuration change invalidates the record. The source archive is the
frozen Git archive whose SHA-256 is `source_archive_sha256`. The preflight is
the `release_host.py` output for the journal's target, and the attestation is
the operator or hypervisor statement for the host. The reservation is a JSON
object with `id`, `starts_at`, `ends_at`, `cpu_count`, `memory_bytes` and
`disk_bytes`. It must cover the whole compilation.

The verifier requires the exact functional `production` command, which begins
`cargo +1.97.1`. A toolchain's own `bin/cargo` rejects `+toolchain` selectors,
so the producer runs Rustup's `cargo` proxy from the declaration's
`cargo_home/bin`. Declare the Rustup executable behind that proxy, such as
`~/.cargo/bin/rustup`, in `host_files` with its SHA-256. The declared
`rust-sysroot` must be `<RUSTUP_HOME>/toolchains/1.97.1-<target>`. Cargo
receives the declaration's explicit offline environment plus
`CARGO_TARGET_DIR`, `RUSTUP_HOME` and `RUSTUP_AUTO_INSTALL=0`. No ambient
Cargo, Rustup or Python setting reaches it.

The attempt is admitted before its output exists. Every input is copied into
the output and read only from that copy. The archive is extracted into a fresh
`build/source`, whose inventory, lockfile and vendor hash must match the
identity, and the executing producer modules must equal the frozen source.
Cargo builds into a fresh `build/target` as one owned process. Its receipt, log
and executable bytes are kept as `production-process.json`, `production.log`
and `tools/cargo`. After its process group drains, the producer requires
exactly the three production executables, no fixture features, the target
architecture and an unchanged source. It then hashes the actual binaries.

The terminal outcome names those binaries as products and selects
`independent-build.json` as its `build_evidence`. The record's references
already use final bundle paths, `native-attempts/<journal-id>/<output>/...`.
Copy the host directory into the bundle unchanged and point the candidate's
`independent` reference at that record. The producer prints a JSON summary
with the record's `bundle_record` path, the binary hashes and the new journal
`head` to anchor. It exits 0 when the build passed, 1 when it failed or was
interrupted, and 2 when the attempt could not be admitted or finished.
A rejected input, failed compilation or cancellation stays in the journal with
any partial products and cannot be selected. The verifier, not the producer,
compares the binaries with the primary build.

### Composing the release manifest

Keep a selections JSON file in the bundle directory. Its `source` names the
exact Git `commit` and the relative paths to its `archive` and `files`
inventory. Use JSON objects mapping IDs to bundle-relative paths for
`configurations`, `artifacts`, `gates`, `candidates` and `journals`.
A gate path selects its original domain evidence. A candidate path selects a
JSON object containing its native `platform`, `primary` and `independent`
records in the acceptance schema. A journal path selects its indexed bytes.
Once both capacity gates, concurrency, the benchmark matrix and the full HA
soak are present, the composer derives `operating-limits.md` from their original
measurements. The report records the reservations, elapsed time, sampled
resource peaks, configured budgets, workload counts, latency and soak results.
The final verifier independently recomputes its bytes. The composer generates
`SHA256SUMS` when all 24 other deliverables are present.

```sh
python3 -B scripts/compose_release_manifest.py /evidence/selections.json \
  --repository /clean/revision --output /evidence/manifest-draft.json --draft
python3 -B scripts/compose_release_manifest.py /evidence/selections.json \
  --repository /clean/revision --output /evidence/release-manifest.json \
  --journal-heads /operator/native-journal-heads.json
```

The draft reports missing artifact IDs, gates and platforms. Use a new output
name for revised selections to keep each draft reproducible. Final publication
of the manifest requires the isolated frozen verifier to certify those exact bytes.

The native input declaration is mandatory; there is no ambient Cargo/Rustup
fallback. See [the assembly input contract](repeatable-assembly.md). The owned
launcher, runner and packager require isolated Python and reject cached
bytecode before importing local helpers. The owned
launcher retains `launcher.json`, its runner process, descendant group ledger and
terminal census at the output root. Its child produces `assembly/attempt.json`
and the two original outputs, `assembly/assembly-a-output` and
`assembly/assembly-b-output`; the first contains the candidate package and OCI
build context. Both complete outputs, process transcripts, native probes and
original failed attempts remain under the exclusive output directory. The
registered `repeatable-assembly` adapter checks those two outputs against the
selected candidate on each native target.
The assembly transport command runs only after the owned launcher verifies its
original child graph and two outputs. It inventories every retained file and
directory, writes a bounded raw PAX tar preserving file and directory modes,
and publishes a separate native producer identity and receipt last. A failed
or interrupted original directory uses `snapshot-failure` with separate raw
archive, producer and failure receipt names. Its `failed` or `interrupted`
disposition cannot be selected as a passing assembly receipt. This is
transport custody, not domain acceptance.
The raw tar contains explicit ordered directory members, including empty
directories, plus every regular file; its canonical manifest binds the same
complete roster and byte digests. Symlinks and special files fail capture.

For a terminal failure with an original output directory, preserve its raw
bytes before cleanup, using the expected workflow target and Git identity as
context. A failed attempt without a complete launcher cannot prove its own
source identity:

```sh
python3 -B -S /absolute/evidence/final-functional/source/scripts/transport_assembly_evidence.py snapshot-failure \
  --assembly /absolute/artifacts/repeatable-assembly-001 \
  --archive /absolute/artifacts/assembly-failed-<target>-<commit>-<attempt>.tar \
  --producer /absolute/artifacts/assembly-failed-producer-<target>-<commit>-<attempt>.json \
  --receipt /absolute/artifacts/assembly-failure-transport.json \
  --max-bytes <positive-native-assembly-byte-cap> \
  --expected-target <target> --expected-source-commit <commit> \
  --expected-source-tree <tree>
```

Use Python 3.11 or newer and Rust 1.97.1. Run packaging on the same native build
host with its original Cargo registry cache. The packager rejects failed or
incomplete gates, missing compiled-dependency inventory, changed logs/source/
lockfiles/executables, an executable architecture inconsistent with the recorded
host, substituted file links, and missing or mismatched notices. It copies the
exact tested production binaries; it does not rebuild replacements. Its own
source and the gate runner must match the frozen source. Output directories are
exclusive; failed partial directories remain for inspection.

Use the same Python interpreter as the functional runner. The recorded concurrency
and every command must match the current gate contract, including doctests,
strict Clippy targets and production feature flags. Old evidence missing these
required fields is rejected. When executing scripts directly from frozen source,
set `PYTHONDONTWRITEBYTECODE=1` so imports cannot create new source inputs.

`SHA256SUMS` covers both archives. The package's `provenance.json` retains source,
tree, lockfile, executable, functional-evidence and packager hashes. `sbom.spdx.json`
lists packages actually reported by Cargo's production gate, including cached
artifacts and host build dependencies. License/notice files are checked against
the exact checksum-bound published crate, or the frozen workspace/vendor source.
Additional upstream texts are pinned in `release/licenses/sources.json`. They
are not downloaded during packaging. Original nested native-source notices are
retained when supplied by a crate. A separate platform inventory is still needed
for OS shared libraries and the OCI base image.

The [SPDX 2.3 document](https://spdx.github.io/spdx-spec/v2.3/document-creation-information/)
and [package fields](https://spdx.github.io/spdx-spec/v2.3/package-information/)
define the inventory format. A declared license is retained separately from a
license conclusion. Where upstream offers alternatives and this distribution
selects one, the pinned supplement states that choice and keeps the original
declaration.

Archive order, file modes, owners, tar timestamps and gzip headers are normalized
to the source commit's timestamp. This makes assembly reproducible for identical
inputs. It does not prove bit-identical recompilation: compiler, linker, system
packages and path-remapping need a separately pinned build environment and an
actual second-build comparison.

## Candidate workflow

`.github/workflows/release-candidate.yml` is manually dispatched against reviewed
source on dedicated ephemeral self-hosted runners. Provision `kasumi-acceptance`
runners for Linux X64, Linux ARM64 and macOS ARM64 with at least 16 GiB RAM and
64 GiB free workspace disk, Python 3.11+, Git and the native platform build tools.
Linux needs Docker; macOS needs rustup, Xcode command-line tools and CMake.
The labels identify operator-provisioned hosts; adding this workflow does not
provision them or establish a passing run. Keep production identities and data
off these acceptance hosts.

Preflight checks at least 15 GiB of effective memory after kernel reservations
and visible Linux cgroup ceilings. The previous 7 GiB container limit killed a
debug test linker in the frozen `d403c55` run. Larger source tests therefore
require the updated 16 GiB reference allocation; this is a build-host requirement,
not a minimum memory claim for every deployed database workload.

The workflow freezes the checked-out commit, records host/image/package identity,
and runs the full functional gate set with two Cargo jobs. Linux uses the pinned
Rust image and Debian snapshot repositories from the validation Dockerfile.
Actions are pinned to exact commits. Provision the repository variable
`KASUMI_ASSEMBLY_INPUTS_DIR` to the host directory containing `inputs.json` and
its referenced host inventory evidence. Linux mounts it at `/assembly-inputs`;
its declaration must describe paths inside the actual native build container.
macOS uses the host paths. Missing input declarations fail before functional
execution. The owned assembly runner retains two complete invocations and
compares their actual archives. Independent recompilation remains separate.
Set the repository variable `KASUMI_FUNCTIONAL_MAX_BYTES` to an explicit
positive decimal byte cap that fits the native runner's available storage and
the separately retained upload/download budget. There is no implicit default.
Set `KASUMI_ASSEMBLY_MAX_BYTES` independently to a positive decimal cap for
the complete owned assembly directory, including dependency blobs and both
package outputs. Its raw tar and producer record are uploaded separately.
After a failed or interrupted owned attempt, the workflow snapshots any
original assembly directory into a separate bounded raw tar and failure
producer record. The Linux cleanup helper does this after stopping the owned
container and restores host ownership without changing original modes; an
always-run host step retries if that helper could not publish the failure
receipt. macOS uses the always-run step. Both raw files are uploaded separately
and their upload digests are checked against the typed native failure receipt.
If the assembly producer succeeded but subsequent container cleanup or custody
checking fails, the original passing transport files remain for diagnosis and
a separate `interrupted` raw snapshot is selected for the failed job. A passed
transport receipt is never promoted from a failed candidate step. If a passing
receipt exists but its raw archive or producer is missing or unreadable, the
always-run step attempts the interrupted snapshot and fails the job.
If Docker stop fails, the original container may still be running when a
snapshot is taken. Retain `container-terminal.json` where available and keep
the candidate failed: a consistent snapshot does not prove terminal bytes.
If no original assembly root was created, the workflow writes an explicit
`assembly-absence.json` observation. A missing frozen transport script, unreadable
owner mode, exceeded cap, or hard host loss can prevent raw capture. The job
fails closed and records a custody failure where the host remains available;
it does not certify complete failed-attempt retention in that case. Runner
temporary storage is not durable custody. Keep the failed original in a
separately configured durable operator store before cleaning the host, and
leave release acceptance open if its full bytes and modes cannot be proven.
The always-run candidate artifact is diagnostic only: ordinary directory
upload may omit hidden entries and does not preserve original file modes.
Each successful native job exports the complete declared functional evidence
as a mode-preserving raw PAX tar and creates a separate producer JSON record
from the original run, checked-out commit/tree and verified tar. The workflow
uploads each raw file separately, checks each upload digest against its native
sidecar, and cross-checks the uploaded tar digest, export manifest, target and
source identities against the producer record. Keep the tar, producer JSON,
upload IDs and digests, and failed-attempt files together in operator custody.

Download the raw owned-assembly tar and its separate producer JSON from the
same selected native workflow run. Obtain the producer artifact SHA-256 from
the upload result or artifact metadata, independently of both downloaded
files. Use the matching frozen source for strict readback:

```sh
python3.12 scripts/transport_assembly_evidence.py collect \
  --archive /absolute/downloaded/assembly-<target>-<commit>-<attempt>.tar \
  --producer-manifest /absolute/downloaded/assembly-producer-<target>-<commit>-<attempt>.json \
  --producer-sha256 <independently-observed-assembly-producer-digest> \
  --max-bytes <positive-local-assembly-byte-cap> \
  --output /absolute/owned-assembly-readback
```

The assembly collector requires the external producer digest, rechecks the raw
tar's complete byte and mode roster, and reopens the original launcher and
both assembly invocations for a `passed` producer before publishing `receipt.json`.
For a failure producer, use its `assembly-failed-*` tar and
`assembly-failed-producer-*` JSON with the same `collect` command: readback
publishes only a typed `failed` or `interrupted` receipt and does not infer
semantic success from an exit code. It does not create
a final `kasumi-release-acceptance-v1` domain result, host attestation or
reservation, independent build, or permanent attempt index. The adapter
registry remains closed pending those contracts and native qualification.

After downloading both raw artifacts, obtain the producer artifact SHA-256
from the selected workflow run's upload output or artifact metadata,
independently of the downloaded files and their sidecars. Use the matching
frozen source revision to collect and verify readback:

```sh
python3.12 scripts/collect_functional_evidence.py \
  --archive /absolute/downloaded/functional-<target>-<commit>-<attempt>.tar \
  --producer-manifest /absolute/downloaded/producer-<target>-<commit>-<attempt>.json \
  --producer-sha256 <independently-observed-producer-artifact-digest> \
  --max-bytes <positive-local-byte-cap> \
  --output /absolute/fresh-collection
```

The collector preserves the complete verified `readback/run` roster, a 0600
copy of the producer record and a success receipt only after final readback.
Retain the downloaded tar separately: the receipt names its absolute path.
This workflow and collector still require native end-to-end qualification and
semantic acceptance adapters before a candidate can count as a release.
The Linux job also runs preflight inside its actual two-CPU, 15 GiB container,
records the created and terminal container states, and stops that owned container
on failure or interruption. Host preflight alone cannot establish an inner
container's effective memory. The terminal record includes Docker's container
OOM status. Diagnosing an OOM kill of an individual compiler or test child also
requires kernel or cgroup evidence; a false container OOM flag cannot rule it out.
The gate runner retains hashed before/after observations of visible cgroup memory
counters for every command, including failures. Missing counters are recorded as
unavailable. Cumulative peaks and ancestor counters may cover other work and must
not be presented as an isolated per-gate measurement. Packaging requires these
records to remain unchanged alongside the logs.
Both failed-run logs and successful candidate archives are uploaded as workflow
artifacts. Hard runner loss can interrupt that upload, so keep the exclusive
workspace until evidence is copied to operator storage. The workflow does not
publish a GitHub release or certify the separate release acceptance gates.

The [GitHub runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
documents runner platforms and hosted limits. This workflow uses explicit
acceptance hosts because the ordinary hosted disk allocation is smaller than
the observed full debug-test and release-build workspace.

## OCI image

`scripts/oci_image.py` assembles the image without a container build, so the
same inputs always produce the same archive bytes. It takes the pinned Debian
Bookworm slim base as an OCI layout whose platform manifest must hash to the
digest in `release/oci/base-image.json`, and the candidate package produced by
the matching packager:

```sh
python3 -I -B -S scripts/run_oci_image_owned.py \
  --journal /absolute/native-custody --attempt-id arm64-image-001 \
  --output /absolute/native-custody/image-001 --evidence /absolute/functional \
  --base-layout /absolute/base-layout \
  --package /absolute/artifacts/kasumi-0.1.0-aarch64-unknown-linux-gnu.tar.gz
```

Run this command on each native Linux target with its own package, functional
evidence, and initialized native journal. The producer reads the build time
from the functional evidence, verifies the packaged provenance and binaries,
and writes the image archive, image SBOM and `image.json` under
`image-001/image/`. Select these original files from the transported journal.
The assembler adds one uncompressed layer: the delivered
package under `/opt/kasumi` (binaries, notices and Cargo SBOM) and an empty
private `/var/lib/kasumi` owned by the numeric runtime user 65532:65532, which
has no passwd entry. The default entrypoint serves
`/var/lib/kasumi/installation/kasumi.json`; initialize into that mounted volume
first, as the same user. Initialization remains offline and loopback-bound;
network exposure requires an explicit listener and TLS client configuration.
Use `/opt/kasumi/bin/kasumi-authority` as an explicit entrypoint for a separately
installed authority group. No installation identity or fixture state is baked in.

It also writes the image SBOM, which lists what the dependency SBOM cannot: the
base image and every installed Debian package, read from the base layers' dpkg
database. `verify` recomputes the image, candidate binary and SBOM bindings from
the archive alone. `scripts/run_oci_smoke.py` is the acceptance producer: it
verifies the archive, loads it into a native container runtime, initializes a
fresh volume, makes authenticated native and MCP requests before and after a
restart, and requires a zero exit on the stop signal. The `oci-smoke` adapter in
`scripts/verify_release_acceptance.py` checks that run. No image built from
current source has passed it yet.

## Native systemd qualification

Run the systemd smoke on each dedicated Linux qualification machine with systemd
as PID 1 and a cgroup v2 hierarchy. Install the package binaries at their
documented paths and prepare both service accounts and private data and
authority enrollments. The test needs root access to the system manager.
Both published unit names must be free at dispatch. The smoke exclusively
creates the delivered unit bytes under `/run/systemd/system`, checks them
with `systemd-analyze verify`, starts and restarts each service, verifies
its authenticated operator endpoint and stops it. The evidence includes
kernel PID birth, cgroup, executable hash, UID, listener ownership and the
journal's successful deactivation for each service invocation. The runner
checks the installed inode before removing each temporary unit.

Use a plan with schema `kasumi-systemd-smoke-v1`, `data_client` set to the
absolute installed Control profile for the data service, and `authority_client`
set to its installed authority maintenance client. Its enrolled authority peers
must provide quorum throughout the smoke.
The account running the smoke must own its client profiles, private keys and
bearer files with owner-only permissions. The service accounts retain their
own runtime files.

```sh
python3 -I -B -S scripts/run_systemd_smoke.py --evidence "$functional" \
  --journal "$journal" --attempt-id "$attempt" --output "$output" \
  --package "$package" --systemd-data "$data_unit" \
  --systemd-authority "$authority_unit" --plan "$plan"
```

## systemd installation

The supplied units use separate static service users, owner-only state, an empty
capability set and a read-only filesystem outside each service's state directory.
They send SIGTERM and allow actual storage/worker ownership to drain without an
automatic stop timeout. SIGHUP requests atomic TLS reload; invalid replacements
retain the previous valid configuration and log failure. Signer and wrapping-key
rotation use their explicit maintenance operations.

For a fresh standalone host, install the binaries into `/usr/local/bin`, create
the dedicated user and parent directory, and initialize as that same user. Supply
the owner-only explicit placement map documented in the
[standalone runbook](standalone.md):

```sh
sudo useradd --system --user-group --home-dir /var/lib/kasumi --shell /usr/sbin/nologin kasumi
sudo install -d -o kasumi -g kasumi -m 0700 /var/lib/kasumi
sudo -u kasumi /usr/local/bin/kasumid init --mode standalone /var/lib/kasumi/installation --directory-policy /etc/kasumi/directory-policy.json --file-allocation-policy /etc/kasumi/file-allocation-policy.json --network /etc/kasumi/standalone-network.json --tenant-audit-placements /etc/kasumi/tenant-audit-placements.json
sudo install -m 0644 systemd/kasumid.service /etc/systemd/system/kasumid.service
sudo systemctl daemon-reload
sudo systemctl enable --now kasumid
```

The initialization directory must not already exist. Preserve the generated
private profiles and operator key backup using the [standalone procedures](standalone.md).
The explicit standalone network file selects loopback listeners before genesis. The authority unit instead
requires a separately installed HA authority, a `kasumi-authority` service user
and private `/var/lib/kasumi-authority/authority.json`. HA data members may use
the data unit after installing the exact HA configuration at its configured path.
If an installation uses external archive/key paths, explicitly configure the
unit's required read/write directories to match those installed resources.

On native Debian ARM64 at `0e0a6d9d`, the shipped Data and Authority
units each passed `systemd-analyze verify`, authenticated startup, a restart
with a new PID and invocation ID, and a clean SIGTERM with an empty cgroup.
These runs exercised the units with `LimitCORE=0`, `MemorySwapMax=0` and the
Data unit's `LimitNOFILE=65536`. The Data exercise took 9.88 seconds. The
Authority exercise took 19.46 seconds, with two other enrolled voters serving
the same operational membership after the systemd-managed voter stopped.
Both ran on one shared development guest. Repeat the complete two-role
package smoke with the accepted artifacts on both native Linux architectures.
The release integration log records the source and scope of these checks.

These are candidate artifacts. Complete cross-platform functional validation,
external-service/recovery/capacity/retention/performance gates and the actual
24-hour soak remain required before release publication. OCI assembly, full
platform SBOMs and bit-identical compiler-build acceptance remain separate work.

Run the installed lifecycle on each of the three native targets with the frozen
functional interpreter. Allocate four consecutive free loopback ports and a
new custody directory under the native attempt journal.

```sh
"$PYTHON" -I -B -S "$FUNCTIONAL/source/scripts/run_installed.py" \
  --evidence "$FUNCTIONAL" --journal "$JOURNAL" --output "$INSTALLED_RUN" \
  --attempt-id "$ATTEMPT_ID" --base-port "$PORT"
```

The runner creates a private standalone installation, exercises authenticated
native and MCP operations, rotates credentials and keys, and reads the
checkpoint after an exclusive offline restore. It verifies both local
discovery suppression and the metadata returned for an explicitly configured
loopback HTTPS issuer. Its journal retains the original outcomes of credential
and exclusive-lock refusals. Preserve the entire custody directory with the
functional evidence for that target.
