# Candidate artifact assembly

`scripts/package_release.py` assembles three production executables, normalized
binary/source archives, checksums, an SPDX 2.3 Cargo compilation inventory,
original third-party notices and systemd units. It consumes a successful frozen
functional run made with this source's runner and packager:

```sh
python3 scripts/release_gate.py \
  --output /absolute/evidence/final-functional \
  --execution-description 'Describe the actual pinned native host or VM' --jobs 2
python3 -B -S /absolute/evidence/final-functional/source/scripts/run_repeatable_assembly_owned.py \
  --evidence /absolute/evidence/final-functional \
  --native-inputs /absolute/native-inputs/inputs.json \
  --output /absolute/artifacts/repeatable-assembly-001
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

The native input declaration is mandatory; there is no ambient Cargo/Rustup
fallback. See [the assembly input contract](repeatable-assembly.md). The owned
launcher retains `launcher.json`, its runner process, descendant group ledger and
terminal census at the output root. Its child produces `assembly/attempt.json`
and the two original outputs, `assembly/assembly-a-output` and
`assembly/assembly-b-output`; the first contains the candidate package and OCI
build context. Both complete outputs, process transcripts, native probes and
original failed attempts remain under the exclusive output directory. The final
domain registry remains disabled
until native runner validation and its acceptance integration are complete.
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

## OCI image recipe

The runtime recipe in `release/oci/Dockerfile` uses an exact Debian Bookworm slim
index; `release/oci/base-image.json` retains its resolved platform manifests.
Build only from the candidate directory produced by the matching packager:

```sh
docker buildx build --platform linux/arm64 \
  --file /absolute/evidence/final-functional/source/release/oci/Dockerfile \
  --output type=oci,dest=/absolute/artifacts/kasumi-linux-arm64.oci.tar \
  /absolute/artifacts/candidate-001
```

Select `linux/amd64` only for the independently validated Linux x86-64 candidate.
The packager supplies the minimal build context and binary SHA-256 list; the
image checks those exact copied executables. It contains the full candidate
notices and Cargo SBOM under `/opt/kasumi` and runs as UID/GID 65532. Initialize
and serve with the same private mounted data volume and user. The initialization
directory must be absent. Initialization remains offline and loopback-bound;
network exposure requires an explicit listener and TLS client configuration.
Use `/opt/kasumi/bin/kasumi-authority` as an explicit entrypoint for a separately
installed authority group. No installation identity or fixture state is baked in.

Record the BuildKit version/image, OCI digest, base package inventory and a full
image SBOM, then exercise offline initialization, restart and shutdown with the
exported image before accepting it. An initial ARM64 recipe smoke built and ran
a Docker image using historical `8e90ff2` production binaries, including offline
initialization, authenticated access, backup verification and restart. That
source's workspace gate failed. The smoke does not approve those binaries or
replace an actual final candidate, OCI-layout export and platform SBOM gate.
Its failures and exact environment are retained in
`docs/evidence/linux-image-systemd-smoke-20260908`.

## systemd installation

The supplied units use separate static service users, owner-only state, an empty
capability set and a read-only filesystem outside each service's state directory.
They send SIGTERM and allow actual storage/worker ownership to drain without an
automatic stop timeout. SIGHUP requests atomic TLS reload; invalid replacements
retain the previous valid configuration and log failure. Signer and wrapping-key
rotation use their explicit maintenance operations.

For a fresh standalone host, install the binaries into `/usr/local/bin`, create
the dedicated user and parent directory, and initialize as that same user:

```sh
sudo useradd --system --user-group --home-dir /var/lib/kasumi --shell /usr/sbin/nologin kasumi
sudo install -d -o kasumi -g kasumi -m 0700 /var/lib/kasumi
sudo -u kasumi /usr/local/bin/kasumid init --mode standalone /var/lib/kasumi/installation --directory-policy /etc/kasumi/directory-policy.json --network /etc/kasumi/standalone-network.json
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

The exact data unit passed an initial native Debian ARM64 smoke with historical
`8e90ff2` binaries: dedicated-user startup, authenticated requests, TLS reload,
restart and drained shutdown. Both units passed `systemd-analyze verify`; the
authority unit still requires actual HA runtime validation. Repeat these checks
with the final accepted artifacts.

These are candidate artifacts. Complete cross-platform functional validation,
external-service/recovery/capacity/retention/performance gates and the actual
24-hour soak remain required before release publication. OCI assembly, full
platform SBOMs and bit-identical compiler-build acceptance remain separate work.
