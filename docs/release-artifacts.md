# Candidate artifact assembly

`scripts/package_release.py` assembles three production executables, normalized
binary/source archives, checksums, an SPDX 2.3 Cargo compilation inventory,
original third-party notices and systemd units. It consumes a successful frozen
functional run made with this source's runner and packager:

```sh
python3 scripts/release_gate.py \
  --output /absolute/evidence/final-functional \
  --execution-description 'Describe the actual pinned native host or VM' --jobs 2
python3 scripts/package_release.py \
  --evidence /absolute/evidence/final-functional \
  --output /absolute/artifacts/candidate-001
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
runners for Linux X64, Linux ARM64 and macOS ARM64 with at least 8 GiB RAM and
64 GiB free workspace disk, Python 3.11+, Git and the native platform build tools.
Linux needs Docker; macOS needs rustup, Xcode command-line tools and CMake.
The labels identify operator-provisioned hosts; adding this workflow does not
provision them or establish a passing run. Keep production identities and data
off these acceptance hosts.

The workflow freezes the checked-out commit, records host/image/package identity,
and runs the full functional gate set with two Cargo jobs. Linux uses the pinned
Rust image and Debian snapshot repositories from the validation Dockerfile.
Actions are pinned to exact commits. Packaging runs twice and compares archive
checksums; this verifies assembly reproducibility, not independent recompilation.
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
exported image before accepting it. The recipe is present; those actual OCI
build/runtime and platform SBOM gates have not yet passed.

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
sudo -u kasumi /usr/local/bin/kasumid init --mode standalone /var/lib/kasumi/installation
sudo install -m 0644 systemd/kasumid.service /etc/systemd/system/kasumid.service
sudo systemctl daemon-reload
sudo systemctl enable --now kasumid
```

The initialization directory must not already exist. Preserve the generated
private profiles and operator key backup using the [standalone procedures](standalone.md).
Loopback listeners remain the initialization default. The authority unit instead
requires a separately installed HA authority, a `kasumi-authority` service user
and private `/var/lib/kasumi-authority/authority.json`. HA data members may use
the data unit after installing the exact HA configuration at its configured path.
If an installation uses external archive/key paths, explicitly configure the
unit's required read/write directories to match those installed resources.

These are candidate artifacts. Complete cross-platform functional validation,
external-service/recovery/capacity/retention/performance gates and the actual
24-hour soak remain required before release publication. OCI assembly, full
platform SBOMs and bit-identical compiler-build acceptance remain separate work.
