# Linux acceptance environment

`lima-linux-arm64.yaml` defines a dedicated Debian 13 ARM64 reference VM with a
digest-pinned base image. Lima plain mode disables dynamic host port forwarding;
host files and SSH agent credentials are not mounted or forwarded. Run all data,
Control, authority and fixture services inside the guest. Do not repurpose a VM
that owns another task's files or processes.

```sh
limactl start --tty=false --name=kasumi-production-arm64 scripts/validation/lima-linux-arm64.yaml
limactl shell kasumi-production-arm64 uname -a
```

The initial 8 GiB/2 CPU allocation supports compilation and functional tests.
Capacity and HA endurance runs must use an explicit, recorded resource allocation
large enough for their three resident copies and maintenance reserve. The default
is not a claim that a 3 GiB three-voter capacity run fits in 8 GiB of node RAM.

`../linux-validation.Dockerfile` pins the official Rust 1.97.1 multi-platform
image by digest. `rust-image.json` records the resolved index and Linux AMD64 and
ARM64 manifests. Build the validation image, preserve its image ID and installed
package inventory, and use that same image for every gate in an acceptance run.
The Debian VM package inventory is recorded under
`/opt/kasumi-acceptance/debian-packages.txt`; package updates must create a new
recorded environment identity. Copy a frozen source archive into guest storage
and record its digest; do not compile from a changing host checkout.

The [Lima usage documentation](https://lima-vm.io/docs/usage/) describes creation,
copy and shell commands. [Plain mode](https://lima-vm.io/docs/config/port/) controls
automatic forwarding. These recipes provision a test environment; only actual
source-bound results close the [release gates](../../docs/release-checklist.md).

The validation Dockerfile accepts `RUST_BUILD_IMAGE` for an explicit platform
manifest from `rust-image.json`. This avoids a legacy Docker image-store conflict
when building both architectures from the same multi-platform index on one VM.
Keep the compiler check in `validate_linux.sh`; a build argument never waives the
Rust 1.97.1 requirement. Record the exact recipe, selected manifest and built image
identity in acceptance evidence. Translated x86 execution is not native
performance or endurance acceptance.
