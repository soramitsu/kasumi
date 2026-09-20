# Linux acceptance environment

`scripts/validation/lima-linux-arm64.yaml` creates a dedicated Debian 13 ARM64
VZ guest with no host directory mounts, SSH agent forwarding or dynamic service
port forwarding. It reserves 16 GiB RAM, two CPUs and 200 GiB disk. This is the
build environment; capacity tests must record their separately configured
resources. The pinned Debian image and official Rust image manifests are stored
under `scripts/validation/`.

The guest uses the host's already installed Rosetta to execute Linux x86-64
containers. Lima's plain mode disables Rosetta; the recipe explicitly enables
the guest agent and blocks automatic port forwarding for every guest interface
and both protocols. See [Lima plain mode](https://lima-vm.io/docs/config/plain/)
and [Rosetta configuration](https://lima-vm.io/docs/config/multi-arch/).

Native Linux ARM64 and translated Linux x86-64 results must be labeled separately.
Translated checks cannot satisfy any native Linux x86-64 release gate, including
functional, performance and endurance acceptance. A separate native x86-64
runner is required. The
reference software acceptance deployment is Linux; host durability and independent
failure domains remain required for deployment.

During environment preparation, Debian QEMU user 10.0.11 ran x86 shell utilities
but the pinned Rust 1.97.1 compiler segfaulted, including direct executable and
alternate CPU probes. Enabling existing Rosetta successfully executed that exact
compiler. These are environment diagnostics and do not pass a release gate.
The Linux ARM64 production compilation of frozen `f8e9618` is a development run;
its outputs cannot certify later integration commits.

On September 20, 2026 the existing `kasumi-production-arm64` VM was observed
running with the configured two CPUs, 16 GiB memory and 200 GiB disk, no running
Docker containers and no Kasumi or Rust build processes. Its guest reported
`aarch64`, kernel `6.12.107+deb13-cloud-arm64`, 16,360,668 KiB total memory and
79,553,540,096 free filesystem bytes at observation. This is a resource
observation, not a reservation for a future workload or an acceptance result.
Recheck admission and record exclusive workload ownership before dispatch;
capacity and endurance still require their own explicit resource allocation.
