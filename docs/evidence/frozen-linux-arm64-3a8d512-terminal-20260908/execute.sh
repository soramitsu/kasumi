#!/bin/bash
set -euo pipefail
python3 /workspace/scripts/release_host.py --output /evidence/host.json --target aarch64-unknown-linux-gnu
python3 /workspace/scripts/release_gate.py --repository /workspace --output /evidence/run --jobs 2 --execution-description 'Native Linux ARM64 VZ reference VM; Debian 13 host, 2 vCPU, 16 GiB provisioned RAM, 200 GiB disk; pinned Rust1.97.1 Bookworm build image abf802c3daf7460f7498869910288b63bf5e138efc28e3c0704bf931b99e1ed4; container CPU2/memory15GiB/no extra swap. Shared macOS physical host. Host/image/package records retained. Functional integration checkpoint, not final capacity or endurance acceptance.'
python3 /evidence/run/source/scripts/package_release.py --evidence /evidence/run --output /evidence/candidate
python3 /evidence/run/source/scripts/package_release.py --evidence /evidence/run --output /evidence/repeated-assembly
cmp /evidence/candidate/SHA256SUMS /evidence/repeated-assembly/SHA256SUMS
