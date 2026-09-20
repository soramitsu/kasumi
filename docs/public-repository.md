# Public repository checks

Kasumi is an open source Redis-like database licensed under Apache-2.0. Keep
source, examples, documentation and release artifacts suitable for public use.
Use synthetic test data and generated local credentials; keep deployment keys,
customer data, private service addresses and internal project references out of
the repository. See [SECURITY.md](../SECURITY.md) for vulnerability reporting.

## Secret scanning

The [secret scan workflow](../.github/workflows/secret-scan.yml) runs on pull
requests, pushes, manual dispatch and weekly. It uses a pinned checkout action
and a checksum-verified [Gitleaks 8.30.1 release](https://github.com/gitleaks/gitleaks/releases/tag/v8.30.1).
It scans the checked-out files and all history reachable from the branches and
tags fetched by checkout, including merge diffs. Findings are redacted in logs.

Install the same Gitleaks version from its release page, verify the archive
against its published checksum, then run from the repository root:

```sh
# Current files, including uncommitted changes and untracked files.
gitleaks dir --config .gitleaks.toml --redact=100 \
  --ignore-gitleaks-allow --gitleaks-ignore-path /dev/null .

# All locally available branches and tags; fetch intended publication refs first.
gitleaks git --config .gitleaks.toml --redact=100 \
  --ignore-gitleaks-allow --gitleaks-ignore-path /dev/null \
  --log-opts="--all --full-history -m" .
```

The configuration inherits every upstream detector. Do not add broad path,
commit or rule exclusions to make a scan pass. Any exception must identify
verified public test data and constrain the detector, path and matched value.
Inline suppression comments and fingerprint ignore files are disabled in the
commands above and in CI.

The existing exceptions cover reviewed source checksum entries in specific
evidence files and the exact expired, self-signed TLS key used by a historical
unit-test fixture. Other credential fields and different private keys at those
paths remain subject to scanning.
Never suppress a live credential finding.

## Before publishing

Review both the current tree and the history to be published. Removing a file
from the latest commit does not remove older copies. If a real credential was
committed, revoke or rotate it and remove it from the publication history.
Coordinate any history rewrite with contributors before replacing shared refs.

Also review commit messages, branch and tag names, release assets, logs, issue
content and repository settings. These are outside the file and patch scans.
Pattern matching cannot establish that arbitrary data is safe to publish; inspect
new fixtures and generated evidence before committing them. Keep the Apache-2.0
license and third-party license notices in source and release distributions.

Retained validation evidence describes the source and environment at the time
of each run. Public copies may redact unrelated host details. After a history
rewrite, original commit IDs and source hashes in those reports remain historical
identifiers; they do not certify the rewritten checkout or replace fresh release
validation.
