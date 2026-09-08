# Security reporting

Kasumi's first production release is under implementation. The acceptance ledger
in `docs/production-release.md` records the outstanding gates. There is currently
no released production version for which this branch claims a support window.

Use GitHub's private vulnerability reporting for
https://github.com/soramitsu/kasumi when it is enabled. Otherwise contact a
repository maintainer privately to establish a secure reporting channel before
sharing sensitive details. Do not post credentials, customer data or an
uncoordinated exploit in a public issue.

Include the affected source revision and build identity, supported platform,
configuration with secrets removed, a minimal reproduction, expected behavior,
and the observed impact. Identify whether the failure concerns authorization,
confidentiality, acknowledged-write durability, consistency, or availability.

Treat the host operating system and explicitly trusted embedding application as
trust boundaries. Deployment operators must protect key material, prevent
plaintext memory dumps/swap where required, and use storage that honors durable
flush requests. These requirements do not replace testing the implementation.
