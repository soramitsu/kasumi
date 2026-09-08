# Native authority signing-key reload

Intermediate macOS ARM64 evidence for clean `7d8c817`, integrated at `ebfb82c`.
The native reload action verifies the exact physical verifier/domain, durable
revision and activated certificate before swapping an immutable signer slot.
Private descriptor/key validation and original finite response fences apply.

Four source/initializer tests, one actual pinned TLS replacement test, 37 authority
tests, strict workspace Clippy, fixture-free production checks and formatting
passed. All logs in `evidence.json` were hash-checked when copied, including
initial compile, private-file protection and retained-owner fixture failures.
Historical executable hashes that were not captured are explicitly unavailable.

This does not complete the replicated signing head, remote verifier acknowledgments,
issuer retirement drains or coordinated global rotation. Final release gates remain open.
