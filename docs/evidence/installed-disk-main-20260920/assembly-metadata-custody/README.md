# Packaging metadata custody prerequisite

Status: **target-only proposal; tests prepared but not executed**. Sole master checkout; no actual source edits, Rust builds, Python tests, external assembly, or release acceptance was performed. Python AST parsing and `git apply --check` are static checks only.

Patch: `metadata.patch`, SHA-256 `fbd5f8ff5cee7c0818ffe3c8ea63fdfdbbf84829d2497e04d85f7bc206b637a8`. Five files, eight new tests. Exact before/proposed file hashes are in `manifest.json`.

## Why this prerequisite comes before registration

The existing repeatable-assembly branch only compares a second package/source reference to the delivered hashes. `DOMAIN_ADAPTERS` is intentionally empty, so those labels cannot currently certify an assembly. The existing package assembler also invokes Cargo metadata using raw `subprocess.check_output`. An outer Python process receipt does not bind that input-producing child's stdout, dispatch identity, or actual cleanup. A complete semantic adapter cannot simply trust a report asserting two assemblies.

This package directly replaces that raw metadata invocation; it does **not** register repeatable-assembly or any unrelated final-release domain. `verify_release_acceptance.py` remains unchanged. Both assemblies and full final-release acceptance remain unimplemented/unqualified.

## Implemented proposal

`gate_process.run` receives a required explicit stderr sink. Existing functional-gate callers deliberately keep `subprocess.STDOUT`; metadata uses a distinct owned stderr file. The helper retains and synchronizes both streams before its final observation, and records the actual resolved working directory. Existing executable resolution, original deadline, signal handling, group ownership and actual drain rules remain.

`package_release.capture_metadata` creates one exclusive `metadata-custody` directory alongside the package tree. It writes a running attempt before dispatch, retains the selected executable's actual bytes, and dispatches the reconstructed absolute Cargo command with the pinned toolchain, locked dependencies, offline mode, format version 1, no default features and the exact native target. Its 600-second command deadline is fixed source policy. This is a metadata operation bound, not an assembly/release qualification duration or an elapsed-time completion rule.

The process receipt binds separate stdout/stderr hashes only after its actual group is known drained. The attempt also retains exact source inventories before and after the run. Failure, signals, deadline expiry, uncertain inspection, changed executable, changed source, malformed stdout, duplicate/nonfinite JSON, and missing metadata structure prevent consumption. A failed/partial directory is never overwritten or deleted by the assembler. Hard loss leaves a running receipt that cannot be selected as passed and requires actual external ownership recovery.

`verify_metadata_capture` is a read-only consumer. It reconstructs the exact command and matches process cwd/executable/output references, checks successful terminal process ownership with the existing verifier, requires both source inventories equal the caller's previously verified frozen inventory, and parses only the exact bounded stdout bytes. Diagnostics are never stripped from mixed stdout as a fallback. It rechecks every referenced artifact and the attempt bytes before returning the document. The raw metadata process receipt and output remain outside normalized package/source archives, so variable PIDs and timings are not inserted into assembly artifacts.

The eight tests use a deliberately synthetic Cargo script as an **actual dispatched subprocess**, isolating the custody primitive from native Cargo/packaging qualification. They cover separate outputs and actual cleanup; copied JSON/asserted status without custody; rehashed substituted output that does not match its process; changed command/cwd/executable/deadline or missing drain; real failed child plus immutable failed directory; changed frozen source and mixed diagnostic stdout; same-byte symlink substitution; and continued absence of final domain registration. No fixture result is claimed as native Cargo or assembly evidence.

## Exact remaining hooks for the complete repeatable-assembly domain

1. A fixed frozen runner must launch two distinct actual packaging invocations into separately created output directories. Each invocation needs its own process/cwd/executable/deadline/terminal receipt and input/result inventory. Comparing two copied archives or two asserted scenario labels is insufficient.
2. Bind the runner's full Python/runtime identity and Cargo/Rustup-selected toolchain children, environment and external Cargo configuration/cache inputs. This prerequisite records the actual dispatched Cargo path/bytes, which may be a Rustup proxy; it does not pretend that hash covers the selected native Cargo implementation, its libraries, or all transitive metadata inputs.
3. Bind each invocation to the exact functional evidence, native production executables, source commit/tree/archive/files, Cargo.lock, source epoch, package script and supplemental-license inputs. The current package verifier checks much of this, but a domain receipt must retain its own complete before/after input census including consumed external notices/manifests. This patch's source snapshot is only the frozen source portion.
4. Bind each generated binary/source archive and notice/SBOM/provenance output to its originating invocation, then independently compare the actual artifact bytes. Preserve both process logs and all failed/interrupted attempts in the permanent attempt namespace. A final domain adapter must reconstruct the exact frozen command from those verified inputs, not accept arbitrary source-path labels.
5. Only then register the repeatable-assembly adapter and replace its label-only structural detail branch with the concrete semantic contract. Other domains remain unregistered; this does not establish independent compiler reproducibility or a final release.

This intentionally bounded prerequisite improves a real packaging operation without issuing an unsupported domain pass. No compatibility wrapper, legacy receipt parser, or user-selectable acceptance escape is added.
