# Focused design review: backup session claim before owned paths

The proposed direction is sound within the path-admission scope: derive the claim from the already retained NodeDiskDirectory and a stack UUID component, publish it under the same State serialization, and only then allocate put's owned paths. This is a design review of frozen candidate03's known issue, not approval of an uninspected successor. Candidate03 manifest: 16b112ad641fd9dadaeac0274418d5d319400a972fda8123548ba331ed39de66; patch: d7392ce6c5e0cd411af096ba65351c0ba16f2aaafc1d0f09db034dcad2f941f1.

Candidate03 put calls slot.relative(session_id) and constructs claim_path before the claim. The first call allocates an unused String, and the second PathBuf remains alive after claim Drop. Callers blocked on State can each own those paths without the single accepted lane bounding their aggregate bytes. Inside claim_namespace, directory::names also allocates a vector/CStrings while acquiring the claim; deriving the existing fixed binding removes that allocation too.

Required identity and policy checks:

- Derive exactly NamespaceBinding::root(configured_root.identity), then every retained DirectoryOwner name, then the framed components c"sessions" and the lowercase hyphenated session UUID. Borrow existing owned names; do not clone them or accept a separately supplied root/path as authority. Check exact NodeDisk Arc identity and enrolled settled parent binding under State. Preserve the configured-root case with an empty retained name list and nested-directory cases.
- Check claim/batch/pending occupancy and publish the new monotonic generation under the same State guard as derivation. Fail without altering generation/claim on invalid input, foreign owner, unavailable device, quota/policy rejection or generation overflow. Do not call an API that obtains State again from inside this guard.
- Preserve name/depth rules: directory::names currently rejects component count >= max_depth, so use checked retained-depth + 2 and preserve that strict boundary. Both sessions (8 bytes) and UUID (36 bytes) must fit max_name_bytes. Do not infer the later object filename's capacity from the shorter UUID claim component.
- Validate non-nil session and non-nil Object UUID directly. All other UUID bit patterns/versions previously accepted remain accepted. Encode the UUID into a 37-byte stack buffer with one NUL terminator and use borrowed CStr; no to_string, CString or PathBuf is needed before claim. Do not call slot.relative merely for validation.

Required drop/error behavior:

Declare the actual claim before all owned operation resources: paths, Strings, vectors, child Directory wrappers, files and aggregate-admission witness. Include resources returned by helper functions and shadowed/moved locals in the audit. Every early return and unwind must destroy them before NamespaceClaim Drop returns the lane. Pre-effect classification/header errors should preserve the existing healthy release behavior. A partial/abandoned namespace batch must still remain State-owned, cause claim witness retirement/fencing as today, and await the existing accepted census; the path correction must not make it cancellable. Do not put a retained-directory owner destructor under its own State lock.

Returned anyhow diagnostic storage, caller-owned ciphertext, the preexisting Directory wrapper, async/blocking worker and thread stack are not covered by this lifetime correction. A returned error/context allocation can outlive the claim. Do not claim complete per-call memory or worker admission from the new allocation-free path entry.

Focused regression requirements:

1. A competing valid busy claim rejects before terminal classification and before owned path creation. Separately hold State and prove a waiting valid caller has not allocated its path. Create test threads/channels outside allocation measurement and preserve the original deadline; thread creation itself is not part of the path proof.
2. Nil session and nil Object IDs reject with no claim/filesystem change; representative other UUID versions remain accepted. The public anyhow conversion may allocate diagnostics, so a no-path-allocation assertion must not be described as a zero-allocation proof for every returned error.
3. Derivation equals the existing framed binding for root and nested directory wrappers. Test exact name/depth boundaries and a foreign physical provider/owner; preserve existing geometry and quotas.
4. An accepted lane retires owned path resources before its release on normal completion and relevant early-error/unwind paths. A failed admitted operation retains the original batch/claim census state and witness semantics.
5. Retain the existing paused published-name/reserve-name two-wrapper race test. The losing wrapper must still fail before either classification, and the claim must span all settlement/publication work.

No source/proposal was changed, no native/Cargo command was run, and no whole-call worker/ciphertext admission proof is claimed. The implementation author received these notes while preparing a distinct successor.
