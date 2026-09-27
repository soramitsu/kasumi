# Independent source review: original initialization entry

Reviewed by the primary implementation agent independently of the author of
the atomic-initialization change, on 2026-09-27. This is a reviewed development
dependency checkpoint, **not an immutable or qualified release**. No human
owner signature or operational authority is asserted.

## Exact scope

The existing 600-file OpenRaft tree has exactly four changed files, with no
added, missing, linked or special inputs. `reviewed-delta.json` records their
old/new hashes, byte sizes and modes; `source-inventory.json` captures all 600
files. The predecessor manifest and checkpoint remain retained. The diff and
native consumer hashes identify the code actually reviewed.

## Findings

No blocking correctness finding was found in this bounded review:

- The public typed initializer and core dispatch both reject a non-membership
  entry. They pass the original typed entry to the existing engine. The engine
  still checks pristine log/vote state, assigns its own first log identity,
  requires the local voter, appends through normal storage, and starts election.
  Existing task-capacity admission remains before dispatch to that engine.
- The ordinary initializer constructs the same membership entry through the
  type's own constructor. Kasumi's constructor explicitly sets no cause; the
  separate authorized target initializer attaches the signed original cause.
  A copied caller-selected log position is not retained by the engine.
- Kasumi validates the bounded canonical cause signature, original accepted
  Start and Initialize identities, installed materialization set, target
  prebinding, voter set and peer addresses before any first-entry append. A
  prebound target cannot append a cause-free ordinary membership. A supplied
  cause cannot attach to an application, blank, or later membership entry.
- Application records the first membership, cause, local association and
  applied cursor in the same custody write. Retained cause reads require real
  committed/applied coverage. Snapshot admission and publication reject cause
  erasure, substitution and downgrade; reopening cannot manufacture the cause
  from journal history. A current read capability and quorum barrier remain
  separate from this historical consensus fact.
- The new native entry requires the explicit initialization slot and rejects
  unknown fields. No old entry decoder, migration, execution-capability recovery
  path, or compatibility command was introduced. Debug formatting omits the
  attached cause, avoiding disclosure of its full accepted request history.

The original logs were inspected: 219 upstream library, 13 client API, 23
lifecycle and 41 membership cases passed with zero ignored/filtered cases.
The separate Kasumi native scenarios exercise protected TLS, lost replies,
original-node shutdown, expired authority, exact storage negatives, snapshots,
purge, completion, drains and ordinary reopen. Those scenario logs are retained
in the preceding atomic-entry lane; no controlled shutdown is relabeled as an
OS-process crash. The zero-case first API filter is not evidence of execution.

## Remaining qualification

The first-entry API's direct non-membership rejection should receive an explicit
public-API regression in the next upstream cohort. Full frozen upstream feature
and platform checks, strict lint, all integrated Kasumi gates, OS crash matrix,
nine independent product processes, exact deletion and the 24-hour soak remain
required. The dependency verifier checks reviewed source custody only; advancing
its inventory does not satisfy those separate release gates.
