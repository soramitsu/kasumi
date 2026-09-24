# Filesystem backup session aggregate admission contract

Target-only next stage, over frozen `directory-managed-namespace-generic` (manifest `db42b5c363ec219f60bf4d67af7b599adec3da532231777a18ec1191fd1d1f82`). No caller implementation is complete. This draft pins concrete mechanics before introducing a partial per-child migration.

## Durable terminal capacity

An admitted distinct session must have two actual durable fixed-extent inodes outside `objects/`: one reserved for its immutable intent and one for its immutable outcome. New terminal publication writes and renames the matching existing reserve inode rather than allocating a later inode or growing beyond its admitted length. A cold census therefore reconstructs the logical-length/physical sparse promise and F count directly from actual files, including reservations whose payload has not been written. No transient in-memory reservation is treated as durable across restart.

Source bounds are `MAX_SESSION_RECORD_BYTES = 64 KiB`, `HEADER_LIMIT = 2 MiB`, envelope overhead 84 bytes: each slot requires **2,162,772 bytes of ciphertext allowance**, plus a strict fixed container header and filesystem rounding. Neither source bound is reduced. Two terminal slots cost at least 4.13 MiB per session before directory/allocator costs; measured retention limits must include that cost. A terminal object remains at its fixed admitted length after publication, so no shrink/retry can accidentally release capacity needed by a later settlement attempt.

The filesystem terminal container directly replaces the filesystem intent/outcome representation. It must have one canonical magic/version, expected session UUID and slot kind, checked used length, exact fixed total length, ciphertext integrity check and canonical zero padding. `session_get` unwraps that container to the exact original encrypted bytes before existing cryptographic intent/outcome verification. Published unframed/unknown-version inputs must reject; no legacy decoder. This does not change S3 object representation or public Rust/gRPC/MCP values. A reservation path is never served as an outcome, and a partial reservation payload is never treated as authorization.

Existing intent, outcome and session identities remain permanent. `objects/` is still the only authenticated deletable subtree. An unused terminal reservation remains permanently charged until the matching exact terminal publication; it is not GC debris.

## Finite operation plan

A caller first resolves the exact enrolled prefix and the full finite missing set. For a previously absent session the maximum is three directories (`sessions`, UUID, `objects`), two terminal reserve inodes, and—only for an object-first put—the current object inode. There is no unbounded component collector. Existing prefix directories and reserve files may be used only via the retained enrolled identity and strict canonical slot checks; raw `AlreadyExists` does not authorize adoption.

A single State-owned batch record retains the exact bound names, typed directory/file permits, extent promises and admitted backing. It precharges all required F, D, map, owner-slot and byte demand before the first mkdir/open/create/growth. The complete metadata workspace, including not-yet-published owner backing, must be included in the installed owner envelope. A public handle is only a witness for that retained record; dropping it with unused/effected work cannot release unknown resources.

Ordinary creation checks must include every outstanding reserved logical slot, so another operation cannot spend a batch's future F/D capacity. Each selected child operation consumes exactly its precharged permit into the actual operation and eventual inode ledger, with no second `reserve` charge. A file permit contains the admitted maximum length: creation transfers those bytes/pending into the file Budget and AccountedFile record before growth, and `reserve_growth` must see the existing allowance rather than charging it again. Fixed-bank absent-insertion checks/rebuilds remain before effects, under the same State guard; no post-effect table allocation is permitted.

The batch cannot hold State across existing file I/O methods that acquire State themselves. Permit checking/consumption is under State; the actual long-running owner is retained across each unlocked I/O phase. Every error/unwind preserves the batch and actual file/directory owner plus the original outcome, and seals further admission until exact resolution or explicit complete census. A definite cancellation with no effects may retire backing and release only its provably unused permits.

## Exclusive terminal publication

The matching reservation inode needs an exclusive claim for the entire write/sync/publish phase, not merely a new `open_file` handle or one lock per write call. Multiple destination wrappers for the same physical root must share that claim. The claim must be registered before writer wait and cannot hold State while waiting; after the original wait/deadline expires, the actual worker and permit remain retained until its original outcome. A second intent/outcome put must resolve the immutable published record or the existing claimed attempt, never interleave writes in the reserve inode.

This claim and exact permit transfer are implementation prerequisites. Adding a per-destination mutex would not prove physical exclusivity across two wrappers. Preparing directories alone would not prove terminal durability or F/extent liveness. The production caller migration must directly switch `backup_sessions_fs`, FilesystemBackupDestination initialization and FilesystemAuditArchive initialization together once their admitted contract is implemented; no raw fallback branch.

## Required validation

Native tests must challenge every shortage before the first new-session effect; count exact F/D and shared pending charges through every permit transfer; reopen between reserve preparation and intent/outcome publication; fill unrelated capacity after intent and prove the reserved terminal still settles without growth/new F; race two physical destination wrappers for the same session; inject original write/sync/publish/close failures and retain both primary and close outcomes; and repeat authenticated aborted-object cleanup without removing intent/outcome/reservations. Measure permanent per-session limits and full resident/native workspace separately.
