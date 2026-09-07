# Verified closed retirement custody

The complete workspace run passed 319 tests; two opt-in external-provider tests
remain ignored. Strict all-target/all-feature Clippy, workspace/included-file
formatting and diff checks passed. All 152 Rust, protocol and manifest inputs in
`verification.json` remained unchanged throughout. Rust 1.97.1 ran with locked,
offline dependencies and one Cargo build job in the isolated target.

This includes actual encrypted source retirement and restart; commit-before-apply
recovery and exhausted completion capacity; application-key/credential-unavailable
native startup; current administrator rotation and immutable exact command replay;
queued and post-commit credential expiry; repeated proof reads at full mutation
capacity; count/byte budget expansion without deleting history; failed audit
publication; three-voter quorum isolation; same-position snapshot substitution
rejection; secure pinned-mTLS SDK proof release; and healthy native local/three-node
restore and restart. Metadata fixture cases and actual engine/runtime tests remain
separate in the source and are not conflated into deployed DR acceptance.

The earlier run at `../custody-rotation-20260907-a` is retained. It had 316 passing
tests and one restore-fixture failure, and review found a read-induced permanent
custody capacity lockout. The corrected read path uses exact independently keyed
security audit records, without permanent mutation IDs, and repeats current quorum
after audit completion. Full configured mutation budgets can expand only through
current-Admin exact commands whose complete candidate retains every old record.

Independent serving leases, unavailable-source fencing, cross-host target
activation, and archival maintenance beyond the hard custody administrative
ceilings are not implemented or certified by this checkpoint. Current-quorum
custody proof recovery cannot grant serving permission or recover a nonretired
Stopped outcome after normal serving authority expires.
