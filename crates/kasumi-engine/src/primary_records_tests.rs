use super::AllocationGuard;
use crate::primary_tree::records::*;
use crate::primary_tree::{CodecError, ObjectId, OverflowRef, PageRef, Totals};
use sha2::{Digest, Sha256};

fn object(byte: u8, ordinal: u64) -> ObjectId {
    ObjectId {
        attempt: [byte; 16],
        ordinal,
    }
}
fn totals() -> Totals {
    Totals {
        live_count: 3,
        archived_count: 2,
        live_body_bytes: 17,
        archived_metadata_bytes: 21,
    }
}
fn manifest() -> Manifest {
    Manifest {
        scope: [0x11; 32],
        name_hash: [0x22; 32],
        tree_id: [0x33; 16],
        definition: OverflowRef {
            id: object(0x44, 5),
            encoded_bytes: 65_537,
            sha256: [0x55; 32],
        },
        data_epoch: 7,
        revision: 9,
        root: Some(Root {
            reference: PageRef {
                id: object(0x66, 8),
                sha256: [0x77; 32],
            },
            level: 2,
        }),
        totals: totals(),
    }
}
fn selector() -> Selector {
    Selector {
        boundary: Boundary::Entry,
        scope: [0x11; 32],
        bootstrap_sha256: [0x22; 32],
        projection_epoch: [0x33; 16],
        revision: 9,
        revision_base: 7,
        catalog: CatalogId(object(0x44, 5)),
        collection_count: 2,
        totals: totals(),
        activation_attempt: [0x66; 16],
        boundary_digest: [0x77; 32],
    }
}
fn gc() -> GcState {
    GcState {
        current: Some([0x11; 16]),
        building: Some([0x22; 16]),
        retired: None,
    }
}
fn epoch() -> Epoch {
    Epoch {
        scope: [0x11; 32],
        id: [0x22; 16],
        head: Some([0x33; 16]),
        tail: Some([0x44; 16]),
        pending: Some([0x44; 16]),
        live_resources: 3,
    }
}
fn attempt() -> Attempt {
    Attempt {
        phase: AttemptPhase::Committed,
        scope: [0x11; 32],
        epoch: [0x22; 16],
        id: [0x33; 16],
        previous: Some([0x44; 16]),
        next: Some([0x55; 16]),
        next_object: 10,
        live_resources: 3,
        retire_count: 4,
        abort_object_cursor: 0,
        retire_cursor: 2,
        journal_erase_cursor: 0,
    }
}
fn inventory() -> Inventory {
    Inventory {
        kind: ResourceKind::Live,
        phase: InventoryPhase::Complete,
        scope: [0x11; 32],
        id: object(0x22, 3),
        tree_id: [0x44; 16],
        encoded_bytes: 65_537,
        sha256: [0x55; 32],
        total_units: 2,
        completed_units: 2,
        cleanup_unit_cursor: 0,
        catalog_dense_count: 0,
    }
}
fn retire() -> Retire {
    Retire {
        target: object(0x22, 3),
    }
}

// Expected SHA-256 values were generated independently from the documented
// field order using Python struct.pack; no encoder-derived snapshot approval.
macro_rules! golden {
    ($type:ident,$size:ident,$value:expr,$hash:literal) => {{
        let value = $value;
        let mut bytes = [0xaa; $size];
        let guard = AllocationGuard::begin();
        value.encode(&mut bytes).unwrap();
        assert_eq!($type::decode(&bytes).unwrap(), value);
        let hash: [u8; 32] = Sha256::digest(bytes).into();
        assert_eq!(hash, boundary::raw_digest($hash).unwrap());
        assert_eq!(guard.finish(), 0);
    }};
}
#[test]
fn fixed_primary_record_golden_layouts_without_heap() {
    golden!(
        Manifest,
        MANIFEST_BYTES,
        manifest(),
        "ba28ed6fead29fd953e25d10dde29eb67106fdd51a2f48cdb1470a16a6156e46"
    );
    golden!(
        Selector,
        SELECTOR_BYTES,
        selector(),
        "bf7c0256c721f8defd8f82fa4dcb45af1b3d007db1b31c201ab1d3d061c3bc90"
    );
    golden!(
        GcState,
        GC_BYTES,
        gc(),
        "0608fcaf5b0ee4dd2e67376f97604474c680e4b407eaea0bc96bbc97188cf6b7"
    );
    golden!(
        Epoch,
        EPOCH_BYTES,
        epoch(),
        "c25096d28248b98415884600a9c5839992f63172a746dd045f50614e3370cbb3"
    );
    golden!(
        Attempt,
        ATTEMPT_BYTES,
        attempt(),
        "76c38055129e4e25a0998dececdc9d7a823962fb05d114aa5b8deaf204c460be"
    );
    golden!(
        Inventory,
        INVENTORY_BYTES,
        inventory(),
        "75e8679d792f4c0f80f499ed97023a2f4729b995fc4ef02311c3026f84489fe4"
    );
    golden!(
        Retire,
        RETIRE_BYTES,
        retire(),
        "f41d0f78efffe7ccb739b2a4cb1af4758890ed74c2f3e6a0d0c3da752cadb683"
    );
}
macro_rules! framing {
    ($type:ident,$size:ident,$value:expr) => {{
        let mut bytes = [0; $size];
        $value.encode(&mut bytes).unwrap();
        let guard = AllocationGuard::begin();
        for len in 0..$size {
            assert_eq!($type::decode(&bytes[..len]), Err(CodecError::Length));
        }
        let mut extended = [0; $size + 1];
        extended[..$size].copy_from_slice(&bytes);
        assert_eq!($type::decode(&extended), Err(CodecError::Length));
        for at in 0..10 {
            let mut changed = bytes;
            changed[at] ^= 0x80;
            assert_eq!($type::decode(&changed), Err(CodecError::Format));
        }
        let mut short = [0xbb; $size - 1];
        assert_eq!($value.encode(&mut short), Err(CodecError::Length));
        assert_eq!(short, [0xbb; $size - 1]);
        assert_eq!(guard.finish(), 0);
    }};
}
#[test]
fn fixed_primary_record_rejects_every_truncation_and_wrong_header() {
    framing!(Manifest, MANIFEST_BYTES, manifest());
    framing!(Selector, SELECTOR_BYTES, selector());
    framing!(GcState, GC_BYTES, gc());
    framing!(Epoch, EPOCH_BYTES, epoch());
    framing!(Attempt, ATTEMPT_BYTES, attempt());
    framing!(Inventory, INVENTORY_BYTES, inventory());
    framing!(Retire, RETIRE_BYTES, retire());
}
macro_rules! mutated {
    ($type:ident,$size:ident,$value:expr,$positions:expr,$error:expr) => {{
        let mut bytes = [0; $size];
        $value.encode(&mut bytes).unwrap();
        for at in $positions {
            let mut changed = bytes;
            changed[at] = 0x80;
            assert_eq!($type::decode(&changed), Err($error), "byte {at}");
        }
    }};
}
#[test]
fn fixed_primary_record_rejects_unknown_tags_reserved_bits_and_padding() {
    mutated!(
        Manifest,
        MANIFEST_BYTES,
        manifest(),
        [10],
        CodecError::Padding
    );
    mutated!(
        Selector,
        SELECTOR_BYTES,
        selector(),
        [10],
        CodecError::Padding
    );
    mutated!(Selector, SELECTOR_BYTES, selector(), [11], CodecError::Kind);
    mutated!(GcState, GC_BYTES, gc(), 10..16, CodecError::Padding);
    mutated!(Epoch, EPOCH_BYTES, epoch(), 10..16, CodecError::Padding);
    mutated!(Attempt, ATTEMPT_BYTES, attempt(), [10], CodecError::Kind);
    mutated!(
        Attempt,
        ATTEMPT_BYTES,
        attempt(),
        11..16,
        CodecError::Padding
    );
    mutated!(
        Inventory,
        INVENTORY_BYTES,
        inventory(),
        10..12,
        CodecError::Kind
    );
    mutated!(
        Inventory,
        INVENTORY_BYTES,
        inventory(),
        12..16,
        CodecError::Padding
    );
    mutated!(Retire, RETIRE_BYTES, retire(), [10], CodecError::Kind);
    mutated!(Retire, RETIRE_BYTES, retire(), 11..16, CodecError::Padding);
    mutated!(Retire, RETIRE_BYTES, retire(), 40..48, CodecError::Padding);
}
macro_rules! refused {
    ($type:ident,$size:ident,$value:expr,$error:expr) => {{
        let mut bytes = [0xab; $size];
        assert_eq!($value.encode(&mut bytes), Err($error));
        assert_eq!(bytes, [0xab; $size]);
    }};
}
#[test]
fn fixed_primary_manifest_root_and_reference_contracts() {
    let mut empty = manifest();
    empty.root = None;
    empty.totals = Totals::default();
    let mut bytes = [0; MANIFEST_BYTES];
    empty.encode(&mut bytes).unwrap();
    assert_eq!(Manifest::decode(&bytes), Ok(empty));
    assert!(bytes[172..260].iter().all(|byte| *byte == 0));
    bytes[172] = 1;
    assert_eq!(Manifest::decode(&bytes), Err(CodecError::Padding));
    bytes[172] = 0;
    bytes[11] = 1;
    assert_eq!(Manifest::decode(&bytes), Err(CodecError::Padding));
    empty.totals = totals();
    refused!(Manifest, MANIFEST_BYTES, empty, CodecError::Totals);
    let mut invalid = manifest();
    invalid.definition.encoded_bytes = 0;
    refused!(Manifest, MANIFEST_BYTES, invalid, CodecError::Length);
    invalid = manifest();
    invalid.definition.id.attempt = [0; 16];
    refused!(Manifest, MANIFEST_BYTES, invalid, CodecError::Identity);
    invalid = manifest();
    invalid.tree_id = [0; 16];
    refused!(Manifest, MANIFEST_BYTES, invalid, CodecError::Identity);
    invalid = manifest();
    invalid.root.as_mut().unwrap().reference.id.attempt = [0; 16];
    refused!(Manifest, MANIFEST_BYTES, invalid, CodecError::Identity);
    invalid = manifest();
    invalid.root.as_mut().unwrap().level = 64;
    refused!(Manifest, MANIFEST_BYTES, invalid, CodecError::Level);
    invalid = manifest();
    invalid.data_epoch = 10;
    refused!(Manifest, MANIFEST_BYTES, invalid, CodecError::Version);
    invalid = manifest();
    invalid.totals.live_count = u64::MAX;
    refused!(Manifest, MANIFEST_BYTES, invalid, CodecError::Overflow);
    let value = manifest();
    value.encode(&mut bytes).unwrap();
    let reference = ManifestRef {
        id: object(7, 8),
        sha256: Sha256::digest(bytes).into(),
    };
    assert_eq!(Manifest::decode_referenced(&bytes, reference), Ok(value));
    bytes[12] ^= 1;
    assert_eq!(
        Manifest::decode_referenced(&bytes, reference),
        Err(CodecError::Digest)
    );
    assert_eq!(
        value.validate_context(value.scope, value.name_hash, 9),
        Ok(())
    );
    assert_eq!(
        value.validate_context([0; 32], value.name_hash, 9),
        Err(CodecError::Identity)
    );
    assert_eq!(
        value.validate_context(value.scope, [0; 32], 9),
        Err(CodecError::Identity)
    );
    assert_eq!(
        value.validate_context(value.scope, value.name_hash, 8),
        Err(CodecError::Version)
    );
}
#[test]
fn fixed_primary_selector_empty_bootstrap_and_revision_contracts() {
    let mut value = selector();
    value.collection_count = 0;
    value.totals = Totals::default();
    value.boundary = Boundary::Bootstrap;
    value.boundary_digest = value.bootstrap_sha256;
    value.revision_base = value.revision;
    let mut bytes = [0; SELECTOR_BYTES];
    value.encode(&mut bytes).unwrap();
    assert_eq!(Selector::decode(&bytes), Ok(value));
    let mut wrong_revision = value;
    wrong_revision.revision_base -= 1;
    refused!(
        Selector,
        SELECTOR_BYTES,
        wrong_revision,
        CodecError::Version
    );
    let mut wrong_bytes = bytes;
    wrong_bytes[100..108].copy_from_slice(&wrong_revision.revision_base.to_le_bytes());
    assert_eq!(Selector::decode(&wrong_bytes), Err(CodecError::Version));
    value.boundary_digest[0] ^= 1;
    refused!(Selector, SELECTOR_BYTES, value, CodecError::Digest);
    value = selector();
    value.revision_base = 10;
    refused!(Selector, SELECTOR_BYTES, value, CodecError::Version);
    value = selector();
    value.projection_epoch = [0; 16];
    refused!(Selector, SELECTOR_BYTES, value, CodecError::Identity);
    value = selector();
    value.activation_attempt = [0; 16];
    refused!(Selector, SELECTOR_BYTES, value, CodecError::Identity);
    value = selector();
    value.catalog.0.attempt = [0; 16];
    refused!(Selector, SELECTOR_BYTES, value, CodecError::Identity);
    value = selector();
    value.collection_count = 0;
    refused!(Selector, SELECTOR_BYTES, value, CodecError::Totals);
    // Collections may be empty; collection count is not a document count.
    value = selector();
    value.totals = Totals::default();
    value.encode(&mut bytes).unwrap();
    assert_eq!(Selector::decode(&bytes), Ok(value));
}
#[test]
fn fixed_primary_optional_uuid_flags_and_link_shape_are_canonical() {
    let mut bytes = [0; GC_BYTES];
    gc().encode(&mut bytes).unwrap();
    bytes[11] &= !1;
    assert_eq!(GcState::decode(&bytes), Err(CodecError::Padding));
    gc().encode(&mut bytes).unwrap();
    bytes[16..32].fill(0);
    assert_eq!(GcState::decode(&bytes), Err(CodecError::Identity));
    let mut value = gc();
    value.retired = Some([3; 16]);
    refused!(GcState, GC_BYTES, value, CodecError::Range);
    value = gc();
    value.building = value.current;
    refused!(GcState, GC_BYTES, value, CodecError::Identity);
    value = GcState {
        current: None,
        building: None,
        retired: None,
    };
    value.encode(&mut bytes).unwrap();
    assert_eq!(GcState::decode(&bytes), Ok(value));
    value.retired = Some([3; 16]);
    refused!(GcState, GC_BYTES, value, CodecError::Identity);
    value.retired = None;
    value.building = Some([3; 16]);
    value.encode(&mut bytes).unwrap();
    assert_eq!(GcState::decode(&bytes), Ok(value));
    let mut epoch = epoch();
    epoch.tail = None;
    refused!(Epoch, EPOCH_BYTES, epoch, CodecError::Identity);
    epoch.head = None;
    refused!(Epoch, EPOCH_BYTES, epoch, CodecError::Range);
    epoch.pending = None;
    epoch.live_resources = 0;
    let mut eb = [0; EPOCH_BYTES];
    epoch.encode(&mut eb).unwrap();
    assert_eq!(Epoch::decode(&eb), Ok(epoch));
    let mut attempt = attempt();
    attempt.previous = Some(attempt.id);
    refused!(Attempt, ATTEMPT_BYTES, attempt, CodecError::Identity);
    attempt.previous = attempt.next;
    refused!(Attempt, ATTEMPT_BYTES, attempt, CodecError::Identity);
}
#[test]
fn fixed_primary_attempt_counters_check_before_output_and_decode() {
    for (offset, value, error) in [
        (120, 11, CodecError::Range),
        (136, 11, CodecError::Range),
        (144, 5, CodecError::Range),
        (152, 15, CodecError::Range),
        (112, u64::MAX, CodecError::Overflow),
    ] {
        let mut bytes = [0; ATTEMPT_BYTES];
        attempt().encode(&mut bytes).unwrap();
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert_eq!(Attempt::decode(&bytes), Err(error));
    }
    let mut value = attempt();
    value.journal_erase_cursor = 1;
    refused!(Attempt, ATTEMPT_BYTES, value, CodecError::Range);
    value.live_resources = 0;
    value.retire_cursor = value.retire_count;
    value.journal_erase_cursor = 14;
    let mut bytes = [0; ATTEMPT_BYTES];
    value.encode(&mut bytes).unwrap();
    assert_eq!(Attempt::decode(&bytes), Ok(value));
    value.next_object = u64::MAX;
    refused!(Attempt, ATTEMPT_BYTES, value, CodecError::Overflow);
}
#[test]
fn fixed_primary_inventory_kind_completion_and_deletion_contracts() {
    assert_eq!(chunk_count(0), Err(CodecError::Length));
    for (bytes, count) in [(1, 1), (65_536, 1), (65_537, 2), (u64::MAX, 1_u64 << 48)] {
        assert_eq!(chunk_count(bytes), Ok(count));
    }
    for kind in [
        ResourceKind::Live,
        ResourceKind::Archived,
        ResourceKind::Definition,
        ResourceKind::Page,
        ResourceKind::CollectionManifest,
        ResourceKind::Catalog,
    ] {
        let mut value = inventory();
        value.kind = kind;
        match kind {
            ResourceKind::Page => {
                value.encoded_bytes = 16_384;
                value.total_units = 1;
                value.completed_units = 1;
            }
            ResourceKind::CollectionManifest => {
                value.encoded_bytes = 260;
                value.total_units = 1;
                value.completed_units = 1;
            }
            ResourceKind::Catalog => {
                value.tree_id = [0; 16];
                value.encoded_bytes = 0;
                value.sha256 = [0; 32];
                value.catalog_dense_count = value.total_units;
            }
            _ => {}
        }
        let mut bytes = [0; INVENTORY_BYTES];
        value.encode(&mut bytes).unwrap();
        assert_eq!(Inventory::decode(&bytes), Ok(value));
        let mut invalid = value;
        invalid.completed_units += 1;
        refused!(Inventory, INVENTORY_BYTES, invalid, CodecError::Range);
        invalid = value;
        invalid.completed_units -= 1;
        refused!(Inventory, INVENTORY_BYTES, invalid, CodecError::Range);
        invalid.phase = InventoryPhase::Allocating;
        invalid.encode(&mut bytes).unwrap();
        assert_eq!(Inventory::decode(&bytes), Ok(invalid));
        invalid.phase = InventoryPhase::Deleting;
        invalid.cleanup_unit_cursor = invalid.completed_units;
        invalid.encode(&mut bytes).unwrap();
        assert_eq!(Inventory::decode(&bytes), Ok(invalid));
        invalid.cleanup_unit_cursor += 1;
        refused!(Inventory, INVENTORY_BYTES, invalid, CodecError::Range);
        invalid = value;
        invalid.cleanup_unit_cursor = 1;
        refused!(Inventory, INVENTORY_BYTES, invalid, CodecError::Range);
        if kind == ResourceKind::Catalog {
            invalid = value;
            invalid.tree_id[0] = 1;
            refused!(Inventory, INVENTORY_BYTES, invalid, CodecError::Padding);
            invalid = value;
            invalid.sha256[0] = 1;
            refused!(Inventory, INVENTORY_BYTES, invalid, CodecError::Padding);
            invalid = value;
            invalid.encoded_bytes = 1;
            refused!(Inventory, INVENTORY_BYTES, invalid, CodecError::Padding);
            invalid = value;
            invalid.catalog_dense_count += 1;
            refused!(Inventory, INVENTORY_BYTES, invalid, CodecError::Range);
        } else {
            invalid = value;
            invalid.catalog_dense_count = 1;
            refused!(Inventory, INVENTORY_BYTES, invalid, CodecError::Padding);
            invalid = value;
            invalid.tree_id = [0; 16];
            refused!(Inventory, INVENTORY_BYTES, invalid, CodecError::Identity);
        }
    }
    let mut page = inventory();
    page.kind = ResourceKind::Page;
    refused!(Inventory, INVENTORY_BYTES, page, CodecError::Length);
    page.kind = ResourceKind::CollectionManifest;
    refused!(Inventory, INVENTORY_BYTES, page, CodecError::Length);
}
#[test]
fn fixed_primary_scope_and_name_hashes_are_length_delimited_without_heap() {
    let guard = AllocationGuard::begin();
    assert_eq!(
        scope_hash("tenant", "db1", [0x22; 32]).unwrap(),
        boundary::raw_digest("44b4c31b2c39efdede43f164e579d7a738a17e83a8c5d0f670e8d1327a055d8b")
            .unwrap()
    );
    assert_eq!(
        name_hash("accounts").unwrap(),
        boundary::raw_digest("5603789f2bdfe9bc953b25938e09fed52477e3eb9cd6a3c54cebc5ade3997a50")
            .unwrap()
    );
    assert_ne!(
        scope_hash("ab", "c", [7; 32]),
        scope_hash("a", "bc", [7; 32])
    );
    assert_ne!(
        scope_hash("ab", "c", [7; 32]),
        scope_hash("ab", "c", [8; 32])
    );
    for value in [
        "",
        "00",
        "000000000000000000000000000000000000000000000000000000000000000G",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert_eq!(boundary::raw_digest(value), Err(CodecError::Digest));
    }
    assert_eq!(guard.finish(), 0);
}
#[test]
fn fixed_primary_boundary_fingerprints_match_real_producer_and_checkpoint() {
    use kasumi_raft::{
        ApplicationBoundaryRef, AppliedEntryContext, SelectedAppliedRef, SnapshotRestoreContext,
        SnapshotRestoreMode,
    };
    use openraft::{
        BasicNode, CommittedLeaderId, LogId, Membership, SnapshotMeta, StoredMembership,
    };
    use std::collections::{BTreeMap, BTreeSet};
    let id = LogId::new(CommittedLeaderId::new(4, 2), 7);
    let membership = StoredMembership::new(
        Some(id),
        Membership::new(
            vec![BTreeSet::from([1, 2])],
            BTreeMap::from([(1, BasicNode::new("one")), (2, BasicNode::new("two"))]),
        ),
    );
    let position = AppliedEntryContext {
        log_id: id,
        previous: Some(LogId::new(CommittedLeaderId::new(4, 2), 6)),
        membership: membership.clone(),
        command_sha256: "ab".repeat(32),
        retirement_seed: None,
    };
    let checkpoint = SnapshotRestoreContext {
        mode: SnapshotRestoreMode::Install,
        backend_sha256: "cd".repeat(32),
        meta: SnapshotMeta {
            last_log_id: Some(id),
            last_membership: membership,
            snapshot_id: "actual-snapshot".into(),
        },
    };
    let expected_checkpoint =
        boundary::raw_digest(&checkpoint.checkpoint_sha256().unwrap()).unwrap();
    let expected_entry: [u8; 32] = Sha256::digest(
        serde_json::to_vec(&(
            "kasumi.primary.entry.v1",
            &position.log_id,
            &position.previous,
            &position.membership,
            &position.command_sha256,
        ))
        .unwrap(),
    )
    .into();
    let guard = AllocationGuard::begin();
    let entry = boundary::producer(ApplicationBoundaryRef::Entry(&position)).unwrap();
    assert_eq!(entry.kind, Boundary::Entry);
    assert_eq!(entry.sha256, expected_entry);
    assert_eq!(
        entry,
        boundary::selected(
            Some(SelectedAppliedRef::Entry {
                log_id: position.log_id,
                previous: position.previous,
                membership: &position.membership,
                command_sha256: &position.command_sha256
            }),
            "unused for entry"
        )
        .unwrap()
    );
    let snapshot = boundary::producer(ApplicationBoundaryRef::Snapshot(&checkpoint)).unwrap();
    assert_eq!(snapshot.kind, Boundary::Snapshot);
    assert_eq!(snapshot.sha256, expected_checkpoint);
    assert_eq!(
        snapshot,
        boundary::selected(
            Some(SelectedAppliedRef::Snapshot {
                meta: &checkpoint.meta,
                backend_sha256: &checkpoint.backend_sha256,
                snapshot_sha256: "full proof checks this separate envelope"
            }),
            "unused for snapshot"
        )
        .unwrap()
    );
    let bootstrap = boundary::selected(None, &position.command_sha256).unwrap();
    assert_eq!(bootstrap.kind, Boundary::Bootstrap);
    assert_eq!(bootstrap.sha256, [0xab; 32]);
    assert_eq!(guard.finish(), 0);
    let mut changed = position.clone();
    changed.previous = None;
    assert_ne!(
        boundary::producer(ApplicationBoundaryRef::Entry(&changed)).unwrap(),
        entry
    );
    changed = position.clone();
    changed.log_id.index += 1;
    assert_ne!(
        boundary::producer(ApplicationBoundaryRef::Entry(&changed)).unwrap(),
        entry
    );
    changed = position;
    changed.command_sha256 = "ef".repeat(32);
    assert_ne!(
        boundary::producer(ApplicationBoundaryRef::Entry(&changed)).unwrap(),
        entry
    );
}

#[test]
fn fixed_primary_accepted_mutations_are_canonical_without_heap() {
    macro_rules! canonical {
        ($type:ident, $size:ident, $value:expr) => {{
            let mut original = [0; $size];
            $value.encode(&mut original).unwrap();
            let guard = AllocationGuard::begin();
            // Corrupt every field bit independently. Valid alternate scalar
            // values may decode, but no alternate reserved/padding encoding
            // may normalize silently when it is encoded again.
            for at in 0..$size {
                for bit in 0..8 {
                    let mut changed = original;
                    changed[at] ^= 1 << bit;
                    if let Ok(value) = $type::decode(&changed) {
                        let mut encoded = [0; $size];
                        value.encode(&mut encoded).unwrap();
                        assert_eq!(changed, encoded);
                    }
                }
            }
            assert_eq!(guard.finish(), 0);
        }};
    }
    canonical!(Manifest, MANIFEST_BYTES, manifest());
    canonical!(Selector, SELECTOR_BYTES, selector());
    canonical!(GcState, GC_BYTES, gc());
    canonical!(Epoch, EPOCH_BYTES, epoch());
    canonical!(Attempt, ATTEMPT_BYTES, attempt());
    canonical!(Inventory, INVENTORY_BYTES, inventory());
    canonical!(Retire, RETIRE_BYTES, retire());
}
