use super::*;
use crate::{TenantEngine, admission::NodeAdmission, backup_verify::VerificationDeadline};
use kasumi_store::{
    NodeDiskMemoryAdmission, ScratchDisk, StorageCensusDisposition, test_utils::TestDiskMemory,
};
use kasumi_types::{
    Action, CollectionDefinition, CollectionRetentionClass, CollectionWriteMode, Command,
    ErrorCode, Grant, Limits, MutationBatch, Operation, Policy, RequestAuthorization,
    RequestContext,
};
use std::{io::Read, os::unix::fs::PermissionsExt, sync::Arc};

struct EncodedFixture {
    bytes: Vec<u8>,
    _charge: kasumi_store::DiskMemoryLease,
}
impl EncodedFixture {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

fn encoded_fixture(engine: &TenantEngine, disk: &Arc<ScratchDisk>) -> EncodedFixture {
    let image = engine.logical_snapshot(disk).unwrap();
    let size = usize::try_from(image.len()).unwrap();
    let charge = disk
        .memory()
        .clone()
        .reserve_installed((size as u64).checked_add(4096).unwrap())
        .unwrap();
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(size).unwrap();
    assert!(bytes.capacity() as u64 <= size as u64 + 4096);
    bytes.resize(size, 0);
    image.reader().read_exact(&mut bytes).unwrap();
    EncodedFixture {
        bytes,
        _charge: charge,
    }
}

#[tokio::test]
async fn blocking_snapshot_creation_failure_keeps_registered_original_across_public_handoff() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let scratch_path = directory.path().join("scratch");
    let memory = TestDiskMemory::new(64 << 20, 64);
    let disk = ScratchDisk::fixture(&scratch_path, memory.clone());
    let engine = TenantEngine::new(
        "snapshot-owner".into(),
        "generation".into(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: [Action::Write, Action::Admin].into_iter().collect(),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap();
    let context = RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: "snapshot-owner".into(),
        scopes: [Action::Write, Action::Admin].into_iter().collect(),
        request_id: "snapshot-constructor-fixture".into(),
    };
    engine
        .apply_command(
            &disk,
            1,
            Command {
                context: context.clone(),
                timestamp_ms: 1,
                operation: Operation::CreateCollection(CollectionDefinition {
                    name: "docs".into(),
                    schema: serde_json::json!({"type":"object"}),
                    indexes: vec![],
                    strict_read_audit: false,
                    retention_class: CollectionRetentionClass::Operational,
                    write_mode: CollectionWriteMode::Mutable,
                }),
            },
        )
        .unwrap()
        .unwrap();
    engine
        .apply_command(
            &disk,
            2,
            Command {
                context,
                timestamp_ms: 2,
                operation: Operation::Mutate(
                    MutationBatch::with_key("snapshot-fixture-row").insert(
                        "docs",
                        "one",
                        serde_json::json!({"value":1}),
                    ),
                ),
            },
        )
        .unwrap()
        .unwrap();
    // The authenticated nonempty receipt prefix makes the decoder create its
    // actual registered scratch table while reading the header.
    assert_eq!(
        engine
            .generation()
            .unwrap()
            .state
            .mutation_receipt_head
            .count,
        1
    );
    let baseline = memory.snapshot();
    let encoded = encoded_fixture(&engine, &disk);
    let permissions = std::fs::metadata(&scratch_path).unwrap().permissions();
    std::fs::set_permissions(&scratch_path, std::fs::Permissions::from_mode(0o755)).unwrap();

    let admission = NodeAdmission::new(Default::default()).unwrap();
    let reservation = Arc::new(admission.reserve(1 << 20, None).unwrap());
    let worker_disk = disk.clone();
    let deadline = VerificationDeadline::new(60_000).unwrap();
    let original = deadline
        .blocking(
            reservation,
            None,
            move || -> Result<(), ScratchOperationFailure> {
                // Borrowing through the owner captures both the actual bytes and
                // their same original charge in the worker.
                crate::snapshot_codec::read(&worker_disk, &mut encoded.as_bytes()).map(|_| ())
            },
        )
        .await
        .unwrap_err();
    std::fs::set_permissions(&scratch_path, permissions).unwrap();
    let creation = original
        .creation()
        .expect("actual scratch creation remained typed");
    let id = creation
        .owner_id()
        .expect("constructor registered before its directory refusal");
    let census = memory.storage_census();
    assert!((0..census.snapshot().capacity).any(|index| census.owner_at(index) == Some(id)));
    let original_address = creation.with_diagnostic(|report| {
        report
            .unwrap()
            .admission_error()
            .expect("original directory refusal") as *const std::io::Error as usize
    });
    let retained = memory.snapshot();
    assert!(retained.live_reservations > baseline.live_reservations);
    let public = SnapshotFailure::from(original);
    assert!(public.operation_error().is_none());
    assert_eq!(public.creation().unwrap().owner_id(), Some(id));
    assert_eq!(
        public.creation().unwrap().with_diagnostic(|report| report
            .unwrap()
            .admission_error()
            .unwrap()
            as *const std::io::Error
            as usize),
        original_address
    );
    assert_eq!(
        memory.snapshot().live_reservations,
        retained.live_reservations
    );
    assert_eq!(memory.snapshot().used_bytes, retained.used_bytes);
    let returned = public.into_scratch_failure();
    assert_eq!(returned.creation().unwrap().owner_id(), Some(id));
    assert_eq!(
        returned.creation().unwrap().with_diagnostic(|report| report
            .unwrap()
            .admission_error()
            .unwrap()
            as *const std::io::Error
            as usize),
        original_address
    );
    let ScratchOperationFailure::Creation(original) = returned else {
        unreachable!()
    };
    assert_eq!(
        original.retire().disposition(),
        StorageCensusDisposition::Retired
    );
    assert_eq!(
        memory.snapshot().live_reservations,
        baseline.live_reservations
    );
    assert_eq!(memory.snapshot().used_bytes, baseline.used_bytes);
}

#[test]
fn snapshot_operation_public_boundary_moves_original_kind_and_message() {
    let original = Error::new(ErrorCode::Sealed, "original sealed snapshot");
    let message_address = original.message.as_ptr();
    let public = SnapshotFailure::from(ScratchOperationFailure::Operation(original.into()));
    let original = public.operation_error().unwrap();
    assert_eq!(original.code, ErrorCode::Sealed);
    assert_eq!(original.message.as_ptr(), message_address);
    assert!(public.creation().is_none());
}

#[derive(Debug)]
struct OriginalSource(u64);
impl std::fmt::Display for OriginalSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "original source {}", self.0)
    }
}
impl std::error::Error for OriginalSource {}

#[test]
fn snapshot_source_public_boundary_keeps_original_allocation_and_native_type() {
    let original = anyhow::Error::new(OriginalSource(47));
    let address =
        original.downcast_ref::<OriginalSource>().unwrap() as *const OriginalSource as usize;
    let public = SnapshotFailure::from(ScratchOperationFailure::Operation(original));
    assert!(public.operation_error().is_none());
    assert!(public.creation().is_none());
    assert_eq!(
        public
            .source_error()
            .unwrap()
            .downcast_ref::<OriginalSource>()
            .unwrap() as *const OriginalSource as usize,
        address
    );
    let returned = public.into_scratch_failure();
    assert_eq!(
        returned
            .operation_error()
            .unwrap()
            .downcast_ref::<OriginalSource>()
            .unwrap() as *const OriginalSource as usize,
        address
    );
}

#[derive(Debug)]
struct OwningContext(std::sync::Arc<std::sync::atomic::AtomicUsize>);
impl std::fmt::Display for OwningContext {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("owning snapshot context")
    }
}

#[test]
fn snapshot_admission_refusals_cross_public_and_native_boundaries_without_allocation() {
    use crate::primary_tree::tests::AllocationGuard;
    for refused in [
        ScratchAdmissionRefusal::Busy,
        ScratchAdmissionRefusal::Sealed,
    ] {
        let measured = AllocationGuard::begin();
        let public = SnapshotFailure::from(ScratchOperationFailure::AdmissionRefused(refused));
        assert_eq!(public.admission_refusal(), Some(refused));
        assert!(public.creation().is_none());
        assert!(public.operation_error().is_none());
        assert!(public.source_error().is_none());
        let returned = public.into_scratch_failure();
        assert!(
            matches!(returned, ScratchOperationFailure::AdmissionRefused(value) if value == refused)
        );
        assert_eq!(measured.finish(), 0);
    }
}
impl Drop for OwningContext {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }
}

#[test]
fn snapshot_application_error_context_keeps_original_outer_owner_until_final_drop() {
    let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let original = anyhow::Error::new(Error::new(ErrorCode::Sealed, "original sealed value"))
        .context(OwningContext(drops.clone()));
    let outer: &(dyn std::error::Error + Send + Sync + 'static) = original.as_ref();
    let outer_address = std::ptr::from_ref(outer).cast::<()>();
    let context_address = std::ptr::from_ref(original.downcast_ref::<OwningContext>().unwrap());
    let public = SnapshotFailure::from(ScratchOperationFailure::Operation(original));
    assert!(public.operation_error().is_none());
    assert!(public.creation().is_none());
    let preserved = public.source_error().unwrap();
    let outer: &(dyn std::error::Error + Send + Sync + 'static) = preserved.as_ref();
    assert_eq!(std::ptr::from_ref(outer).cast::<()>(), outer_address);
    assert_eq!(
        std::ptr::from_ref(preserved.downcast_ref::<OwningContext>().unwrap()),
        context_address
    );
    assert_eq!(
        preserved.downcast_ref::<Error>().unwrap().code,
        ErrorCode::Sealed
    );
    assert_eq!(drops.load(std::sync::atomic::Ordering::Acquire), 0);
    let returned = public.into_scratch_failure();
    let preserved = returned.operation_error().unwrap();
    let outer: &(dyn std::error::Error + Send + Sync + 'static) = preserved.as_ref();
    assert_eq!(std::ptr::from_ref(outer).cast::<()>(), outer_address);
    assert_eq!(
        std::ptr::from_ref(preserved.downcast_ref::<OwningContext>().unwrap()),
        context_address
    );
    assert_eq!(drops.load(std::sync::atomic::Ordering::Acquire), 0);
    drop(returned);
    assert_eq!(drops.load(std::sync::atomic::Ordering::Acquire), 1);
}
