//! Foreign statuses borrow diagnosis only after the actual paid slot capture.
use super::*;
use crate::administration::OriginalRecoveries;
use kasumi_engine::{SnapshotFailure, admission::NodeAdmission};
use kasumi_types::{Action, Error, ErrorCode, RequestAuthorization};
use std::{
    collections::BTreeSet,
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicUsize, Ordering},
    task::{Context, Poll},
};

async fn auth() -> Arc<Authenticator> {
    Authenticator::with_test_keys(
        crate::auth::AuthConfig {
            issuer: "https://issuer.example".into(),
            audience: "https://kasumi.example/mcp".into(),
            source: crate::auth::AuthKeySource::ExternalOAuth {
                jwks_uri: "https://issuer.example/keys".into(),
                trusted_ca_pem: None,
            },
            algorithms: vec![jsonwebtoken::Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
        },
        serde_json::from_value(serde_json::json!({"keys":[]})).unwrap(),
    )
    .await
}
fn context() -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "actual-custody-test".into(),
        tenant: "tenant-a".into(),
        scopes: BTreeSet::from([Action::Admin]),
        request_id: "actual-rpc-custody".into(),
    }
}
fn code(status: &Status) -> ErrorCode {
    serde_json::from_slice::<Error>(status.details())
        .unwrap()
        .code
}

#[tokio::test]
async fn real_initial_quote_error_remains_owned_after_foreign_status_and_alias_drop() {
    use kasumi_store::{
        EncryptedTable, NodeDiskMemoryAdmission, ScratchDisk, test_utils::TestDiskMemory,
    };
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let baseline = admission.snapshot().reserved_bytes;
    let inventory = OriginalRecoveries::new(
        &admission,
        crate::administration::OriginalRecoveryParticipants::one("tenant-a"),
    )
    .unwrap();
    let charged = admission.snapshot().reserved_bytes;
    assert_eq!(
        charged,
        baseline
            + OriginalRecoveries::required_bytes(
                admission.policy(),
                crate::administration::OriginalRecoveryParticipants::one("tenant-a")
            )
            .unwrap()
    );
    let admin = NativeAdmin::new(DatabaseRegistry::default(), auth().await, inventory.clone());
    let memory = TestDiskMemory::new(64 << 20, 32);
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::isolated_fixture(directory.path(), 16 << 20, memory.clone());
    let mut fillers = Vec::new();
    for _ in memory.snapshot().live_reservations..32 {
        fillers.push(memory.clone().reserve_installed(0).unwrap());
    }
    let before = memory.snapshot();
    let native_before = disk.snapshot();
    let status = admin
        .snapshot_call(&context(), false, async {
            let original = EncryptedTable::new(&disk, 8 << 20, disk.native_cache_config())
                .err()
                .unwrap();
            assert!(original.owner_id().is_none());
            Err::<(), _>(SnapshotFailure::Creation(original))
        })
        .await
        .unwrap_err();
    assert_eq!(code(&status), ErrorCode::Unavailable);
    assert_eq!(memory.snapshot().attempts, before.attempts + 1);
    assert_eq!(memory.snapshot().live_reservations, 32);
    assert_eq!(memory.snapshot().used_bytes, before.used_bytes);
    assert_eq!(disk.snapshot().live_files, native_before.live_files);
    let identity = |original: &SnapshotFailure| {
        original.creation().unwrap().with_diagnostic(|report| {
            let report = report.unwrap();
            assert!(report.opening_error().is_none());
            let original = report.admission_error().unwrap();
            assert_eq!(original.kind(), std::io::ErrorKind::OutOfMemory);
            original as *const std::io::Error as usize
        })
    };
    let address = inventory.with_rpc_original(0, identity).unwrap();
    drop(status);
    drop(admin);
    for _ in 0..3 {
        assert_eq!(inventory.with_rpc_original(0, identity), Some(address));
    }
    drop(inventory);
    // No opaque IO destruction or native disposal witness was minted by the
    // foreign marker or final alias Drop. The same original grant stays held.
    assert_eq!(admission.snapshot().reserved_bytes, charged);
    drop(fillers);
}

#[tokio::test]
async fn owning_context_is_not_unwrapped_into_a_scope_code_at_the_status_boundary() {
    #[derive(Debug)]
    struct ContextOwner(Arc<AtomicUsize>);
    impl std::fmt::Display for ContextOwner {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("actual scope context")
        }
    }
    impl Drop for ContextOwner {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::AcqRel);
        }
    }
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let inventory = OriginalRecoveries::new(
        &admission,
        crate::administration::OriginalRecoveryParticipants::one("tenant-a"),
    )
    .unwrap();
    let registry = DatabaseRegistry::default();
    let original = registry.database(&context()).err().unwrap();
    assert_eq!(original.code, ErrorCode::Forbidden);
    let drops = Arc::new(AtomicUsize::new(0));
    let original = anyhow::Error::new(original).context(ContextOwner(drops.clone()));
    let outer: &(dyn std::error::Error + Send + Sync + 'static) = original.as_ref();
    let address = outer as *const _ as *const () as usize;
    let admin = NativeAdmin::new(registry, auth().await, inventory.clone());
    let status = admin
        .snapshot_call(&context(), true, async {
            Err::<(), _>(SnapshotFailure::Source(original))
        })
        .await
        .unwrap_err();
    assert_eq!(code(&status), ErrorCode::UnknownOutcome);
    assert_eq!(drops.load(Ordering::Acquire), 0);
    inventory
        .with_rpc_original(0, |original| {
            let outer: &(dyn std::error::Error + Send + Sync + 'static) =
                original.source_error().unwrap().as_ref();
            assert_eq!(outer as *const _ as *const () as usize, address);
        })
        .unwrap();
    drop(status);
    drop(admin);
    drop(inventory);
    assert_eq!(drops.load(Ordering::Acquire), 0);
}

#[tokio::test]
async fn original_scope_code_and_mutation_release_remain_exact() {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let inventory = OriginalRecoveries::new(
        &admission,
        crate::administration::OriginalRecoveryParticipants::one("tenant-a"),
    )
    .unwrap();
    let registry = DatabaseRegistry::default();
    let original = registry.database(&context()).err().unwrap();
    let message = original.message.clone();
    let admin = NativeAdmin::new(registry, auth().await, inventory.clone());
    let status = admin
        .snapshot_call(&context(), true, async {
            Err::<(), _>(SnapshotFailure::Operation(original))
        })
        .await
        .unwrap_err();
    assert_eq!(code(&status), ErrorCode::Forbidden);
    assert_eq!(status.message(), message);
    assert!(inventory.with_rpc_original(0, |_| ()).is_none());
    let status = admin
        .snapshot_call(&context(), true, async {
            Err::<(), _>(SnapshotFailure::Operation(Error::new(
                ErrorCode::Conflict,
                "original final fence changed",
            )))
        })
        .await
        .unwrap_err();
    assert_eq!(code(&status), ErrorCode::UnknownOutcome);
    assert!(inventory.with_rpc_original(0, |_| ()).is_none());
}

struct RpcPanicOriginal {
    _charge: kasumi_engine::admission::Reservation,
    stage: &'static str,
    drops: Arc<AtomicUsize>,
}
impl Drop for RpcPanicOriginal {
    fn drop(&mut self) {
        self.drops.fetch_add(1, Ordering::SeqCst);
    }
}
struct RpcOriginalFuture {
    returned: Option<SnapshotFailure>,
    poll_panic: Option<RpcPanicOriginal>,
    disposal_panic: Option<RpcPanicOriginal>,
}
impl Future for RpcOriginalFuture {
    type Output = std::result::Result<(), SnapshotFailure>;
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        match self.returned.take() {
            Some(original) => Poll::Ready(Err(original)),
            None => std::panic::panic_any(self.poll_panic.take().unwrap()),
        }
    }
}
impl Drop for RpcOriginalFuture {
    fn drop(&mut self) {
        std::panic::panic_any(self.disposal_panic.take().unwrap());
    }
}
fn original_panic(
    admission: &Arc<NodeAdmission>,
    stage: &'static str,
    drops: &Arc<AtomicUsize>,
) -> RpcPanicOriginal {
    RpcPanicOriginal {
        _charge: admission
            .memory()
            .reserve_resident(std::mem::size_of::<RpcPanicOriginal>() as u64)
            .unwrap(),
        stage,
        drops: drops.clone(),
    }
}

#[tokio::test]
async fn returned_scope_error_and_original_disposal_panic_stay_independent_before_status() {
    use crate::administration::original_serving_runtime::CleanupEntry;
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let inventory = OriginalRecoveries::new(
        &admission,
        crate::administration::OriginalRecoveryParticipants::one("tenant-a"),
    )
    .unwrap();
    let registry = DatabaseRegistry::default();
    let original = registry.database(&context()).err().unwrap();
    assert_eq!(original.code, ErrorCode::Forbidden);
    let error_message_address = original.message.as_ptr() as usize;
    let drops = Arc::new(AtomicUsize::new(0));
    let body = RpcOriginalFuture {
        returned: Some(SnapshotFailure::Operation(original)),
        poll_panic: None,
        disposal_panic: Some(original_panic(&admission, "disposal", &drops)),
    };
    let charged = admission.snapshot().reserved_bytes;
    let admin = NativeAdmin::new(registry, auth().await, inventory.clone());
    let status = admin
        .snapshot_call(&context(), true, body)
        .await
        .unwrap_err();
    assert_eq!(code(&status), ErrorCode::UnknownOutcome);
    let identity =
        |report: crate::administration::original_serving_runtime::RpcConstructorReport<'_>| {
            let original = match report.original().unwrap() {
                SnapshotFailure::Operation(original) => original,
                _ => panic!("same original scope error"),
            };
            assert_eq!(original.code, ErrorCode::Forbidden);
            assert_eq!(original.message.as_ptr() as usize, error_message_address);
            assert!(report.output().is_none());
            assert_eq!(report.observation().entry(), CleanupEntry::Returned);
            assert_eq!(
                report.observation().future_disposal(),
                CleanupEntry::Panicked
            );
            assert!(report.observation().with_panic(|_| ()).is_none());
            report
                .observation()
                .with_disposal_panic(|payload| {
                    let original = payload.downcast_ref::<RpcPanicOriginal>().unwrap();
                    assert_eq!(original.stage, "disposal");
                    original as *const RpcPanicOriginal as usize
                })
                .unwrap()
        };
    let address = inventory.with_rpc_report(0, identity).unwrap();
    assert!(inventory.retained().await);
    drop(status);
    drop(admin);
    for _ in 0..3 {
        assert_eq!(inventory.with_rpc_report(0, identity), Some(address));
    }
    drop(inventory);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(admission.snapshot().reserved_bytes, charged);
}

#[tokio::test]
async fn original_poll_and_disposal_panics_without_returned_error_use_retained_status() {
    use crate::administration::original_serving_runtime::CleanupEntry;
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let inventory = OriginalRecoveries::new(
        &admission,
        crate::administration::OriginalRecoveryParticipants::one("tenant-a"),
    )
    .unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let body = RpcOriginalFuture {
        returned: None,
        poll_panic: Some(original_panic(&admission, "poll", &drops)),
        disposal_panic: Some(original_panic(&admission, "disposal", &drops)),
    };
    let charged = admission.snapshot().reserved_bytes;
    let admin = NativeAdmin::new(DatabaseRegistry::default(), auth().await, inventory.clone());
    let status = admin
        .snapshot_call(&context(), false, body)
        .await
        .unwrap_err();
    assert_eq!(code(&status), ErrorCode::Unavailable);
    let identity =
        |report: crate::administration::original_serving_runtime::RpcConstructorReport<'_>| {
            assert!(report.original().is_none(), "poll panic returned no error");
            assert!(report.output().is_none());
            assert_eq!(report.observation().entry(), CleanupEntry::Panicked);
            assert_eq!(
                report.observation().future_disposal(),
                CleanupEntry::Panicked
            );
            let poll = report
                .observation()
                .with_panic(|payload| {
                    let original = payload.downcast_ref::<RpcPanicOriginal>().unwrap();
                    assert_eq!(original.stage, "poll");
                    original as *const RpcPanicOriginal as usize
                })
                .unwrap();
            let disposal = report
                .observation()
                .with_disposal_panic(|payload| {
                    let original = payload.downcast_ref::<RpcPanicOriginal>().unwrap();
                    assert_eq!(original.stage, "disposal");
                    original as *const RpcPanicOriginal as usize
                })
                .unwrap();
            assert_ne!(poll, disposal);
            (poll, disposal)
        };
    let addresses = inventory.with_rpc_report(0, identity).unwrap();
    assert!(inventory.retained().await);
    drop(status);
    drop(admin);
    for _ in 0..3 {
        assert_eq!(inventory.with_rpc_report(0, identity), Some(addresses));
    }
    drop(inventory);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    assert_eq!(admission.snapshot().reserved_bytes, charged);
}
