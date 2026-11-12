//! Each case runs the real encoder over a generation whose one document is
//! stored, so encoding must read that body through an injected resolver, or
//! write into a failing scratch stream. A body read, scratch or key-access
//! failure keeps its cause; only integrity failures stay `Corruption`.
use crate::document_store::GenerationDocuments;
use crate::test_utils::SnapshotFixture as _;
use crate::{Generation, TenantEngine};
use kasumi_store::{
    NodeStore, ScratchDisk, TenantStore,
    test_utils::{LocalKeyProvider, TestDiskMemory},
};
use kasumi_types::{
    Action, AdmittedDocumentOwner, CollectionDefinition, CollectionRetentionClass,
    CollectionWriteMode, Command, Document, DocumentResolver, DocumentSlot, Error, ErrorCode,
    Grant, Limits, MutationBatch, Operation, Policy, RequestAuthorization, RequestContext,
    SharedDocument, StoredDocument,
};
use sha2::{Digest, Sha256};
use std::{
    io,
    sync::{Arc, OnceLock},
};

const TENANT: &str = "snapshot-encoding";

type Outcome = (ErrorCode, String);
type BodyRead = fn() -> anyhow::Result<()>;
type WriteFailure = fn() -> io::Error;

struct Fixture {
    disk: Arc<ScratchDisk>,
    engine: TenantEngine,
    /// The engine's own generation; its one document is still pending.
    base: Arc<Generation>,
    document: Document,
    _directory: tempfile::TempDir,
}

fn fixture() -> Fixture {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let disk = ScratchDisk::fixture(
        directory.path().join("scratch"),
        TestDiskMemory::new(64 << 20, 64),
    );
    let actions = [Action::Write, Action::Admin];
    let engine = TenantEngine::new(
        TENANT.into(),
        "generation".into(),
        Policy {
            grants: vec![Grant {
                principal: "owner".into(),
                collection: None,
                actions: actions.into_iter().collect(),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap();
    let context = RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "owner".into(),
        tenant: TENANT.into(),
        scopes: actions.into_iter().collect(),
        request_id: "snapshot-encoding-fixture".into(),
    };
    let collection = Operation::CreateCollection(CollectionDefinition {
        name: "docs".into(),
        schema: serde_json::json!({"type": "object"}),
        indexes: vec![],
        strict_read_audit: false,
        retention_class: CollectionRetentionClass::Operational,
        write_mode: CollectionWriteMode::Mutable,
    });
    let insert = Operation::Mutate(MutationBatch::with_key("snapshot-encoding-row").insert(
        "docs",
        "one",
        serde_json::json!({"value": 1}),
    ));
    for (revision, operation) in [(1, collection), (2, insert)] {
        let command = Command {
            context: context.clone(),
            timestamp_ms: revision,
            operation,
        };
        engine
            .apply_command(&disk, revision, command)
            .unwrap()
            .unwrap();
    }
    let base = engine.generation().unwrap();
    let DocumentSlot::Pending(document) = &*base.state.collections["docs"].documents["one"] else {
        panic!("an engine without native storage keeps its document pending");
    };
    let document = Document::clone(document);
    Fixture {
        disk,
        engine,
        base,
        document,
        _directory: directory,
    }
}

/// `base` with its one document stored: encoding must load the body through
/// `resolver`, as it does from native storage or a cold archive.
fn stored(base: &Generation, resolver: Arc<dyn GenerationDocuments>) -> Generation {
    let mut state = base.state.clone();
    let documents = &mut state.collections.get_mut("docs").unwrap().documents;
    let DocumentSlot::Pending(document) = &*documents["one"] else {
        panic!("fixture document is already stored");
    };
    let descriptor = StoredDocument::from_document(document, [42; 32], 100, 1 << 20, 4096).unwrap();
    documents.insert("one".into(), Arc::new(DocumentSlot::Stored(descriptor)));
    let document_sources = OnceLock::new();
    assert!(document_sources.set(resolver).is_ok());
    Generation {
        state,
        receipts: base.receipts.clone(),
        backup_bindings: base.backup_bindings.clone(),
        terminals: base.terminals.clone(),
        target_resolutions: base.target_resolutions.clone(),
        indexes: base.indexes.clone(),
        snapshot_accounting: base.snapshot_accounting.clone(),
        application_selection: OnceLock::new(),
        staged_documents: None,
        document_sources,
        _read_reservations: vec![],
    }
}

struct Owner(Document);
impl AdmittedDocumentOwner for Owner {
    fn document(&self) -> &Document {
        &self.0
    }
}

/// Lends `document` once `check` passes, like a body read whose storage, key
/// access and admission checks run before it lends anything.
struct Resolver<F> {
    document: Document,
    check: F,
}
impl<F: Fn() -> anyhow::Result<()> + Send + Sync> DocumentResolver for Resolver<F> {
    fn load(&self, _: &StoredDocument) -> anyhow::Result<SharedDocument> {
        (self.check)()?;
        Ok(SharedDocument::from_admitted_owner(Arc::new(Owner(
            self.document.clone(),
        ))))
    }
}
impl<F: Fn() -> anyhow::Result<()> + Send + Sync> GenerationDocuments for Resolver<F> {}

fn resolver(
    document: Document,
    check: impl Fn() -> anyhow::Result<()> + Send + Sync + 'static,
) -> Arc<dyn GenerationDocuments> {
    Arc::new(Resolver { document, check })
}

fn encode(generation: &Generation) -> std::result::Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    TenantEngine::write_generation(generation, &mut bytes)?;
    Ok(bytes)
}

fn outcome(error: Error) -> Outcome {
    (error.code, error.message)
}

fn corruption() -> Outcome {
    (ErrorCode::Corruption, "snapshot encoding failed".into())
}

fn io_failed(kind: io::ErrorKind) -> Outcome {
    (
        ErrorCode::Unavailable,
        format!("snapshot encoding I/O failed: {kind}"),
    )
}

#[test]
fn body_read_failures_keep_their_cause_and_integrity_failures_stay_corruption() {
    let fixture = fixture();
    // The stored form encodes exactly the pending original, so each failure
    // below comes from its body read alone.
    let lent = stored(&fixture.base, resolver(fixture.document.clone(), || Ok(())));
    assert_eq!(encode(&lent).unwrap(), encode(&fixture.base).unwrap());

    let cases: [(BodyRead, Outcome); 7] = [
        // A cold archive read reports its own engine error through context.
        (
            || {
                Err(anyhow::Error::new(Error::new(
                    ErrorCode::Unavailable,
                    "cold archive segment unavailable",
                ))
                .context("cold body read"))
            },
            (
                ErrorCode::Unavailable,
                "cold archive segment unavailable".into(),
            ),
        ),
        (
            || {
                Err(Error::new(
                    ErrorCode::ResourceExhausted,
                    "document read workspace is exhausted",
                )
                .into())
            },
            (
                ErrorCode::ResourceExhausted,
                "document read workspace is exhausted".into(),
            ),
        ),
        (
            || {
                Err(anyhow::Error::new(io::Error::from(io::ErrorKind::TimedOut))
                    .context("cold archive segment read"))
            },
            io_failed(io::ErrorKind::TimedOut),
        ),
        // A generic kind proves no capacity refusal, even a full volume.
        (
            || Err(io::Error::from(io::ErrorKind::StorageFull).into()),
            io_failed(io::ErrorKind::StorageFull),
        ),
        // A carried engine error is the original, whatever its wrapper says.
        (
            || {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    Error::new(ErrorCode::Unavailable, "document source retired"),
                )
                .into())
            },
            (ErrorCode::Unavailable, "document source retired".into()),
        ),
        // Stored bytes that fail authentication, or an unrecognized cause.
        (
            || Err(io::Error::from(io::ErrorKind::InvalidData).into()),
            corruption(),
        ),
        (
            || anyhow::bail!("selected document manifest identity differs"),
            corruption(),
        ),
    ];
    for (check, expected) in cases {
        let generation = stored(&fixture.base, resolver(fixture.document.clone(), check));
        assert_eq!(outcome(encode(&generation).unwrap_err()), expected);
    }

    // A lent body that differs from its descriptor's digest is corrupt state.
    let mut altered = fixture.document.clone();
    altered.body = serde_json::json!({"value": 2});
    let generation = stored(&fixture.base, resolver(altered, || Ok(())));
    assert_eq!(outcome(encode(&generation).unwrap_err()), corruption());
    // The byte accounting check before encoding stays corruption as well.
    let mut generation = stored(&fixture.base, resolver(fixture.document.clone(), || Ok(())));
    generation.state.limits.max_snapshot_bytes = 1;
    assert_eq!(
        outcome(encode(&generation).unwrap_err()),
        (
            ErrorCode::Corruption,
            "snapshot byte accounting mismatch".into()
        )
    );
}

/// A scratch spool or checked stream that refuses its first write.
struct FailingWriter(fn() -> io::Error);
impl io::Write for FailingWriter {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        Err((self.0)())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn scratch_and_stream_failures_keep_their_cause() {
    let fixture = fixture();
    let cases: [(WriteFailure, Outcome); 4] = [
        // The spool's byte budget or its volume is full.
        (
            || io::ErrorKind::StorageFull.into(),
            io_failed(io::ErrorKind::StorageFull),
        ),
        (
            || io::ErrorKind::BrokenPipe.into(),
            io_failed(io::ErrorKind::BrokenPipe),
        ),
        // A checked stream carries its cancellation as the engine's own error.
        (
            || io::Error::other(Error::new(ErrorCode::Unavailable, "query cancelled")),
            (ErrorCode::Unavailable, "query cancelled".into()),
        ),
        // Its deadline is a plain message: still not corruption.
        (
            || io::Error::other(anyhow::anyhow!("backup verification deadline expired")),
            io_failed(io::ErrorKind::Other),
        ),
    ];
    for (failure, expected) in cases {
        let error =
            TenantEngine::write_generation(&fixture.base, &mut FailingWriter(failure)).unwrap_err();
        assert_eq!(outcome(error), expected);
    }
}

#[test]
fn logical_snapshots_return_the_cause_instead_of_rewrapping_it_as_corruption() {
    let fixture = fixture();
    let unavailable = stored(
        &fixture.base,
        resolver(fixture.document.clone(), || {
            Err(anyhow::Error::new(Error::new(
                ErrorCode::Unavailable,
                "cold archive segment unavailable",
            ))
            .context("cold body read"))
        }),
    );
    fixture
        .engine
        .publish_generation(Some(Arc::new(unavailable)));
    let expected: Outcome = (
        ErrorCode::Unavailable,
        "cold archive segment unavailable".into(),
    );
    assert_eq!(
        outcome(fixture.engine.logical_snapshot(&fixture.disk).unwrap_err()),
        expected
    );
    // History and backup fixtures capture through the same path.
    let failure = fixture.engine.fixture_snapshot(&fixture.disk).unwrap_err();
    assert_eq!(
        failure.operation_error().cloned().map(outcome),
        Some(expected)
    );

    let mut altered = fixture.document.clone();
    altered.body = serde_json::json!({"value": 2});
    let corrupt = stored(&fixture.base, resolver(altered, || Ok(())));
    fixture.engine.publish_generation(Some(Arc::new(corrupt)));
    assert_eq!(
        outcome(fixture.engine.logical_snapshot(&fixture.disk).unwrap_err()),
        corruption()
    );

    // The original generation still captures exactly its direct encoding.
    fixture
        .engine
        .publish_generation(Some(fixture.base.clone()));
    let image = fixture.engine.logical_snapshot(&fixture.disk).unwrap();
    assert_eq!(
        image.sha256(),
        hex::encode(Sha256::digest(encode(&fixture.base).unwrap()))
    );
}

#[tokio::test]
async fn a_store_sealed_during_encoding_reports_sealed_not_corruption() {
    let fixture = fixture();
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let memory = TestDiskMemory::new(64 << 20, 64);
    kasumi_store::private_files::create_directory(&directory.path().join("persistent")).unwrap();
    let node = NodeStore::create_new_fixture(
        directory.path().join("persistent/node.kv"),
        kasumi_store::test_utils::NODE_STORE_ID,
        memory.clone(),
        ScratchDisk::fixture(directory.path().join("scratch"), memory),
    )
    .unwrap();
    let store = TenantStore::initialize_catalog_fixture(
        node.clone(),
        TENANT.into(),
        Arc::new(LocalKeyProvider::new([61; 32])),
    )
    .await
    .unwrap();
    store.check_access().unwrap();
    // The key lease lapses while the body is read, after the generation was
    // admitted: the reader's own access check finds the store sealed.
    let sealing = store.clone();
    let generation = stored(
        &fixture.base,
        resolver(fixture.document.clone(), move || {
            sealing.seal();
            sealing.check_access()
        }),
    );
    let sealed: Outcome = (
        ErrorCode::Sealed,
        "tenant key authorization expired; recovery required".into(),
    );
    assert_eq!(outcome(encode(&generation).unwrap_err()), sealed);
    fixture
        .engine
        .publish_generation(Some(Arc::new(generation)));
    assert_eq!(
        outcome(fixture.engine.logical_snapshot(&fixture.disk).unwrap_err()),
        sealed
    );
    assert!(
        store
            .check_access()
            .unwrap_err()
            .is::<kasumi_store::KeyAccessDenied>()
    );
    // The engine's generation holds the resolver's store handle.
    drop(fixture);
    store.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

#[test]
fn engine_errors_pass_through_unchanged() {
    let original = Error::new(ErrorCode::QuotaExceeded, "original snapshot quota");
    let address = original.message.as_ptr();
    let returned = super::encoding_error(original.into());
    assert_eq!(returned.code, ErrorCode::QuotaExceeded);
    // Moved, not rebuilt from its text.
    assert_eq!(returned.message.as_ptr(), address);
}

#[test]
fn retirement_failure_takes_precedence_over_its_original_capacity_error() {
    for wrapped in [false, true] {
        let capacity = Error::new(
            ErrorCode::ResourceExhausted,
            "original read capacity refusal",
        );
        let retirement = kasumi_store::PointRetirementFailure::new(capacity.into(), Box::new(()));
        let error = if wrapped {
            anyhow::Error::new(io::Error::other(retirement))
        } else {
            anyhow::Error::new(retirement)
        };
        let classified = super::encoding_error(error.context("snapshot document read"));
        assert_eq!(classified.code, ErrorCode::Unavailable);
        assert_eq!(
            classified.message,
            "selected document storage is unavailable"
        );
    }
}
