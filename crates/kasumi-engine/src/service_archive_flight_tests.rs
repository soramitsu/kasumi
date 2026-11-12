// Archive requests that reuse the identity of an archive still in flight on
// this node: its export is running or its publication proposal is admitted.

/// Fixture bound for a retry waiting on a held original. The production bound
/// is the write deadline; this only limits how long a broken fixture waits.
const ARCHIVE_FLIGHT_FIXTURE_WAIT: Duration = Duration::from_secs(600);

/// A filesystem destination that records every upload attempt. It holds the
/// first upload until released, then writes it or fails it without writing.
struct ArchiveFlightDestination {
    inner: Arc<kasumi_store::FilesystemBackupDestination>,
    root: std::path::PathBuf,
    puts: Mutex<Vec<uuid::Uuid>>,
    hold_first: AtomicBool,
    fail_held: AtomicBool,
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}
impl ArchiveFlightDestination {
    fn puts(&self) -> Vec<uuid::Uuid> {
        self.puts.lock().unwrap().clone()
    }

    /// The published objects actually present in the destination.
    fn objects(&self) -> BTreeSet<uuid::Uuid> {
        std::fs::read_dir(&self.root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter_map(|name| {
                name.strip_suffix(".kasumi")
                    .map(|id| uuid::Uuid::parse_str(id).unwrap())
            })
            .collect()
    }
}
#[async_trait::async_trait]
impl BackupDestination for ArchiveFlightDestination {
    fn namespace_binding(&self) -> anyhow::Result<kasumi_types::BackupNamespaceBinding> {
        kasumi_store::BackupDestination::namespace_binding(self.inner.as_ref())
    }
    async fn put(&self, id: uuid::Uuid, bytes: kasumi_store::BackupUpload) -> anyhow::Result<()> {
        self.puts.lock().unwrap().push(id);
        if self.hold_first.swap(false, Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
            if self.fail_held.load(Ordering::SeqCst) {
                anyhow::bail!("fixture upload failed before writing");
            }
        }
        self.inner.put(id, bytes).await
    }
    async fn get(&self, id: uuid::Uuid, max_bytes: usize) -> anyhow::Result<Vec<u8>> {
        self.inner.get(id, max_bytes).await
    }
}

/// An archivable collection with three revisions of history, and an archive
/// request for all of it through a held `ArchiveFlightDestination`.
async fn archive_flight_fixture(
    fixture: &CredentialFixture,
) -> (Arc<ArchiveFlightDestination>, ArchiveHistory) {
    fixture
        .db
        .administer(
            fixture.context.clone(),
            Operation::CreateCollection(CollectionDefinition {
                name: "history".into(),
                write_mode: CollectionWriteMode::AppendOnly,
                retention_class: CollectionRetentionClass::ArchivableHistory,
                schema: json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            }),
        )
        .await
        .unwrap();
    let mut cutoff = 0;
    for n in 0..3 {
        cutoff = fixture
            .db
            .mutate(
                fixture.context.clone(),
                MutationBatch {
                    idempotency_key: format!("history-{n}"),
                    read_set: vec![],
                    operations: vec![Mutation::Put {
                        collection: "history".into(),
                        id: format!("h{n}"),
                        body: json!({"n": n}),
                        expected: Precondition::Absent,
                    }],
                },
            )
            .await
            .unwrap()
            .revision;
    }
    let root = fixture._directory.path().join("persistent/archive-flight");
    let destination = Arc::new(ArchiveFlightDestination {
        inner: Arc::new(
            kasumi_store::FilesystemBackupDestination::new(
                &root,
                16 << 20,
                fixture.storage.persistent.clone(),
            )
            .unwrap(),
        ),
        root,
        puts: Mutex::new(vec![]),
        hold_first: AtomicBool::new(true),
        fail_held: AtomicBool::new(false),
        entered: tokio::sync::Notify::new(),
        release: tokio::sync::Notify::new(),
    });
    fixture
        .db
        .install_archive_destination("cold".into(), destination.clone())
        .unwrap();
    let request = ArchiveHistory {
        archive_id: "period".into(),
        collection: "history".into(),
        cutoff_revision: cutoff,
        destination: "cold".into(),
    };
    (destination, request)
}

/// The committed archive's manifest and chunk objects.
fn archive_flight_referenced(archive: &RetainedHistoryArchive) -> BTreeSet<uuid::Uuid> {
    archive
        .manifest
        .chunks
        .iter()
        .map(|chunk| chunk.object_id.as_str())
        .chain([archive.manifest_object_id.as_str()])
        .map(|id| uuid::Uuid::parse_str(id).unwrap())
        .collect()
}

fn assert_write_deadline(error: Error) {
    assert_eq!(
        (error.code, error.message.as_str()),
        (
            ErrorCode::UnknownOutcome,
            "write deadline exceeded; resolve or retry with the same idempotency key"
        )
    );
}

#[tokio::test]
async fn archive_retry_waits_for_in_flight_publication_and_never_uploads_again() {
    let fixture = CredentialFixture::new().await;
    archive_retry_waits_for_in_flight_publication(&fixture).await;
    fixture.close().await;
}

// The pinned requests borrow the fixture's database until this returns.
async fn archive_retry_waits_for_in_flight_publication(fixture: &CredentialFixture) {
    let (destination, request) = archive_flight_fixture(fixture).await;
    let db = &fixture.db;
    let context = fixture.context.clone();
    let mut different = request.clone();
    different.cutoff_revision -= 1;
    // The original's start audit has committed and it holds the identity.
    let mut original = std::pin::pin!(db.archive_history(context.clone(), request.clone()));
    tokio::select! {
        biased;
        result = &mut original => panic!("archive finished before its first upload: {result:?}"),
        reached = tokio::time::timeout(Duration::from_secs(300), destination.entered.notified()) => {
            reached.expect("archive did not reach its first upload within 300 seconds");
        }
    }
    let error = db
        .archive_history(context.clone(), different.clone())
        .await
        .unwrap_err();
    assert_eq!(
        (error.code, error.message.as_str()),
        (
            ErrorCode::Conflict,
            "archive identity reused for different request"
        )
    );
    // An identical request whose own write deadline passes first reports the
    // same uncertain outcome a missed publication deadline does.
    db.archive_flights.set_wait_budget_for_test(Duration::ZERO);
    assert_write_deadline(
        db.archive_history(context.clone(), request.clone())
            .await
            .unwrap_err(),
    );
    assert_eq!(destination.puts().len(), 1, "only the original uploads");

    // Hold the publication in the ordered proposal queue, between upload and
    // publication. The original misses its production write deadline, as on
    // a loaded host, and the admitted publication outlives that caller.
    let gate = db.proposal_gate.lock().await;
    destination.release.notify_one();
    assert_write_deadline(original.await.unwrap_err());
    assert!(db.archive_flights.publishing_for_test(&request.archive_id));
    let uploaded = destination.objects();
    assert_eq!(uploaded.len(), 2, "one chunk and its manifest");
    assert_eq!(
        destination.puts().into_iter().collect::<BTreeSet<_>>(),
        uploaded
    );

    // The client retries at once with the same archive identity, as the
    // uncertain outcome invites. It waits rather than exporting again.
    db.archive_flights
        .set_wait_budget_for_test(ARCHIVE_FLIGHT_FIXTURE_WAIT);
    let mut retry = std::pin::pin!(db.archive_history(context.clone(), request.clone()));
    db.archive_flights
        .wait_for_waiter_for_test(retry.as_mut())
        .await;
    assert_eq!(destination.puts().len(), 2);
    drop(gate);
    let receipt = retry.await.unwrap();
    let generation = db.engine().generation().unwrap();
    let archive = generation.state.history_archives[&request.archive_id].clone();
    assert!(generation.state.collections["history"].documents.is_empty());
    drop(generation);
    assert_eq!(
        receipt,
        WriteReceipt {
            revision: archive.published_revision,
            versions: BTreeMap::new(),
        }
    );
    // The destination holds exactly the original's objects, each uploaded
    // once and all referenced by the committed archive.
    assert_eq!(destination.objects(), uploaded);
    assert_eq!(archive_flight_referenced(&archive), uploaded);
    assert_eq!(destination.puts().len(), uploaded.len());

    // Once applied, the identity replays its receipt and rejects a different
    // request as before.
    assert_eq!(
        db.archive_history(context.clone(), request.clone())
            .await
            .unwrap(),
        receipt
    );
    let error = db
        .archive_history(context.clone(), different)
        .await
        .unwrap_err();
    assert_eq!(
        (error.code, error.message.as_str()),
        (
            ErrorCode::Conflict,
            "archive identity reused for different request"
        )
    );
    assert_eq!(destination.objects(), uploaded);
    assert_eq!(destination.puts().len(), uploaded.len());
}

#[tokio::test]
async fn archive_retries_waiting_for_a_failed_original_export_exactly_once() {
    let fixture = CredentialFixture::new().await;
    archive_retry_takes_over_failed_original(&fixture).await;
    fixture.close().await;
}

async fn archive_retry_takes_over_failed_original(fixture: &CredentialFixture) {
    let (destination, request) = archive_flight_fixture(fixture).await;
    destination.fail_held.store(true, Ordering::SeqCst);
    let db = &fixture.db;
    let context = fixture.context.clone();
    let mut original = std::pin::pin!(db.archive_history(context.clone(), request.clone()));
    tokio::select! {
        biased;
        result = &mut original => panic!("archive finished before its first upload: {result:?}"),
        reached = tokio::time::timeout(Duration::from_secs(300), destination.entered.notified()) => {
            reached.expect("archive did not reach its first upload within 300 seconds");
        }
    }
    db.archive_flights
        .set_wait_budget_for_test(ARCHIVE_FLIGHT_FIXTURE_WAIT);
    let mut first = std::pin::pin!(db.archive_history(context.clone(), request.clone()));
    db.archive_flights
        .wait_for_waiter_for_test(first.as_mut())
        .await;
    let mut second = std::pin::pin!(db.archive_history(context.clone(), request.clone()));
    db.archive_flights
        .wait_for_waiter_for_test(second.as_mut())
        .await;
    // The original's upload fails before writing, so its verification finds
    // no object and it fails before publication.
    destination.release.notify_one();
    let error = original.await.unwrap_err();
    assert_eq!(
        (error.code, error.message.as_str()),
        (
            ErrorCode::Unavailable,
            "required history object is missing or unavailable"
        )
    );
    assert_eq!(destination.puts().len(), 1);
    assert!(destination.objects().is_empty());
    // The waiting retries resume together. One claims the identity and exports
    // exactly once; the other waits for it and replays its receipt.
    let (first, second) = tokio::join!(first, second);
    let receipt = first.unwrap();
    assert_eq!(second.unwrap(), receipt);
    let archive =
        db.engine().generation().unwrap().state.history_archives[&request.archive_id].clone();
    assert_eq!(receipt.revision, archive.published_revision);
    let referenced = archive_flight_referenced(&archive);
    assert_eq!(destination.objects(), referenced);
    assert_eq!(destination.puts().len(), 1 + referenced.len());
}
