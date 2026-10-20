//! Records that queue behind a commit share the next store batch. Sequences,
//! hot accounting, refusals and fencing match one-at-a-time recording.
use super::*;
use kasumi_store::{
    NodeStore,
    test_utils::{FaultBackend, LocalKeyProvider, ManualClock},
};
use kasumi_types::{
    SECURITY_AUDIT_RECORD_FORMAT, SecurityAuditStatus,
    drain::{DrainCompletion, DrainFailure, DrainIssueRef},
};
use std::{
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

fn event(request_id: &str) -> SecurityEvent {
    SecurityEvent {
        kind: SecurityEventKind::AccessDenied,
        principal: Some("principal".into()),
        tenant: Some("tenant".into()),
        request_id: request_id.into(),
        outcome: SecurityOutcome::Denied,
    }
}

/// The largest closed metadata: every name at its 256-byte limit.
fn large_event() -> SecurityEvent {
    SecurityEvent {
        principal: Some("p".repeat(256)),
        tenant: Some("t".repeat(256)),
        ..event(&"l".repeat(256))
    }
}

/// One byte of hot accounting per request ID byte.
fn filler(request_id_bytes: usize) -> SecurityEvent {
    SecurityEvent {
        principal: None,
        tenant: None,
        ..event(&"f".repeat(request_id_bytes))
    }
}

/// Hot bytes the writer charges for `event` at `sequence`, at a current
/// millisecond timestamp.
fn hot_bytes(sequence: u64, event: &SecurityEvent) -> u64 {
    let record = SecurityAuditRecord {
        format: SECURITY_AUDIT_RECORD_FORMAT,
        sequence,
        timestamp_ms: 1_000_000_000_000,
        event: event.clone(),
        transport: None,
    };
    serde_json::to_vec(&record).unwrap().len() as u64 + 8
}

fn commits(audit: &SecurityAudit) -> usize {
    audit.writer.record_commits.load(Ordering::SeqCst)
}

fn queued(audit: &SecurityAudit) -> usize {
    audit.writer.records.lock().unwrap().waiting.len()
}

/// The caller holds the sequence, so the first recorder leads but cannot take
/// its batch. Each recorder starts once the previous one has queued, which
/// fixes their arrival order.
fn queue_records(
    audit: &Arc<SecurityAudit>,
    events: Vec<SecurityEvent>,
) -> Vec<tokio::task::JoinHandle<Result<()>>> {
    let before = queued(audit);
    let mut recorders = Vec::new();
    for event in events {
        let recorder = audit.clone();
        recorders.push(tokio::task::spawn_blocking(move || {
            recorder.record_sync(event)
        }));
        let deadline = Instant::now() + Duration::from_secs(30);
        while queued(audit) < before + recorders.len() {
            assert!(Instant::now() < deadline, "record did not queue");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    recorders
}

async fn outcomes(recorders: Vec<tokio::task::JoinHandle<Result<()>>>) -> Vec<Result<()>> {
    let mut outcomes = Vec::new();
    for recorder in recorders {
        outcomes.push(recorder.await.unwrap());
    }
    outcomes
}

/// Strictly reread the committed head, then check every hot row against it:
/// keys and record sequences are contiguous from zero, the byte count and tail
/// digest match the writer. Returns the request IDs in sequence order.
fn hot_request_ids(audit: &SecurityAudit) -> (SecurityAuditStatus, Vec<String>) {
    let status = audit.status().unwrap();
    let head = retention::Head::open(
        audit.store(),
        &audit.writer.destination.identity(),
        &audit.writer.budget,
    )
    .unwrap();
    assert_eq!(head.position, status.position);
    let rows = audit.store().scan("security.audit").unwrap();
    let mut hot = 0;
    let mut tail = None;
    let mut ids = Vec::new();
    for (sequence, (key, bytes)) in (&rows).into_iter().enumerate() {
        let sequence = sequence as u64;
        assert_eq!(key, &sequence.to_be_bytes()[..]);
        let record: SecurityAuditRecord = serde_json::from_slice(bytes).unwrap();
        assert_eq!(record.sequence, sequence);
        hot += bytes.len() as u64 + 8;
        tail = Some(kasumi_types::audit_record_sha256(bytes));
        ids.push(record.event.request_id);
    }
    assert_eq!(ids.len() as u64, status.position.next_sequence);
    assert_eq!(hot, status.position.hot_bytes);
    assert_eq!(tail, status.hot_tail_sha256);
    (status, ids)
}

#[tokio::test]
async fn queued_records_share_one_commit_and_keep_one_contiguous_sequence() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let (persistent_config, scratch_config) =
        crate::test_utils::fixture_disk_configs(directory.path()).unwrap();
    let storage = crate::test_utils::FixtureStorage::open(
        &persistent_config,
        &scratch_config,
        Default::default(),
    )
    .unwrap();
    let path = directory.path().join("persistent/batch-security.kv");
    let provider = Arc::new(LocalKeyProvider::new([91; 32]));
    let node = storage
        .create_new(&path, kasumi_store::test_utils::NODE_STORE_ID)
        .unwrap();
    let store = TenantStore::initialize_catalog_fixture(
        node.clone(),
        SECURITY_TENANT.into(),
        provider.clone(),
    )
    .await
    .unwrap();
    let audit = SecurityAudit::initialize(
        store.clone(),
        AuditRetentionBudget::default(),
        storage.admission.clone(),
    )
    .unwrap();
    let mut expected = Vec::new();
    // A record with no commit in progress is its own batch.
    for index in 0..3 {
        expected.push(format!("alone-{index}"));
        audit.record(event(&expected[index])).await.unwrap();
    }
    assert_eq!(commits(&audit), 3);

    // Records that queue behind a commit follow in arrival order, at most
    // MAX_RECORD_BATCH to a store batch.
    let names: Vec<String> = (0..MAX_RECORD_BATCH + 3)
        .map(|index| format!("queued-{index}"))
        .collect();
    let held = audit.writer.sequence.lock().unwrap();
    let recorders = queue_records(&audit, names.iter().map(|name| event(name)).collect());
    drop(held);
    for outcome in outcomes(recorders).await {
        outcome.unwrap();
    }
    assert_eq!(commits(&audit), 5);
    expected.extend(names);
    let (_, ids) = hot_request_ids(&audit);
    assert_eq!(ids, expected);

    // Free-running recorders form whatever batches they meet; every record is
    // committed once, in one contiguous sequence.
    let mut recorders = Vec::new();
    for thread in 0..8 {
        let names: Vec<String> = (0..12)
            .map(|index| format!("free-{thread}-{index}"))
            .collect();
        expected.extend(names.iter().cloned());
        let recorder = audit.clone();
        recorders.push(tokio::task::spawn_blocking(move || {
            names
                .iter()
                .try_for_each(|name| recorder.record_sync(event(name)))
        }));
    }
    for outcome in outcomes(recorders).await {
        outcome.unwrap();
    }
    assert!(commits(&audit) <= 5 + 8 * 12);
    let (status, mut ids) = hot_request_ids(&audit);
    assert_eq!(
        ids[..3 + MAX_RECORD_BATCH + 3],
        expected[..3 + MAX_RECORD_BATCH + 3]
    );
    ids.sort();
    expected.sort();
    assert_eq!(ids, expected);

    // The batches are durable: a reopened writer resumes after the last one.
    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
    drop(audit);
    drop(store);
    drop(node);
    let node = storage
        .open_existing(&path, kasumi_store::test_utils::NODE_STORE_ID)
        .unwrap();
    let store = TenantStore::open_existing_fixture(node.clone(), SECURITY_TENANT.into(), provider)
        .await
        .unwrap();
    let audit = SecurityAudit::open(
        store.clone(),
        AuditRetentionBudget::default(),
        storage.admission.clone(),
    )
    .unwrap();
    assert_eq!(audit.status().unwrap().position, status.position);
    audit.record(event("reopened")).await.unwrap();
    let (reopened, ids) = hot_request_ids(&audit);
    assert_eq!(
        reopened.position.next_sequence,
        status.position.next_sequence + 1
    );
    assert_eq!(ids.last().unwrap(), "reopened");
    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn a_queued_record_beyond_the_hot_budget_refuses_only_itself() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let (persistent_config, scratch_config) =
        crate::test_utils::fixture_disk_configs(directory.path()).unwrap();
    let storage = crate::test_utils::FixtureStorage::open(
        &persistent_config,
        &scratch_config,
        Default::default(),
    )
    .unwrap();
    let node = storage
        .create_new(
            directory.path().join("persistent/budget-security.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let store = TenantStore::initialize_catalog_fixture(
        node.clone(),
        SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([92; 32])),
    )
    .await
    .unwrap();
    let budget = AuditRetentionBudget {
        hot_bytes: 128 << 10,
        archive_bytes: 128 << 20,
    };
    let audit = SecurityAudit::initialize(store.clone(), budget.clone(), storage.admission.clone())
        .unwrap();
    // The writer's timestamps have the 13 digits that hot_bytes assumes.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    assert_eq!(now.as_millis().to_string().len(), 13);
    let (first, large, second) = (event("fits-first"), large_event(), event("fits-second"));

    // No archive turn may drain the hot range until the batch is decided.
    let maintenance = audit.writer.maintenance.lock().await;
    // Fill until a batch of [first, large, second] admits `first`, then finds
    // no room for `large` but still room for `second`.
    let before = loop {
        let status = audit.status().unwrap();
        let next = status.position.next_sequence;
        let room = budget.hot_bytes - status.position.hot_bytes;
        let fits = hot_bytes(next, &first) + hot_bytes(next + 1, &second);
        let refused = hot_bytes(next, &first) + hot_bytes(next + 1, &large);
        if (fits..refused).contains(&room) {
            break status;
        }
        assert!(room >= refused, "fill overshot the window");
        let excess = room - (fits + refused) / 2;
        let fill = if excess >= hot_bytes(next, &large) {
            large_event()
        } else {
            let base = hot_bytes(next, &filler(1)) - 1;
            filler((excess - base).min(256) as usize)
        };
        audit.record(fill).await.unwrap();
    };
    let next = before.position.next_sequence;
    let committed = commits(&audit);

    let held = audit.writer.sequence.lock().unwrap();
    let recorders = queue_records(&audit, vec![first.clone(), large.clone(), second.clone()]);
    drop(held);
    let outcomes = outcomes(recorders).await;
    outcomes[0].as_ref().unwrap();
    let refusal = outcomes[1].as_ref().unwrap_err();
    assert!(refusal.downcast_ref::<DrainFailure>().is_none());
    assert!(refusal.to_string().contains("hot budget exhausted"));
    outcomes[2].as_ref().unwrap();
    // `second` takes the sequence `large` would have had, in the same commit.
    assert_eq!(commits(&audit), committed + 1);
    let (status, ids) = hot_request_ids(&audit);
    assert!(!status.persistence_failed);
    assert_eq!(status.position.next_sequence, next + 2);
    assert_eq!(
        status.position.hot_bytes,
        before.position.hot_bytes + hot_bytes(next, &first) + hot_bytes(next + 1, &second)
    );
    assert_eq!(ids[next as usize..], ["fits-first", "fits-second"]);

    // The refusal fenced nothing: once maintenance drains, the same metadata fits.
    drop(maintenance);
    while audit.status().unwrap().position.hot_bytes > budget.drains_to() {
        audit.maintain().await.unwrap();
    }
    audit.record(large).await.unwrap();
    assert_eq!(audit.status().unwrap().position.next_sequence, next + 3);
    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}

#[tokio::test]
async fn an_uncertain_batch_commit_fails_every_record_in_it_and_fences_the_rest() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let (persistent_config, scratch_config) =
        crate::test_utils::fixture_disk_configs(directory.path()).unwrap();
    let storage = crate::test_utils::FixtureStorage::open(
        &persistent_config,
        &scratch_config,
        Default::default(),
    )
    .unwrap();
    let archive = Arc::new(
        kasumi_store::FilesystemAuditArchive::open(
            directory.path().join("persistent/archive"),
            storage.persistent.clone(),
        )
        .unwrap(),
    );
    let admission = storage.admission.clone();
    let disk = FaultBackend::new();
    let clock = Arc::new(ManualClock::new());
    let provider = Arc::new(LocalKeyProvider::new([93; 32]));
    let store = TenantStore::initialize_catalog_fixture_with_clock(
        NodeStore::create_fixture_backend_on_disk(
            disk.clone(),
            kasumi_store::test_utils::storage_admission(),
            storage.persistent.clone(),
            storage.scratch.clone(),
        )
        .unwrap(),
        SECURITY_TENANT.into(),
        provider.clone(),
        clock.clone(),
    )
    .await
    .unwrap();
    let audit = SecurityAudit::initialize_with_archive(
        store.clone(),
        AuditRetentionBudget::default(),
        archive.clone(),
        admission.clone(),
    )
    .unwrap();
    audit.record(event("before")).await.unwrap();

    // One full batch, plus one record left queued behind it.
    let names: Vec<String> = (0..=MAX_RECORD_BATCH)
        .map(|index| format!("uncertain-{index}"))
        .collect();
    let held = audit.writer.sequence.lock().unwrap();
    let recorders = queue_records(&audit, names.iter().map(|name| event(name)).collect());
    // The key lease expires during the batch's durable sync: its outcome is unknown.
    disk.advance_clock_on_next_sync(clock.clone(), Duration::from_secs(60));
    drop(held);
    let outcomes = outcomes(recorders).await;
    let issues: Vec<DrainIssueRef> = outcomes[..MAX_RECORD_BATCH]
        .iter()
        .map(|outcome| {
            let error = outcome.as_ref().unwrap_err();
            assert!(error.to_string().contains("outcome unknown"));
            error.downcast_ref::<DrainFailure>().unwrap().issues()[0].clone()
        })
        .collect();
    assert!(
        issues.len() > 1,
        "the uncertain commit held several records"
    );
    assert!(
        issues
            .iter()
            .all(|issue| DrainIssueRef::ptr_eq(issue, &issues[0]))
    );
    assert_eq!(issues[0].component(), "audit persistence");
    // The record beyond the batch is fenced without a write of its own.
    let fenced = outcomes[MAX_RECORD_BATCH].as_ref().unwrap_err();
    assert!(fenced.downcast_ref::<DrainFailure>().is_none());
    assert!(fenced.to_string().contains("requires recovery"));
    assert_eq!(commits(&audit), 2);
    // Renewed key access neither clears the fence nor reuses the counter.
    store.refresh_lease().await.unwrap();
    assert!(audit.status().unwrap().persistence_failed);
    assert!(audit.record_sync(event("after")).is_err());

    // The whole batch committed atomically and recovery continues after it.
    let recovered = TenantStore::open_existing_fixture_with_clock(
        NodeStore::open_fixture_backend_on_disk(
            disk.crash(),
            kasumi_store::test_utils::storage_admission(),
            storage.persistent.clone(),
            storage.scratch.clone(),
        )
        .unwrap(),
        SECURITY_TENANT.into(),
        provider,
        clock,
    )
    .await
    .unwrap();
    let reopened = SecurityAudit::open_with_archive(
        recovered.clone(),
        AuditRetentionBudget::default(),
        archive,
        admission,
    )
    .unwrap();
    reopened.record(event("recovered")).await.unwrap();
    let (_, ids) = hot_request_ids(&reopened);
    let mut expected = vec!["before".to_owned()];
    expected.extend(names[..MAX_RECORD_BATCH].iter().cloned());
    expected.push("recovered".to_owned());
    assert_eq!(ids, expected);

    let drained = audit.shutdown().await.unwrap_err();
    assert_eq!(drained.completion(), DrainCompletion::Complete);
    assert!(
        drained
            .issues()
            .iter()
            .any(|issue| DrainIssueRef::ptr_eq(issue, &issues[0]))
    );
    reopened.shutdown().await.unwrap();
}
