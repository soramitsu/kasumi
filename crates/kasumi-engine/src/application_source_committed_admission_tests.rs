//! A committed entry's apply spends native capacity admitted before consensus.
//! Native Resident traffic shares every byte and ledger slot that ordinary
//! operations leave free, and RSS pressure refuses every new reservation. After
//! a local proposer's admission either may refuse new requests, but neither may
//! fail the committed apply and close the tenant.
use super::*;
use crate::admission::{MemorySource, Reservation};
use crate::application_sources::completion::{CompletionCheckpoint, CompletionFault};
use kasumi_store::NodeDiskMemoryAdmission as _;
use std::sync::atomic::AtomicU64;

/// Hold every remaining byte and ledger slot as native Resident traffic does.
fn exhaust_native(admission: &Arc<NodeAdmission>) -> Vec<Reservation> {
    let max = admission.policy().max_inflight_bytes.unwrap();
    let free = max - admission.snapshot().reserved_bytes;
    let mut held = vec![admission.reserve_resident(free).unwrap()];
    while let Ok(slot) = admission.reserve_resident(0) {
        held.push(slot);
    }
    held
}

/// The committed apply drew its native leases from the escrow its proposer
/// admitted, and at least half of that escrow remained as headroom.
fn spent_escrow() {
    let peak = crate::admission::ApplyEscrow::take_last_peak_for_test()
        .expect("committed apply entered no admitted escrow");
    assert!(
        peak > 0 && peak <= crate::admission::ApplyEscrow::BYTES / 2,
        "committed apply native peak {peak}"
    );
}

fn revision(fixture: &OrdinaryFixture) -> u64 {
    fixture.engine.generation().unwrap().state.revision
}

fn applied(response: &AppliedResponse) -> kasumi_types::Result<WriteReceipt> {
    serde_json::from_slice(&response.data).unwrap()
}

fn admit_documents(fixture: &OrdinaryFixture, input: &Input) -> Result<u64> {
    let command: Command = serde_json::from_slice(&input.bytes)?;
    let before = fixture.fixture.storage.admission.snapshot().reserved_bytes;
    fixture.engine.admit_document_publication(&command)?;
    let after = fixture.fixture.storage.admission.snapshot().reserved_bytes;
    Ok(after - before)
}

/// The tenant keeps serving: a later proposal admits and applies normally.
fn serves_next(fixture: &OrdinaryFixture) -> Result<()> {
    let next = fixture.input(Operation::SetPolicy(policy()))?;
    let before = revision(fixture);
    fixture.engine.admit_publication()?;
    let response = fixture.apply(&next, || {})?;
    spent_escrow();
    applied(&response)?;
    assert_eq!(revision(fixture), before + 1);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn committed_queue_spends_native_capacity_admitted_before_proposal()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = OrdinaryFixture::new().await?;
    let admission = fixture.fixture.storage.admission.clone();
    let input = fixture.input(Operation::SetPolicy(policy()))?;
    let before = revision(&fixture);
    // The local proposer admits its committed publication before consensus.
    fixture.engine.admit_publication()?;
    // The planner has run and the grant is spent; native traffic then takes
    // everything before RootPreparation queues its registered read.
    let held = Arc::new(Mutex::new(Vec::new()));
    let window = held.clone();
    let traffic = admission.clone();
    fixture.fixture.roots.arm_completion_fault_for_test(
        CompletionCheckpoint::BeforeQueue,
        CompletionFault::Window(Box::new(move || {
            *window.lock().unwrap() = exhaust_native(&traffic);
            assert!(traffic.reserve_resident(0).is_err());
        })),
    );
    let response = fixture.apply(&input, || {})?;
    spent_escrow();
    assert!(!held.lock().unwrap().is_empty(), "queue window did not run");
    applied(&response)?;
    assert_eq!(revision(&fixture), before + 1);
    // Only new work is refused while that traffic holds the capacity.
    assert_eq!(
        fixture.engine.admit_publication().unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    held.lock().unwrap().clear();
    serves_next(&fixture)?;
    drop(response);
    drop(input);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn committed_entry_sink_and_capture_spend_native_capacity_admitted_before_proposal()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = OrdinaryFixture::new().await?;
    let admission = fixture.fixture.storage.admission.clone();
    let create = fixture.input(Operation::CreateCollection(definition()))?;
    fixture.engine.admit_publication()?;
    applied(&fixture.apply(&create, || {})?)?;
    spent_escrow();
    let input = fixture.input(put("native-window", json!({"n": 1}), Precondition::Any))?;
    let before = revision(&fixture);
    admit_documents(&fixture, &input)?;
    // Between admission and apply, native traffic holds every byte and slot:
    // the Entry sink planner, queued reader, publication write and capture
    // must all run on capacity admitted before the proposal.
    let held = exhaust_native(&admission);
    assert!(admission.memory().clone().reserve_installed(0).is_err());
    let response = fixture.apply(&input, || {})?;
    spent_escrow();
    applied(&response)?;
    assert_eq!(revision(&fixture), before + 1);
    // Publication completed under exhausted capacity. A new decoded read is
    // separately admitted after the interfering traffic releases its grants.
    drop(held);
    let current = fixture.engine.generation()?;
    assert_eq!(
        current.state.collections["docs"].documents["row"]
            .load_owned(current.document_resolver())?
            .body,
        json!({"n": 1})
    );
    drop(current);
    serves_next(&fixture)?;
    drop(response);
    drop(input);
    drop(create);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn committed_document_replace_and_patch_decode_dense_old_body_with_only_preadmitted_credit()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = OrdinaryFixture::new().await?;
    let admission = fixture.fixture.storage.admission.clone();
    let create = fixture.input(Operation::CreateCollection(definition()))?;
    admit_documents(&fixture, &create)?;
    applied(&fixture.apply(&create, || {})?)?;
    let raw = (0..4097)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let old = json!({"dense":vec![0; 8192], "proof":hex::encode(&raw), "tag":"old"});
    let initial = fixture.input(put("dense-initial", old.clone(), Precondition::Absent))?;
    admit_documents(&fixture, &initial)?;
    applied(&fixture.apply(&initial, || {})?)?;
    {
        let generation = fixture.engine.generation()?;
        let descriptor = generation.state.collections["docs"].documents["row"].stored()?;
        assert!(
            descriptor.body_decode_work > descriptor.body_bytes * 128,
            "dense fixture must exceed the discarded canonical-byte multiplier"
        );
    }
    for (index, operation) in [
        put(
            "dense-replace",
            json!({"dense":vec![1;8192], "proof":hex::encode(&raw), "tag":"replace"}),
            Precondition::Any,
        ),
        Operation::Mutate(MutationBatch {
            idempotency_key: "dense-patch".into(),
            read_set: vec![],
            operations: vec![Mutation::Patch {
                collection: "docs".into(),
                id: "row".into(),
                patch: json!({"tag":"patch"}),
                expected: Precondition::Any,
            }],
        }),
    ]
    .into_iter()
    .enumerate()
    {
        let input = fixture.input(operation)?;
        let admitted = admit_documents(&fixture, &input)?;
        let held = exhaust_native(&admission);
        let before = revision(&fixture);
        let response = fixture.apply(&input, || {})?;
        applied(&response)?;
        let peak = crate::admission::ApplyEscrow::take_last_peak_for_test().unwrap();
        assert!(
            peak > 0 && peak <= admitted,
            "apply peak {peak}, admitted {admitted}"
        );
        eprintln!(
            "committed document admission: case={index} admitted_bytes={admitted} spent_peak_bytes={peak}; enforced grants, not process RSS"
        );
        assert_eq!(revision(&fixture), before + 1);
        drop(held);
        let generation = fixture.engine.generation()?;
        let slot = &generation.state.collections["docs"].documents["row"];
        assert!(matches!(
            slot.as_ref(),
            kasumi_types::DocumentSlot::Stored(_)
        ));
        let document = generation.load_document(slot)?;
        assert_eq!(document.body["dense"], json!(vec![1; 8192]));
        assert_eq!(document.body["proof"], json!(hex::encode(&raw)));
        assert_eq!(
            document.body["tag"],
            if index == 0 { "replace" } else { "patch" }
        );
    }
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn document_preproposal_refusal_preserves_original_generation_and_recovers()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = OrdinaryFixture::new().await?;
    let create = fixture.input(Operation::CreateCollection(definition()))?;
    admit_documents(&fixture, &create)?;
    applied(&fixture.apply(&create, || {})?)?;
    let input = fixture.input(put(
        "refused-proof",
        json!({"proof":"ab".repeat(32768)}),
        Precondition::Absent,
    ))?;
    let original = fixture.engine.generation()?;
    let held = exhaust_native(&fixture.fixture.storage.admission);
    let command: Command = serde_json::from_slice(&input.bytes)?;
    assert_eq!(
        fixture
            .engine
            .admit_document_publication(&command)
            .unwrap_err()
            .code,
        ErrorCode::ResourceExhausted
    );
    assert!(Arc::ptr_eq(&original, &fixture.engine.generation()?));
    assert!(original.state.collections["docs"].documents.is_empty());
    drop(held);
    admit_documents(&fixture, &input)?;
    applied(&fixture.apply(&input, || {})?)?;
    assert_eq!(revision(&fixture), original.state.revision + 1);
    drop(original);
    fixture.close().await
}

struct Rss(AtomicU64);
impl MemorySource for Rss {
    fn resident_bytes(&self) -> anyhow::Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}
async fn observe_pressure(admission: &Arc<NodeAdmission>, pressured: bool) {
    for _ in 0..1000 {
        if admission.reserve_resident(0).is_err() == pressured {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
    }
    panic!("RSS pressure {pressured} was not observed");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(
    clippy::result_large_err,
    reason = "This fixture returns whole native failure custody; boxing or erasing it would change the ownership behavior under test."
)]
async fn committed_entry_applies_when_rss_pressure_begins_after_its_admission()
-> crate::test_fixture_failure::FixtureResult<()> {
    let rss = Arc::new(Rss(AtomicU64::new(0)));
    let fixture = OrdinaryFixture::with_memory(Some(rss.clone())).await?;
    let admission = fixture.fixture.storage.admission.clone();
    let input = fixture.input(Operation::SetPolicy(policy()))?;
    let before = revision(&fixture);
    fixture.engine.admit_publication()?;
    // The process crosses its RSS high-water mark after the proposal was
    // admitted and before its committed entry applies.
    rss.0.store(1 << 30, Ordering::SeqCst);
    observe_pressure(&admission, true).await;
    assert!(admission.snapshot().pressured);
    let response = fixture.apply(&input, || {})?;
    spent_escrow();
    applied(&response)?;
    assert_eq!(revision(&fixture), before + 1);
    // New work is refused under pressure, never the committed entry.
    assert_eq!(
        fixture.engine.admit_publication().unwrap_err().code,
        ErrorCode::ResourceExhausted
    );
    rss.0.store(0, Ordering::SeqCst);
    observe_pressure(&admission, false).await;
    serves_next(&fixture)?;
    drop(response);
    drop(input);
    fixture.close().await
}
