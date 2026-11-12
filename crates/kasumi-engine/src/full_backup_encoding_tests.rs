use super::*;

fn generation() -> crate::Generation {
    let engine = TenantEngine::new(
        "backup-encoding".into(),
        "generation".into(),
        Policy {
            grants: vec![kasumi_types::Grant {
                principal: "owner".into(),
                collection: None,
                actions: [Action::Admin].into_iter().collect(),
            }],
            strict_read_audit: false,
        },
        Limits::default(),
    )
    .unwrap();
    let generation = engine.generation().unwrap();
    drop(engine);
    Arc::try_unwrap(generation).ok().unwrap()
}

fn work(generation: crate::Generation) -> (StreamWork, tokio::sync::mpsc::Receiver<Vec<u8>>) {
    let admission = NodeAdmission::new(Default::default()).unwrap();
    let document_budget = crate::admission::DocumentReadBudget::bind(
        &admission,
        admission.reserve(1 << 20, None).unwrap(),
        64 << 10,
        64 << 10,
    )
    .unwrap();
    let (sender, receiver) = tokio::sync::mpsc::channel(1);
    let cancellation = QueryCancellation::default();
    let registration = Arc::new(WorkFence::default())
        .begin(cancellation.clone())
        .unwrap();
    let work = StreamWork {
        generation: Arc::new(generation),
        writer: StateStream {
            sender,
            buffer: Vec::with_capacity(CHUNK_BYTES),
            hash: Sha256::new(),
            total: 0,
            limit: 1 << 20,
            cancellation,
            stopped: false,
            pause_before_check: None,
        },
        _reservation: document_budget.reservation(),
        document_budget,
        _permit: Arc::new(
            Arc::new(tokio::sync::Semaphore::new(1))
                .try_acquire_owned()
                .unwrap(),
        ),
        _registration: registration,
    };
    (work, receiver)
}

#[test]
fn backup_encoder_integrity_failure_remains_corruption() {
    let mut generation = generation();
    generation.state.staged_terminal_head.count += 1;
    let (work, _receiver) = work(generation);
    let Err(ProducerFailure::Failed(error)) = work.run() else {
        panic!("a mismatched terminal owner must fail the producer");
    };
    assert_eq!(error.code, ErrorCode::Corruption);
}

#[test]
fn backup_encoder_format_limit_breach_is_corruption() {
    let (mut work, _receiver) = work(generation());
    work.writer.limit = 0;
    let Err(ProducerFailure::Failed(error)) = work.run() else {
        panic!("state exceeding its format limit must fail the producer");
    };
    assert_eq!(error.code, ErrorCode::Corruption);
}

#[test]
fn backup_encoder_cancellation_keeps_stopped_custody() {
    let (work, _receiver) = work(generation());
    work.writer.cancellation.cancel();
    let Err(ProducerFailure::Stopped(error)) = work.run() else {
        panic!("cancelled producer must retain the stopped outcome");
    };
    assert_eq!(error.code, ErrorCode::ResourceExhausted);
    assert_eq!(error.message, "query work cancelled");
}

#[test]
fn backup_encoder_closed_consumer_keeps_stopped_custody() {
    let (work, receiver) = work(generation());
    drop(receiver);
    let Err(ProducerFailure::Stopped(error)) = work.run() else {
        panic!("closed consumer must retain the stopped outcome");
    };
    assert_eq!(error.code, ErrorCode::Unavailable);
}
