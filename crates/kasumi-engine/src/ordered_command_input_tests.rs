//! Actual backend input refusal and the production byte-binding constructor.
//! Positive authority/durable-cursor assertions live in separate real-sink
//! tests. Specialized dispatch regressions retain their own fixture boundaries.
//! This publisher can only refuse and counts any accidental callback.
use super::*;
use crate::state::ordered_command::ByteBoundCommand;
use kasumi_raft::{AppliedEntryContext, AppliedInput, ApplyPublisher, StateMachineBackend as _};

const MISMATCH: &str = "ordered command bytes differ from applied digest";

#[derive(Default)]
struct RefusingPublisher {
    plain: usize,
    selected: usize,
}
impl ApplyPublisher for RefusingPublisher {
    fn with_completion(
        &mut self,
        _: &kasumi_raft::CompletionIdentity,
        _: &mut dyn kasumi_raft::CompletionAction,
    ) -> std::result::Result<(), kasumi_raft::CompletionCallError> {
        Err(kasumi_raft::CompletionCallError::Unsupported)
    }

    fn commit(
        &mut self,
        _: kasumi_raft::AppliedResponse,
        _: &[kasumi_store::WriteOp],
    ) -> std::result::Result<(), kasumi_raft::PublishCallError> {
        self.plain += 1;
        Err(kasumi_raft::PublishCallError::Failed)
    }
    fn commit_with_selection<'call>(
        &mut self,
        _: kasumi_raft::AppliedResponse,
        _: &[kasumi_store::WriteOp],
        _: &mut dyn kasumi_raft::SelectionPreparer,
        _: kasumi_raft::PublicationChallenge<'call>,
    ) -> std::result::Result<
        kasumi_raft::JointPublicationReceipt<'call>,
        kasumi_raft::PublishCallError,
    > {
        self.selected += 1;
        Err(kasumi_raft::PublishCallError::Failed)
    }
}
fn position(bytes: &[u8]) -> AppliedEntryContext {
    AppliedEntryContext {
        log_id: openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), 4),
        previous: Some(openraft::LogId::new(
            openraft::CommittedLeaderId::new(1, 1),
            3,
        )),
        membership: Default::default(),
        command_sha256: hex::encode(Sha256::digest(bytes)),
        retirement_seed: None,
    }
}
fn mismatch(error: &anyhow::Error) {
    let typed = error
        .root_cause()
        .downcast_ref::<Error>()
        .expect("actual typed byte-binding refusal, not a decoder/publication error");
    assert_eq!(typed.code, ErrorCode::Corruption);
    assert_eq!(typed.message, MISMATCH);
}
fn unchanged(engine: &CodecFixture, original: &Arc<Generation>) {
    let current = engine.generation().unwrap();
    assert!(Arc::ptr_eq(original, &current));
    assert!(Arc::ptr_eq(&original.indexes, &current.indexes));
    assert_eq!(current.state.revision, 3);
    assert_eq!(
        current.state.mutation_receipt_head,
        original.state.mutation_receipt_head
    );
    assert_eq!(
        current.state.collections["docs"].documents["row"].version,
        3
    );
    assert_eq!(text_matches(original, "original"), vec![("row".into(), 3)]);
    assert_eq!(text_matches(&current, "original"), vec![("row".into(), 3)]);
    assert!(text_matches(&current, "replacement").is_empty());
    assert!(engine.apply_lock.try_lock().is_ok());
}
fn seeded() -> CodecFixture {
    let engine = text_engine(1 << 20);
    apply(
        &engine,
        3,
        Operation::Mutate(document_batch(
            "original-input",
            "row",
            json!({"value":"original","tag":"occupied"}),
        )),
    )
    .unwrap();
    engine
}

#[test]
fn ordered_command_actual_backend_rejects_raw_digest_before_mutation_or_publication() {
    let engine = seeded();
    let original = engine.generation().unwrap();
    let replacement = command(
        Operation::Mutate(document_batch(
            "replacement-input",
            "row",
            json!({"value":"replacement","tag":"occupied"}),
        )),
        4,
    );
    let bytes = serde_json::to_vec(&replacement).unwrap();
    let correct = position(&bytes);
    let wrong = position(b"a different actual command").command_sha256;
    assert_ne!(wrong, correct.command_sha256);
    // Include the full other-command digest and malformed encodings. None may
    // be accepted by a prefix/case-insensitive or partial comparison.
    let uppercase = correct.command_sha256.to_ascii_uppercase();
    assert_ne!(uppercase, correct.command_sha256);
    for digest in [
        wrong,
        uppercase,
        correct.command_sha256[..63].to_owned(),
        format!("{}0", correct.command_sha256),
        "g".repeat(64),
    ] {
        let context = AppliedEntryContext {
            command_sha256: digest,
            ..correct.clone()
        };
        let mut publisher = RefusingPublisher::default();
        let error = engine
            .apply_with_publisher(&context, AppliedInput::Command(&bytes), &mut publisher)
            .unwrap_err();
        mismatch(
            error
                .operation_error()
                .expect("actual byte-binding operation failure"),
        );
        assert_eq!((publisher.plain, publisher.selected), (0, 0));
        unchanged(&engine, &original);
    }
    let receipt_key = staged_digest(&("owner", "replacement-input")).unwrap().0;
    assert!(original.receipts.get(&receipt_key).unwrap().is_none());
    let original_key = staged_digest(&("owner", "original-input")).unwrap().0;
    assert!(original.receipts.get(&original_key).unwrap().is_some());
}

#[test]
fn ordered_command_actual_backend_checks_digest_before_json_and_each_special_prefix() {
    let engine = seeded();
    let original = engine.generation().unwrap();
    // The suffix is deliberately invalid. The concrete mismatch must precede
    // the ordinary decoder AND each specialized decoder, not merely fail later.
    for prefix in [
        b"".as_slice(),
        crate::state::recovery::PREFIX,
        crate::state::target::PREFIX,
        crate::state::tenant_audit::PREFIX,
    ] {
        let mut bytes = prefix.to_vec();
        bytes.extend_from_slice(b"{");
        let mut context = position(&bytes);
        context.command_sha256 = position(b"different bytes").command_sha256;
        let mut publisher = RefusingPublisher::default();
        let error = engine
            .apply_with_publisher(&context, AppliedInput::Command(&bytes), &mut publisher)
            .unwrap_err();
        mismatch(
            error
                .operation_error()
                .expect("actual byte-binding operation failure"),
        );
        assert_eq!((publisher.plain, publisher.selected), (0, 0));
        unchanged(&engine, &original);
    }
    // With the actual raw digest, the same malformed ordinary input reaches
    // its existing decoder. This is a typed EOF failure, not the digest error.
    let bytes = b"{";
    let context = position(bytes);
    let mut publisher = RefusingPublisher::default();
    let error = engine
        .apply_with_publisher(&context, AppliedInput::Command(bytes), &mut publisher)
        .unwrap_err();
    let decoder = error
        .operation_error()
        .expect("matching digest reached the ordinary decoder")
        .root_cause()
        .downcast_ref::<serde_json::Error>()
        .expect("matching raw digest must reach the canonical JSON decoder");
    assert!(decoder.is_eof());
    assert_eq!((publisher.plain, publisher.selected), (0, 0));
    unchanged(&engine, &original);
}

#[test]
fn ordered_command_actual_byte_binding_success_has_zero_requested_heap() {
    // Hash exact arbitrary bytes, including prefixed and large inputs. This
    // measures only the real production constructor, not serde or a fixture
    // hash implementation. All owned input/context setup precedes the window.
    for prefix in [
        b"".as_slice(),
        crate::state::recovery::PREFIX,
        crate::state::target::PREFIX,
        crate::state::tenant_audit::PREFIX,
    ] {
        let mut bytes = prefix.to_vec();
        bytes.extend((0..(256 << 10)).map(|index| (index % 251) as u8));
        let context = position(&bytes);
        let (bound, live, peak, allocations) =
            crate::document_pool::allocation_tests::measure_topology_input(|| {
                ByteBoundCommand::check(&context, &bytes)
            });
        assert!(bound.is_ok());
        assert_eq!((live, peak, allocations), (0, 0, 0));
    }
}
