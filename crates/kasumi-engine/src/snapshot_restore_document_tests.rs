mod proof_documents {
    use super::*;
    use crate::admission::{AdmissionConfig, DocumentReadBudget};
    use crate::snapshot_codec::{Record, WireChangeRecord};
    use kasumi_types::*;
    use std::collections::BTreeMap;

    const ROWS: u64 = 256;
    const NODE_BYTES: u64 = 128 << 20;

    fn document(ordinal: u64, proof: &str) -> Document {
        Document {
            id: format!("proof-{ordinal:04}"),
            version: ordinal,
            body: serde_json::json!({"proof": proof, "ordinal": ordinal}),
        }
    }

    fn receipt_row(
        ordinal: u64,
        previous: &str,
        incarnation: &str,
        proof: &str,
    ) -> crate::mutation_receipt::Row {
        let document = document(ordinal, proof);
        let key = format!("restore-{ordinal:04}");
        let batch = MutationBatch::with_key(&key).insert("proofs", &document.id, document.body);
        let request_digest = batch.digest().unwrap();
        let mut context = RequestContext::trusted("tenant", "owner", [Action::Write]);
        context.request_id = format!("restore-command-{ordinal:04}");
        let command = Command {
            context,
            timestamp_ms: 1000,
            operation: Operation::Mutate(batch),
        };
        crate::mutation_receipt::Row {
            ordinal,
            key: staged_digest(&("owner", &key)).unwrap().0,
            previous_sha256: previous.into(),
            applied: crate::staged_terminal::AppliedIdentity {
                incarnation: incarnation.into(),
                revision: ordinal,
                timestamp_ms: command.timestamp_ms,
                command_sha256: hex::encode(Sha256::digest(serde_json::to_vec(&command).unwrap())),
                origin: crate::staged_terminal::AppliedOrigin::Raft {
                    term: 1,
                    leader: 1,
                    index: ordinal,
                    context_sha256: "cd".repeat(32),
                },
            },
            receipt: StoredReceipt {
                scope: MutationReceiptScope {
                    tenant: "tenant".into(),
                    incarnation: incarnation.into(),
                    principal: "owner".into(),
                },
                idempotency_key: key,
                recorded_revision: ordinal,
                request_digest,
                collections: vec!["proofs".into()],
                outcome: Ok(WriteReceipt {
                    revision: ordinal,
                    versions: BTreeMap::from([(format!("/proofs/{}", document.id), ordinal)]),
                }),
            },
        }
    }

    fn change(ordinal: u64, proof: &str) -> (ChangeCommit, WireChangeRecord) {
        let document = document(ordinal, proof);
        let wire = WireChangeRecord {
            collection: "proofs".into(),
            id: document.id.clone(),
            document: Some(OwnedDocument::Pending(Arc::new(document))),
        };
        let commit = ChangeCommit {
            revision: ordinal,
            first_sequence: ordinal,
            records: vec![],
            record_bytes: crate::accounting::encoded_len(&wire).unwrap(),
        };
        (commit, wire)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn repeated_proof_restore_keeps_real_grant_and_streams_more_data_than_resident_workspace()
    {
        let incarnation = uuid::Uuid::new_v4().to_string();
        let config = crate::test_utils::admission_config_with_bookkeeping(AdmissionConfig {
            max_inflight_bytes: Some(NODE_BYTES),
            ..Default::default()
        })
        .unwrap();
        let (
            (_source_dir, source, source_store),
            (_target_dir, target, target_store),
            admission,
            _,
        ) = admitted_pair(&incarnation, config).await;
        // This producer owns only one proof, one document/receipt and bounded
        // encoder buffers at a time; it never creates a Vec of decoded rows.
        let producer = admission.reserve(16 << 20, None).unwrap();
        let proof = "ab".repeat(256 << 10);
        let mut state = source.generation().unwrap().state.clone();
        state.revision = ROWS;
        state.policy_epoch = 1;
        state.schema_epoch = 1;
        state.document_count = ROWS;
        state.limits.max_snapshot_bytes = 512 << 20;
        state.limits.history.max_feed_bytes = 256 << 20;
        state.change_feed.next_sequence = ROWS + 1;
        state.change_feed.event_count = ROWS as usize;
        let collection = CollectionState {
            definition: CollectionDefinition {
                name: "proofs".into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: serde_json::json!({"type":"object"}),
                indexes: vec![],
                strict_read_audit: false,
            },
            data_epoch: ROWS,
            documents: Default::default(),
            archived_documents: Default::default(),
            archived_document_bytes: 0,
        };
        state
            .collections
            .insert("proofs".into(), collection.clone());
        for ordinal in 1..=ROWS {
            state.logical_bytes +=
                crate::accounting::encoded_len(&document(ordinal, &proof).body).unwrap() as u64;
            let row = receipt_row(
                ordinal,
                &state.mutation_receipt_head.sha256,
                &incarnation,
                &proof,
            );
            row.validate(&state).unwrap();
            crate::mutation_receipt::advance(&mut state.mutation_receipt_head, &row).unwrap();
            let (commit, _) = change(ordinal, &proof);
            state.change_feed.encoded_commit_bytes +=
                crate::change_feed_state::entry_bytes(ordinal, &commit).unwrap();
        }
        let image = kasumi_store::SnapshotImage::capture(
            source_store.scratch_disk(),
            512 << 20,
            |writer| {
                let purpose = serde_json::to_vec(source_store.storage_access().purpose())?;
                let mut envelope = Encoder {
                    writer,
                    digest: Sha256::new(),
                    counts: Counts::default(),
                };
                envelope.bytes(MAGIC)?;
                envelope.bytes(&(purpose.len() as u64).to_be_bytes())?;
                envelope.bytes(&purpose)?;
                let mut logical = LogicalWriter {
                    encoder: &mut envelope,
                    buffer: Vec::with_capacity(CHUNK),
                };
                let mut encoder = crate::snapshot_codec::Encoder::new(&mut logical)?;
                encoder.record(Record::Header(Box::new(crate::snapshot_codec::metadata(
                    &state,
                ))))?;
                encoder.record(Record::Collection("proofs".into(), collection))?;
                for ordinal in 1..=ROWS {
                    encoder.record(Record::Document(
                        "proofs".into(),
                        OwnedDocument::Pending(Arc::new(document(ordinal, &proof))),
                    ))?;
                }
                let mut head = MutationReceiptHead::empty("tenant", &incarnation)?;
                for ordinal in 1..=ROWS {
                    let row = receipt_row(ordinal, &head.sha256, &incarnation, &proof);
                    crate::mutation_receipt::advance(&mut head, &row)?;
                    encoder.record(Record::Receipt(Box::new(row)))?;
                }
                assert_eq!(head, state.mutation_receipt_head);
                for ordinal in 1..=ROWS {
                    encoder.record(Record::Change(ordinal, Arc::new(change(ordinal, &proof).0)))?;
                }
                for ordinal in 1..=ROWS {
                    encoder.record(Record::ChangeItem(ordinal, 0, change(ordinal, &proof).1))?;
                }
                encoder.finish()?;
                logical.finish()?;
                envelope.bytes(&[END])?;
                envelope.bytes(&envelope.counts.encode())?;
                envelope.writer.write_all(&envelope.digest.finalize())?;
                Ok(())
            },
        )
        .unwrap();
        drop(proof);
        drop(producer);
        let layout = inspect(&mut image.reader()).unwrap();
        let quote = layout.materialization_workspace().unwrap();
        assert!(
            state.logical_bytes > quote,
            "logical={} workspace={quote}",
            state.logical_bytes
        );
        assert!(quote < NODE_BYTES);
        assert_eq!(layout.kinds[3].records, ROWS);
        assert_eq!(layout.kinds[10].records, ROWS);
        let held = admission.reserve(NODE_BYTES - (quote - 1), None).unwrap();
        let files = (
            image.disk().snapshot().live_files,
            target_store.scratch_disk().snapshot().live_files,
        );
        let error = target
            .prepare_snapshot_restore(image.clone(), admission.clone(), 60_000)
            .await
            .err()
            .expect("restore must admit complete workspace before staging");
        assert_eq!(
            error.operation_error().unwrap().code,
            ErrorCode::ResourceExhausted
        );
        assert_eq!(
            (
                image.disk().snapshot().live_files,
                target_store.scratch_disk().snapshot().live_files,
            ),
            files
        );
        drop(held);
        let prepared = target
            .prepare_snapshot_restore(image.clone(), admission.clone(), 60_000)
            .await
            .unwrap();
        assert_eq!(prepared.image(), &image);
        assert_eq!(prepared.revision(), ROWS);
        assert_eq!(target.generation().unwrap().state.revision, 0);

        // Exercise the same reader with its actual materialization reservation
        // still live, then inspect every result before releasing that owner.
        let reservation = Arc::new(admission.reserve(quote, None).unwrap());
        let budget = DocumentReadBudget::bind_shared(
            &admission,
            reservation.clone(),
            layout.materialization_base_workspace().unwrap(),
            layout.document_workspace().unwrap(),
        )
        .unwrap();
        let scope = budget.enter().unwrap();
        assert_eq!(
            reservation
                .handoff_workspace(&admission, 0)
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        let baseline = CapturedValidation::capture(&target).unwrap();
        let generation = read(
            &target,
            &baseline.baseline(),
            &mut image.reader(),
            Some(layout),
        )
        .unwrap();
        assert_eq!(generation.state.logical_bytes, state.logical_bytes);
        assert_eq!(generation.receipts.head(), &state.mutation_receipt_head);
        for ordinal in 1..=ROWS {
            let id = format!("proof-{ordinal:04}");
            let slot = &generation.state.collections["proofs"].documents[&id];
            let DocumentSlot::Stored(descriptor) = slot.as_ref() else {
                panic!("current proof stayed decoded")
            };
            let document = slot.load_owned(generation.document_resolver()).unwrap();
            assert_eq!(document.id, id);
            assert_eq!(document.version, ordinal);
            assert_eq!(document.body["ordinal"], ordinal);
            let proof = document.body["proof"].as_str().unwrap();
            assert_eq!(proof.len(), 512 << 10);
            assert!(proof.as_bytes().chunks_exact(2).all(|bytes| bytes == b"ab"));
            assert_eq!(document.body.as_object().unwrap().len(), 2);
            drop(document);
            let commit = &generation.state.change_feed.commits[&ordinal];
            assert_eq!(commit.records.len(), 1);
            let after = commit.records[0].document.as_ref().unwrap();
            let DocumentSlot::Stored(feed_descriptor) = after.as_ref() else {
                panic!("feed proof stayed decoded")
            };
            assert_eq!(feed_descriptor, descriptor);
            let after = after.load_owned(generation.document_resolver()).unwrap();
            assert_eq!(after.id, id);
            assert_eq!(after.version, ordinal);
            assert_eq!(after.body["ordinal"], ordinal);
            assert_eq!(after.body.as_object().unwrap().len(), 2);
            let proof = after.body["proof"].as_str().unwrap();
            assert_eq!(proof.len(), 512 << 10);
            assert!(proof.as_bytes().chunks_exact(2).all(|bytes| bytes == b"ab"));
            let row = generation.receipts.row(ordinal).unwrap();
            let expected = receipt_row(ordinal, &row.previous_sha256, &incarnation, proof);
            assert_eq!(row.sha256().unwrap(), expected.sha256().unwrap());
        }
        assert_eq!(
            reservation
                .handoff_workspace(&admission, 0)
                .unwrap_err()
                .code,
            ErrorCode::Conflict
        );
        eprintln!(
            "proof restore: logical_current_bytes={} resident_workspace={quote} documents={ROWS}",
            state.logical_bytes
        );
        drop(generation);
        drop(baseline);
        drop(scope);
        reservation.handoff_workspace(&admission, 0).unwrap();
        drop(reservation);
        drop(prepared);
        drop(image);
        source_store.shutdown().await.unwrap();
        target_store.shutdown().await.unwrap();
    }
}
