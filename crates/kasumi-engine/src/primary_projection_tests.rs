//! Encrypted real-producer fixtures. The fresh Entry bridge is deliberately
//! test-private; ordinary Entry publication has no rebuild route in production.
use super::*;
use crate::{
    admission::{AdmissionConfig, NodeAdmission},
    application_sources::{SourceRoots, SourceRootsRef},
    primary_tree::{
        self as tree,
        records::{self, Attempt, Epoch, Inventory, Manifest, ManifestRef, Selector},
        stage::{
            CanonicalDto, PrimaryStage,
            bulk::build_fresh_collection,
            cow::{BaselineVerifier, CommittedBaseline, PendingReplacement, VerifiedBaseline},
        },
    },
};
use anyhow::Result;
use kasumi_raft::{
    ApplicationBoundaryRef, ApplicationSourceCustody as _, AppliedEntryContext, AppliedResponse,
};
use kasumi_store::{TenantStorageSet, WriteOp, test_utils::LocalKeyProvider};
use serde_json::json;
use sha2::{Digest, Sha256};

struct Fixture {
    engine: TenantEngine,
    roots: SourceRootsRef,
    stores: Arc<TenantStorageSet>,
    node: kasumi_store::NodeStore,
    storage: crate::test_utils::FixtureStorage,
    _buffers: Arc<kasumi_raft::SnapshotBufferOwner>,
    _input: Reservation,
    _directory: Option<tempfile::TempDir>,
}
type Prepared<'a> = PreparedOrderedCommand<'a, 'a>;
struct CommandInput {
    position: AppliedEntryContext,
    bytes: Vec<u8>,
}

impl Fixture {
    async fn new() -> crate::test_fixture_failure::FixtureResult<Self> {
        Self::new_with_node(|storage, path| {
            storage
                .create_new(path, kasumi_store::test_utils::NODE_STORE_ID)
                .map_err(crate::test_fixture_failure::FixtureFailure::NodeStartup)
        })
        .await
    }
    async fn new_with_node(
        create: impl FnOnce(
            &crate::test_utils::FixtureStorage,
            &std::path::Path,
        )
            -> crate::test_fixture_failure::FixtureResult<kasumi_store::NodeStore>,
    ) -> crate::test_fixture_failure::FixtureResult<Self> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (mut persistent, mut scratch) =
            crate::test_utils::fixture_disk_configs(directory.path())?;
        persistent.native_storage.cache.byte_limit = 0;
        scratch.native_cache_bytes = 0;
        let config = crate::test_utils::isolated_disk_admission_config(
            AdmissionConfig {
                max_inflight_bytes: Some(256 << 20),
                ..Default::default()
            },
            &persistent,
            &scratch,
        )?;
        let admission = NodeAdmission::with_fixed_memory(config, 2 << 30, 0)?;
        let storage =
            crate::test_utils::FixtureStorage::with_admission(&persistent, &scratch, admission)?;
        let input = storage.admission.reserve_resident(32 << 20)?;
        let node = create(&storage, &directory.path().join("persistent/node.kv"))?;
        let stores = TenantStorageSet::initialize_catalogs_fixture(
            node.clone(),
            "cow".into(),
            Arc::new(LocalKeyProvider::new([77; 32])),
            Arc::new(LocalKeyProvider::new([78; 32])),
        )
        .await?;
        let incarnation = uuid::Uuid::from_u128(971).to_string();
        let initial = TenantEngine::new(
            "cow".into(),
            incarnation.clone(),
            policy(),
            Limits::default(),
        )?;
        let image = initial.logical_snapshot(stores.application().scratch_disk())?;
        crate::bootstrap::persist_fixture_bootstrap(
            &stores,
            &image,
            1,
            &format!("cow/{incarnation}"),
        )?;
        let (roots, binding) = SourceRoots::new(
            stores.clone(),
            storage.admission.clone(),
            kasumi_raft::RaftLimits::default(),
        )?;
        let buffers = storage.admission.snapshot_buffer_owner()?;
        roots.bind_lifecycle(&buffers, binding)?;
        crate::test_utils::install_fixture_audit_placement(stores.application())?;
        let engine = TenantEngine::from_bootstrap("cow", &image)?;
        engine.install_storage_access(stores.application())?;
        engine.install_application_sources(roots.clone(), &image)?;
        Ok(Self {
            engine,
            roots,
            stores,
            node,
            storage,
            _buffers: buffers,
            _input: input,
            _directory: Some(directory),
        })
    }
    fn command(&self, operation: Operation) -> Result<CommandInput> {
        let revision = self.engine.current_generation()?.state.revision + 1;
        let command = Command {
            context: RequestContext {
                authorization: RequestAuthorization::service_identity(),
                principal: "owner".into(),
                tenant: "cow".into(),
                scopes: [Action::Read, Action::Write, Action::Admin]
                    .into_iter()
                    .collect(),
                request_id: format!("request-{revision}"),
            },
            timestamp_ms: revision,
            operation,
        };
        let bytes = serde_json::to_vec(&command)?;
        let position = AppliedEntryContext {
            log_id: log(revision),
            previous: (revision > 1).then(|| log(revision - 1)),
            membership: Default::default(),
            command_sha256: hex::encode(Sha256::digest(&bytes)),
            retirement_seed: None,
        };
        Ok(CommandInput { position, bytes })
    }
    fn prepare<'a>(
        &'a self,
        input: &'a CommandInput,
    ) -> crate::test_fixture_failure::FixtureResult<Prepared<'a>> {
        let prepared = PreparedOrderedCommand::prepare(
            &self.engine,
            ByteBoundCommand::check(&input.position, &input.bytes)?,
        )?;
        let outcome: kasumi_types::Result<WriteReceipt> =
            serde_json::from_slice(&prepared.response().data)?;
        assert!(
            outcome.is_ok(),
            "actual accepted fixture command: {outcome:?}"
        );
        Ok(prepared)
    }
    fn publish(&self, operation: Operation) -> Result<()> {
        let input = self.command(operation)?;
        kasumi_raft::with_application_publisher_bound_for_test(
            &self._buffers,
            &self.stores,
            &input.position,
            |publisher| {
                kasumi_raft::StateMachineBackend::apply_with_publisher(
                    &self.engine,
                    &input.position,
                    kasumi_raft::AppliedInput::Command(&input.bytes),
                    publisher,
                )
            },
        )?;
        Ok(())
    }
    fn seed(&self, rows: usize, long: bool) -> Result<()> {
        self.publish(Operation::CreateCollection(definition("docs")))?;
        self.publish(puts(
            "seed",
            (0..rows)
                .map(|n| ("docs".to_owned(), id(n, long), json!({"value":n})))
                .collect(),
        ))
    }
    fn fresh(&self) -> crate::test_fixture_failure::FixtureResult<CommittedBaseline> {
        let command_input = self.command(Operation::SetPolicy(policy()))?;
        let prepared = self.prepare(&command_input)?;
        let proof = {
            let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
            let stage = PrimaryStage::begin_fresh(&mut authority)?.begin_catalog()?;
            let mut stage = stage;
            for (name, collection) in &input.accepted().state.collections {
                let source = crate::index_source::StateCollection::new(
                    &input.accepted().state,
                    name,
                    collection,
                );
                let (next, built) = build_fresh_collection(
                    stage,
                    &source,
                    input.accepted().state.revision,
                    collection.data_epoch,
                    &kasumi_query::QueryCancellation::default(),
                )
                .unwrap();
                stage = next.append_catalog(name, built.manifest_ref())?;
            }
            let catalog = loop {
                let (next, catalog) = stage.finish_catalog_step(64)?;
                stage = next;
                if let Some(value) = catalog {
                    break value;
                }
            };
            let mut verifier = BaselineVerifier::begin(stage, &input, &catalog).unwrap();
            let (next, done) = verifier.step(0).unwrap();
            assert!(!done);
            verifier = next;
            loop {
                let (next, done) = verifier.step(64).unwrap();
                verifier = next;
                if done {
                    break;
                }
            }
            let proof = verifier.finish().unwrap();
            assert_eq!(proof.epoch().pending, Some(proof.attempt().id));
            assert_eq!(proof.catalog(), catalog.id());
            assert_eq!(proof.members(), catalog.member_count());
            assert_eq!(proof.totals(), catalog.totals());
            proof
        };
        Ok(self.publish_baseline(prepared, proof)?)
    }
    fn publish_baseline(
        &self,
        prepared: Prepared<'_>,
        proof: VerifiedBaseline,
    ) -> Result<CommittedBaseline> {
        let (accepted, position, response) = prepared.into_primary_test_parts()?;
        let effects = {
            let (_authority, input) = accepted.primary_input()?.split();
            proof.fresh_effects(&input, position)?
        };
        let mut prior = None;
        kasumi_raft::with_application_publisher_for_test(
            &self.stores,
            position,
            |publisher| -> anyhow::Result<()> {
                let expectation =
                    self.roots
                        .publication_expectation(position, effects.writes(), &response)?;
                let mut preparation = self.roots.publication_preparation();
                let receipt = publisher.commit_with_selection(
                    response,
                    effects.writes(),
                    &mut preparation,
                    expectation.challenge()?,
                )?;
                let selected = preparation
                    .finish_publication(&expectation, receipt)?
                    .capture(ApplicationBoundaryRef::Entry(position), false)?;
                let captured = selected.clone();
                {
                    let (mut authority, input) = accepted.primary_input()?.split();
                    prior = Some(
                        proof
                            .bind_selected(&mut authority, &input, selected, &effects)
                            .unwrap(),
                    );
                }
                accepted
                    .candidate()
                    .application_selection
                    .set(captured)
                    .map_err(|_| anyhow::anyhow!("fixture source already set"))?;
                accepted.publish();
                Ok(())
            },
        )?;
        prior
            .context("actual baseline publication omitted result")
            .map_err(Into::into)
    }
    fn read<T>(
        &self,
        namespace: &str,
        key: &[u8],
        max: usize,
        lend: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T> {
        let mut grant = self.storage.admission.reserve_document_source(4096)?;
        let mut reader = self.roots.open_primary_current()?;
        let value = reader.with_record(&mut grant, 4096, namespace, key, max, lend);
        let closed = reader.close();
        let value = value?;
        closed?;
        Ok(value)
    }
    fn selector(&self) -> Result<Selector> {
        self.read(
            "engine.primary.meta",
            b"selected",
            records::SELECTOR_BYTES,
            |b| decode(Selector::decode(b.context("selector absent")?)),
        )
    }
    fn epoch(&self, id: [u8; 16]) -> Result<Epoch> {
        self.read("engine.primary.epochs", &id, records::EPOCH_BYTES, |b| {
            decode(Epoch::decode(b.context("epoch absent")?))
        })
    }
    fn attempt(&self, id: [u8; 16]) -> Result<Attempt> {
        self.read(
            "engine.primary.attempts",
            &id,
            records::ATTEMPT_BYTES,
            |b| decode(Attempt::decode(b.context("attempt absent")?)),
        )
    }
    async fn close(self) -> crate::test_fixture_failure::FixtureResult<()> {
        drop(self.engine);
        self._buffers.drain_startup().await?;
        std::future::poll_fn(|cx| self.roots.poll_drain(cx)).await?;
        self.storage.admission.drain_snapshot_startups().await?;
        self.stores.shutdown().await?;
        self.node.shutdown().await?;
        Ok(())
    }
}
fn policy() -> Policy {
    Policy {
        grants: vec![Grant {
            principal: "owner".into(),
            collection: None,
            actions: [Action::Admin, Action::Read, Action::Write]
                .into_iter()
                .collect(),
        }],
        strict_read_audit: false,
    }
}
fn definition(name: &str) -> CollectionDefinition {
    CollectionDefinition {
        name: name.into(),
        schema: json!({"type":"object"}),
        indexes: vec![],
        strict_read_audit: false,
        retention_class: CollectionRetentionClass::Operational,
        write_mode: CollectionWriteMode::Mutable,
    }
}
fn log(index: u64) -> openraft::LogId<u64> {
    openraft::LogId::new(openraft::CommittedLeaderId::new(1, 1), index)
}
fn id(n: usize, long: bool) -> String {
    if long {
        format!("{n:04}{}", "x".repeat(252))
    } else {
        format!("row-{n:04}")
    }
}
fn puts(key: &str, rows: Vec<(String, String, serde_json::Value)>) -> Operation {
    Operation::Mutate(MutationBatch {
        idempotency_key: key.into(),
        read_set: vec![],
        operations: rows
            .into_iter()
            .map(|(collection, id, body)| Mutation::Put {
                collection,
                id,
                body,
                expected: Precondition::Any,
            })
            .collect(),
    })
}
fn decode<T>(value: std::result::Result<T, tree::CodecError>) -> Result<T> {
    value.map_err(|e| anyhow::anyhow!("fixture codec: {e:?}"))
}
fn key(id: tree::ObjectId) -> [u8; 24] {
    let mut b = [0; 24];
    b[..16].copy_from_slice(&id.attempt);
    b[16..].copy_from_slice(&id.ordinal.to_le_bytes());
    b
}
fn put(namespace: &str, key: &[u8], value: &[u8]) -> WriteOp {
    WriteOp::Put {
        namespace: namespace.into(),
        key: key.to_vec(),
        value: value.to_vec(),
    }
}

// Keep actual key renewal runnable during this long synchronous staging/abort loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_cow_actual_accepted_path_is_unselected_and_abort_is_separately_bounded()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    fixture.seed(50, true)?;
    let prior = fixture.fresh()?;
    let selected = fixture.selector()?;
    let old_epoch = fixture.epoch(selected.projection_epoch)?;
    let old_tail = fixture.attempt(selected.activation_attempt)?;
    let old_generation = fixture.engine.generation()?;
    let command_input = fixture.command(puts(
        "replace",
        vec![(
            "docs".into(),
            id(27, true),
            json!({"changed":"z".repeat(140_000)}),
        )],
    ))?;
    let prepared = fixture.prepare(&command_input)?;
    let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
    let pending =
        PendingReplacement::prepare(&mut authority, &input, prior, &mut || Ok(())).unwrap();
    let attempt = pending.attempt();
    let manifest = pending.manifest();
    assert_eq!(pending.collection(), "docs");
    assert_eq!(pending.id(), id(27, true));
    assert_eq!(manifest.root.unwrap().level, 1);
    assert_eq!(attempt.next_object, 4);
    assert_eq!(attempt.retire_count, 4);
    assert_eq!(manifest.definition, pending.old_manifest().definition);
    assert_ne!(pending.manifest_ref(), pending.old_manifest_ref());
    assert_eq!(pending.object().id.ordinal, 0);
    assert_eq!(fixture.selector()?, selected);
    assert_eq!(fixture.attempt(old_tail.id)?, old_tail);
    assert!(Arc::ptr_eq(&old_generation, &fixture.engine.generation()?));
    let prior = pending.close().unwrap();
    drop(authority);
    drop(prepared);
    drop(command_input);
    let mut authority = fixture.engine.lock_primary_apply()?;
    let mut abort =
        PrimaryStage::resume_incremental_abort(&mut authority)?.context("pending absent")?;
    let before = fixture.attempt(attempt.id)?;
    let (next, done) = abort.incremental_abort_step(0)?;
    abort = next;
    assert!(!done);
    assert_eq!(fixture.attempt(attempt.id)?, before);
    let mut saw_last_intention = false;
    let mut saw_settlement = false;
    for _ in 0..32 {
        let before = fixture.attempt(attempt.id)?;
        let (next, done) = abort.incremental_abort_step(1)?;
        abort = next;
        if before.live_resources == 0
            && before.journal_erase_cursor == before.next_object + before.retire_count
        {
            assert!(done);
            saw_settlement = true;
        }
        if !done {
            let after = fixture.attempt(attempt.id)?;
            if after.journal_erase_cursor == after.next_object + after.retire_count
                && after.live_resources == 0
            {
                assert_eq!(fixture.epoch(old_epoch.id)?.pending, Some(attempt.id));
                saw_last_intention = true;
            }
        }
        if done {
            break;
        }
    }
    assert!(saw_last_intention && saw_settlement);
    abort.close()?;
    drop(authority);
    assert_eq!(fixture.epoch(old_epoch.id)?, old_epoch);
    assert_eq!(fixture.attempt(old_tail.id)?, old_tail);
    assert_eq!(fixture.selector()?, selected);
    // Old accepted source remains live after every pending resource was erased.
    assert_eq!(
        old_generation.state.collections["docs"].documents[&id(27, true)].body,
        json!({"value":27})
    );
    let reader = crate::primary_tree::read::SelectedPrimary::open(
        old_generation
            .application_selection
            .get()
            .context("old source absent")?,
        &fixture.roots,
        &old_generation.state,
        "docs",
    )
    .unwrap();
    let (reader, value) = reader
        .lookup(&id(27, true), |record| {
            let kasumi_query::Record::Live(document) = record else {
                anyhow::bail!("old native kind differs")
            };
            assert_eq!(document.body, json!({"value":27}));
            Ok(document.version)
        })
        .unwrap();
    assert_eq!(value, Some(2));
    reader.close().unwrap();

    drop(prior);
    drop(old_generation);
    fixture.close().await
}

#[tokio::test]
async fn primary_cow_complete_map_diff_rejects_omitted_id_and_real_multi_id_shape()
-> crate::test_fixture_failure::FixtureResult<()> {
    for forged in [false, true] {
        let fixture = Fixture::new().await?;
        fixture.seed(3, false)?;
        let command_input = fixture.command(puts(
            if forged { "forged" } else { "two" },
            vec![
                ("docs".into(), id(0, false), json!({"value":"a"})),
                ("docs".into(), id(1, false), json!({"value":"b"})),
            ],
        ))?;
        let mut prepared = fixture.prepare(&command_input)?;
        if forged {
            prepared.omit_primary_id_for_test("docs", &id(1, false));
        }
        let (_authority, input) = prepared.accepted()?.primary_input()?.split();
        let error = input
            .replacement()
            .err()
            .context("unsupported diff accepted")?;
        assert!(error.to_string().contains(if forged {
            "omitted another changed ID"
        } else {
            "one changed ID"
        }));
        drop(_authority);
        drop(prepared);
        drop(command_input);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn primary_cow_foreign_apply_guard_on_same_store_pair_is_refused_before_pending()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    // A different engine can be installed over the same actual pair/scope in
    // this adversarial private fixture. Its mutex cannot authorize this input.
    let image = fixture
        .engine
        .logical_snapshot(fixture.stores.application().scratch_disk())?;
    let foreign = TenantEngine::from_bootstrap("cow", &image)?;
    foreign.install_storage_access(fixture.stores.application())?;
    foreign.install_application_sources(fixture.roots.clone(), &image)?;
    fixture.seed(1, false)?;
    let prior = fixture.fresh()?;
    let selected = fixture.selector()?;
    let epoch = fixture.epoch(selected.projection_epoch)?;
    let command_input = fixture.command(puts(
        "one",
        vec![("docs".into(), id(0, false), json!({"new":true}))],
    ))?;
    let prepared = fixture.prepare(&command_input)?;
    let (_original, input) = prepared.accepted()?.primary_input()?.split();
    let mut foreign_guard = foreign.lock_primary_apply()?;
    let failure = PendingReplacement::prepare(&mut foreign_guard, &input, prior, &mut || Ok(()))
        .err()
        .context("foreign guard accepted")?;
    assert!(
        failure
            .original()
            .to_string()
            .contains("accepted apply guard differs")
    );
    assert_eq!(fixture.epoch(epoch.id)?, epoch);
    assert_eq!(fixture.selector()?, selected);
    drop(failure);
    drop(foreign_guard);
    drop(_original);
    drop(prepared);
    drop(command_input);
    drop(foreign);
    fixture.close().await
}

#[tokio::test]
async fn primary_cow_captured_mapping_refuses_valid_alternate_manifest_with_unchanged_selector()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    fixture.seed(2, false)?;
    let prior = fixture.fresh()?;
    let selected = fixture.selector()?;
    let epoch = fixture.epoch(selected.projection_epoch)?;
    let name_hash = decode(records::name_hash("docs"))?;
    let mapping = fixture.read(
        "engine.primary.catalog",
        &records::CatalogEntry::key(selected.catalog, name_hash),
        records::CATALOG_ENTRY_BYTES,
        |b| decode(records::CatalogEntry::decode(b.context("mapping absent")?)),
    )?;
    let manifest = fixture.read(
        "engine.primary.manifests",
        &key(mapping.manifest.id),
        records::MANIFEST_BYTES,
        |b| {
            decode(Manifest::decode_referenced(
                b.context("manifest absent")?,
                mapping.manifest,
            ))
        },
    )?;
    // Same locally valid immutable graph, different physical manifest identity.
    // The selected source retains its original mapping. This direct test write
    // deliberately bypasses the future immutable namespace owner.
    let mut bytes = [0; records::MANIFEST_BYTES];
    decode(manifest.encode(&mut bytes))?;
    let alternate = ManifestRef {
        id: tree::ObjectId {
            attempt: [99; 16],
            ordinal: 7,
        },
        sha256: Sha256::digest(bytes).into(),
    };
    let mut changed = mapping;
    changed.manifest = alternate;
    let mut mb = [0; records::CATALOG_ENTRY_BYTES];
    decode(changed.encode(&mut mb))?;
    fixture.stores.application().write_batch(&[
        put("engine.primary.manifests", &key(alternate.id), &bytes),
        put(
            "engine.primary.catalog",
            &records::CatalogEntry::key(selected.catalog, name_hash),
            &mb,
        ),
    ])?;
    let command_input = fixture.command(puts(
        "one",
        vec![("docs".into(), id(0, false), json!({"new":true}))],
    ))?;
    let prepared = fixture.prepare(&command_input)?;
    let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
    let failure = PendingReplacement::prepare(&mut authority, &input, prior, &mut || Ok(()))
        .err()
        .context("substituted mapping accepted")?;
    assert!(
        failure
            .original()
            .to_string()
            .contains("current mapping differs from captured prior")
    );
    assert_eq!(fixture.selector()?, selected);
    assert_eq!(fixture.epoch(epoch.id)?, epoch);
    drop(failure);
    drop(authority);
    drop(prepared);
    drop(command_input);
    fixture.close().await
}

#[tokio::test]
async fn primary_cow_abort_rejects_bootstrap_missing_inventory_and_ambiguous_committed_phase()
-> crate::test_fixture_failure::FixtureResult<()> {
    for fault in 0..4 {
        let fixture = Fixture::new().await?;
        fixture.seed(1, false)?;
        let prior = fixture.fresh()?;
        let selected = fixture.selector()?;
        let command_input = fixture.command(puts(
            "one",
            vec![("docs".into(), id(0, false), json!({"new":true}))],
        ))?;
        let prepared = fixture.prepare(&command_input)?;
        let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
        let pending =
            PendingReplacement::prepare(&mut authority, &input, prior, &mut || Ok(())).unwrap();
        let attempt = pending.attempt();
        let prior = pending.close().unwrap();
        drop(authority);
        drop(prepared);
        drop(command_input);
        match fault {
            0 => {
                let mut changed = selected;
                changed.bootstrap_sha256[0] ^= 1;
                let mut bytes = [0; records::SELECTOR_BYTES];
                decode(changed.encode(&mut bytes))?;
                fixture.stores.application().write_batch(&[put(
                    "engine.primary.meta",
                    b"selected",
                    &bytes,
                )])?;
            }
            1 => {
                fixture
                    .stores
                    .application()
                    .write_batch(&[WriteOp::Delete {
                        namespace: "engine.primary.inventory".into(),
                        key: key(tree::ObjectId {
                            attempt: attempt.id,
                            ordinal: 0,
                        })
                        .to_vec(),
                    }])?;
            }
            3 => {
                let mut changed = fixture.epoch(selected.projection_epoch)?;
                changed.live_resources = 0;
                let mut bytes = [0; records::EPOCH_BYTES];
                decode(changed.encode(&mut bytes))?;
                fixture.stores.application().write_batch(&[put(
                    "engine.primary.epochs",
                    &changed.id,
                    &bytes,
                )])?;
            }
            _ => {
                let mut changed = attempt;
                changed.phase = records::AttemptPhase::Committed;
                let mut bytes = [0; records::ATTEMPT_BYTES];
                decode(changed.encode(&mut bytes))?;
                fixture.stores.application().write_batch(&[put(
                    "engine.primary.attempts",
                    &attempt.id,
                    &bytes,
                )])?;
            }
        }
        let mut authority = fixture.engine.lock_primary_apply()?;
        let error = match PrimaryStage::resume_incremental_abort(&mut authority) {
            Err(error) => error,
            Ok(Some(stage)) => {
                assert_eq!(fault, 1);
                let (stage, done) = stage.incremental_abort_step(1)?;
                assert!(!done);
                stage
                    .incremental_abort_step(1)
                    .err()
                    .context("missing inventory silently cleaned")?
            }
            Ok(None) => return Err(anyhow::anyhow!("fault erased pending ownership").into()),
        };
        let message = format!("{error:#}");
        assert!(
            message.contains(match fault {
                0 => "incremental bootstrap differs",
                1 => "primary inventory absent",
                2 => "not positively uncommitted",
                _ => "incremental resource/cursor differs",
            }),
            "{message}"
        );
        assert_eq!(
            fixture.epoch(selected.projection_epoch)?.pending,
            Some(attempt.id)
        );
        // No committed old resource or mapping is ever a cleanup target.
        assert_eq!(
            fixture.attempt(selected.activation_attempt)?.phase,
            records::AttemptPhase::Committed
        );
        drop(error);
        drop(authority);
        drop(prior);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn primary_cow_cancel_during_new_chunks_retains_original_and_pending_is_abortable()
-> crate::test_fixture_failure::FixtureResult<()> {
    #[derive(Debug)]
    struct Stop;
    impl std::fmt::Display for Stop {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("actual COW stop")
        }
    }
    impl std::error::Error for Stop {}
    let fixture = Fixture::new().await?;
    fixture.seed(1, false)?;
    let prior = fixture.fresh()?;
    let selected = fixture.selector()?;
    let command_input = fixture.command(puts(
        "large",
        vec![(
            "docs".into(),
            id(0, false),
            json!({"new":"x".repeat(200_000)}),
        )],
    ))?;
    let prepared = fixture.prepare(&command_input)?;
    let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
    let stop = anyhow::Error::new(Stop);
    let pointer = stop.downcast_ref::<Stop>().unwrap() as *const Stop;
    let mut stop = Some(stop);
    let mut chunks = 0;
    let failure = {
        let mut check = || -> Result<()> {
            let epoch = fixture.epoch(selected.projection_epoch)?;
            if let Some(attempt) = epoch.pending {
                let inventory = fixture.read(
                    "engine.primary.inventory",
                    &key(tree::ObjectId {
                        attempt,
                        ordinal: 0,
                    }),
                    records::INVENTORY_BYTES,
                    |b| b.map(|bytes| decode(Inventory::decode(bytes))).transpose(),
                )?;
                if inventory.is_some_and(|value| {
                    value.completed_units >= 1 && value.phase == records::InventoryPhase::Allocating
                }) {
                    chunks += 1;
                    return Err(stop.take().expect("original callback once"));
                }
            }
            Ok(())
        };
        PendingReplacement::prepare(&mut authority, &input, prior, &mut check)
            .err()
            .context("cancelled COW completed")?
    };
    assert_eq!(chunks, 1);
    assert_eq!(
        failure.original().downcast_ref::<Stop>().unwrap() as *const Stop,
        pointer
    );
    assert_eq!(fixture.selector()?, selected);
    assert!(fixture.epoch(selected.projection_epoch)?.pending.is_some());
    drop(failure);
    drop(authority);
    drop(prepared);
    drop(command_input);
    let mut authority = fixture.engine.lock_primary_apply()?;
    let mut stage = PrimaryStage::resume_incremental_abort(&mut authority)?
        .context("partial attempt absent")?;
    loop {
        let (next, done) = stage.incremental_abort_step(1)?;
        stage = next;
        if done {
            break;
        }
    }
    stage.close()?;
    drop(authority);
    fixture.close().await
}

fn archive(fixture: &Fixture, name: &str) -> Result<()> {
    let generation = fixture.engine.generation()?;
    let state = &generation.state;
    let archive_id = format!("archive-{name}");
    let document = state.collections[name].documents["same"].clone();
    let chunk = HistoryArchiveChunk {
        kind: HistoryArchiveKind::HistorySubset,
        archive_id: archive_id.clone(),
        source_incarnation: state.incarnation.clone(),
        collection: name.into(),
        index: 0,
        documents: vec![document],
    };
    let (digest, bytes) = staged_digest(&chunk)?;
    let operation = Operation::PublishHistoryArchive(PublishHistoryArchive {
        manifest: HistoryArchiveManifest {
            kind: HistoryArchiveKind::HistorySubset,
            archive_id,
            tenant: state.tenant.clone(),
            source_incarnation: state.incarnation.clone(),
            collection: name.into(),
            cutoff_revision: state.revision,
            source_schema_epoch: state.schema_epoch,
            destination: "local".into(),
            document_count: 1,
            chunks: vec![ArchiveChunkDescriptor {
                object_id: uuid::Uuid::new_v4().to_string(),
                ciphertext_sha256: "12".repeat(32),
                plaintext_sha256: digest,
                plaintext_bytes: bytes,
                document_count: 1,
                first_id: "same".into(),
                last_id: "same".into(),
            }],
        },
        manifest_object_id: uuid::Uuid::new_v4().to_string(),
        manifest_ciphertext_sha256: "34".repeat(32),
        expected_policy_epoch: state.policy_epoch,
    });
    drop(generation);
    fixture.publish(operation)
}

#[tokio::test]
async fn primary_cow_baseline_rejects_cross_collection_dto_alias_even_with_same_tree_identity()
-> crate::test_fixture_failure::FixtureResult<()> {
    for archived in [false, true] {
        let fixture = Fixture::new().await?;
        for name in ["alpha", "beta"] {
            let mut definition = definition(name);
            if archived {
                definition.retention_class = CollectionRetentionClass::ArchivableHistory;
                definition.write_mode = CollectionWriteMode::AppendOnly;
            }
            fixture.publish(Operation::CreateCollection(definition))?;
        }
        fixture.publish(Operation::Mutate(MutationBatch {
            idempotency_key: "same".into(),
            read_set: vec![],
            operations: ["alpha", "beta"]
                .into_iter()
                .map(|collection| Mutation::Put {
                    collection: collection.into(),
                    id: "same".into(),
                    body: json!({"identical": true}),
                    expected: Precondition::Absent,
                })
                .collect(),
        }))?;
        if archived {
            archive(&fixture, "alpha")?;
            archive(&fixture, "beta")?;
        }
        let command_input = fixture.command(Operation::SetPolicy(policy()))?;
        let prepared = fixture.prepare(&command_input)?;
        let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
        let mut stage = PrimaryStage::begin_fresh(&mut authority)?.begin_catalog()?;
        let mut first = None;
        let shared_tree = [47; 16];
        for (name, collection) in &input.accepted().state.collections {
            let (next, definition) = stage.stage_dto(
                shared_tree,
                CanonicalDto::Definition(&collection.definition),
            )?;
            stage = next;
            let record =
                crate::index_source::record(collection, "same", collection.data_epoch)?.unwrap();
            let (dto, kind, version, semantic) = match record {
                kasumi_query::Record::Live(document) => (
                    CanonicalDto::Live(document),
                    tree::RecordKind::Live,
                    document.version,
                    crate::accounting::encoded_len(&document.body)? as u64,
                ),
                kasumi_query::Record::Archived(reference) => (
                    CanonicalDto::Archived(reference),
                    tree::RecordKind::Archived,
                    reference.version,
                    0,
                ),
            };
            let (next, actual) = stage.stage_dto(shared_tree, dto)?;
            stage = next;
            let chosen = *first.get_or_insert(actual); // second real DTO becomes unreachable
            let semantic = if archived {
                decode(tree::archived_metadata_bytes("same", chosen.encoded_bytes))?
            } else {
                semantic
            };
            let (next, page) = stage.stage_page(
                shared_tree,
                collection.data_epoch,
                0,
                &[tree::Entry {
                    id: "same",
                    value: tree::Value::Leaf(tree::Leaf {
                        version,
                        kind,
                        object: chosen,
                        semantic_bytes: semantic,
                    }),
                }],
            )?;
            stage = next;
            let manifest = Manifest {
                scope: input.scope(),
                name_hash: decode(records::name_hash(name))?,
                tree_id: shared_tree,
                definition,
                data_epoch: collection.data_epoch,
                revision: input.accepted().state.revision,
                root: Some(records::Root {
                    reference: page.reference,
                    level: 0,
                }),
                totals: page.totals,
            };
            let (next, reference) = stage.stage_manifest(manifest)?;
            stage = next.append_catalog(name, reference)?;
        }
        let catalog = loop {
            let (next, catalog) = stage.finish_catalog_step(1)?;
            stage = next;
            if let Some(value) = catalog {
                break value;
            }
        };
        let mut verifier = BaselineVerifier::begin(stage, &input, &catalog).unwrap();
        let failure = loop {
            match verifier.step(1) {
                Ok((next, done)) => {
                    assert!(!done, "aliased graph certified");
                    verifier = next;
                }
                Err(failure) => break failure,
            }
        };
        assert!(
            failure
                .original()
                .to_string()
                .contains("DTO alias/order differs"),
            "{failure:?}"
        );
        // Live rows truly have identical accepted canonical DTOs. Archived rows
        // use real distinct accepted manifests; their foreign reference is still
        // rejected by interval/ownership before canonical hash comparison.
        drop(failure);
        drop(authority);
        drop(prepared);
        drop(command_input);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn primary_cow_baseline_checks_actual_inventory_count_and_original_cancellation()
-> crate::test_fixture_failure::FixtureResult<()> {
    for fault in 0..3 {
        let fixture = Fixture::new().await?;
        fixture.seed(1, false)?;
        let command_input = fixture.command(Operation::SetPolicy(policy()))?;
        let prepared = fixture.prepare(&command_input)?;
        let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
        let mut stage = PrimaryStage::begin_fresh(&mut authority)?.begin_catalog()?;
        let collection = &input.accepted().state.collections["docs"];
        let source =
            crate::index_source::StateCollection::new(&input.accepted().state, "docs", collection);
        let (next, built) = build_fresh_collection(
            stage,
            &source,
            input.accepted().state.revision,
            collection.data_epoch,
            &Default::default(),
        )
        .unwrap();
        stage = next.append_catalog("docs", built.manifest_ref())?;
        let (stage, catalog) = stage.finish_catalog_step(1)?;
        let catalog = catalog.context("one-member catalog incomplete")?;
        let stage = if fault == 2 {
            // A Complete but unreachable object after the final manifest is
            // not excused by locally valid counters or a canonical DTO hash.
            stage
                .stage_dto(
                    built.manifest().tree_id,
                    CanonicalDto::Live(collection.documents[&id(0, false)].as_ref()),
                )?
                .0
        } else {
            stage
        };
        let verifier = BaselineVerifier::begin(stage, &input, &catalog).unwrap();
        let failure = if fault == 0 {
            let mut inventory = fixture.read(
                "engine.primary.inventory",
                &key(catalog.id().0),
                records::INVENTORY_BYTES,
                |b| decode(Inventory::decode(b.context("catalog inventory absent")?)),
            )?;
            inventory.total_units += 1;
            inventory.completed_units += 1;
            inventory.catalog_dense_count += 1;
            let mut bytes = [0; records::INVENTORY_BYTES];
            decode(inventory.encode(&mut bytes))?;
            fixture.stores.application().write_batch(&[put(
                "engine.primary.inventory",
                &key(catalog.id().0),
                &bytes,
            )])?;
            verifier
                .step(1)
                .err()
                .context("altered actual count accepted")?
        } else if fault == 2 {
            let mut verifier = verifier;
            loop {
                match verifier.step(1) {
                    Ok((next, done)) => {
                        assert!(!done, "unreachable Complete object certified");
                        verifier = next;
                    }
                    Err(failure) => break failure,
                }
            }
        } else {
            let token = kasumi_query::QueryCancellation::default();
            token.cancel();
            verifier
                .step_checked(1, &mut || token.check().map_err(Into::into))
                .err()
                .context("cancelled verifier completed")?
        };
        assert!(
            failure.original().to_string().contains(match fault {
                0 => "catalog inventory differs",
                1 => "query work cancelled",
                _ => "complete graph cardinality differs",
            }),
            "{failure:?}"
        );
        drop(failure);
        drop(authority);
        drop(prepared);
        drop(command_input);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test]
async fn primary_cow_actual_two_page_working_set_and_retirement_are_precharged()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    for which in 0..3 {
        let mut authority = fixture.engine.lock_primary_apply()?;
        let crate::primary_tree::stage::cow::WorkMeasurement {
            addresses,
            charged,
            live,
            peak,
            allocations,
            owner: work,
        } = crate::primary_tree::stage::cow::measure_work_for_test(&mut authority)?;
        assert!(
            addresses[0] != addresses[1] && live >= 2 * tree::PAGE_BYTES as i64 && allocations >= 6
        );
        assert!(
            peak as u64 <= charged,
            "actual COW work heap {peak} exceeds real quote {charged}"
        );
        let held = fixture.storage.admission.snapshot().reserved_bytes;
        crate::document_pool::allocation_tests::check_topology_input_drop(
            addresses[which],
            move || drop(work),
            || {
                assert_eq!(
                    fixture.storage.admission.snapshot().reserved_bytes,
                    held,
                    "work credit retired before actual page deallocation"
                );
            },
        );
        drop(authority);
    }
    fixture.close().await
}

#[tokio::test]
async fn primary_cow_real_slot_refusal_precedes_pending_effects()
-> crate::test_fixture_failure::FixtureResult<()> {
    let fixture = Fixture::new().await?;
    fixture.seed(1, false)?;
    let prior = fixture.fresh()?;
    let selected = fixture.selector()?;
    let epoch = fixture.epoch(selected.projection_epoch)?;
    let command_input = fixture.command(puts(
        "one",
        vec![("docs".into(), id(0, false), json!({"new":true}))],
    ))?;
    let prepared = fixture.prepare(&command_input)?;
    let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
    let mut pressure = Vec::new();
    while let Ok(grant) = fixture.storage.admission.reserve_resident(1) {
        pressure.push(grant);
    }
    let failure = PendingReplacement::prepare(&mut authority, &input, prior, &mut || Ok(()))
        .err()
        .context("unfunded COW admitted")?;
    assert!(
        failure.original().chain().any(|cause| cause
            .downcast_ref::<Error>()
            .is_some_and(|error| error.code == ErrorCode::ResourceExhausted)),
        "{failure:?}"
    );
    drop(pressure);
    assert_eq!(fixture.selector()?, selected);
    assert_eq!(fixture.epoch(epoch.id)?, epoch);
    drop(failure);
    drop(authority);
    drop(prepared);
    drop(command_input);
    fixture.close().await
}

#[path = "primary_cow_unknown_staging_tests.rs"]
mod unknown_staging;

#[path = "primary_projection_publication_tests.rs"]
mod publication;

#[path = "ordered_command_publication_tests.rs"]
mod ordered_command_publication;
