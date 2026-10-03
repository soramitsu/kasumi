//! Actual accepted fixture publication, never a production fresh/replay route.
use super::*;
use crate::primary_tree::stage::cow::{PreparedReplacement, PublicationFailure};
use kasumi_raft::{PreparedSelectionPlan, SelectionPreparer};

struct Advancing<'a> {
    inner: crate::application_sources::PublicationPreparation<'a>,
}
impl SelectionPreparer for Advancing<'_> {
    fn prepare(
        &mut self,
        plan: &PreparedSelectionPlan,
        points: kasumi_store::PreparedTenantPointWorkspace,
    ) -> Result<()> {
        plan.require_advancing_entry()?;
        self.inner.prepare(plan, points)
    }
}

#[allow(
    clippy::large_enum_variant,
    reason = "Actual failure/prior owners stay inline; no unadmitted enclosing Box."
)]
pub(super) enum PreparationFailure {
    // Fixed enclosing test owner is covered by Fixture::_input. The original
    // stage failure owns its actual candidate/resources/grants without erasure.
    Cow(crate::primary_tree::stage::cow::CowFailure),
    Before {
        original: anyhow::Error,
        _prior: CommittedBaseline,
    },
}
impl std::fmt::Debug for PreparationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("PrimaryPreparationFailure")
            .field(self.original())
            .finish()
    }
}
impl PreparationFailure {
    fn original(&self) -> &anyhow::Error {
        match self {
            Self::Cow(failure) => failure.original(),
            Self::Before { original, .. } => original,
        }
    }
}
#[allow(
    clippy::result_large_err,
    reason = "Actual refusal and prior proof remain inline."
)]
pub(super) fn prepare<'a>(
    fixture: &'a Fixture,
    prepared: Prepared<'a>,
    prior: CommittedBaseline,
) -> std::result::Result<(Prepared<'a>, PreparedReplacement), PreparationFailure> {
    prepare_checked(fixture, prepared, prior, &mut || Ok(()))
}
#[allow(
    clippy::result_large_err,
    reason = "Actual refusal and prior proof remain inline."
)]
fn prepare_checked<'a>(
    fixture: &'a Fixture,
    prepared: Prepared<'a>,
    prior: CommittedBaseline,
    check: &mut dyn FnMut() -> Result<()>,
) -> std::result::Result<(Prepared<'a>, PreparedReplacement), PreparationFailure> {
    let preflight = prepared
        .accepted()
        .and_then(|accepted| {
            accepted.require_publication(&fixture.engine, Some(prepared.position()))
        })
        .and_then(|()| prior.require_next_for_test(prepared.position()));
    if let Err(original) = preflight {
        return Err(PreparationFailure::Before {
            original,
            _prior: prior,
        });
    }
    let publication = {
        let input = match prepared
            .accepted()
            .and_then(AcceptedGeneration::primary_input)
        {
            Ok(input) => input,
            Err(original) => {
                return Err(PreparationFailure::Before {
                    original,
                    _prior: prior,
                });
            }
        };
        let (mut authority, input) = input.split();
        let pending = PendingReplacement::prepare(&mut authority, &input, prior, check)
            .map_err(PreparationFailure::Cow)?;
        pending
            .prepare_publication(&input, prepared.position())
            .map_err(PreparationFailure::Cow)?
    };
    Ok((prepared, publication))
}
#[allow(
    clippy::result_large_err,
    reason = "Original publication error and graph custody stay inline."
)]
pub(super) fn publish(
    fixture: &Fixture,
    prepared: Prepared<'_>,
    mut publication: PreparedReplacement,
    after_commit: &mut dyn FnMut(&[WriteOp]) -> Result<()>,
) -> std::result::Result<CommittedBaseline, PublicationFailure> {
    let (accepted, position, response) = match prepared.into_primary_test_parts() {
        Ok(parts) => parts,
        Err(original) => return Err(publication.into_failure(original)),
    };
    let mut accepted = Some(accepted);
    let outcome =
        kasumi_raft::with_application_publisher_for_test(&fixture.stores, position, |publisher| {
            accepted
                .as_ref()
                .expect("owned accepted")
                .require_publication(&fixture.engine, Some(position))?;
            let expectation =
                fixture
                    .roots
                    .publication_expectation(position, publication.writes(), &response)?;
            let mut preparation = Advancing {
                inner: fixture.roots.publication_preparation(),
            };
            let receipt = publisher.commit_with_selection(
                response,
                publication.writes(),
                &mut preparation,
                expectation.challenge()?,
            )?;
            after_commit(publication.writes())?;
            let selected = preparation
                .inner
                .finish_publication(&expectation, receipt)?
                .capture(ApplicationBoundaryRef::Entry(position), false)?;
            {
                let (authority, input) = accepted
                    .as_ref()
                    .expect("owned accepted")
                    .primary_input()?
                    .split();
                publication.bind_captured(&authority, &input, selected, &mut || Ok(()))?;
                publication.retire_graph(&authority, &input)?;
            }
            publication.install_selected()?;
            publication.enter_visibility()?;
            accepted.take().expect("owned accepted").publish();
            Ok(())
        });
    // Actual finish retained its original publication/backend errors; graph,
    // effects and candidate never moved into the publisher's unwind catcher.
    drop(accepted);
    if let Err(original) = outcome {
        return Err(publication.into_failure(original));
    }
    let current = match fixture.engine.generation() {
        Ok(current) => current,
        Err(original) => return Err(publication.into_failure(original.into())),
    };
    publication.finish(&current)
}

/// Deliberately bypass the Engine apply guard to reproduce a real canonical
/// commit whose backend failed before resident visibility. No fake sink.
fn advance_without_visibility(fixture: &Fixture, prepared: &Prepared<'_>) -> Result<()> {
    assert!(prepared.response().retirement.is_none());
    let response = AppliedResponse::application(prepared.response().data.clone());
    let error = kasumi_raft::with_application_publisher_for_test(
        &fixture.stores,
        prepared.position(),
        |publisher| {
            publisher.commit(response, &[])?;
            anyhow::bail!("fixture canonical commit before visibility");
        },
    )
    .err()
    .context("canonical-only fixture unexpectedly acknowledged")?;
    assert!(
        error
            .to_string()
            .contains("fixture canonical commit before visibility")
    );
    Ok(())
}
fn selected_version(
    fixture: &Fixture,
    generation: &Generation,
    collection: &str,
    row: &str,
    body: &serde_json::Value,
) -> Result<u64> {
    let reader = crate::primary_tree::read::SelectedPrimary::open(
        generation
            .application_selection
            .get()
            .context("selected absent")?,
        &fixture.roots,
        &generation.state,
        collection,
    )
    .unwrap();
    let (reader, version) = reader
        .lookup(row, |record| {
            let kasumi_query::Record::Live(document) = record else {
                anyhow::bail!("live record absent");
            };
            assert_eq!(&document.body, body);
            Ok(document.version)
        })
        .unwrap();
    reader.close().unwrap();
    version.context("selected row absent")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_cow_two_real_publications_preserve_old_pin_and_commit_five_effects() -> Result<()>
{
    let fixture = Fixture::new().await?;
    fixture.seed(50, true)?;
    fixture.publish(Operation::CreateCollection(definition("other")))?;
    fixture.publish(puts(
        "other",
        vec![("other".into(), "stable".into(), json!({"untouched":true}))],
    ))?;
    let mut prior = fixture.fresh()?;
    let original = fixture.engine.generation()?;
    let mut old_reader = crate::primary_tree::read::SelectedPrimary::open(
        original.application_selection.get().unwrap(),
        &fixture.roots,
        &original.state,
        "docs",
    )
    .unwrap();
    let mut previous_resources = fixture
        .epoch(fixture.selector()?.projection_epoch)?
        .live_resources;
    let old_gc = fixture
        .stores
        .application()
        .get("engine.primary.meta", b"gc")?;
    let other_key = records::CatalogEntry::key(
        fixture.selector()?.catalog,
        decode(records::name_hash("other"))?,
    );
    let other_mapping = fixture
        .stores
        .application()
        .get("engine.primary.catalog", &other_key)?;
    for round in 0..2 {
        let expected_revision = 6 + round;
        let expected_body = json!({"changed":round,"padding":"p".repeat(90_000)});
        let next_input = fixture.command(puts(
            &format!("edit-{round}"),
            vec![("docs".into(), id(27, true), expected_body.clone())],
        ))?;
        let next = fixture.prepare(&next_input)?;
        let previous_tail = fixture.attempt(fixture.selector()?.activation_attempt)?;
        let (next, publication) = prepare(&fixture, next, prior).unwrap();
        assert_eq!(publication.writes().len(), 5);
        let values: usize = publication
            .writes()
            .iter()
            .map(|op| match op {
                WriteOp::Put { value, .. } => value.len(),
                _ => 0,
            })
            .sum();
        assert_eq!(values, 820);
        let WriteOp::Put { value, .. } = &publication.writes()[2] else {
            unreachable!()
        };
        let new_attempt = decode(Attempt::decode(value))?;
        assert_eq!(new_attempt.next_object, 4, "real two-level path");
        assert_eq!(new_attempt.retire_count, 4);
        assert_eq!(new_attempt.retire_cursor, 0);
        let expected_effects = publication.writes().to_vec(); // fixture input grant owns fixed five copied rows
        prior = publish(&fixture, next, publication, &mut |_| Ok(())).unwrap();
        for op in expected_effects {
            let WriteOp::Put {
                namespace,
                key,
                value,
            } = op
            else {
                unreachable!()
            };
            assert_eq!(
                fixture.stores.application().get(&namespace, &key)?,
                Some(value)
            );
        }
        let selected = fixture.selector()?;
        assert_eq!(selected.revision, expected_revision);
        let epoch = fixture.epoch(selected.projection_epoch)?;
        assert_eq!(epoch.live_resources, previous_resources + 4);
        previous_resources = epoch.live_resources;
        assert!(epoch.pending.is_none());
        let after_old_tail = fixture.attempt(previous_tail.id)?;
        assert_eq!(
            after_old_tail,
            Attempt {
                next: Some(new_attempt.id),
                ..previous_tail
            }
        );
        for ordinal in 0..4 {
            let intent = fixture.read(
                "engine.primary.retire",
                &key(tree::ObjectId {
                    attempt: new_attempt.id,
                    ordinal,
                }),
                records::RETIRE_BYTES,
                |bytes| decode(records::Retire::decode(bytes.context("retire absent")?)),
            )?;
            let inventory = fixture.read(
                "engine.primary.inventory",
                &key(intent.target),
                records::INVENTORY_BYTES,
                |bytes| decode(Inventory::decode(bytes.context("old inventory absent")?)),
            )?;
            assert_eq!(inventory.phase, records::InventoryPhase::Complete);
            assert_eq!(inventory.cleanup_unit_cursor, 0);
        }
        assert_eq!(
            fixture
                .stores
                .application()
                .get("engine.primary.meta", b"gc")?,
            old_gc
        );
        assert_eq!(
            fixture
                .stores
                .application()
                .get("engine.primary.catalog", &other_key)?,
            other_mapping
        );
        let current = fixture.engine.generation()?;
        assert_eq!(
            selected_version(&fixture, &current, "docs", &id(27, true), &expected_body)?,
            expected_revision
        );
        assert_eq!(
            selected_version(
                &fixture,
                &current,
                "other",
                "stable",
                &json!({"untouched":true})
            )?,
            4
        );
        let (reader, old) = old_reader
            .lookup(&id(27, true), |record| {
                let kasumi_query::Record::Live(document) = record else {
                    anyhow::bail!("old live absent");
                };
                assert_eq!(document.body, json!({"value":27}));
                Ok(document.version)
            })
            .unwrap();
        old_reader = reader;
        assert_eq!(old, Some(2));
    }
    old_reader.close().unwrap();
    let held = fixture.storage.admission.snapshot().reserved_bytes;
    drop(prior);
    assert_eq!(
        fixture.storage.admission.snapshot().reserved_bytes,
        held - ((std::mem::size_of::<CommittedBaseline>()).next_power_of_two() + 64) as u64,
        "actual new fixed baseline grant was not retired after nonfinal payload handles"
    );
    drop(original);
    drop(old_gc);
    drop(other_mapping);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_cow_actual_durable_ahead_refuses_before_new_attempt() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.seed(1, false)?;
    let prior = fixture.fresh()?;
    let selected = fixture.selector()?;
    let epoch = fixture.epoch(selected.projection_epoch)?;
    let old = fixture.engine.generation()?;
    let command_input = fixture.command(puts(
        "ahead",
        vec![("docs".into(), id(0, false), json!({"new":1}))],
    ))?;
    let prepared = fixture.prepare(&command_input)?;
    advance_without_visibility(&fixture, &prepared)?;
    {
        let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
        let failure = PendingReplacement::prepare(&mut authority, &input, prior, &mut || Ok(()))
            .err()
            .context("ahead source staged a new attempt")?;
        assert!(
            failure
                .original()
                .to_string()
                .contains("current durable predecessor differs"),
            "{failure:?}"
        );
        assert_eq!(fixture.epoch(epoch.id)?, epoch);
        assert_eq!(fixture.selector()?, selected);
        assert!(Arc::ptr_eq(&old, &fixture.engine.generation()?));
        drop(failure);
    }
    drop(prepared);
    drop(command_input);
    drop(old);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_cow_late_actual_replay_refuses_before_final_effects() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.seed(1, false)?;
    let prior = fixture.fresh()?;
    let selected = fixture.selector()?;
    let old = fixture.engine.generation()?;
    let command_input = fixture.command(puts(
        "late",
        vec![("docs".into(), id(0, false), json!({"new":2}))],
    ))?;
    let prepared = fixture.prepare(&command_input)?;
    let (prepared, publication) = prepare(&fixture, prepared, prior).unwrap();
    let pending = fixture.epoch(selected.projection_epoch)?;
    advance_without_visibility(&fixture, &prepared)?;
    let failure = publish(&fixture, prepared, publication, &mut |_| Ok(()))
        .err()
        .context("late replay acknowledged primary effects")?;
    assert!(
        failure.original().chain().any(|error| error
            .to_string()
            .contains("primary publication requires an advancing Entry")),
        "{failure:?}"
    );
    assert!(!failure.visibility_entered());
    assert_eq!(failure.proposed_writes().len(), 5);
    assert_eq!(fixture.epoch(pending.id)?, pending);
    assert_eq!(fixture.selector()?, selected);
    assert!(Arc::ptr_eq(&old, &fixture.engine.generation()?));
    drop(failure);
    drop(old);
    drop(command_input);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_cow_authentic_receipt_rejects_captured_mapping_substitution() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.seed(1, false)?;
    let prior = fixture.fresh()?;
    let old = fixture.engine.generation()?;
    let command_input = fixture.command(puts(
        "mapping",
        vec![("docs".into(), id(0, false), json!({"new":3}))],
    ))?;
    let prepared = fixture.prepare(&command_input)?;
    let (prepared, publication) = prepare(&fixture, prepared, prior).unwrap();
    let WriteOp::Put {
        key: mapping_key, ..
    } = &publication.writes()[1]
    else {
        unreachable!()
    };
    let old_mapping = fixture
        .stores
        .application()
        .get("engine.primary.catalog", mapping_key)?
        .context("old mapping absent")?;
    // Deliberate fixture bypass of the apply guard AFTER actual commit: valid
    // old manifest mapping, same key/width; not a supported concurrent producer.
    let failure = publish(&fixture, prepared, publication, &mut |writes| {
        let WriteOp::Put { namespace, key, .. } = &writes[1] else {
            unreachable!()
        };
        fixture
            .stores
            .write_batch(&[put(namespace, key, &old_mapping)], &[])?;
        Ok(())
    })
    .err()
    .context("substituted primary mapping became visible")?;
    assert!(
        failure
            .original()
            .to_string()
            .contains("captured primary effect differs"),
        "{failure:?}"
    );
    assert!(!failure.visibility_entered());
    assert!(Arc::ptr_eq(&old, &fixture.engine.generation()?));
    assert_eq!(
        fixture.selector()?.revision,
        4,
        "actual durable publication happened"
    );
    drop(failure);
    drop(old_mapping);
    drop(old);
    drop(command_input);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_cow_closed_factory_retains_cancellation_and_final_grant_refusal() -> Result<()> {
    for cancel in [true, false] {
        let fixture = Fixture::new().await?;
        fixture.seed(1, false)?;
        let prior = fixture.fresh()?;
        let selected = fixture.selector()?;
        let command_input = fixture.command(puts(
            "refuse",
            vec![("docs".into(), id(0, false), json!({"next":true}))],
        ))?;
        let prepared = fixture.prepare(&command_input)?;
        if cancel {
            let token = kasumi_query::QueryCancellation::default();
            token.cancel();
            let failure = prepare_checked(&fixture, prepared, prior, &mut || {
                token.check().map_err(Into::into)
            })
            .err()
            .context("cancelled factory prepared publication")?;
            assert!(
                failure
                    .original()
                    .to_string()
                    .contains("query work cancelled"),
                "{failure:?}"
            );
            assert!(fixture.epoch(selected.projection_epoch)?.pending.is_none());
            drop(failure);
        } else {
            // Physical COW is complete before pressure. The final effects/new
            // baseline constructor itself must refuse under the real ledger.
            let failure = {
                let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
                let pending =
                    PendingReplacement::prepare(&mut authority, &input, prior, &mut || Ok(()))
                        .unwrap();
                let mut pressure = Vec::new();
                while let Ok(grant) = fixture.storage.admission.reserve_resident(1) {
                    pressure.push(grant);
                }
                let failure = pending
                    .prepare_publication(&input, prepared.position())
                    .err()
                    .context("unfunded final owner admitted")?;
                assert!(
                    failure.original().chain().any(|cause| cause
                        .downcast_ref::<Error>()
                        .is_some_and(|error| error.code == ErrorCode::ResourceExhausted)),
                    "{failure:?}"
                );
                drop(pressure);
                failure
            };
            drop(failure);
            drop(prepared);
        }
        drop(command_input);
        assert_eq!(fixture.selector()?, selected);
        fixture.close().await?;
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_cow_real_publisher_admission_refusal_keeps_exact_final_effects() -> Result<()> {
    let fixture = Fixture::new().await?;
    fixture.seed(1, false)?;
    let prior = fixture.fresh()?;
    let selected = fixture.selector()?;
    let command_input = fixture.command(puts(
        "publish-pressure",
        vec![("docs".into(), id(0, false), json!({"next":4}))],
    ))?;
    let prepared = fixture.prepare(&command_input)?;
    let (prepared, publication) = prepare(&fixture, prepared, prior).unwrap();
    let pending = fixture.epoch(selected.projection_epoch)?;
    let mut pressure = Vec::new();
    while let Ok(grant) = fixture.storage.admission.reserve_resident(1) {
        pressure.push(grant);
    }
    let failure = publish(&fixture, prepared, publication, &mut |_| Ok(()))
        .err()
        .context("unfunded publisher acknowledged")?;
    assert!(!failure.visibility_entered());
    assert_eq!(failure.proposed_writes().len(), 5);
    // The real sink must fund its native custody reads before it can call
    // SelectionPreparer. Installed MemoryCore admission preserves this io
    // original; it is not an Engine query-admission error.
    let native = failure
        .original()
        .root_cause()
        .downcast_ref::<std::io::Error>()
        .context("native publisher admission original absent")?;
    assert_eq!(
        native.kind(),
        std::io::ErrorKind::OutOfMemory,
        "{failure:?}"
    );
    drop(pressure);
    assert_eq!(fixture.selector()?, selected);
    assert_eq!(fixture.epoch(pending.id)?, pending);
    drop(failure);
    drop(command_input);
    fixture.close().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn primary_cow_actual_final_effect_allocations_and_baseline_grants_retire_in_order()
-> Result<()> {
    for which in 0..2 {
        let fixture = Fixture::new().await?;
        fixture.seed(1, false)?;
        let prior = fixture.fresh()?;
        let command_input = fixture.command(puts(
            "allocator",
            vec![("docs".into(), id(0, false), json!({"new":which}))],
        ))?;
        let prepared = fixture.prepare(&command_input)?;
        let (publication, live, peak, allocations) = {
            let (mut authority, input) = prepared.accepted()?.primary_input()?.split();
            let pending =
                PendingReplacement::prepare(&mut authority, &input, prior, &mut || Ok(())).unwrap();
            let (publication, live, peak, allocations) =
                pending.measure_publication_for_test(&input, prepared.position());
            (publication.unwrap(), live, peak, allocations)
        };
        let witness = publication.into_allocation_witness()?;
        assert!(
            allocations >= 16,
            "five actual namespace/key/value sets plus WriteOp backing"
        );
        assert!(
            live > 0 && peak as u64 <= witness.charged(),
            "actual final allocation live={live} peak={peak} quote={}",
            witness.charged()
        );
        let address = witness.addresses()[which];
        let held = fixture.storage.admission.snapshot().reserved_bytes;
        let charged = witness.charged();
        crate::document_pool::allocation_tests::check_topology_input_drop(
            address,
            move || drop(witness),
            || {
                assert_eq!(
                    fixture.storage.admission.snapshot().reserved_bytes,
                    held,
                    "final effect/baseline credits retired before actual System.dealloc"
                );
            },
        );
        assert_eq!(
            fixture.storage.admission.snapshot().reserved_bytes,
            held - charged
        );
        drop(prepared);
        drop(command_input);
        fixture.close().await?;
    }
    Ok(())
}
