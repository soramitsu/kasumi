//! Test-only final primary effects and captured graph binding. The real fixture
//! owns accepted/context/response provenance; this owner never invokes a sink.
use super::*;
use records::boundary;

struct Effects {
    selector: Selector,
    attempt: Attempt,
    epoch: Epoch,
    gc: GcState,
    writes: Vec<WriteOp>,
    charged: u64,
    _grant: Reservation,
}

/// Detached, still-frozen proof. No mutation/refresh helper or raw constructor
/// escapes. Final effects and selected evidence outlive the publisher closure.
pub(crate) struct PreparedReplacement {
    resources: Option<PrimaryResources>,
    work: Option<Work>,
    prior: Option<CommittedBaseline>,
    candidate: Arc<Generation>,
    selected: Option<SelectedApplication>,
    baseline: Option<CommittedBaseline>,
    old: Manifest,
    old_ref: ManifestRef,
    new: Manifest,
    new_ref: ManifestRef,
    object: OverflowRef,
    name: Name,
    id: Name,
    effects: Effects,
    baseline_grant: Option<Reservation>,
    verified: bool,
    visibility_entered: bool,
}
/// Inline terminal ownership, with no blanket anyhow erasure/extra shell.
pub(crate) struct PublicationFailure {
    original: anyhow::Error,
    prepared: PreparedReplacement,
}
impl std::fmt::Debug for PublicationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrimaryPublicationFailure")
            .field("original", &self.original)
            .field("visibility_entered", &self.prepared.visibility_entered)
            .finish_non_exhaustive()
    }
}
impl PublicationFailure {
    pub(crate) fn original(&self) -> &anyhow::Error {
        &self.original
    }
    pub(crate) fn proposed_writes(&self) -> &[WriteOp] {
        self.prepared.writes()
    }
    pub(crate) fn visibility_entered(&self) -> bool {
        self.prepared.visibility_entered
    }
}

#[allow(
    clippy::result_large_err,
    reason = "Actual original and admitted proof stay inline."
)]
impl PendingReplacement<'_, '_> {
    pub(crate) fn prepare_publication(
        self,
        input: &PrimaryCandidate<'_>,
        position: &kasumi_raft::AppliedEntryContext,
    ) -> CowResult<PreparedReplacement> {
        let outcome = self.publication_parts(input, position);
        self.detach_publication(outcome)
    }
    pub(crate) fn measure_publication_for_test(
        self,
        input: &PrimaryCandidate<'_>,
        position: &kasumi_raft::AppliedEntryContext,
    ) -> (CowResult<PreparedReplacement>, i64, i64, usize) {
        // Measure the very same actual constructors, excluding retirement of
        // a reader whose allocations predate this observation window.
        let (outcome, live, peak, allocations) =
            crate::document_pool::allocation_tests::measure_topology_input(|| {
                self.publication_parts(input, position)
            });
        (self.detach_publication(outcome), live, peak, allocations)
    }
    fn publication_parts(
        &self,
        input: &PrimaryCandidate<'_>,
        position: &kasumi_raft::AppliedEntryContext,
    ) -> Result<(Effects, Reservation)> {
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            input.require_authority(self.stage._authority)?;
            ensure!(
                Arc::ptr_eq(&self.candidate, input.accepted()),
                "COW publication candidate differs"
            );
            self.prior
                .selected
                .require_next_primary_entry(position, self.candidate.state.revision_base)?;
            ensure!(
                self.prior.generation.state.revision.checked_add(1)
                    == Some(self.candidate.state.revision)
                    && self
                        .candidate
                        .state
                        .revision_base
                        .checked_add(position.log_id.index)
                        == Some(self.candidate.state.revision),
                "COW publication revision differs"
            );
            ensure!(
                self.stage.resources.cow_frozen && self.stage.resources.old_reader.is_none(),
                "COW publication is not frozen"
            );
            let effects = Effects::new(self, position)?;
            let grant = input
                .roots()
                .primary_installation()
                .1
                .reserve_application_source(allocated(std::mem::size_of::<CommittedBaseline>())?)?;
            Ok::<_, anyhow::Error>((effects, grant))
        }))
        .unwrap_or_else(|payload| Err(original_panic(payload)))
    }
    fn detach_publication(
        mut self,
        outcome: Result<(Effects, Reservation)>,
    ) -> CowResult<PreparedReplacement> {
        let outcome = outcome.and_then(|owned| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.stage.resources.close_reader()
            }))
            .unwrap_or_else(|payload| Err(original_panic(payload)))?;
            Ok(owned)
        });
        match outcome {
            Ok((effects, grant)) => Ok(PreparedReplacement {
                resources: Some(self.stage.resources),
                work: Some(self.work),
                prior: Some(self.prior),
                candidate: self.candidate,
                selected: None,
                baseline: None,
                old: self.old_manifest,
                old_ref: self.old_reference,
                new: self.manifest,
                new_ref: self.reference,
                object: self.object,
                name: self.name,
                id: self.id,
                effects,
                baseline_grant: Some(grant),
                verified: false,
                visibility_entered: false,
            }),
            Err(original) => Err(CowFailure {
                original,
                _candidate: Some(self.candidate),
                _work: Some(self.work),
                _resources: Some(self.stage.resources),
                _selected: None,
                _baseline: None,
                _prior: Some(self.prior),
            }),
        }
    }
}
impl Effects {
    fn new(
        pending: &PendingReplacement<'_, '_>,
        position: &kasumi_raft::AppliedEntryContext,
    ) -> Result<Self> {
        let r = &pending.stage.resources;
        let mut attempt = r.attempt.context("COW final attempt absent")?;
        let mut epoch = r.epoch.context("COW final epoch absent")?;
        let mut tail = pending.prior.tail;
        let count = pending.work.frames.len() as u64 + 2;
        ensure!(
            attempt.phase == AttemptPhase::Building
                && attempt.previous == Some(tail.id)
                && attempt.next.is_none()
                && attempt.next_object == count
                && attempt.live_resources == count
                && attempt.retire_count == count
                && attempt.abort_object_cursor == 0
                && attempt.retire_cursor == 0
                && attempt.journal_erase_cursor == 0
                && epoch.pending == Some(attempt.id)
                && epoch.tail == Some(tail.id)
                && epoch.head == pending.prior.epoch.head
                && tail.next.is_none()
                && epoch.live_resources
                    == pending
                        .prior
                        .epoch
                        .live_resources
                        .checked_add(count)
                        .context("COW final resource overflow")?,
            "COW final publication journal differs"
        );
        let fingerprint = codec(boundary::producer(
            kasumi_raft::ApplicationBoundaryRef::Entry(position),
        ))?;
        let mut selector = pending.prior.selector;
        let old = pending.old_manifest.totals;
        let new = pending.manifest.totals;
        let adjust = |total: u64, old: u64, new: u64| {
            total
                .checked_sub(old)
                .and_then(|value| value.checked_add(new))
                .context("COW publication total overflow")
        };
        selector.totals = Totals {
            live_count: adjust(selector.totals.live_count, old.live_count, new.live_count)?,
            archived_count: adjust(
                selector.totals.archived_count,
                old.archived_count,
                new.archived_count,
            )?,
            live_body_bytes: adjust(
                selector.totals.live_body_bytes,
                old.live_body_bytes,
                new.live_body_bytes,
            )?,
            archived_metadata_bytes: adjust(
                selector.totals.archived_metadata_bytes,
                old.archived_metadata_bytes,
                new.archived_metadata_bytes,
            )?,
        };
        selector.revision = pending.candidate.state.revision;
        selector.boundary = fingerprint.kind;
        selector.boundary_digest = fingerprint.sha256;
        selector.activation_attempt = attempt.id;
        attempt.phase = AttemptPhase::Committed;
        tail.next = Some(attempt.id);
        epoch.tail = Some(attempt.id);
        epoch.pending = None;
        let mapping = CatalogEntry {
            catalog: selector.catalog,
            scope: selector.scope,
            name_hash: pending.manifest.name_hash,
            manifest: pending.reference,
        };
        let gc = r.gc.context("COW final GC absent")?;
        let fixed = allocated(std::mem::size_of::<PreparedReplacement>())?
            .checked_add(allocated(std::mem::size_of::<PublicationFailure>())?)
            .and_then(|n| n.checked_add(allocated(5 * std::mem::size_of::<WriteOp>()).ok()?))
            .context("COW final owner quote overflow")?;
        let shapes = [
            (META, 8, records::SELECTOR_BYTES),
            (CATALOG, 56, records::CATALOG_ENTRY_BYTES),
            (ATTEMPTS, 16, records::ATTEMPT_BYTES),
            (ATTEMPTS, 16, records::ATTEMPT_BYTES),
            (EPOCHS, 16, records::EPOCH_BYTES),
        ];
        let mut bytes = fixed;
        for (namespace, key, value) in shapes {
            bytes = bytes
                .checked_add(allocated(namespace.len())?)
                .and_then(|n| n.checked_add(allocated(key).ok()?))
                .and_then(|n| n.checked_add(allocated(value).ok()?))
                .context("COW final buffer quote overflow")?;
        }
        let grant = r
            .roots
            .primary_installation()
            .1
            .reserve_application_source(bytes)?;
        let mut result = Self {
            selector,
            attempt,
            epoch,
            gc,
            writes: Vec::new(),
            charged: bytes,
            _grant: grant,
        };
        result.writes.try_reserve_exact(5)?;
        ensure!(
            result.writes.capacity() == 5,
            "COW final effect capacity differs"
        );
        let mut selected = [0; records::SELECTOR_BYTES];
        codec(selector.encode(&mut selected))?;
        let mut mapped = [0; records::CATALOG_ENTRY_BYTES];
        codec(mapping.encode(&mut mapped))?;
        let mut new_attempt = [0; records::ATTEMPT_BYTES];
        codec(attempt.encode(&mut new_attempt))?;
        let mut old_tail = [0; records::ATTEMPT_BYTES];
        codec(tail.encode(&mut old_tail))?;
        let mut current_epoch = [0; records::EPOCH_BYTES];
        codec(epoch.encode(&mut current_epoch))?;
        let mapping_key = CatalogEntry::key(selector.catalog, pending.manifest.name_hash);
        for (namespace, key, value) in [
            (META, b"selected".as_slice(), selected.as_slice()),
            (CATALOG, mapping_key.as_slice(), mapped.as_slice()),
            (ATTEMPTS, attempt.id.as_slice(), new_attempt.as_slice()),
            (ATTEMPTS, tail.id.as_slice(), old_tail.as_slice()),
            (EPOCHS, epoch.id.as_slice(), current_epoch.as_slice()),
        ] {
            result.writes.push(WriteOp::Put {
                namespace: exact_namespace(namespace)?,
                key: exact_bytes(key)?,
                value: exact_bytes(value)?,
            });
        }
        Ok(result)
    }
}

impl PreparedReplacement {
    pub(crate) fn writes(&self) -> &[WriteOp] {
        &self.effects.writes
    }
    pub(crate) fn into_failure(self, original: anyhow::Error) -> PublicationFailure {
        PublicationFailure {
            original,
            prepared: self,
        }
    }
    /// Called only after the real receipt has been consumed and actual capture
    /// returned. This independently validates the primary graph on that pin.
    pub(crate) fn bind_captured(
        &mut self,
        authority: &PrimaryApplyGuard<'_>,
        input: &PrimaryCandidate<'_>,
        selected: SelectedApplication,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        ensure!(
            self.selected.is_none() && self.baseline.is_none(),
            "COW capture repeated"
        );
        self.selected = Some(selected);
        input.require_authority(authority)?;
        ensure!(
            Arc::ptr_eq(input.accepted(), &self.candidate),
            "COW captured candidate differs"
        );
        let selected = self.selected.as_ref().expect("owned selected");
        let (bootstrap, fingerprint, revision) =
            selected.primary_read_proof(self.candidate.state.revision_base)?;
        ensure!(
            bootstrap == self.effects.selector.bootstrap_sha256
                && revision == self.candidate.state.revision
                && fingerprint.kind == self.effects.selector.boundary
                && fingerprint.sha256 == self.effects.selector.boundary_digest,
            "COW captured producer differs"
        );
        let r = self
            .resources
            .as_mut()
            .context("COW publication resources absent")?;
        ensure!(
            r.cow_frozen && r.reader.is_none() && r.old_reader.is_none(),
            "COW captured reader phase differs"
        );
        r.reader = Some(selected.open_primary_reader(&r.roots)?);
        for operation in &self.effects.writes {
            let WriteOp::Put {
                namespace,
                key,
                value,
            } = operation
            else {
                anyhow::bail!("COW final non-put effect");
            };
            r.read(namespace, key, value.len(), |actual| {
                ensure!(
                    actual == Some(value.as_slice()),
                    "COW captured primary effect differs"
                );
                Ok(())
            })?;
        }
        ensure!(r.gc_record()? == self.effects.gc, "COW captured GC differs");
        r.attempt = Some(self.effects.attempt);
        r.epoch = Some(self.effects.epoch);
        let collection = self
            .candidate
            .state
            .collections
            .get(self.name.text())
            .context("COW captured collection absent")?;
        let document = collection
            .documents
            .get(self.id.text())
            .context("COW captured document absent")?;
        // Completeness was already established before effects on this exact Arc.
        // No second collection scan/diff/allocation is performed after commit.
        verify_graph(
            r,
            self.work.as_mut().context("COW publication work absent")?,
            document,
            self.id.text(),
            collection.data_epoch,
            self.candidate.state.revision,
            self.old,
            self.old_ref,
            self.new,
            self.new_ref,
            self.object,
            check,
        )?;
        r.close_reader()?;
        self.verified = true;
        Ok(())
    }
    /// Retire only positively closed, readless graph work while the actual
    /// accepted owner still holds its guard. Final effects remain in this owner.
    pub(crate) fn retire_graph(
        &mut self,
        authority: &PrimaryApplyGuard<'_>,
        input: &PrimaryCandidate<'_>,
    ) -> Result<()> {
        input.require_authority(authority)?;
        ensure!(
            Arc::ptr_eq(input.accepted(), &self.candidate)
                && self.verified
                && self.baseline.is_none(),
            "COW graph retirement phase differs"
        );
        let r = self
            .resources
            .as_ref()
            .context("COW publication resources absent")?;
        ensure!(
            r.reader.is_none() && r.old_reader.is_none(),
            "COW graph reader not closed"
        );
        self.baseline = Some(CommittedBaseline::from_replacement(self)?);
        drop(self.work.take());
        drop(self.resources.take());
        // Nonfinal: accepted.previous still holds its installed selected handle.
        drop(self.prior.take());
        Ok(())
    }
    #[allow(
        clippy::type_complexity,
        reason = "Fixed consuming parts are private to the actual proof constructor."
    )]
    pub(in super::super) fn take_baseline_parts(
        &mut self,
    ) -> Result<(
        Arc<Generation>,
        SelectedApplication,
        Arc<TenantStorageSet>,
        Selector,
        Epoch,
        Attempt,
        Reservation,
    )> {
        ensure!(
            self.verified && self.baseline.is_none() && !self.visibility_entered,
            "COW baseline proof phase differs"
        );
        let resources = self
            .resources
            .as_ref()
            .context("COW baseline resources absent")?;
        ensure!(
            resources.reader.is_none() && resources.old_reader.is_none(),
            "COW baseline reader remains live"
        );
        ensure!(
            self.selected.is_some() && self.baseline_grant.is_some(),
            "COW baseline owned parts absent"
        );
        Ok((
            self.candidate.clone(),
            self.selected.take().expect("checked selected"),
            resources.stores.clone(),
            self.effects.selector,
            self.effects.epoch,
            self.effects.attempt,
            self.baseline_grant.take().expect("checked baseline grant"),
        ))
    }
    pub(crate) fn install_selected(&mut self) -> Result<()> {
        let selected = self
            .baseline
            .as_ref()
            .context("COW baseline not ready")?
            .selected
            .clone();
        if let Err(selected) = self.candidate.application_selection.set(selected) {
            self.selected = Some(selected);
            anyhow::bail!("COW candidate source already installed");
        }
        Ok(())
    }
    pub(crate) fn enter_visibility(&mut self) -> Result<()> {
        ensure!(
            self.baseline.is_some()
                && self.work.is_none()
                && self.resources.is_none()
                && self.prior.is_none()
                && !self.visibility_entered,
            "COW visibility phase differs"
        );
        self.visibility_entered = true;
        Ok(())
    }
    /// The fixture calls this only after actual ApplyPublication::finish and
    /// exact current-Arc observation. There is no raw-root success constructor.
    #[allow(
        clippy::result_large_err,
        reason = "Original failure and complete admitted owner remain inline."
    )]
    pub(crate) fn finish(
        mut self,
        current: &Arc<Generation>,
    ) -> Result<CommittedBaseline, PublicationFailure> {
        if !self.visibility_entered || !Arc::ptr_eq(current, &self.candidate) {
            return Err(self.into_failure(anyhow::anyhow!("COW visible candidate differs")));
        }
        match self.baseline.take() {
            Some(baseline) => Ok(baseline),
            None => Err(self.into_failure(anyhow::anyhow!("COW final baseline absent"))),
        }
    }
}

/// Actual final-effect backing plus the independently preclaimed inline
/// baseline grant. This witness cannot publish, select, or resume graph work.
pub(crate) struct PublicationAllocationWitness {
    effects: Effects,
    _baseline: Reservation,
}
impl PreparedReplacement {
    pub(crate) fn into_allocation_witness(self) -> Result<PublicationAllocationWitness> {
        ensure!(
            self.selected.is_none() && self.baseline.is_none() && !self.visibility_entered,
            "allocation witness after publication"
        );
        let Self {
            resources,
            work,
            prior,
            candidate,
            effects,
            baseline_grant,
            ..
        } = self;
        drop(work);
        drop(resources);
        drop(prior);
        drop(candidate);
        Ok(PublicationAllocationWitness {
            effects,
            _baseline: baseline_grant.context("baseline grant absent")?,
        })
    }
}
impl PublicationAllocationWitness {
    pub(crate) fn addresses(&self) -> [usize; 2] {
        let WriteOp::Put { value, .. } = &self.effects.writes[0] else {
            unreachable!()
        };
        [
            self.effects.writes.as_ptr() as usize,
            value.as_ptr() as usize,
        ]
    }
    pub(crate) fn charged(&self) -> u64 {
        self.effects.charged
            + allocated(std::mem::size_of::<CommittedBaseline>()).expect("fixed baseline quote")
    }
}
