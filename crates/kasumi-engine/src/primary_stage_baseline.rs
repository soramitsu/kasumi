//! Test-private fresh publication bridge: proof remains distinct from receipt.
use super::*;
use records::boundary;

pub(crate) struct FreshEffects {
    selector: Selector,
    gc: GcState,
    epoch: Epoch,
    attempt: Attempt,
    writes: Vec<WriteOp>,
    _grant: Reservation,
}
impl FreshEffects {
    pub(crate) fn writes(&self) -> &[WriteOp] {
        &self.writes
    }
}
/// Fixed prior capability. There is no previous-capability field or Arc chain.
/// Its captured source and Generation are the exact same accepted publication.
pub(crate) struct CommittedBaseline {
    pub(super) generation: Arc<Generation>,
    pub(super) selected: SelectedApplication,
    pub(super) stores: Arc<TenantStorageSet>,
    pub(super) selector: Selector,
    pub(super) epoch: Epoch,
    pub(super) tail: Attempt,
    _grant: Reservation,
}
#[allow(
    clippy::result_large_err,
    reason = "Original failures, frozen source custody and preclaimed work move inline; boxing requires separate outer admission."
)]
impl VerifiedBaseline {
    pub(crate) fn fresh_effects(
        &self,
        input: &PrimaryCandidate<'_>,
        position: &kasumi_raft::AppliedEntryContext,
    ) -> Result<FreshEffects> {
        ensure!(
            Arc::ptr_eq(&self.candidate, input.accepted())
                && input.scope() == self.scope
                && input.bootstrap() == self.bootstrap,
            "baseline accepted owner differs"
        );
        same_stores(&self.stores, input.roots().primary_installation().0)?;
        ensure!(
            self.candidate
                .state
                .revision_base
                .checked_add(position.log_id.index)
                == Some(self.candidate.state.revision),
            "baseline publication revision differs"
        );
        let fingerprint = codec(boundary::producer(
            kasumi_raft::ApplicationBoundaryRef::Entry(position),
        ))?;
        let selector = Selector {
            boundary: fingerprint.kind,
            scope: self.scope,
            bootstrap_sha256: self.bootstrap,
            projection_epoch: self.epoch.id,
            revision: self.candidate.state.revision,
            revision_base: self.candidate.state.revision_base,
            catalog: self.catalog,
            collection_count: self.members,
            totals: self.totals,
            activation_attempt: self.attempt.id,
            boundary_digest: fingerprint.sha256,
        };
        let gc = GcState {
            current: Some(self.epoch.id),
            building: None,
            retired: None,
        };
        let mut epoch = self.epoch;
        epoch.pending = None;
        let mut attempt = self.attempt;
        attempt.phase = AttemptPhase::Committed;
        let bytes = allocated(4 * std::mem::size_of::<WriteOp>())?
            .checked_add(
                4 * (allocated(32)? + allocated(24)? + allocated(records::SELECTOR_BYTES)?),
            )
            .context("fresh effects quote overflow")?;
        let grant = input
            .roots()
            .primary_installation()
            .1
            .reserve_application_source(bytes)?;
        let mut result = FreshEffects {
            selector,
            gc,
            epoch,
            attempt,
            writes: Vec::new(),
            _grant: grant,
        };
        result.writes.try_reserve_exact(4)?;
        ensure!(
            result.writes.capacity() == 4,
            "fresh effects capacity differs"
        );
        let mut sb = [0; records::SELECTOR_BYTES];
        codec(selector.encode(&mut sb))?;
        let mut gb = [0; records::GC_BYTES];
        codec(gc.encode(&mut gb))?;
        let mut eb = [0; records::EPOCH_BYTES];
        codec(epoch.encode(&mut eb))?;
        let mut ab = [0; records::ATTEMPT_BYTES];
        codec(attempt.encode(&mut ab))?;
        for (namespace, key, value) in [
            (META, b"selected".as_slice(), sb.as_slice()),
            (META, b"gc".as_slice(), gb.as_slice()),
            (EPOCHS, epoch.id.as_slice(), eb.as_slice()),
            (ATTEMPTS, attempt.id.as_slice(), ab.as_slice()),
        ] {
            result.writes.push(WriteOp::Put {
                namespace: exact_namespace(namespace)?,
                key: exact_bytes(key)?,
                value: exact_bytes(value)?,
            });
        }
        Ok(result)
    }
    /// The caller is the private accepted state owner, after actual receipt
    /// consumption/capture. Exact storage effects are independently checked.
    pub(crate) fn bind_selected(
        self,
        authority: &mut PrimaryApplyGuard<'_>,
        input: &PrimaryCandidate<'_>,
        selected: SelectedApplication,
        effects: &FreshEffects,
    ) -> CowResult<CommittedBaseline> {
        let mut stage = match PrimaryStage::allocate(authority) {
            Ok(stage) => stage,
            Err(original) => {
                return Err(CowFailure {
                    original,
                    _candidate: None,
                    _work: None,
                    _resources: None,
                    _selected: Some(selected),
                    _baseline: Some(self),
                    _prior: None,
                });
            }
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<()> {
            input.require_authority(stage._authority)?;
            ensure!(
                Arc::ptr_eq(&self.candidate, input.accepted()),
                "baseline capture accepted owner differs"
            );
            same_stores(&self.stores, &stage.resources.stores)?;
            let (bootstrap, fingerprint, revision) =
                selected.primary_read_proof(self.candidate.state.revision_base)?;
            ensure!(
                bootstrap == self.bootstrap
                    && revision == self.candidate.state.revision
                    && fingerprint.kind == effects.selector.boundary
                    && fingerprint.sha256 == effects.selector.boundary_digest,
                "baseline selected producer differs"
            );
            let r = &mut stage.resources;
            r.close_reader()?;
            r.reader = Some(selected.open_primary_reader(&r.roots)?);
            r.cow_frozen = true;
            let selector = r.selector()?;
            let gc = r.gc_record()?;
            ensure!(
                selector == effects.selector
                    && gc == effects.gc
                    && r.read_epoch(self.epoch.id)? == effects.epoch
                    && r.read_attempt(self.attempt.id)? == effects.attempt,
                "baseline captured publication effects differ"
            );
            let mut hash = Sha256::new();
            for ordinal in 0..self.members {
                let member = r.member(self.catalog, ordinal)?;
                let mapping = r.mapping(self.catalog, member.name_hash)?;
                // Captured mapping bytes, not just selected root/receipt equality.
                hash_mapping(&mut hash, member, mapping)?;
            }
            ensure!(
                <[u8; 32]>::from(hash.finalize()) == self.catalog_digest,
                "baseline captured mappings differ"
            );
            r.close_reader()?;
            Ok(())
        }))
        .unwrap_or_else(|payload| Err(original_panic(payload)));
        if let Err(original) = result {
            return Err(CowFailure {
                original,
                _candidate: None,
                _work: None,
                _resources: Some(stage.resources),
                _selected: Some(selected),
                _baseline: Some(self),
                _prior: None,
            });
        }
        drop(stage);
        Ok(CommittedBaseline {
            generation: self.candidate,
            selected,
            stores: self.stores,
            selector: effects.selector,
            epoch: effects.epoch,
            tail: effects.attempt,
            _grant: self._grant,
        })
    }
}
pub(super) fn hash_mapping(
    hash: &mut Sha256,
    member: CatalogMember,
    mapping: CatalogEntry,
) -> Result<()> {
    let mut mb = [0; records::CATALOG_MEMBER_BYTES];
    codec(member.encode(&mut mb))?;
    let mut eb = [0; records::CATALOG_ENTRY_BYTES];
    codec(mapping.encode(&mut eb))?;
    hash.update(mb);
    hash.update(eb);
    Ok(())
}
impl PrimaryResources {
    pub(super) fn selector(&mut self) -> Result<Selector> {
        self.read(META, b"selected", records::SELECTOR_BYTES, |b| {
            codec(Selector::decode(b.context("primary selector absent")?))
        })
    }
    pub(super) fn gc_record(&mut self) -> Result<GcState> {
        self.read(META, b"gc", records::GC_BYTES, |b| {
            codec(GcState::decode(b.context("primary GC absent")?))
        })
    }
    fn member(&mut self, catalog: CatalogId, ordinal: u64) -> Result<CatalogMember> {
        let scope = self.scope;
        self.read(
            MEMBERS,
            &CatalogMember::key(catalog, ordinal),
            records::CATALOG_MEMBER_BYTES,
            |b| {
                codec(CatalogMember::decode(
                    b.context("primary member absent")?,
                    catalog,
                    scope,
                    ordinal,
                ))
            },
        )
    }
}

impl CommittedBaseline {
    pub(crate) fn require_next_for_test(
        &self,
        position: &kasumi_raft::AppliedEntryContext,
    ) -> Result<()> {
        self.selected
            .require_next_primary_entry(position, self.generation.state.revision_base)
    }
}

// This constructor accepts only the actual sealed/verified replacement owner,
// never independently supplied roots, records, grants or a caller readiness flag.
impl CommittedBaseline {
    pub(super) fn from_replacement(owner: &mut PreparedReplacement) -> Result<Self> {
        let (generation, selected, stores, selector, epoch, tail, grant) =
            owner.take_baseline_parts()?;
        Ok(Self {
            generation,
            selected,
            stores,
            selector,
            epoch,
            tail,
            _grant: grant,
        })
    }
}
