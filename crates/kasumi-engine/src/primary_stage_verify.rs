//! One-pin accepted fresh graph verification. Ordinal intervals plus ordered
//! DTO ordinals and page ranges prove no aliases without an all-object set.
use super::*;
use kasumi_query::Record;

struct Collection {
    member: CatalogMember,
    manifest: Manifest,
    reference: ManifestRef,
    first: u64,
    last: u64,
    last_dto: u64,
    last_id: Name,
    pages: u64,
    rows: u64,
    totals: Totals,
}
pub(crate) struct BaselineVerifier<'guard, 'engine> {
    stage: PrimaryStage<'guard, 'engine>,
    work: Work,
    candidate: Arc<Generation>,
    bootstrap: [u8; 32],
    catalog: CatalogId,
    inventory: Inventory,
    epoch: Epoch,
    attempt: Attempt,
    member: u64,
    previous_end: Option<u64>,
    previous_name: Name,
    objects: u64,
    totals: Totals,
    collection: Option<Collection>,
    bound: bool,
    catalog_hash: Sha256,
    proof_grant: Reservation,
}
#[allow(
    clippy::result_large_err,
    reason = "Original failures, frozen source custody and preclaimed work move inline; boxing requires separate outer admission."
)]
impl<'guard, 'engine> BaselineVerifier<'guard, 'engine> {
    pub(crate) fn begin(
        stage: PrimaryStage<'guard, 'engine>,
        input: &PrimaryCandidate<'_>,
        catalog: &catalog::StagedCatalog,
    ) -> CowResult<Self> {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
            || -> Result<(Work, Reservation, Epoch, Attempt)> {
                input.require_authority(stage._authority)?;
                same_stores(
                    &stage.resources.stores,
                    input.roots().primary_installation().0,
                )?;
                ensure!(
                    stage.resources.scope == input.scope()
                        && stage.resources.bootstrap == input.bootstrap()
                        && catalog.scope() == input.scope(),
                    "accepted baseline scope differs"
                );
                let work = Work::allocate(&stage.resources)?;
                let proof_bytes = allocated(std::mem::size_of::<VerifiedBaseline>())?
                    .checked_add(allocated(std::mem::size_of::<Self>())?)
                    .context("baseline owner quote overflow")?;
                let proof_grant = input
                    .roots()
                    .primary_installation()
                    .1
                    .reserve_application_source(proof_bytes)?;
                Ok((
                    work,
                    proof_grant,
                    stage.resources.epoch.context("fresh epoch absent")?,
                    stage.resources.attempt.context("fresh attempt absent")?,
                ))
            },
        ))
        .unwrap_or_else(|payload| Err(original_panic(payload)));
        let (work, proof_grant, epoch, attempt) = match outcome {
            Ok(value) => value,
            Err(original) => {
                return Err(CowFailure {
                    original,
                    _candidate: Some(input.accepted().clone()),
                    _work: None,
                    _resources: Some(stage.resources),
                    _selected: None,
                    _baseline: None,
                    _prior: None,
                });
            }
        };
        // Actual values are bound by the first positive step. Zero work does
        // not refresh a pin, mutate a journal or manufacture readiness.
        let inventory = Inventory {
            kind: ResourceKind::Catalog,
            phase: InventoryPhase::Complete,
            scope: input.scope(),
            id: catalog.id().0,
            tree_id: [0; 16],
            encoded_bytes: 0,
            sha256: [0; 32],
            total_units: catalog.member_count(),
            completed_units: catalog.member_count(),
            cleanup_unit_cursor: 0,
            catalog_dense_count: catalog.member_count(),
        };
        Ok(Self {
            stage,
            work,
            candidate: input.accepted().clone(),
            bootstrap: input.bootstrap(),
            catalog: catalog.id(),
            inventory,
            epoch,
            attempt,
            member: 0,
            previous_end: None,
            previous_name: Name::NONE,
            objects: 1,
            totals: Totals::default(),
            collection: None,
            bound: false,
            catalog_hash: Sha256::new(),
            proof_grant,
        })
    }
    /// A unit examines one collection header, page entry, or closing frame.
    /// A DTO uses bounded 64 KiB chunks; serializer latency has the same explicit
    /// per-value limit as the existing checked writer, not a preemption claim.
    pub(crate) fn step(self, units: usize) -> CowResult<(Self, bool)> {
        self.step_checked(units, &mut || Ok(()))
    }
    pub(crate) fn step_checked(
        mut self,
        units: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> CowResult<(Self, bool)> {
        if units == 0 {
            return Ok((self, false));
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<bool> {
            check()?;
            if !self.bound {
                self.bind()?;
            }
            for _ in 0..units.min(64) {
                check()?;
                if self.collection.is_none() {
                    if self.member == self.inventory.total_units {
                        self.finish_counts()?;
                        return Ok(true);
                    }
                    self.begin_collection(check)?;
                } else if self.work.frames.is_empty() {
                    self.finish_collection()?;
                } else {
                    self.entry(check)?;
                }
            }
            Ok(false)
        }))
        .unwrap_or_else(|payload| Err(original_panic(payload)));
        match result {
            Ok(done) => Ok((self, done)),
            Err(original) => Err(CowFailure {
                original,
                _candidate: Some(self.candidate),
                _work: Some(self.work),
                _resources: Some(self.stage.resources),
                _selected: None,
                _baseline: None,
                _prior: None,
            }),
        }
    }
    fn bind(&mut self) -> Result<()> {
        self.stage.resources.refresh()?;
        let r = &mut self.stage.resources;
        ensure!(
            r.read(META, b"selected", records::SELECTOR_BYTES, |bytes| Ok(
                bytes.is_none()
            ))?,
            "accepted first baseline already has a selector"
        );
        let actual = r.read_inventory(self.catalog.0)?;
        PrimaryResources::require_catalog_inventory(actual)?;
        ensure!(
            actual == self.inventory && actual.phase == InventoryPhase::Complete,
            "accepted catalog inventory differs"
        );
        let attempt = r.read_attempt(self.attempt.id)?;
        let epoch = r.read_epoch(self.epoch.id)?;
        let gc = r.read(META, b"gc", records::GC_BYTES, |bytes| {
            codec(GcState::decode(bytes.context("GC absent")?))
        })?;
        ensure!(
            attempt == self.attempt
                && epoch == self.epoch
                && attempt.phase == AttemptPhase::Building
                && attempt.id == self.catalog.0.attempt
                && attempt.epoch == epoch.id
                && attempt.scope == r.scope
                && epoch.scope == r.scope
                && epoch.head == Some(attempt.id)
                && epoch.tail == Some(attempt.id)
                && epoch.pending == Some(attempt.id)
                && attempt.previous.is_none()
                && attempt.next.is_none()
                && attempt.retire_count == 0
                && attempt.abort_object_cursor == 0
                && attempt.retire_cursor == 0
                && attempt.journal_erase_cursor == 0
                && gc.current.is_none()
                && gc.building == Some(epoch.id)
                && gc.retired.is_none()
                && actual.total_units == self.candidate.state.collections.len() as u64,
            "accepted fresh journal differs"
        );
        r.cow_frozen = true;
        self.bound = true;
        Ok(())
    }
    fn begin_collection(&mut self, check: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        let r = &mut self.stage.resources;
        let scope = r.scope;
        let catalog = self.catalog;
        let ordinal = self.member;
        let member = r.read(
            MEMBERS,
            &CatalogMember::key(self.catalog, self.member),
            records::CATALOG_MEMBER_BYTES,
            |bytes| {
                codec(CatalogMember::decode(
                    bytes.context("accepted catalog member absent")?,
                    catalog,
                    scope,
                    ordinal,
                ))
            },
        )?;
        ensure!(
            self.previous_name.len == 0 || self.previous_name.text() < member.name(),
            "accepted catalog order differs"
        );
        let accepted = self
            .candidate
            .state
            .collections
            .get(member.name())
            .context("accepted collection absent")?;
        let mapping = r.mapping(self.catalog, member.name_hash)?;
        ensure!(mapping.scope == r.scope, "accepted mapping scope differs");
        baseline::hash_mapping(&mut self.catalog_hash, member, mapping)?;
        let manifest = r.manifest(mapping.manifest)?;
        codec(manifest.validate_context(r.scope, member.name_hash, self.candidate.state.revision))?;
        ensure!(
            manifest.revision == self.candidate.state.revision
                && manifest.data_epoch == accepted.data_epoch,
            "accepted manifest revision differs"
        );
        r.check_complete(
            mapping.manifest.id,
            manifest.tree_id,
            ResourceKind::CollectionManifest,
            records::MANIFEST_BYTES as u64,
            mapping.manifest.sha256,
        )?;
        let first = manifest.definition.id.ordinal;
        let last = mapping.manifest.id.ordinal;
        ensure!(
            manifest.definition.id.attempt == self.attempt.id
                && mapping.manifest.id.attempt == self.attempt.id
                && first < last
                && last < self.attempt.next_object
                && self.previous_end.is_none_or(|prior| prior < first)
                && !(first..=last).contains(&self.catalog.0.ordinal),
            "accepted resource interval overlaps"
        );
        r.canonical(
            manifest.definition,
            manifest.tree_id,
            CanonicalDto::Definition(&accepted.definition),
            check,
        )?;
        if manifest.root.is_some() {
            self.work.frames.push(Frame::root(manifest)?);
        }
        self.collection = Some(Collection {
            member,
            manifest,
            reference: mapping.manifest,
            first,
            last,
            last_dto: first,
            last_id: Name::NONE,
            pages: 0,
            rows: 0,
            totals: Totals::default(),
        });
        Ok(())
    }
    fn entry(&mut self, check: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        let collection = self.collection.as_mut().expect("bound collection");
        let index = self.work.frames.len() - 1;
        let frame = self.work.frames[index];
        self.work.read_page(
            &mut self.stage.resources,
            frame,
            collection.manifest.tree_id,
        )?;
        let page = codec(tree::validate(
            &self.work.page,
            frame.expected(collection.manifest.tree_id),
        ))?;
        if frame.next == 0 {
            ensure!(
                frame.reference.id.attempt == self.attempt.id
                    && frame.reference.id.ordinal > collection.first
                    && frame.reference.id.ordinal < collection.last,
                "accepted page outside resource interval"
            );
            self.stage.resources.check_complete(
                frame.reference.id,
                collection.manifest.tree_id,
                ResourceKind::Page,
                tree::PAGE_BYTES as u64,
                frame.reference.sha256,
            )?;
            collection.pages = collection
                .pages
                .checked_add(1)
                .context("page count overflow")?;
        }
        let Some(entry) = page.entries().nth(frame.next) else {
            self.work.frames.pop();
            return Ok(());
        };
        // The validated page borrows the immutable local frame's bounds.
        // Advance only the stored traversal cursor, leaving those bounds live.
        let next = frame.next + 1;
        self.work.frames[index].next = next;
        match entry.value {
            Value::Child(child) => {
                ensure!(
                    self.work.frames.len() < DEPTH,
                    "accepted graph depth exceeded"
                );
                let upper = page
                    .entries()
                    .nth(next)
                    .map(|next| next.id)
                    .or(frame.upper.optional());
                self.work.frames.push(Frame {
                    reference: child.reference,
                    level: frame.level - 1,
                    generation: page.spec().generation,
                    totals: child.totals,
                    lower: Name::new(Some(entry.id))?,
                    upper: Name::new(upper)?,
                    next: 0,
                });
            }
            Value::Leaf(leaf) => {
                ensure!(
                    collection.last_id.len == 0 || collection.last_id.text() < entry.id,
                    "accepted row order differs"
                );
                ensure!(
                    leaf.object.id.attempt == self.attempt.id
                        && leaf.object.id.ordinal > collection.last_dto
                        && leaf.object.id.ordinal < collection.last,
                    "accepted DTO alias/order differs"
                );
                let state = self
                    .candidate
                    .state
                    .collections
                    .get(collection.member.name())
                    .expect("accepted collection retained");
                ensure!(
                    !(state.documents.contains_key(entry.id)
                        && state.archived_documents.contains_key(entry.id)),
                    "accepted graph contains hydrated duplicate"
                );
                let record = crate::index_source::record(state, entry.id, state.data_epoch)?
                    .context("accepted row absent")?;
                ensure!(
                    record.version() == leaf.version,
                    "accepted row version differs"
                );
                let totals = match record {
                    Record::Live(document) => {
                        ensure!(leaf.kind == RecordKind::Live, "accepted row kind differs");
                        let mut count = CountHash::new();
                        {
                            let mut writer = check::CheckedWriter::new(&mut count, check);
                            let serialized = serde_json::to_writer(&mut writer, &document.body)
                                .map_err(Into::into);
                            writer.finish(serialized)?;
                        }
                        ensure!(
                            count.bytes == leaf.semantic_bytes,
                            "accepted body accounting differs"
                        );
                        self.stage.resources.canonical(
                            leaf.object,
                            collection.manifest.tree_id,
                            CanonicalDto::Live(document),
                            check,
                        )?;
                        Totals {
                            live_count: 1,
                            live_body_bytes: count.bytes,
                            ..Totals::default()
                        }
                    }
                    Record::Archived(document) => {
                        ensure!(
                            leaf.kind == RecordKind::Archived
                                && codec(tree::archived_metadata_bytes(
                                    entry.id,
                                    leaf.object.encoded_bytes
                                ))? == leaf.semantic_bytes,
                            "accepted archive accounting differs"
                        );
                        self.stage.resources.canonical(
                            leaf.object,
                            collection.manifest.tree_id,
                            CanonicalDto::Archived(document),
                            check,
                        )?;
                        Totals {
                            archived_count: 1,
                            archived_metadata_bytes: leaf.semantic_bytes,
                            ..Totals::default()
                        }
                    }
                };
                collection.totals = codec(collection.totals.add(totals))?;
                collection.rows = collection
                    .rows
                    .checked_add(1)
                    .context("row count overflow")?;
                collection.last_id = Name::new(Some(entry.id))?;
                collection.last_dto = leaf.object.id.ordinal;
            }
        }
        Ok(())
    }
    fn finish_collection(&mut self) -> Result<()> {
        let collection = self.collection.take().expect("bound collection");
        let accepted = self
            .candidate
            .state
            .collections
            .get(collection.member.name())
            .expect("accepted collection retained");
        let count = collection
            .pages
            .checked_add(collection.rows)
            .and_then(|n| n.checked_add(2))
            .context("resource count overflow")?;
        ensure!(
            count == collection.last - collection.first + 1
                && collection.totals == collection.manifest.totals
                && collection.totals.live_count == accepted.documents.len() as u64
                && collection.totals.archived_count == accepted.archived_documents.len() as u64
                && collection.totals.archived_metadata_bytes
                    == accepted.archived_document_bytes as u64,
            "accepted unique resource cardinality/totals differs"
        );
        ensure!(
            collection.reference.id.ordinal == collection.last,
            "accepted closing manifest differs"
        );
        self.objects = self
            .objects
            .checked_add(count)
            .context("resource total overflow")?;
        self.totals = codec(self.totals.add(collection.totals))?;
        self.previous_end = Some(collection.last);
        self.previous_name = Name::new(Some(collection.member.name()))?;
        self.member = self
            .member
            .checked_add(1)
            .context("member count overflow")?;
        Ok(())
    }
    fn finish_counts(&self) -> Result<()> {
        ensure!(
            self.objects == self.attempt.next_object
                && self.objects == self.attempt.live_resources
                && self.objects == self.epoch.live_resources
                && self
                    .totals
                    .live_count
                    .checked_add(self.totals.archived_count)
                    == Some(self.candidate.state.document_count)
                && self.totals.live_body_bytes == self.candidate.state.logical_bytes,
            "accepted complete graph cardinality differs"
        );
        Ok(())
    }
    pub(crate) fn finish(mut self) -> CowResult<VerifiedBaseline> {
        if !self.bound || self.collection.is_some() || self.member != self.inventory.total_units {
            return Err(CowFailure {
                original: anyhow::anyhow!("accepted baseline verification incomplete"),
                _candidate: Some(self.candidate),
                _work: Some(self.work),
                _resources: Some(self.stage.resources),
                _selected: None,
                _baseline: None,
                _prior: None,
            });
        }
        if let Err(original) = self.finish_counts() {
            return Err(CowFailure {
                original,
                _candidate: Some(self.candidate),
                _work: Some(self.work),
                _resources: Some(self.stage.resources),
                _selected: None,
                _baseline: None,
                _prior: None,
            });
        }
        let closed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.stage.resources.close_reader()
        }))
        .unwrap_or_else(|payload| Err(original_panic(payload)));
        if let Err(original) = closed {
            return Err(CowFailure {
                original,
                _candidate: Some(self.candidate),
                _work: Some(self.work),
                _resources: Some(self.stage.resources),
                _selected: None,
                _baseline: None,
                _prior: None,
            });
        }
        let proof = VerifiedBaseline {
            candidate: self.candidate,
            stores: self.stage.resources.stores.clone(),
            scope: self.stage.resources.scope,
            bootstrap: self.bootstrap,
            catalog: self.catalog,
            epoch: self.epoch,
            attempt: self.attempt,
            members: self.member,
            totals: self.totals,
            catalog_digest: self.catalog_hash.finalize().into(),
            _grant: self.proof_grant,
        };
        drop(self.work);
        drop(self.stage);
        Ok(proof)
    }
}
