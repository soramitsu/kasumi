//! Existing-key, live-to-live physical COW only. The pending result cannot
//! publish or select; it retains the original accepted borrow's apply guard.
use super::*;
use crate::state::primary_projection::Replacement;
#[path = "primary_stage_publish.rs"]
mod publication;
pub(crate) use publication::{PreparedReplacement, PublicationFailure};

struct Edited {
    old: Manifest,
    old_ref: ManifestRef,
    new: Manifest,
    new_ref: ManifestRef,
    object: OverflowRef,
    name: Name,
    id: Name,
}
pub(crate) struct PendingReplacement<'guard, 'engine> {
    stage: PrimaryStage<'guard, 'engine>,
    work: Work,
    prior: CommittedBaseline,
    candidate: Arc<Generation>,
    old_manifest: Manifest,
    old_reference: ManifestRef,
    manifest: Manifest,
    reference: ManifestRef,
    object: OverflowRef,
    name: Name,
    id: Name,
}
#[allow(
    clippy::result_large_err,
    reason = "Original failures, frozen source custody and preclaimed work move inline; boxing requires separate outer admission."
)]
impl<'guard, 'engine> PendingReplacement<'guard, 'engine> {
    pub(crate) fn prepare(
        authority: &'guard mut PrimaryApplyGuard<'engine>,
        input: &PrimaryCandidate<'_>,
        prior: CommittedBaseline,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> CowResult<Self> {
        let mut stage = match PrimaryStage::allocate(authority) {
            Ok(stage) => stage,
            Err(original) => {
                return Err(CowFailure {
                    original,
                    _candidate: Some(input.accepted().clone()),
                    _work: None,
                    _resources: None,
                    _selected: None,
                    _baseline: None,
                    _prior: Some(prior),
                });
            }
        };
        let mut work = None;
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<Edited> {
                check()?;
                input.require_authority(stage._authority)?;
                ensure!(
                    stage.resources.scope == input.scope()
                        && stage.resources.bootstrap == input.bootstrap(),
                    "COW authority scope differs"
                );
                ensure!(
                    Arc::ptr_eq(input.previous(), &prior.generation),
                    "COW prior accepted owner differs"
                );
                same_stores(&prior.stores, &stage.resources.stores)?;
                ensure!(
                    input.scope() == prior.selector.scope
                        && input.bootstrap() == prior.selector.bootstrap_sha256,
                    "COW scope/bootstrap differs"
                );
                let (bootstrap, fingerprint, revision) = prior
                    .selected
                    .primary_read_proof(prior.generation.state.revision_base)?;
                ensure!(
                    bootstrap == input.bootstrap()
                        && revision == prior.generation.state.revision
                        && revision == prior.selector.revision
                        && fingerprint.kind == prior.selector.boundary
                        && fingerprint.sha256 == prior.selector.boundary_digest,
                    "COW prior producer differs"
                );
                let replacement = input.replacement()?;
                let name = Name::new(Some(replacement.collection()))?;
                let id = Name::new(Some(replacement.id()))?;
                work = Some(Work::allocate(&stage.resources)?);
                let work = work.as_mut().expect("allocated COW work");
                let r = &mut stage.resources;
                let selected = r.selector()?;
                ensure!(selected == prior.selector, "COW current selector differs");
                let gc = r.gc_record()?;
                let epoch = r.read_epoch(prior.epoch.id)?;
                let tail = r.read_attempt(prior.tail.id)?;
                ensure!(
                    gc.current == Some(epoch.id)
                        && gc.building.is_none()
                        && gc.retired.is_none()
                        && epoch == prior.epoch
                        && epoch.pending.is_none()
                        && tail == prior.tail
                        && tail.phase == AttemptPhase::Committed
                        && tail.next.is_none(),
                    "COW committed journal differs"
                );
                // Bind one mapping on the capability's exact captured source; a
                // current selector alone cannot certify its current mapping.
                let name_hash = codec(records::name_hash(name.text()))?;
                r.close_reader()?;
                r.reader = Some(prior.selected.open_primary_reader(&r.roots)?);
                let prior_mapping = r.mapping(prior.selector.catalog, name_hash)?;
                let prior_cursor = r
                    .reader
                    .as_mut()
                    .context("prior reader absent")?
                    .primary_applied_cursor_fingerprint(&mut r.reservation, r.baseline)?;
                r.close_reader()?;
                r.reader = Some(r.roots.open_primary_current()?);
                ensure!(
                    r.selector()? == selected,
                    "COW selector changed during point binding"
                );
                let mapping = r.mapping(selected.catalog, name_hash)?;
                let current_cursor = r
                    .reader
                    .as_mut()
                    .context("current reader absent")?
                    .primary_applied_cursor_fingerprint(&mut r.reservation, r.baseline)?;
                ensure!(
                    current_cursor == prior_cursor,
                    "COW current durable predecessor differs from captured prior"
                );
                let current_gc = r.gc_record()?;
                ensure!(
                    current_gc == gc
                        && r.read_epoch(epoch.id)? == epoch
                        && r.read_attempt(tail.id)? == tail,
                    "COW current journal changed during point binding"
                );
                r.gc = Some(current_gc);
                ensure!(
                    mapping == prior_mapping,
                    "COW current mapping differs from captured prior"
                );
                ensure!(mapping.scope == r.scope, "COW mapping scope differs");
                let old = r.manifest(mapping.manifest)?;
                let previous = input
                    .previous()
                    .state
                    .collections
                    .get(name.text())
                    .context("COW prior collection absent")?;
                codec(old.validate_context(r.scope, mapping.name_hash, revision))?;
                ensure!(
                    old.data_epoch == previous.data_epoch,
                    "COW previous data epoch differs"
                );
                r.check_complete(
                    mapping.manifest.id,
                    old.tree_id,
                    ResourceKind::CollectionManifest,
                    records::MANIFEST_BYTES as u64,
                    mapping.manifest.sha256,
                )?;
                let mut frame = Frame::root(old)?;
                loop {
                    check()?;
                    ensure!(work.frames.len() < DEPTH, "COW path depth exceeded");
                    work.read_page(r, frame, old.tree_id)?;
                    r.check_complete(
                        frame.reference.id,
                        old.tree_id,
                        ResourceKind::Page,
                        tree::PAGE_BYTES as u64,
                        frame.reference.sha256,
                    )?;
                    work.target(frame.reference.id)?;
                    work.frames.push(frame);
                    let page = codec(tree::validate(&work.page, frame.expected(old.tree_id)))?;
                    if frame.level == 0 {
                        let leaf =
                            codec(page.lookup(id.text()))?.context("COW existing leaf absent")?;
                        ensure!(
                            leaf.kind == RecordKind::Live
                                && leaf.version == replacement.old().version,
                            "COW prior leaf differs"
                        );
                        let bytes = body_bytes(replacement.old(), check)?;
                        ensure!(
                            leaf.semantic_bytes == bytes,
                            "COW prior body accounting differs"
                        );
                        r.canonical(
                            leaf.object,
                            old.tree_id,
                            CanonicalDto::Live(replacement.old()),
                            check,
                        )?;
                        work.target(leaf.object.id)?;
                        break;
                    }
                    frame = Frame::from_expected(codec(page.route(id.text()))?)?;
                }
                work.target(mapping.manifest.id)?;
                // All preconditions and the complete actual row diff precede effects.
                r.begin_incremental(epoch, tail, check)?;
                let object = r.stage_dto(
                    old.tree_id,
                    CanonicalDto::Live(replacement.new_document()),
                    check,
                )?;
                let leaf = Leaf {
                    version: replacement.new_document().version,
                    kind: RecordKind::Live,
                    object,
                    semantic_bytes: body_bytes(replacement.new_document(), check)?,
                };
                let mut child = None;
                for depth in (0..work.frames.len()).rev() {
                    check()?;
                    let frame = work.frames[depth];
                    work.read_page(r, frame, old.tree_id)?;
                    let page = codec(tree::validate(&work.page, frame.expected(old.tree_id)))?;
                    // The real Work grant preclaims this one bounded heap backing.
                    // It retires before that grant on success, refusal and unwind.
                    let mut entries = work.entry_workspace()?;
                    let mut len = 0;
                    let mut replaced = 0;
                    let wanted = if depth + 1 < work.frames.len() {
                        Some(work.frames[depth + 1].reference)
                    } else {
                        None
                    };
                    for entry in page.entries() {
                        ensure!(len < ENTRIES, "COW entry capacity exceeded");
                        let mut entry = entry;
                        if frame.level == 0 && entry.id == id.text() {
                            entry.value = Value::Leaf(leaf);
                            replaced += 1;
                        } else if let (Some(wanted), Value::Child(old_child)) =
                            (wanted, entry.value)
                            && old_child.reference == wanted
                        {
                            let new: EncodedPage = child.context("COW replacement child absent")?;
                            entry.value = Value::Child(Child {
                                reference: new.reference,
                                totals: new.totals,
                            });
                            replaced += 1;
                        }
                        entries.push(entry);
                        len += 1;
                    }
                    ensure!(replaced == 1, "COW path replacement count differs");
                    let encoded = r.stage_page(
                        old.tree_id,
                        replacement.data_epoch(),
                        frame.level,
                        &entries[..len],
                    )?;
                    work.new_pages.push(encoded);
                    child = Some(encoded);
                }
                let root = child.context("COW new root absent")?;
                let manifest = Manifest {
                    data_epoch: replacement.data_epoch(),
                    revision: replacement.revision(),
                    root: Some(Root {
                        reference: root.reference,
                        level: old.root.context("old root absent")?.level,
                    }),
                    totals: root.totals,
                    ..old
                };
                let reference = r.stage_manifest(manifest)?;
                for target in &work.targets {
                    check()?;
                    r.append_retire(*target)?;
                }
                // One new frozen native root for ALL verification. No refresh or
                // writable helper survives this transition.
                r.refresh()?;
                r.cow_frozen = true;
                verify_delta(
                    r,
                    work,
                    &prior,
                    &replacement,
                    old,
                    mapping.manifest,
                    manifest,
                    reference,
                    object,
                    check,
                )?;
                Ok(Edited {
                    old,
                    old_ref: mapping.manifest,
                    new: manifest,
                    new_ref: reference,
                    object,
                    name,
                    id,
                })
            }))
            .unwrap_or_else(|payload| Err(original_panic(payload)));
        match outcome {
            Ok(Edited {
                old: old_manifest,
                old_ref: old_reference,
                new: manifest,
                new_ref: reference,
                object,
                name,
                id,
            }) => Ok(Self {
                stage,
                work: work.expect("successful work"),
                prior,
                candidate: input.accepted().clone(),
                old_manifest,
                old_reference,
                manifest,
                reference,
                object,
                name,
                id,
            }),
            Err(original) => Err(CowFailure {
                original,
                _candidate: Some(input.accepted().clone()),
                _work: work,
                _resources: Some(stage.resources),
                _selected: None,
                _baseline: None,
                _prior: Some(prior),
            }),
        }
    }
    pub(crate) fn manifest(&self) -> Manifest {
        self.manifest
    }
    pub(crate) fn manifest_ref(&self) -> ManifestRef {
        self.reference
    }
    pub(crate) fn object(&self) -> OverflowRef {
        self.object
    }
    pub(crate) fn attempt(&self) -> Attempt {
        self.stage.resources.attempt.expect("pending attempt")
    }
    pub(crate) fn old_manifest(&self) -> Manifest {
        self.old_manifest
    }
    pub(crate) fn old_manifest_ref(&self) -> ManifestRef {
        self.old_reference
    }
    pub(crate) fn collection(&self) -> &str {
        self.name.text()
    }
    pub(crate) fn id(&self) -> &str {
        self.id.text()
    }
    /// Positive close releases the frozen work pin; durable unselected objects
    /// remain journaled for a newly acquired incremental abort owner.
    pub(crate) fn close(mut self) -> CowResult<CommittedBaseline> {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.stage.resources.close_reader()
        }))
        .unwrap_or_else(|payload| Err(original_panic(payload)));
        if let Err(original) = outcome {
            return Err(CowFailure {
                original,
                _candidate: Some(self.candidate),
                _work: Some(self.work),
                _resources: Some(self.stage.resources),
                _selected: None,
                _baseline: None,
                _prior: Some(self.prior),
            });
        }
        drop(self.work);
        drop(self.stage);
        drop(self.candidate);
        Ok(self.prior)
    }
}
fn body_bytes(document: &Document, check: &mut dyn FnMut() -> Result<()>) -> Result<u64> {
    let mut count = CountHash::new();
    let mut writer = check::CheckedWriter::new(&mut count, check);
    let serialized = serde_json::to_writer(&mut writer, &document.body).map_err(Into::into);
    writer.finish(serialized)?;
    Ok(count.bytes)
}
impl PrimaryResources {
    fn begin_incremental(
        &mut self,
        mut epoch: Epoch,
        tail: Attempt,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        check()?;
        let id = *uuid::Uuid::new_v4().as_bytes();
        ensure!(
            id != tail.id
                && self.read(ATTEMPTS, &id, records::ATTEMPT_BYTES, |b| Ok(b.is_none()))?,
            "COW attempt identity collision"
        );
        let attempt = Attempt {
            phase: AttemptPhase::Building,
            scope: self.scope,
            epoch: epoch.id,
            id,
            previous: Some(tail.id),
            next: None,
            next_object: 0,
            live_resources: 0,
            retire_count: 0,
            abort_object_cursor: 0,
            retire_cursor: 0,
            journal_erase_cursor: 0,
        };
        epoch.pending = Some(id);
        let mut ab = [0; records::ATTEMPT_BYTES];
        codec(attempt.encode(&mut ab))?;
        let mut eb = [0; records::EPOCH_BYTES];
        codec(epoch.encode(&mut eb))?;
        self.put(ATTEMPTS, &id, &ab)?;
        self.put(EPOCHS, &epoch.id, &eb)?;
        self.write()?;
        self.epoch = Some(epoch);
        self.attempt = Some(attempt);
        Ok(())
    }
    fn append_retire(&mut self, target: ObjectId) -> Result<()> {
        let mut attempt = self.attempt.context("COW attempt absent")?;
        ensure!(
            attempt.phase == AttemptPhase::Building && target.attempt != attempt.id,
            "COW retire owner differs"
        );
        let id = ObjectId {
            attempt: attempt.id,
            ordinal: attempt.retire_count,
        };
        ensure!(
            self.read(RETIRES, &object_key(id), records::RETIRE_BYTES, |b| Ok(
                b.is_none()
            ))?,
            "COW retire intention already exists"
        );
        let mut rb = [0; records::RETIRE_BYTES];
        codec(Retire { target }.encode(&mut rb))?;
        attempt.retire_count = attempt
            .retire_count
            .checked_add(1)
            .context("COW retire count overflow")?;
        let mut ab = [0; records::ATTEMPT_BYTES];
        codec(attempt.encode(&mut ab))?;
        self.put(RETIRES, &object_key(id), &rb)?;
        self.put(ATTEMPTS, &attempt.id, &ab)?;
        self.write()?;
        self.attempt = Some(attempt);
        Ok(())
    }
}
#[allow(clippy::too_many_arguments)]
fn verify_delta(
    r: &mut PrimaryResources,
    work: &mut Work,
    prior: &CommittedBaseline,
    replacement: &Replacement<'_>,
    old: Manifest,
    old_ref: ManifestRef,
    new: Manifest,
    new_ref: ManifestRef,
    object: OverflowRef,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    ensure!(r.cow_frozen, "COW verification pin not frozen");
    let attempt = r.read_attempt(r.attempt.context("COW attempt absent")?.id)?;
    let epoch = r.read_epoch(prior.epoch.id)?;
    let count = work.frames.len() as u64 + 2;
    ensure!(
        Some(attempt) == r.attempt
            && Some(epoch) == r.epoch
            && attempt.next_object == count
            && attempt.live_resources == count
            && attempt.retire_count == count
            && epoch.live_resources
                == prior
                    .epoch
                    .live_resources
                    .checked_add(count)
                    .context("COW resource overflow")?
            && epoch.pending == Some(attempt.id)
            && epoch.head == prior.epoch.head
            && epoch.tail == prior.epoch.tail
            && r.read_attempt(prior.tail.id)? == prior.tail
            && r.selector()? == prior.selector
            && Some(r.gc_record()?) == r.gc,
        "COW final pending journal differs"
    );
    ensure!(
        r.mapping(prior.selector.catalog, old.name_hash)?.manifest == old_ref,
        "COW selected mapping changed"
    );
    verify_graph(
        r,
        work,
        replacement.new_document(),
        replacement.id(),
        replacement.data_epoch(),
        replacement.revision(),
        old,
        old_ref,
        new,
        new_ref,
        object,
        check,
    )
}
#[allow(clippy::too_many_arguments)]
fn verify_graph(
    r: &mut PrimaryResources,
    work: &mut Work,
    document: &Document,
    id: &str,
    data_epoch: u64,
    revision: u64,
    old: Manifest,
    old_ref: ManifestRef,
    new: Manifest,
    new_ref: ManifestRef,
    object: OverflowRef,
    check: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    ensure!(r.cow_frozen, "COW graph verification pin not frozen");
    let attempt = r.attempt.context("COW graph attempt absent")?;
    let count = work.frames.len() as u64 + 2;
    r.check_complete(
        old_ref.id,
        old.tree_id,
        ResourceKind::CollectionManifest,
        records::MANIFEST_BYTES as u64,
        old_ref.sha256,
    )?;
    ensure!(
        r.manifest(old_ref)? == old && r.manifest(new_ref)? == new,
        "COW manifest bytes differ"
    );
    ensure!(
        new.definition == old.definition
            && new.tree_id == old.tree_id
            && new.name_hash == old.name_hash
            && new.scope == old.scope
            && new.data_epoch == data_epoch
            && new.revision == revision,
        "COW manifest context differs"
    );
    r.check_complete(
        new_ref.id,
        new.tree_id,
        ResourceKind::CollectionManifest,
        records::MANIFEST_BYTES as u64,
        new_ref.sha256,
    )?;
    r.canonical(object, new.tree_id, CanonicalDto::Live(document), check)?;
    let leaf = Leaf {
        version: document.version,
        kind: RecordKind::Live,
        object,
        semantic_bytes: body_bytes(document, check)?,
    };
    let mut child = None;
    for depth in (0..work.frames.len()).rev() {
        check()?;
        let old_frame = work.frames[depth];
        work.read_page(r, old_frame, old.tree_id)?;
        r.check_complete(
            old_frame.reference.id,
            old.tree_id,
            ResourceKind::Page,
            tree::PAGE_BYTES as u64,
            old_frame.reference.sha256,
        )?;
        if old_frame.level == 0 {
            let page = codec(tree::validate(&work.page, old_frame.expected(old.tree_id)))?;
            let old_leaf = codec(page.lookup(id))?.context("COW old leaf absent")?;
            ensure!(
                old_leaf.kind == RecordKind::Live,
                "COW old leaf kind differs"
            );
            r.check_complete(
                old_leaf.object.id,
                old.tree_id,
                ResourceKind::Live,
                old_leaf.object.encoded_bytes,
                old_leaf.object.sha256,
            )?;
        }
        let encoded = work.new_pages[work.frames.len() - 1 - depth];
        let mut expected = old_frame;
        expected.reference = encoded.reference;
        expected.totals = encoded.totals;
        expected.generation = new.data_epoch;
        work.next_page.clear();
        r.read(
            PAGES,
            &object_key(encoded.reference.id),
            tree::PAGE_BYTES,
            |b| {
                let bytes = b.context("COW new page absent")?;
                codec(tree::validate(bytes, expected.expected(new.tree_id)))?;
                work.next_page.extend_from_slice(bytes);
                Ok(())
            },
        )?;
        r.check_complete(
            encoded.reference.id,
            new.tree_id,
            ResourceKind::Page,
            tree::PAGE_BYTES as u64,
            encoded.reference.sha256,
        )?;
        ensure!(
            encoded.reference.id
                == ObjectId {
                    attempt: attempt.id,
                    ordinal: 1 + (work.frames.len() - 1 - depth) as u64
                },
            "COW page ordinal differs"
        );
        let before = codec(tree::validate(&work.page, old_frame.expected(old.tree_id)))?;
        let after = codec(tree::validate(
            &work.next_page,
            expected.expected(new.tree_id),
        ))?;
        ensure!(
            before.entries().len() == after.entries().len(),
            "COW page shape changed"
        );
        let wanted = if depth + 1 < work.frames.len() {
            Some(work.frames[depth + 1].reference)
        } else {
            None
        };
        let mut edits = 0;
        for (a, b) in before.entries().zip(after.entries()) {
            ensure!(a.id == b.id, "COW page keys changed");
            let expected_value = if old_frame.level == 0 && a.id == id {
                edits += 1;
                Value::Leaf(leaf)
            } else if let (Some(wanted), Value::Child(value)) = (wanted, a.value)
                && value.reference == wanted
            {
                edits += 1;
                let next: EncodedPage = child.context("COW verified child absent")?;
                Value::Child(Child {
                    reference: next.reference,
                    totals: next.totals,
                })
            } else {
                a.value
            };
            ensure!(b.value == expected_value, "COW off-path descriptor changed");
        }
        ensure!(
            edits == 1 && after.spec().generation == new.data_epoch,
            "COW page edit count/generation differs"
        );
        child = Some(encoded);
    }
    let root = child.context("COW verified root absent")?;
    ensure!(
        new.root
            == Some(Root {
                reference: root.reference,
                level: old.root.context("old root absent")?.level
            })
            && new.totals == root.totals
            && object.id
                == ObjectId {
                    attempt: attempt.id,
                    ordinal: 0
                }
            && new_ref.id
                == ObjectId {
                    attempt: attempt.id,
                    ordinal: count - 1
                },
        "COW final root/resource identity differs"
    );
    for (ordinal, target) in work.targets.iter().enumerate() {
        check()?;
        r.read(
            RETIRES,
            &object_key(ObjectId {
                attempt: attempt.id,
                ordinal: ordinal as u64,
            }),
            records::RETIRE_BYTES,
            |b| {
                ensure!(
                    codec(Retire::decode(b.context("COW retire intention absent")?))?.target
                        == *target,
                    "COW retire intention differs"
                );
                Ok(())
            },
        )?;
    }
    Ok(())
}
