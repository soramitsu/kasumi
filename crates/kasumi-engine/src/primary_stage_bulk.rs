//! Fresh physical collection projection, with one fixed frontier per supported
//! page level. No row-sized map/vector, ordinary-update rebuild fallback, COW,
//! candidate publication, schema/archive validation, or serving activation.
//!
//! Arbitrary CollectionRecords and caller revision/epoch do not prove accepted
//! generation provenance. BuiltCollection proves the observed ordered stream's
//! staged framing/reference closure only; the closed producer must still bind
//! and validate that stream before catalog/selector publication.
use super::*;
use crate::primary_tree::{
    self as tree, Child, EncodedPage, Entry, Leaf, RecordKind, Totals, Value,
    records::{Manifest, ManifestRef, Root},
};
use kasumi_query::{CollectionRecords, QueryCancellation, ReadFailure, Record};
use kasumi_types::{Error, ErrorCode};

#[cfg(test)]
#[path = "primary_stage_bulk_frontier_fixture.rs"]
pub(crate) mod frontier_fixture;

const LEVELS: usize = tree::MAX_LEVEL as usize + 1;
const SLOTS: usize = (tree::PAGE_BYTES - tree::HEADER_BYTES) / (2 + 1 + tree::DESCRIPTOR_BYTES);
const EMPTY_VALUE: Value = Value::Child(Child {
    reference: tree::PageRef {
        id: ObjectId {
            attempt: [0; 16],
            ordinal: 0,
        },
        sha256: [0; 32],
    },
    totals: Totals {
        live_count: 0,
        archived_count: 0,
        live_body_bytes: 0,
        archived_metadata_bytes: 0,
    },
});
#[derive(Clone, Copy)]
struct Name {
    bytes: [u8; tree::MAX_ID_BYTES],
    len: usize,
}
impl Name {
    const EMPTY: Self = Self {
        bytes: [0; tree::MAX_ID_BYTES],
        len: 0,
    };
    fn new(id: &str) -> Result<Self> {
        codec(tree::check_id(id))?;
        let mut name = Self::EMPTY;
        name.bytes[..id.len()].copy_from_slice(id.as_bytes());
        name.len = id.len();
        Ok(name)
    }
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).expect("copied UTF-8")
    }
}
#[derive(Clone, Copy)]
struct Slot {
    name: Name,
    value: Value,
}
impl Slot {
    const EMPTY: Self = Self {
        name: Name::EMPTY,
        value: EMPTY_VALUE,
    };
}
struct Level {
    slots: [Slot; SLOTS],
    len: usize,
    used: usize,
}
impl Level {
    fn empty() -> Self {
        Self {
            slots: [Slot::EMPTY; SLOTS],
            len: 0,
            used: tree::HEADER_BYTES,
        }
    }
    fn fits(&self, name: Name) -> bool {
        self.len < SLOTS && self.used + 2 + name.len + tree::DESCRIPTOR_BYTES <= tree::PAGE_BYTES
    }
    fn push(&mut self, slot: Slot) {
        assert!(self.fits(slot.name));
        self.slots[self.len] = slot;
        self.len += 1;
        self.used += 2 + slot.name.len + tree::DESCRIPTOR_BYTES;
    }
    fn clear(&mut self) {
        self.len = 0;
        self.used = tree::HEADER_BYTES;
    }
}
struct Frontier {
    levels: Vec<Level>,
    // Exact Vec backing always dies before its installed grant.
    reservation: Option<Reservation>,
}
struct Resources<'guard, 'engine> {
    stage: Option<PrimaryStage<'guard, 'engine>>,
    frontier: Frontier,
    tree: [u8; 16],
    generation: u64,
    last: Name,
    expected: Totals,
}

/// Intentionally not Clone, and no std::error::Error implementation that would
/// enable implicit anyhow boxing. Both independent original failures survive.
/// Enclosing caller shells/source lifecycle remain their owners' obligations.
pub(crate) struct BuildFailure<'guard, 'engine, E> {
    original: Option<anyhow::Error>,
    input: Option<ReadFailure<E>>,
    panic: Option<Box<dyn std::any::Any + Send>>,
    callback_panic: Option<Box<dyn std::any::Any + Send>>,
    resources: Resources<'guard, 'engine>,
}
impl<E> BuildFailure<'_, '_, E> {
    pub(crate) fn original(&self) -> Option<&anyhow::Error> {
        self.original.as_ref()
    }
    pub(crate) fn input(&self) -> Option<&ReadFailure<E>> {
        self.input.as_ref()
    }
    #[cfg(test)]
    pub(crate) fn panic_payload(&self) -> Option<&(dyn std::any::Any + Send)> {
        self.panic.as_deref()
    }
    #[cfg(test)]
    pub(crate) fn callback_panic_payload(&self) -> Option<&(dyn std::any::Any + Send)> {
        self.callback_panic.as_deref()
    }
    #[cfg(test)]
    pub(crate) fn retire_frontier_for_test(self) -> (usize, impl Send + 'static) {
        // Dispose errors and the non-Send apply guard while retaining the actual
        // production frontier owner for an allocator-boundary witness.
        let Self {
            original,
            input,
            panic,
            callback_panic,
            resources,
        } = self;
        drop((original, input, panic, callback_panic));
        let Resources {
            stage, frontier, ..
        } = resources;
        drop(stage);
        (frontier.levels.as_ptr() as usize, frontier)
    }
}
impl<E: std::fmt::Debug> std::fmt::Debug for BuildFailure<'_, '_, E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrimaryBulkFailure")
            .field("original", &self.original)
            .field("input", &self.input)
            .field("retains_panic", &self.panic.is_some())
            .field("retains_callback_panic", &self.callback_panic.is_some())
            .field("retained_levels", &self.resources.frontier.levels.len())
            .finish()
    }
}
/// Physical stream evidence only. This cannot authorize a catalog/selector or
/// claim the arbitrary input was the accepted application generation.
pub(crate) struct BuiltCollection {
    manifest: Manifest,
    reference: ManifestRef,
}
impl BuiltCollection {
    pub(crate) fn manifest(&self) -> &Manifest {
        &self.manifest
    }
    pub(crate) fn manifest_ref(&self) -> ManifestRef {
        self.reference
    }
}

#[allow(
    clippy::result_large_err,
    reason = "the stage, frontier and original failures retain inline custody; boxing would add a separately admitted shell"
)]
pub(crate) fn build_fresh_collection<'guard, 'engine, R: CollectionRecords + ?Sized>(
    stage: PrimaryStage<'guard, 'engine>,
    source: &R,
    revision: u64,
    data_epoch: u64,
    cancellation: &QueryCancellation,
) -> std::result::Result<
    (PrimaryStage<'guard, 'engine>, BuiltCollection),
    BuildFailure<'guard, 'engine, R::Failure>,
> {
    build_checked(stage, source, revision, data_epoch, &mut || {
        cancellation.check().map_err(Into::into)
    })
}

// Private borrowed checkpoint injection supports deterministic interruption
// tests without racing a timer or relaxing actual staging/admission behavior.
#[allow(
    clippy::result_large_err,
    reason = "the stage, frontier and original failures retain inline custody; boxing would add a separately admitted shell"
)]
pub(crate) fn build_checked<'guard, 'engine, R: CollectionRecords + ?Sized>(
    stage: PrimaryStage<'guard, 'engine>,
    source: &R,
    revision: u64,
    data_epoch: u64,
    check: &mut dyn FnMut() -> Result<()>,
) -> std::result::Result<
    (PrimaryStage<'guard, 'engine>, BuiltCollection),
    BuildFailure<'guard, 'engine, R::Failure>,
> {
    let mut resources = Resources {
        stage: Some(stage),
        frontier: Frontier {
            levels: Vec::new(),
            reservation: None,
        },
        tree: [0; 16],
        generation: data_epoch,
        last: Name::EMPTY,
        expected: Totals::default(),
    };
    let mut input = None;
    let mut callback_error = None;
    let mut callback_panic = None;
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<Option<BuiltCollection>> {
            check()?;
            resources.allocate()?;
            check()?;
            let identity = source.identity();
            let definition = source.definition();
            codec(tree::check_id(&definition.name))?;
            ensure!(
                identity.collection() == definition.name,
                "primary bulk collection identity differs"
            );
            let stage = resources.stage.as_ref().expect("live stage");
            ensure!(
                codec(records::scope_hash(
                    identity.tenant(),
                    identity.incarnation(),
                    stage._authority.bootstrap()
                ))? == stage.resources.scope,
                "primary bulk tenant/incarnation differs"
            );
            ensure!(
                data_epoch <= revision,
                "primary bulk epoch exceeds revision"
            );
            let stable = || -> Result<()> {
                ensure!(
                    source.identity() == identity && std::ptr::eq(source.definition(), definition),
                    "primary bulk input owner/definition changed"
                );
                Ok(())
            };
            stable()?;
            let definition_ref = resources.dto(CanonicalDto::Definition(definition), check)?;
            let visited = source.visit_records(|id, record| {
                // A hostile/buggy source may swallow the previous wire refusal or
                // call again. The retained original permanently closes this pass.
                if callback_error.is_some() || callback_panic.is_some() {
                    return Err(stopped());
                }
                let work = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    stable()?;
                    check()?;
                    resources.row(id, record, check)
                }));
                match work {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(original)) => {
                        callback_error = Some(original);
                        Err(stopped())
                    }
                    Err(payload) => {
                        callback_panic = Some(payload);
                        Err(stopped())
                    }
                }
            });
            // Retain the complete independent source result, even when a staging
            // failure already exists. Never convert Source(E) into a wire error.
            if let Err(failure) = visited {
                input = Some(failure);
            }
            if let Some(original) = callback_error.take() {
                return Err(original);
            }
            if input.is_some() || callback_panic.is_some() {
                return Ok(None);
            }
            stable()?;
            check()?;
            let root = resources.finish_pages(check)?;
            let manifest = Manifest {
                scope: resources
                    .stage
                    .as_ref()
                    .expect("live stage")
                    .resources
                    .scope,
                name_hash: codec(records::name_hash(&definition.name))?,
                tree_id: resources.tree,
                definition: definition_ref,
                data_epoch,
                revision,
                root,
                totals: resources.expected,
            };
            stable()?;
            check()?;
            let stage = resources.stage.take().expect("live stage");
            let (stage, reference) = stage.stage_manifest(manifest)?;
            resources.stage = Some(stage);
            check()?;
            stable()?;
            Ok(Some(BuiltCollection {
                manifest,
                reference,
            }))
        },
    ));
    match outcome {
        Ok(Ok(Some(built))) => {
            let stage = resources.stage.take().expect("successful stage");
            drop(resources);
            Ok((stage, built))
        }
        Ok(Ok(None)) => Err(BuildFailure {
            original: None,
            input,
            panic: None,
            callback_panic,
            resources,
        }),
        Ok(Err(original)) => Err(BuildFailure {
            original: Some(original),
            input,
            panic: None,
            callback_panic,
            resources,
        }),
        Err(panic) => Err(BuildFailure {
            original: callback_error,
            input,
            panic: Some(panic),
            callback_panic,
            resources,
        }),
    }
}
fn stopped() -> Error {
    Error::new(ErrorCode::Corruption, "primary bulk callback stopped")
}

impl Resources<'_, '_> {
    fn workspace_quote() -> Result<u64> {
        let level_scratch = allocated(std::mem::size_of::<Level>())?;
        allocated(
            LEVELS
                .checked_mul(std::mem::size_of::<Level>())
                .context("primary frontier overflow")?,
        )?
        .checked_add(allocated(SLOTS * std::mem::size_of::<Entry<'_>>())?)
        .and_then(|n| n.checked_add(level_scratch))
        // Conservative logical stack/control allowance, not a compiler stack
        // layout or RSS bound: at most LEVELS recursive push continuations.
        .and_then(|n| n.checked_add((LEVELS * (std::mem::size_of::<Slot>() + 512)) as u64))
        .and_then(|n| n.checked_add(8192)) // fixed control and error continuations
        .context("primary bulk quote overflow")
    }
    fn allocate(&mut self) -> Result<()> {
        let baseline = Self::workspace_quote()?;
        let stage = self.stage.as_ref().expect("live stage");
        let (_, admission) = stage.resources.roots.primary_installation();
        self.frontier.reservation = Some(admission.reserve_application_source(baseline)?);
        self.frontier.levels.try_reserve_exact(LEVELS)?;
        ensure!(
            self.frontier.levels.capacity() == LEVELS,
            "primary frontier capacity differs"
        );
        for _ in 0..LEVELS {
            self.frontier.levels.push(Level::empty());
        }
        self.tree = *uuid::Uuid::new_v4().as_bytes();
        ensure!(self.tree != [0; 16], "primary tree identity absent");
        Ok(())
    }
    fn dto(
        &mut self,
        dto: CanonicalDto<'_>,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<OverflowRef> {
        let stage = self.stage.take().expect("live stage");
        let (stage, reference) = stage.stage_dto_checked(self.tree, dto, check)?;
        self.stage = Some(stage);
        Ok(reference)
    }
    fn row(
        &mut self,
        id: &str,
        record: Record<'_>,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let name = Name::new(id)?;
        ensure!(
            self.last.len == 0 || self.last.as_str() < id,
            "primary bulk IDs are not strictly ordered"
        );
        ensure!(
            record.version() <= self.generation,
            "primary bulk row version exceeds data epoch"
        );
        ensure!(
            !matches!(record, Record::Live(doc) if doc.id != id),
            "primary bulk document identity differs"
        );
        let (kind, semantic_bytes, object) = match record {
            Record::Live(doc) => {
                // encoded_len(body) uses the direct borrowed Value writer.
                // Ordering does not change JSON byte length; this pass needs no
                // canonical-map sorter. Full DTO staging funds its own sorter.
                let mut count = CountHash::new();
                let mut writer = check::CheckedWriter::new(&mut count, check);
                let encoded = serde_json::to_writer(&mut writer, &doc.body).map_err(Into::into);
                writer.finish(encoded)?;
                let object = self.dto(CanonicalDto::Live(doc), check)?;

                (RecordKind::Live, count.bytes, object)
            }
            Record::Archived(doc) => {
                let object = self.dto(CanonicalDto::Archived(doc), check)?;
                (
                    RecordKind::Archived,
                    codec(tree::archived_metadata_bytes(id, object.encoded_bytes))?,
                    object,
                )
            }
        };
        let leaf = Leaf {
            version: record.version(),
            kind,
            object,
            semantic_bytes,
        };
        let totals = match kind {
            RecordKind::Live => Totals {
                live_count: 1,
                live_body_bytes: semantic_bytes,
                ..Totals::default()
            },
            RecordKind::Archived => Totals {
                archived_count: 1,
                archived_metadata_bytes: semantic_bytes,
                ..Totals::default()
            },
        };
        self.expected = codec(self.expected.add(totals))?;
        self.push(
            0,
            Slot {
                name,
                value: Value::Leaf(leaf),
            },
            check,
        )?;
        self.last = name;
        Ok(())
    }
    fn push(
        &mut self,
        level: usize,
        slot: Slot,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        ensure!(level < LEVELS, "primary bulk format height exhausted");
        if !self.frontier.levels[level].fits(slot.name) {
            let (name, page) = self.flush(level, check)?;
            self.push(
                level + 1,
                Slot {
                    name,
                    value: Value::Child(Child {
                        reference: page.reference,
                        totals: page.totals,
                    }),
                },
                check,
            )?;
        }
        self.frontier.levels[level].push(slot);
        Ok(())
    }
    fn flush(
        &mut self,
        level: usize,
        check: &mut dyn FnMut() -> Result<()>,
    ) -> Result<(Name, EncodedPage)> {
        check()?;
        let buffer = &mut self.frontier.levels[level];
        ensure!(buffer.len != 0, "primary bulk empty page flush");
        let first = buffer.slots[0].name;
        let mut entries = [Entry {
            id: "",
            value: EMPTY_VALUE,
        }; SLOTS];
        for (entry, slot) in entries.iter_mut().zip(&buffer.slots[..buffer.len]) {
            *entry = Entry {
                id: slot.name.as_str(),
                value: slot.value,
            };
        }
        let stage = self.stage.take().expect("live stage");
        let (stage, page) = stage.stage_page(
            self.tree,
            self.generation,
            level as u8,
            &entries[..buffer.len],
        )?;
        self.stage = Some(stage);
        buffer.clear();
        check()?;
        Ok((first, page))
    }
    fn finish_pages(&mut self, check: &mut dyn FnMut() -> Result<()>) -> Result<Option<Root>> {
        for level in 0..LEVELS {
            if self.frontier.levels[level].len == 0 {
                continue;
            }
            let higher = self.frontier.levels[level + 1..]
                .iter()
                .any(|buffer| buffer.len != 0);
            // A sole carried descriptor already names the final root. Avoid
            // creating an unnecessary unary wrapper (or infinite height walk).
            if !higher && level != 0 && self.frontier.levels[level].len == 1 {
                let Value::Child(child) = self.frontier.levels[level].slots[0].value else {
                    unreachable!("interior descriptor")
                };
                ensure!(
                    child.totals == self.expected,
                    "primary bulk aggregate differs"
                );
                self.frontier.levels[level].clear();
                return Ok(Some(Root {
                    reference: child.reference,
                    level: level as u8 - 1,
                }));
            }
            let (name, page) = self.flush(level, check)?;
            if !higher {
                ensure!(
                    page.totals == self.expected,
                    "primary bulk aggregate differs"
                );
                return Ok(Some(Root {
                    reference: page.reference,
                    level: level as u8,
                }));
            }
            self.push(
                level + 1,
                Slot {
                    name,
                    value: Value::Child(Child {
                        reference: page.reference,
                        totals: page.totals,
                    }),
                },
                check,
            )?;
        }
        ensure!(
            self.expected == Totals::default(),
            "primary bulk lost frontier"
        );
        Ok(None)
    }
}
