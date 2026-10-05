//! Selected-primary point and ordered-header primitives. These are not
//! authorization, root publication, cache provenance or the production adapter.
//! Every record comes from one exact encrypted SourceReader; no current-view
//! refresh, resident fallback, or cleanup/admission retry is permitted.
use super::{
    records::{self, CatalogEntry, Manifest, ResourceKind, Selector},
    *,
};
use crate::{
    admission::Reservation,
    application_sources::{SelectedApplication, SourceReader, SourceRootsRef},
};
use anyhow::{Context as _, Result, ensure};
use kasumi_query::{QueryWorkspace, Record};
use kasumi_types::{ArchivedDocument, CollectionDefinition, Document, TenantState};
use serde::de::DeserializeOwned;
use std::sync::Mutex;

#[path = "primary_read_decode.rs"]
mod decode;
pub(crate) const CATALOG: &str = "engine.primary.catalog";
pub(crate) const MANIFESTS: &str = "engine.primary.manifests";
pub(crate) const PAGES: &str = "engine.primary.pages";
fn codec<T>(value: std::result::Result<T, CodecError>) -> Result<T> {
    value.map_err(|e| anyhow::anyhow!("selected primary record invalid: {e:?}"))
}
fn allocated(bytes: usize) -> Result<u64> {
    u64::try_from(
        bytes
            .checked_next_power_of_two()
            .and_then(|n| n.checked_add(64))
            .context("primary read allocation overflow")?,
    )
    .map_err(Into::into)
}
fn object_key(id: ObjectId) -> [u8; 24] {
    let mut key = [0; 24];
    id.write(&mut key);
    key
}

pub(crate) struct SelectedPrimary {
    resources: Resources,
}
struct Resources {
    reader: Option<SourceReader>,
    wire: Vec<u8>,
    selector: Option<Selector>,
    manifest: Option<Manifest>,
    baseline: u64,
    live: u64,
    // All buffers/readers/errors constructed under this grant retire before it.
    reservation: Reservation,
}
/// Typed and noncloneable. Keep the actual peak grant and exact source reader
/// with the original error. No std::error::Error implementation: that would
/// enable blanket conversion into anyhow and erase this ownership boundary.
/// Enclosing caller allocations and the broader error protocol remain separate.
pub(crate) struct ReadFailure {
    original: anyhow::Error,
    resources: Option<Resources>,
}
impl ReadFailure {
    pub(crate) fn original(&self) -> &anyhow::Error {
        &self.original
    }
    #[cfg(test)]
    pub(crate) fn retained_wire_bytes(&self) -> usize {
        self.resources.as_ref().map_or(0, |r| r.wire.len())
    }
    fn before_resources(original: impl Into<anyhow::Error>) -> Self {
        Self {
            original: original.into(),
            resources: None,
        }
    }
}
impl std::fmt::Debug for ReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SelectedPrimaryReadFailure")
            .field("original", &self.original)
            .field("retains_source", &self.resources.is_some())
            .finish()
    }
}
impl std::fmt::Display for ReadFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.original.fmt(f)
    }
}
struct ReadPanic {
    _payload: Mutex<Box<dyn std::any::Any + Send>>,
}
impl std::fmt::Debug for ReadPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ReadPanic(retained original payload)")
    }
}
impl std::fmt::Display for ReadPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("selected primary read retained original panic")
    }
}
impl std::error::Error for ReadPanic {}

#[allow(
    clippy::result_large_err,
    reason = "the source, wire and grant move inline on failure; boxing would introduce a separately admitted allocation and retirement lifetime"
)]
impl SelectedPrimary {
    /// `state` supplies the caller's authenticated tenant/incarnation and logical
    /// revision expectation. This candidate only accepts exact selected proofs;
    /// covered reconstruction needs the future atomic primary producer binding.
    pub(crate) fn open(
        selected: &SelectedApplication,
        roots: &SourceRootsRef,
        state: &TenantState,
        name: &str,
    ) -> std::result::Result<Self, ReadFailure> {
        let baseline = allocated(std::mem::size_of::<ReadFailure>())
            .map_err(ReadFailure::before_resources)?
            .checked_add(16 << 10)
            .ok_or_else(|| {
                ReadFailure::before_resources(anyhow::anyhow!("primary read quote overflow"))
            })?;
        let reservation = roots
            .primary_installation()
            .1
            .reserve_application_source(baseline)
            .map_err(ReadFailure::before_resources)?;
        let reader = Self {
            resources: Resources {
                reader: None,
                wire: Vec::new(),
                selector: None,
                manifest: None,
                baseline,
                live: baseline,
                reservation,
            },
        };
        reader
            .perform(|r| {
                codec(check_id(name))?;
                ensure!(
                    roots.primary_installation().0.application().tenant() == state.tenant,
                    "primary tenant differs"
                );
                let (bootstrap, fingerprint, revision) =
                    selected.primary_read_proof(state.revision_base)?;
                ensure!(
                    state.revision == revision,
                    "primary selected revision differs"
                );
                let scope = codec(records::scope_hash(
                    &state.tenant,
                    &state.incarnation,
                    bootstrap,
                ))?;
                let name_hash = codec(records::name_hash(name))?;
                r.reader = Some(selected.open_primary_reader(roots)?);
                let selector = r.read(
                    "engine.primary.meta",
                    b"selected",
                    records::SELECTOR_BYTES,
                    |b| codec(Selector::decode(b.context("primary selector absent")?)),
                )?;
                ensure!(
                    selector.scope == scope
                        && selector.bootstrap_sha256 == bootstrap
                        && selector.revision == revision
                        && selector.revision_base == state.revision_base
                        && selector.boundary == fingerprint.kind
                        && selector.boundary_digest == fingerprint.sha256,
                    "primary selector differs from selected producer"
                );
                let mapping = r.read(
                    CATALOG,
                    &CatalogEntry::key(selector.catalog, name_hash),
                    records::CATALOG_ENTRY_BYTES,
                    |b| {
                        codec(CatalogEntry::decode(
                            b.context("primary collection mapping absent")?,
                        ))
                    },
                )?;
                ensure!(
                    mapping.catalog == selector.catalog
                        && mapping.scope == scope
                        && mapping.name_hash == name_hash,
                    "primary catalog mapping identity differs"
                );
                let manifest = r.read(
                    MANIFESTS,
                    &object_key(mapping.manifest.id),
                    records::MANIFEST_BYTES,
                    |b| {
                        codec(Manifest::decode_referenced(
                            b.context("primary collection manifest absent")?,
                            mapping.manifest,
                        ))
                    },
                )?;
                codec(manifest.validate_context(scope, name_hash, revision))?;
                ensure!(
                    selector.collection_count != 0
                        && manifest.totals.live_count <= selector.totals.live_count
                        && manifest.totals.archived_count <= selector.totals.archived_count
                        && manifest.totals.live_body_bytes <= selector.totals.live_body_bytes
                        && manifest.totals.archived_metadata_bytes
                            <= selector.totals.archived_metadata_bytes,
                    "primary collection exceeds selector totals"
                );
                r.selector = Some(selector);
                r.manifest = Some(manifest);
                r.object(manifest.definition, ResourceKind::Definition)?;
                let definition: CollectionDefinition = r.decode()?;
                ensure!(definition.name == name, "primary definition name differs");
                drop(definition);
                r.release_wire();
                Ok(())
            })
            .map(|(reader, ())| reader)
    }
    fn perform<T>(
        mut self,
        work: impl FnOnce(&mut Resources) -> Result<T>,
    ) -> std::result::Result<(Self, T), ReadFailure> {
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| work(&mut self.resources)))
                .unwrap_or_else(|payload| {
                    Err(ReadPanic {
                        _payload: Mutex::new(payload),
                    }
                    .into())
                });
        match result {
            Ok(value) => Ok((self, value)),
            Err(original) => Err(ReadFailure {
                original,
                resources: Some(self.resources),
            }),
        }
    }
    /// The borrowed DTO dies before this operation returns. An owned callback
    /// result needs the caller's separate output admission, as existing loans do.
    pub(crate) fn lookup<T>(
        self,
        id: &str,
        lend: impl for<'a> FnOnce(Record<'a>) -> Result<T>,
    ) -> std::result::Result<(Self, Option<T>), ReadFailure> {
        self.perform(|r| {
            codec(check_id(id))?;
            r.check_access()?;
            let Some(leaf) = r.leaf(id)? else {
                r.check_access()?;
                return Ok(None);
            };
            let manifest = r.manifest.expect("opened manifest");
            ensure!(
                leaf.version <= manifest.data_epoch,
                "primary document version differs"
            );
            let value = match leaf.kind {
                RecordKind::Live => {
                    r.object(leaf.object, ResourceKind::Live)?;
                    let document: Document = r.decode()?;
                    ensure!(
                        document.id == id && document.version == leaf.version,
                        "primary live identity/version differs"
                    );
                    ensure!(
                        decode::encoded_bytes(&kasumi_types::CanonicalJsonValue(&document.body))?
                            == leaf.semantic_bytes,
                        "primary live body accounting differs"
                    );
                    r.check_access()?;
                    lend(Record::Live(&document))?
                }
                RecordKind::Archived => {
                    r.object(leaf.object, ResourceKind::Archived)?;
                    let document: ArchivedDocument = r.decode()?;
                    ensure!(
                        document.version == leaf.version
                            && codec(archived_metadata_bytes(id, leaf.object.encoded_bytes))?
                                == leaf.semantic_bytes,
                        "primary archive identity/accounting differs"
                    );
                    r.check_access()?;
                    lend(Record::Archived(&document))?
                }
            };
            r.check_access()?;
            r.release_wire();
            Ok(Some(value))
        })
    }
    /// Lend the next authenticated primary header without materializing its DTO.
    /// The callback's owned output, if any, needs its own caller admission.
    pub(crate) fn header_after<T>(
        self,
        exclusive_id: Option<&str>,
        cancellation: &kasumi_query::QueryCancellation,
        lend: impl for<'a> FnOnce(Option<kasumi_query::Header<'a>>) -> Result<T>,
    ) -> std::result::Result<(Self, T), ReadFailure> {
        self.perform(|r| {
            cancellation.check()?;
            if let Some(id) = exclusive_id {
                codec(check_id(id))?;
            }
            r.check_access()?;
            let next = r.header_leaf(exclusive_id, cancellation)?;
            cancellation.check()?;
            r.check_access()?;
            let header = next.as_ref().map(|(name, leaf)| kasumi_query::Header {
                id: name.as_str().expect("validated nonempty ID"),
                version: leaf.version,
                kind: match leaf.kind {
                    RecordKind::Live => kasumi_query::RecordKind::Live,
                    RecordKind::Archived => kasumi_query::RecordKind::Archived,
                },
            });
            let result = lend(header)?;
            cancellation.check()?;
            r.check_access()?;
            Ok(result)
        })
    }
    pub(crate) fn close(self) -> std::result::Result<(), ReadFailure> {
        self.perform(|r| {
            r.reader.take().context("primary reader absent")?.close()?;
            Ok(())
        })
        .map(|_| ())
    }
}
impl Resources {
    fn check_access(&mut self) -> Result<()> {
        self.reader
            .as_mut()
            .context("primary reader absent")?
            .check_access()
    }
    fn read<T>(
        &mut self,
        namespace: &str,
        key: &[u8],
        max: usize,
        lend: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T> {
        self.reader
            .as_mut()
            .context("primary reader absent")?
            .with_record(&mut self.reservation, self.live, namespace, key, max, lend)
    }
    fn release_wire(&mut self) {
        drop(std::mem::take(&mut self.wire));
        self.live = self.baseline;
        self.reservation.retain(self.baseline);
    }
    fn object(&mut self, reference: OverflowRef, kind: ResourceKind) -> Result<()> {
        ensure!(
            self.wire.is_empty() && self.wire.capacity() == 0,
            "primary prior DTO still resident"
        );
        let count = usize::try_from(reference.encoded_bytes)?;
        self.live = self
            .baseline
            .checked_add(allocated(count)?)
            .context("primary object quote overflow")?;
        self.reservation.ensure_peak(self.live)?;
        self.wire.try_reserve_exact(count)?;
        ensure!(
            self.wire.capacity() == count,
            "primary DTO capacity differs"
        );
        let manifest = self.manifest.expect("opened manifest");
        super::stage::visit_object(
            self.reader.as_mut().expect("primary reader"),
            &mut self.reservation,
            self.live,
            manifest.scope,
            reference,
            manifest.tree_id,
            kind,
            |bytes| {
                ensure!(
                    bytes.len() <= count - self.wire.len(),
                    "primary DTO exceeds reference"
                );
                self.wire.extend_from_slice(bytes);
                Ok(())
            },
        )?;
        ensure!(self.wire.len() == count, "primary DTO incomplete");
        Ok(())
    }
    fn decode<T: DeserializeOwned + serde::Serialize>(&mut self) -> Result<T> {
        self.reservation.ensure_peak(
            self.live
                .checked_add(decode::preflight(self.wire.len())?)
                .context("primary preflight quote overflow")?,
        )?;
        let quote = decode::quote(&self.wire)?;
        self.reservation.ensure_peak(
            self.live
                .checked_add(quote)
                .context("primary DTO decode quote overflow")?,
        )?;
        let value = serde_json::from_slice(&self.wire)?;
        crate::current_json::require_current_writer_bytes(
            &self.wire,
            &value,
            "selected primary DTO",
        )?;
        Ok(value)
    }
    fn header_leaf(
        &mut self,
        exclusive_id: Option<&str>,
        cancellation: &kasumi_query::QueryCancellation,
    ) -> Result<Option<(Name, Leaf)>> {
        let manifest = self.manifest.expect("opened manifest");
        let Some(root) = manifest.root else {
            return Ok(None);
        };
        let mut sought = Name::from(exclusive_id);
        // If the selected leaf ends before the next key, its exact upper bound
        // is the next sibling's minimum. Re-route once from the same immutable
        // root using that inclusive separator. No ancestry stack is retained.
        for pass in 0..2 {
            let mut route = Route {
                reference: root.reference,
                level: root.level,
                generation: manifest.data_epoch,
                totals: manifest.totals,
                lower: Name::none(),
                upper: Name::none(),
            };
            loop {
                cancellation.check()?;
                let next = self.read(
                    PAGES,
                    &object_key(route.reference.id),
                    PAGE_BYTES,
                    |bytes| {
                        let page = codec(validate(
                            bytes.context("primary page absent")?,
                            ExpectedPage {
                                tree_id: manifest.tree_id,
                                reference: route.reference,
                                generation_ceiling: route.generation,
                                level: route.level,
                                totals: route.totals,
                                range: KeyRange {
                                    lower: route.lower.as_str(),
                                    upper: route.upper.as_str(),
                                },
                            },
                        ))?;
                        if route.level != 0 {
                            let id = sought.as_str().unwrap_or_else(|| {
                                page.entries().next().expect("validated nonempty branch").id
                            });
                            return Ok(HeaderStep::Next(Route::from_expected(codec(
                                page.route(id),
                            )?)));
                        }
                        let entry = match sought.as_str() {
                            Some(id) => codec(page.successor(id, pass == 0))?,
                            None => page.entries().next(),
                        };
                        Ok(HeaderStep::Leaf(entry.map(|entry| {
                            let Value::Leaf(leaf) = entry.value else {
                                unreachable!("validated leaf page")
                            };
                            (Name::from(Some(entry.id)), leaf)
                        })))
                    },
                )?;
                cancellation.check()?;
                match next {
                    HeaderStep::Next(next) => route = next,
                    HeaderStep::Leaf(Some((name, leaf))) => {
                        ensure!(
                            leaf.version <= manifest.data_epoch,
                            "primary header version differs"
                        );
                        ensure!(
                            pass == 0 || name.as_str() == sought.as_str(),
                            "primary successor separator absent"
                        );
                        return Ok(Some((name, leaf)));
                    }
                    HeaderStep::Leaf(None) => {
                        ensure!(pass == 0, "primary successor separator absent");
                        if route.upper.as_str().is_none() {
                            return Ok(None);
                        }
                        sought = route.upper;
                        break;
                    }
                }
            }
        }
        unreachable!("second descent either yields its separator or fails")
    }
    fn leaf(&mut self, id: &str) -> Result<Option<Leaf>> {
        let manifest = self.manifest.expect("opened manifest");
        let Some(root) = manifest.root else {
            return Ok(None);
        };
        let mut route = Route {
            reference: root.reference,
            level: root.level,
            generation: manifest.data_epoch,
            totals: manifest.totals,
            lower: Name::none(),
            upper: Name::none(),
        };
        loop {
            let next = self.read(
                PAGES,
                &object_key(route.reference.id),
                PAGE_BYTES,
                |bytes| {
                    let page = codec(validate(
                        bytes.context("primary page absent")?,
                        ExpectedPage {
                            tree_id: manifest.tree_id,
                            reference: route.reference,
                            generation_ceiling: route.generation,
                            level: route.level,
                            totals: route.totals,
                            range: KeyRange {
                                lower: route.lower.as_str(),
                                upper: route.upper.as_str(),
                            },
                        },
                    ))?;
                    if route.level == 0 {
                        Ok(Step::Leaf(codec(page.lookup(id))?))
                    } else {
                        Ok(Step::Next(Route::from_expected(codec(page.route(id))?)))
                    }
                },
            )?;
            match next {
                Step::Leaf(value) => return Ok(value),
                Step::Next(next) => route = next,
            }
        }
    }
}
// Two fixed names survive the page loan; traversal stores no depth-sized stack.
struct Name {
    bytes: [u8; MAX_ID_BYTES],
    len: usize,
}
impl Name {
    fn none() -> Self {
        Self {
            bytes: [0; MAX_ID_BYTES],
            len: 0,
        }
    }
    fn from(value: Option<&str>) -> Self {
        let mut name = Self::none();
        if let Some(value) = value {
            name.len = value.len();
            name.bytes[..value.len()].copy_from_slice(value.as_bytes());
        }
        name
    }
    fn as_str(&self) -> Option<&str> {
        (self.len != 0)
            .then(|| std::str::from_utf8(&self.bytes[..self.len]).expect("validated name"))
    }
}
struct Route {
    reference: PageRef,
    level: u8,
    generation: u64,
    totals: Totals,
    lower: Name,
    upper: Name,
}
impl Route {
    fn from_expected(page: ExpectedPage<'_>) -> Self {
        Self {
            reference: page.reference,
            level: page.level,
            generation: page.generation_ceiling,
            totals: page.totals,
            lower: Name::from(page.range.lower),
            upper: Name::from(page.range.upper),
        }
    }
}
#[allow(
    clippy::large_enum_variant,
    reason = "one fixed route holds bounded names during iterative traversal; inline storage avoids a heap allocation for every page"
)]
enum Step {
    Leaf(Option<Leaf>),
    Next(Route),
}

#[allow(
    clippy::large_enum_variant,
    reason = "fixed names and one authenticated route stay inline; no per-page allocation or depth-sized stack"
)]
enum HeaderStep {
    Leaf(Option<(Name, Leaf)>),
    Next(Route),
}
