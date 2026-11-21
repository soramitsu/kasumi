//! An exact selected field tree can prove a bounded ordinary uniqueness delta.
//! Every field of a compound tuple must name the same document. A short
//! posting list provides candidates; all remaining fields are native points.
use super::{POSTING, field_prefix, push_value, scan_ids};
use crate::application_primary::ChangedIds;
use crate::index_source::{self, DocumentSourceFailure, SourceResult};
use anyhow::{Context, Result, ensure};
use kasumi_query::{FieldValue, QueryIndexes, Record};
use kasumi_store::{NodeDiskMemoryAdmission, ordered_pages::TreeReader};
use kasumi_types::{DocumentResolver, IndexDefinition, TenantState};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const DOCUMENTS: usize = 32;
const TUPLES: usize = 32;
const ANCHOR_IDS: usize = 16;
const READS: usize = 512;
const SCALAR_BYTES: usize = 256 << 10;
// At most eight prefixes, 16 IDs, one candidate and 32 exact bounded keys
// and digests are retained. Physical pages and overflow own their grants.
const WORKSPACE: u64 = 64 << 10;

pub(crate) fn validate_ordinary(
    previous: &crate::Generation,
    candidate: &TenantState,
    changed: &ChangedIds,
    roots: Option<&crate::application_sources::SourceRootsRef>,
    group: Option<(&crate::Generation, &ChangedIds)>,
) -> SourceResult<()> {
    let base = group.map_or(previous, |(base, _)| base);
    let old = &previous.state;
    let resolver = previous.document_resolver();
    let any_unique = changed.keys().any(|name| {
        old.collections
            .get(name)
            .is_some_and(|c| c.definition.indexes.iter().any(|i| i.unique))
    });
    if any_unique
        && changed.values().map(|ids| ids.len()).sum::<usize>() <= DOCUMENTS
        && let Some((roots, selection)) = roots.zip(base.application_selection.get())
    {
        let proved = selection
            .with_ordered_tuples(
                None,
                &base.state,
                || base.indexes.structured_layout_sha256(),
                changed.keys().map(String::as_str),
                |reader, fields| {
                    let _workspace = roots.memory_owner().clone().reserve_installed(
                        if group.is_some_and(|(_, ids)| !ids.is_empty()) {
                            2 * WORKSPACE
                        } else {
                            WORKSPACE
                        },
                    )?;
                    let overlay = if let Some((_, touched)) = group {
                        let Some(overlay) =
                            group_overlay(&base.state, old, touched, changed, resolver)?
                        else {
                            return Ok(Decision::Inconclusive);
                        };
                        overlay
                    } else {
                        BTreeMap::new()
                    };
                    prove_with_overlay(
                        ClaimTree { reader, fields },
                        &previous.indexes,
                        old,
                        candidate,
                        changed,
                        resolver,
                        &overlay,
                    )
                },
            )
            .map_err(|e| kasumi_query::ReadFailure::Source(DocumentSourceFailure(e)))?;
        match proved {
            Some(Decision::Accepted) => return Ok(()),
            Some(Decision::Conflict(name)) => {
                return Err(kasumi_query::unique_conflict(&name).into());
            }
            Some(Decision::Inconclusive) | None => {}
        }
    }
    index_source::validate_changes_with_resolvers(
        &previous.indexes,
        old,
        candidate,
        changed,
        resolver,
        resolver,
    )
}

struct Budget {
    tuples: usize,
    reads: usize,
    bytes: usize,
}

impl Budget {
    fn read(&mut self) -> bool {
        if self.reads == 0 {
            return false;
        }
        self.reads -= 1;
        true
    }
}

type GroupOverlay = BTreeMap<Vec<u8>, Option<String>>;
fn scoped_tuple(collection: &str, index: &str, tuple: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(4 + collection.len() + index.len() + tuple.len());
    for name in [collection, index] {
        key.extend_from_slice(&(name.len() as u16).to_be_bytes());
        key.extend_from_slice(name.as_bytes());
    }
    key.extend_from_slice(tuple);
    key
}
fn value_at<'a>(record: Record<'a>, path: &str) -> Option<&'a serde_json::Value> {
    match record {
        Record::Live(doc) => doc.body.pointer(path),
        Record::Archived(doc) => doc.indexed_fields.get(path),
    }
}

/// Fold the admitted prior members into a bounded set of point overrides
/// relative to the last physically published directory. All its old owners
/// leave before any of the group's current owners are installed.
pub(super) fn group_overlay(
    base: &TenantState,
    current: &TenantState,
    touched: &ChangedIds,
    changed: &ChangedIds,
    resolver: Option<&dyn DocumentResolver>,
) -> Result<Option<GroupOverlay>> {
    ensure!(
        base.tenant == current.tenant && base.incarnation == current.incarnation,
        "grouped unique source differs"
    );
    let mut rows = GroupOverlay::new();
    let mut work = 0;
    let mut documents = DOCUMENTS;
    for name in changed.keys() {
        let Some(prior) = touched.get(name) else {
            continue;
        };
        let original = base
            .collections
            .get(name)
            .context("group base collection absent")?;
        let logical = current
            .collections
            .get(name)
            .context("group collection absent")?;
        ensure!(
            original.definition == logical.definition,
            "group changed a unique definition"
        );
        if !original.definition.indexes.iter().any(|i| i.unique) {
            continue;
        }
        let Some(remaining) = documents.checked_sub(prior.len()) else {
            return Ok(None);
        };
        documents = remaining;
        for (state, collection, removing) in [(base, original, true), (current, logical, false)] {
            for id in prior {
                let loan = index_source::record(collection, id, state.revision, resolver)
                    .map_err(index_source::into_anyhow)?;
                let Some(loan) = loan else { continue };
                let record = loan.as_record();
                for index in collection.definition.indexes.iter().filter(|i| i.unique) {
                    work += 1;
                    if work > TUPLES {
                        return Ok(None);
                    }
                    if index
                        .fields
                        .iter()
                        .any(|f| value_at(record, &f.path).is_none())
                    {
                        continue;
                    }
                    let Some(key) = kasumi_query::ordered_record_tuple(&index.fields, record)?
                    else {
                        return Ok(None);
                    };
                    let key = scoped_tuple(name, &index.name, &key);
                    if removing {
                        rows.insert(key, None);
                    } else {
                        ensure!(
                            rows.insert(key, Some(id.clone())).flatten().is_none(),
                            "accepted group tuple has two logical owners"
                        );
                    }
                }
            }
        }
    }
    Ok(Some(rows))
}

enum Probe {
    Sparse,
    Inconclusive,
    Known {
        fingerprint: [u8; 32],
        exact: Option<Vec<u8>>,
        owner: Option<String>,
    },
}

/// Include each part length. The digest locates a private candidate bucket.
/// A duplicate requires identical scoped, complete keys before rejection.
fn hash_part(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

#[derive(Clone, Copy)]
pub(super) struct ClaimTree<'a, 's> {
    reader: &'a TreeReader<'s>,
    fields: bool,
}
#[cfg(test)]
impl<'a, 's> ClaimTree<'a, 's> {
    pub(super) fn ordinary(reader: &'a TreeReader<'s>) -> Self {
        Self {
            reader,
            fields: true,
        }
    }
}
fn probe(
    source: ClaimTree<'_, '_>,
    indexes: &QueryIndexes,
    collection: &str,
    index: &IndexDefinition,
    record: Record<'_>,
    budget: &mut Budget,
    overlay: &GroupOverlay,
) -> Result<Probe> {
    let reader = source.reader;
    if index
        .fields
        .iter()
        .any(|field| value_at(record, &field.path).is_none())
    {
        return Ok(Probe::Sparse);
    }
    if budget.tuples == 0 {
        return Ok(Probe::Inconclusive);
    }
    budget.tuples -= 1;
    let mut hash = Sha256::new();
    hash_part(&mut hash, collection.as_bytes());
    hash_part(&mut hash, index.name.as_bytes());
    let exact = kasumi_query::ordered_record_tuple(&index.fields, record)?;
    if let Some(key) = &exact {
        hash_part(&mut hash, key);
    }
    if let Some(key) = &exact
        && !overlay.is_empty()
        && let Some(owner) = overlay.get(&scoped_tuple(collection, &index.name, key))
    {
        return Ok(Probe::Known {
            fingerprint: hash.finalize().into(),
            exact,
            owner: owner.clone(),
        });
    }
    if index.fields.len() > 1
        && let Some(key) = &exact
    {
        if !budget.read() {
            return Ok(Probe::Inconclusive);
        }
        let ordinal = indexes
            .compound_ordinal(collection, &index.name)
            .context("compound absent from selected layout")?;
        let mut native = field_prefix(super::COMPOUND, collection, ordinal);
        native.extend_from_slice(key);
        let owner = reader.with_value(&native, 256, |v| {
            v.map(super::posting_id)
                .transpose()
                .map(|id| id.map(str::to_owned))
        })?;
        return Ok(Probe::Known {
            fingerprint: hash.finalize().into(),
            exact,
            owner,
        });
    }
    if !source.fields {
        return Ok(Probe::Inconclusive);
    }
    let mut prefixes = Vec::with_capacity(index.fields.len());
    let mut absent = false;
    for field in &index.fields {
        let value = value_at(record, &field.path).context("complete unique tuple lost a field")?;
        let component = FieldValue::predicate(value, field.kind)?;
        let Some(left) = budget.bytes.checked_sub(component.bytes.len()) else {
            return Ok(Probe::Inconclusive);
        };
        budget.bytes = left;
        if exact.is_none() {
            hash.update([component.tag]);
            hash_part(&mut hash, &component.bytes);
        }
        let ordinal = indexes
            .structured_field_ordinal(collection, &field.path)
            .context("unique field absent from selected layout")?;
        let mut prefix = field_prefix(POSTING, collection, ordinal);
        let base = prefix.len();
        if push_value(&mut prefix, &component)? && !absent {
            if !budget.read() {
                return Ok(Probe::Inconclusive);
            }
            // Check actual overflow bytes before using its hashed posting.
            let mut key = field_prefix(super::LONG, collection, ordinal);
            key.extend_from_slice(&prefix[base..]);
            absent = reader.with_value(&key, component.bytes.len(), |stored| {
                if let Some(bytes) = stored {
                    ensure!(
                        bytes == component.bytes.as_ref(),
                        "distinct unique scalars share a native digest"
                    );
                }
                Ok(stored.is_none())
            })?;
        }
        prefixes.push(prefix);
    }
    let fingerprint = hash.finalize().into();
    if absent {
        return Ok(Probe::Known {
            fingerprint,
            exact,
            owner: None,
        });
    }
    for (anchor, prefix) in prefixes.iter().enumerate() {
        if !budget.read() {
            break;
        }
        let mut ids = Vec::with_capacity(ANCHOR_IDS);
        let complete = scan_ids(reader, prefix, &mut || Ok(()), &mut |id| {
            if !budget.read() || ids.len() == ANCHOR_IDS {
                return Ok(false);
            }
            ids.push(id.to_owned());
            Ok(true)
        })?;
        if !complete {
            continue;
        }
        let mut owner = None;
        for id in ids {
            let mut matches = true;
            for (i, component) in prefixes.iter().enumerate() {
                if i == anchor {
                    continue;
                }
                if !budget.read() {
                    return Ok(Probe::Inconclusive);
                }
                let mut key = component.clone();
                key.extend_from_slice(id.as_bytes());
                if !reader.with_value(&key, 0, |v| Ok(v.is_some()))? {
                    matches = false;
                    break;
                }
            }
            if matches {
                ensure!(
                    owner.is_none(),
                    "selected unique tuple names multiple original documents"
                );
                owner = Some(id);
            }
        }
        return Ok(Probe::Known {
            fingerprint,
            exact,
            owner,
        });
    }
    Ok(Probe::Inconclusive)
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Decision {
    Accepted,
    Conflict(String),
    Inconclusive,
}

#[cfg(test)]
pub(super) fn prove(
    reader: &TreeReader<'_>,
    indexes: &QueryIndexes,
    old: &TenantState,
    new: &TenantState,
    changed: &ChangedIds,
    resolver: Option<&dyn DocumentResolver>,
) -> Result<Decision> {
    prove_with_overlay(
        ClaimTree::ordinary(reader),
        indexes,
        old,
        new,
        changed,
        resolver,
        &GroupOverlay::new(),
    )
}
pub(super) fn prove_with_overlay(
    source: ClaimTree<'_, '_>,
    indexes: &QueryIndexes,
    old: &TenantState,
    new: &TenantState,
    changed: &ChangedIds,
    resolver: Option<&dyn DocumentResolver>,
    overlay: &GroupOverlay,
) -> Result<Decision> {
    ensure!(
        old.tenant == new.tenant && old.incarnation == new.incarnation,
        "unique delta scope differs"
    );
    let mut budget = Budget {
        tuples: TUPLES,
        reads: READS,
        bytes: SCALAR_BYTES,
    };
    let mut inserted = BTreeMap::new();
    for (name, ids) in changed {
        let previous = old
            .collections
            .get(name)
            .context("unique delta prior collection absent")?;
        let candidate = new
            .collections
            .get(name)
            .context("unique delta collection absent")?;
        ensure!(
            previous.definition == candidate.definition,
            "unique delta changed collection definition"
        );
        if !previous.definition.indexes.iter().any(|i| i.unique) {
            continue;
        }
        // This is the persisted validator's rejection order: changed IDs and
        // unique index names are both ascending. The definition itself may
        // declare its indexes in a different order.
        let mut unique: Vec<_> = previous
            .definition
            .indexes
            .iter()
            .filter(|i| i.unique)
            .collect();
        unique.sort_unstable_by(|a, b| a.name.cmp(&b.name));
        // Every old claim must match. All changed IDs are then considered
        // released together, so a swap is independent of their lexical order.
        for (state, collection, removing) in [(old, previous, true), (new, candidate, false)] {
            for id in ids {
                let loan = index_source::record(collection, id, state.revision, resolver)
                    .map_err(index_source::into_anyhow)?;
                if removing {
                    // The replayable resident delta opens both records on its
                    // removal pass. Retain a real candidate read failure before
                    // a later new-claim conflict can settle its write receipt.
                    drop(
                        index_source::record(candidate, id, new.revision, resolver)
                            .map_err(index_source::into_anyhow)?,
                    );
                }
                let Some(loan) = loan else {
                    continue;
                };
                for index in &unique {
                    let (key, exact, owner) = match probe(
                        source,
                        indexes,
                        name,
                        index,
                        loan.as_record(),
                        &mut budget,
                        overlay,
                    )? {
                        Probe::Sparse => continue,
                        Probe::Inconclusive => return Ok(Decision::Inconclusive),
                        Probe::Known {
                            fingerprint,
                            exact,
                            owner,
                        } => (fingerprint, exact, owner),
                    };
                    if removing {
                        ensure!(
                            owner.as_deref() == Some(id.as_str()),
                            "old unique native mapping differs from delta"
                        );
                        continue;
                    }
                    if owner.as_ref().is_some_and(|id| !ids.contains(id)) {
                        return Ok(Decision::Conflict(index.name.clone()));
                    }
                    let scope = exact.map(|bytes| (name.as_str(), index.name.as_str(), bytes));
                    match inserted.entry(key) {
                        std::collections::btree_map::Entry::Vacant(v) => {
                            v.insert(scope);
                        }
                        std::collections::btree_map::Entry::Occupied(o) => {
                            if scope.is_some() && scope.as_ref() == o.get().as_ref() {
                                return Ok(Decision::Conflict(index.name.clone()));
                            }
                            return Ok(Decision::Inconclusive);
                        }
                    }
                }
            }
        }
    }
    Ok(Decision::Accepted)
}
