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
use std::collections::BTreeSet;

const DOCUMENTS: usize = 32;
const TUPLES: usize = 32;
const ANCHOR_IDS: usize = 16;
const READS: usize = 512;
const SCALAR_BYTES: usize = 256 << 10;
// At most eight native prefixes, sixteen IDs, one candidate point and 32
// fixed digests are retained. Physical pages/overflow reads own their grants.
const WORKSPACE: u64 = 64 << 10;

pub(crate) fn validate_ordinary(
    previous: &crate::Generation,
    candidate: &TenantState,
    changed: &ChangedIds,
    roots: Option<&crate::application_sources::SourceRootsRef>,
) -> SourceResult<()> {
    let old = &previous.state;
    let resolver = previous.document_resolver();
    let any_unique = changed.keys().any(|name| {
        old.collections
            .get(name)
            .is_some_and(|c| c.definition.indexes.iter().any(|i| i.unique))
    });
    if any_unique
        && changed.values().map(|ids| ids.len()).sum::<usize>() <= DOCUMENTS
        && let Some((roots, selection)) = roots.zip(previous.application_selection.get())
    {
        let proved = selection
            .with_structured_records_since(
                None,
                old,
                || previous.indexes.structured_layout_sha256(),
                kasumi_store::structured_manifest::ORDERED_TUPLE_FORMAT,
                |reader| {
                    let _workspace = roots.memory_owner().clone().reserve_installed(WORKSPACE)?;
                    prove(reader, &previous.indexes, old, candidate, changed, resolver)
                },
            )
            .map_err(|e| kasumi_query::ReadFailure::Source(DocumentSourceFailure(e)))?;
        if proved == Some(true) {
            return Ok(());
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

enum Probe {
    Sparse,
    Inconclusive,
    Known {
        fingerprint: [u8; 32],
        owner: Option<String>,
    },
}

/// Include the length of each part. Only equality of two fingerprints can
/// cause a fallback. A digest match never authorizes a write or declares a
/// deterministic conflict.
fn hash_part(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_be_bytes());
    hash.update(value);
}

fn probe(
    reader: &TreeReader<'_>,
    indexes: &QueryIndexes,
    collection: &str,
    index: &IndexDefinition,
    record: Record<'_>,
    budget: &mut Budget,
) -> Result<Probe> {
    let value_at = |path: &str| match record {
        Record::Live(doc) => doc.body.pointer(path),
        Record::Archived(doc) => doc.indexed_fields.get(path),
    };
    if index
        .fields
        .iter()
        .any(|field| value_at(&field.path).is_none())
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
    if index.fields.len() > 1
        && let Some(key) = kasumi_query::ordered_record_tuple(&index.fields, record)?
    {
        if !budget.read() {
            return Ok(Probe::Inconclusive);
        }
        let ordinal = indexes
            .compound_ordinal(collection, &index.name)
            .context("compound absent from selected layout")?;
        hash_part(&mut hash, &key);
        let mut native = field_prefix(super::COMPOUND, collection, ordinal);
        native.extend_from_slice(&key);
        let owner = reader.with_value(&native, 256, |v| {
            v.map(super::posting_id)
                .transpose()
                .map(|id| id.map(str::to_owned))
        })?;
        return Ok(Probe::Known {
            fingerprint: hash.finalize().into(),
            owner,
        });
    }
    let mut prefixes = Vec::with_capacity(index.fields.len());
    let mut absent = false;
    for field in &index.fields {
        let value = value_at(&field.path).context("complete unique tuple lost a field")?;
        let component = FieldValue::predicate(value, field.kind)?;
        let Some(left) = budget.bytes.checked_sub(component.bytes.len()) else {
            return Ok(Probe::Inconclusive);
        };
        budget.bytes = left;
        hash.update([component.tag]);
        hash_part(&mut hash, &component.bytes);
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
        return Ok(Probe::Known { fingerprint, owner });
    }
    Ok(Probe::Inconclusive)
}

pub(super) fn prove(
    reader: &TreeReader<'_>,
    indexes: &QueryIndexes,
    old: &TenantState,
    new: &TenantState,
    changed: &ChangedIds,
    resolver: Option<&dyn DocumentResolver>,
) -> Result<bool> {
    ensure!(
        old.tenant == new.tenant && old.incarnation == new.incarnation,
        "unique delta scope differs"
    );
    let mut budget = Budget {
        tuples: TUPLES,
        reads: READS,
        bytes: SCALAR_BYTES,
    };
    let mut inserted = BTreeSet::new();
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
        // Every old claim must match. All changed IDs are then considered
        // released together, so a swap is independent of their lexical order.
        for (state, collection, removing) in [(old, previous, true), (new, candidate, false)] {
            for id in ids {
                let loan = index_source::record(collection, id, state.revision, resolver)
                    .map_err(index_source::into_anyhow)?;
                let Some(loan) = loan else {
                    continue;
                };
                for index in collection.definition.indexes.iter().filter(|i| i.unique) {
                    let (key, owner) =
                        match probe(reader, indexes, name, index, loan.as_record(), &mut budget)? {
                            Probe::Sparse => continue,
                            Probe::Inconclusive => return Ok(false),
                            Probe::Known { fingerprint, owner } => (fingerprint, owner),
                        };
                    if removing {
                        ensure!(
                            owner.as_deref() == Some(id.as_str()),
                            "old unique native mapping differs from delta"
                        );
                        continue;
                    }
                    if owner.as_ref().is_some_and(|id| !ids.contains(id)) {
                        return Ok(false);
                    }
                    if !inserted.insert(key) {
                        return Ok(false);
                    }
                }
            }
        }
    }
    Ok(true)
}
