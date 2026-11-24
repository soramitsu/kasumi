//! Capture ordinary tuple ownership from the accepted ID journal while pending
//! after-images still have a body. Each loan ends before the next one opens.
//! All old owners are removed before any new owner is installed, including
//! when several accepted group members changed the same document.
use super::*;
use crate::application_primary::ChangedIds;
use crate::index_source;
use kasumi_store::{DiskMemoryLease, NodeDiskMemoryAdmission};
use kasumi_types::DocumentResolver;

const MAX_TUPLES: usize = 64;

#[derive(Default)]
struct Owners {
    old: Option<String>,
    new: Option<String>,
}

pub(crate) struct Captured {
    rows: BTreeMap<(String, usize, Vec<u8>), Owners>,
    _lease: Option<DiskMemoryLease>,
}

impl Captured {
    pub(crate) fn collect(
        previous: &TenantState,
        candidate: &TenantState,
        indexes: &QueryIndexes,
        changed: &ChangedIds,
        resolver: Option<&dyn DocumentResolver>,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Result<Option<Self>> {
        let mut count = 0usize;
        for (name, ids) in changed {
            let Some(old) = previous.collections.get(name) else {
                return Ok(None);
            };
            let Some(new) = candidate.collections.get(name) else {
                return Ok(None);
            };
            if old.definition != new.definition {
                return Ok(None);
            }
            count = count.saturating_add(
                ids.len()
                    .saturating_mul(indexes.compound_count(name))
                    .saturating_mul(2),
            );
            if count > MAX_TUPLES {
                return Ok(None);
            }
        }
        let mut captured = Self {
            rows: BTreeMap::new(),
            _lease: None,
        };
        if count == 0 {
            return Ok(Some(captured));
        }
        // A tuple key, both IDs, the collection name and the B-tree slot.
        // Every decoded body remains covered by its own source loan.
        captured._lease = Some(memory.reserve_installed(
            (4096 + count * (kasumi_query::MAX_ORDERED_TUPLE_BYTES + 3 * 256 + 256)) as u64,
        )?);
        for (name, ids) in changed {
            let indexes_here = indexes.compound_count(name);
            if indexes_here == 0 {
                continue;
            }
            for (state, adding) in [(previous, false), (candidate, true)] {
                let collection = &state.collections[name];
                for id in ids {
                    let loan = index_source::record(collection, id, state.revision, resolver)
                        .map_err(index_source::into_anyhow)?;
                    let Some(loan) = loan else {
                        continue;
                    };
                    for ordinal in 0..indexes_here {
                        let fields = indexes
                            .compound_fields(name, ordinal)
                            .context("captured compound ordinal absent")?;
                        if let Some(key) =
                            kasumi_query::ordered_record_tuple(fields, loan.as_record())?
                        {
                            let pair = captured
                                .rows
                                .entry((name.clone(), ordinal, key))
                                .or_default();
                            let target = if adding { &mut pair.new } else { &mut pair.old };
                            ensure!(
                                target.replace(id.to_owned()).is_none(),
                                "accepted tuple has two document owners"
                            );
                        }
                    }
                }
            }
        }
        Ok(Some(captured))
    }

    pub(super) fn visit<E>(
        &self,
        mut emit: impl FnMut(&str, bool, StructuredRow<'_>) -> Result<bool, E>,
    ) -> Result<bool, E> {
        for ((name, index, key), owners) in &self.rows {
            if owners.old == owners.new {
                continue;
            }
            for (added, owner) in [(false, &owners.old), (true, &owners.new)] {
                if let Some(id) = owner
                    && !emit(
                        name,
                        added,
                        StructuredRow::Compound {
                            index: *index,
                            key,
                            id,
                        },
                    )?
                {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }
}
