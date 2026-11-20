//! Incremental reconstruction from each selected document's actual indexed
//! fields. The cursor orders native row keys inside one field, so reordering
//! an array or removing the covered document cannot skip an unchanged row.
//! Ordinary publications independently mirror their whole bounded delta.
use super::*;
use kasumi_store::primary_manifest::PrimaryCursor;
use kasumi_store::structured_manifest::{
    StructuredCursor, StructuredFieldCursor, StructuredRebuild, StructuredStatus,
};
use kasumi_types::{DocumentResolver, ScalarType};
use serde_json::Value;

const WINDOW_ROWS: usize = 256;
const WINDOW_FIELDS: usize = 128;
// A step can carry one admitted native scalar larger than its ordinary budget.
const WINDOW_BYTES: usize = 4 << 20;
pub(super) const MAX_BATCHES: u32 = 256;

pub(crate) fn seed(
    owner: &StructuredOwner,
    store: &Arc<TenantStore>,
    state: &TenantState,
    indexes: &QueryIndexes,
    applied: Option<&StructuredApplied>,
) -> Result<StructuredPublication> {
    let through = state
        .collections
        .iter()
        .rev()
        .find_map(|(name, c)| {
            c.documents
                .keys()
                .next_back()
                .max(c.archived_documents.keys().next_back())
                .map(|id| PrimaryCursor {
                    collection: name.clone(),
                    after_document: Some(id.clone()),
                })
        })
        .context("large structured rebuild has no terminal document")?;
    let family = SelectedGeneration::adopt(store, structured::FAMILY, &structured::INITIAL_SPACE)?;
    let stage = owner
        .replacement
        .begin(store, structured::FAMILY, family.namespace(0))?;
    stage.seal_empty()?;
    let mut manifest = StructuredManifest::new(
        &state.tenant,
        &state.incarnation,
        state.revision_base,
        state.revision,
        applied.cloned(),
        indexes.structured_layout_sha256(),
        stage.namespace(),
        TreeRoot::new_tree(),
    );
    manifest.status = StructuredStatus::Rebuilding(Box::new(StructuredRebuild {
        captured: applied.cloned(),
        through,
        cursor: None,
    }));
    let mut writes = family.switch_writes(store, &[&stage])?;
    writes.push(manifest.write()?);
    Ok(StructuredPublication::only(writes))
}

struct Window<'a> {
    rows: BTreeMap<Vec<u8>, Vec<u8>>,
    lookups: usize,
    fields: usize,
    bytes: usize,
    large: Option<kasumi_store::DiskMemoryLease>,
    store: &'a TenantStore,
    reader: TreeReader<'a>,
}
impl Window<'_> {
    fn full(&self) -> bool {
        self.lookups >= WINDOW_ROWS || self.fields >= WINDOW_FIELDS || self.bytes >= WINDOW_BYTES
    }
    /// Preserve only the lowest outstanding native keys. An array has at most
    /// 4096 admitted elements. Values remain borrowed while choosing keys,
    /// including when several large strings share an ordered prefix.
    fn field<'s>(
        &mut self,
        name: &str,
        id: &str,
        ordinal: usize,
        after: &[u8],
        kind: ScalarType,
        source: Option<&'s Value>,
    ) -> Result<Option<Vec<u8>>> {
        let room = WINDOW_ROWS - self.lookups;
        let mut eligible: BTreeMap<Vec<u8>, Option<&'s str>> = BTreeMap::new();
        let mut more = false;
        let mut consider = |key: Vec<u8>, value: Option<&'s str>| -> Result<()> {
            let key = checked_key(key)?;
            if key.as_slice() > after {
                eligible.insert(key, value);
                if eligible.len() > room {
                    eligible.pop_last();
                    more = true;
                }
            }
            Ok(())
        };
        if source.is_some() {
            let mut key = field_prefix(PRESENT, name, ordinal);
            key.extend_from_slice(id.as_bytes());
            consider(key, None)?;
        }
        let mut scalar = |item: Option<&'s Value>| -> Result<()> {
            let value = match item {
                Some(v) => FieldValue::predicate(v, kind)?,
                None => FieldValue {
                    tag: 0,
                    bytes: std::borrow::Cow::Borrowed(&[]),
                },
            };
            let mut component = Vec::new();
            if push_value(&mut component, &value)? {
                let mut key = field_prefix(LONG, name, ordinal);
                key.extend_from_slice(&component);
                consider(
                    key,
                    Some(
                        item.and_then(Value::as_str)
                            .context("long structured scalar is not a string")?,
                    ),
                )?;
            }
            let mut key = field_prefix(POSTING, name, ordinal);
            key.extend_from_slice(&component);
            key.extend_from_slice(id.as_bytes());
            consider(key, None)
        };
        if let (ScalarType::StringArray | ScalarType::NumberArray, Some(Value::Array(values))) =
            (kind, source)
        {
            ensure!(
                values.len() <= 4096,
                "structured array exceeds its admitted element bound"
            );
            for v in values {
                scalar(Some(v))?;
            }
        } else {
            scalar(source)?;
        }
        let mut last = after.to_owned();
        for (key, reference) in eligible {
            let value = reference.unwrap_or_default();
            ensure!(
                value.len() <= MAX_VALUE_BYTES,
                "structured scalar exceeds the native value bound"
            );
            let already = key.first() == Some(&LONG)
                && (self.rows.contains_key(&key) || self.reader.contains_key(&key)?);
            let size = if already { 0 } else { key.len() + value.len() };
            if self.bytes.saturating_add(size) > WINDOW_BYTES && self.lookups != 0 {
                return Ok(Some(last));
            }
            if size > WINDOW_BYTES {
                self.large = Some(
                    self.store
                        .plaintext_memory_owner()
                        .clone()
                        .reserve_installed(size as u64)?,
                );
            }
            last = key.clone();
            if !already {
                self.bytes += size;
                self.rows.insert(key, value.as_bytes().to_vec());
            }
            self.lookups += 1;
        }
        Ok(more.then_some(last))
    }
}

fn advance(
    state: &TenantState,
    indexes: &QueryIndexes,
    resolver: Option<&dyn DocumentResolver>,
    progress: &StructuredRebuild,
    window: &mut Window<'_>,
) -> Result<StructuredRebuild> {
    let mut next = progress.clone();
    let start = progress.cursor.as_ref().map_or(Bound::Unbounded, |c| {
        if c.document.after_document.is_some() {
            Bound::Included(c.document.collection.as_str())
        } else {
            Bound::Excluded(c.document.collection.as_str())
        }
    });
    for (name, collection) in state.collections.range::<str, _>((start, Bound::Unbounded)) {
        if name > &progress.through.collection {
            break;
        }
        let cursor = progress
            .cursor
            .as_ref()
            .filter(|c| &c.document.collection == name);
        let after = cursor.and_then(|c| c.document.after_document.as_deref());
        let partial = cursor.and_then(|c| c.field.as_ref());
        let current = partial.and(after).into_iter();
        let following =
            crate::index_source::resident_ids_after(collection, after).map(String::as_str);
        for id in current.chain(following) {
            if name == &progress.through.collection
                && Some(id) > progress.through.after_document.as_deref()
            {
                break;
            }
            let doc = PrimaryCursor {
                collection: name.clone(),
                after_document: Some(id.to_owned()),
            };
            let at = partial.filter(|_| Some(id) == after);
            let record = crate::index_source::record(collection, id, state.revision, resolver)
                .map_err(crate::index_source::into_anyhow)?;
            if let Some(record) = record {
                let count = indexes
                    .structured_field_count(name)
                    .context("structured collection absent")?;
                for ordinal in at.map_or(0, |f| f.ordinal as usize)..count {
                    let resume = at
                        .filter(|c| c.ordinal as usize == ordinal)
                        .map_or(&[][..], |c| c.after.as_slice());
                    let (kind, value) = indexes
                        .structured_field_value(name, ordinal, record.as_record())
                        .context("structured field absent")?;
                    let last = window.field(name, id, ordinal, resume, kind, value)?;
                    window.fields += 1;
                    let pending = if let Some(after) = last {
                        Some((ordinal, after))
                    } else if window.full() && ordinal + 1 < count {
                        Some((ordinal + 1, Vec::new()))
                    } else {
                        None
                    };
                    if let Some((ordinal, after)) = pending {
                        next.cursor = Some(StructuredCursor {
                            document: doc,
                            field: Some(StructuredFieldCursor {
                                ordinal: ordinal.try_into()?,
                                after,
                            }),
                        });
                        return Ok(next);
                    }
                }
            }
            window.fields += 1;
            next.cursor = Some(StructuredCursor {
                document: doc,
                field: None,
            });
            if window.full() {
                return Ok(next);
            }
        }
        if name == &progress.through.collection {
            break;
        }
        window.fields += 1;
        if window.full() {
            next.cursor = Some(StructuredCursor {
                document: PrimaryCursor {
                    collection: name.clone(),
                    after_document: None,
                },
                field: None,
            });
            return Ok(next);
        }
    }
    next.cursor = Some(StructuredCursor {
        document: progress.through.clone(),
        field: None,
    });
    Ok(next)
}

/// Drive one native transaction under the caller's apply gate. Success returns
/// true only when the exact current root and replacement cleanup are settled.
pub(crate) fn maintain(
    owner: &StructuredOwner,
    store: &Arc<TenantStore>,
    state: &TenantState,
    indexes: &QueryIndexes,
    resolver: Option<&dyn DocumentResolver>,
    applied: Option<&StructuredApplied>,
) -> Result<bool> {
    ensure!(
        state
            .revision_base
            .checked_add(applied.map_or(0, |p| p.index))
            == Some(state.revision),
        "structured maintenance observed a different revision"
    );
    owner.recover(store)?;
    let may_replace =
        owner
            .replacement
            .advance(store, structured::FAMILY, &structured::INITIAL_SPACE)?;
    let Some(manifest) = load_or_skip(store)? else {
        return Ok(false);
    };
    if let Some(m) = &manifest
        && (m.tenant != state.tenant
            || m.incarnation != state.incarnation
            || m.revision_base != state.revision_base
            || m.revision > state.revision)
    {
        return Ok(false);
    }
    let layout = indexes.structured_layout_sha256();
    let positioned = manifest.as_ref().is_some_and(|m| {
        m.revision == state.revision && m.matches_applied(applied) && m.layout_sha256 == layout
    });
    if positioned
        && manifest
            .as_ref()
            .is_some_and(StructuredManifest::is_current)
    {
        return Ok(may_replace);
    }
    let Some(mut base) = manifest.filter(|m| positioned && m.rebuild().is_some()) else {
        if may_replace {
            let writes = if bulk_workspace(indexes).is_some() {
                rebuild(store, state, indexes, applied.cloned(), Some(owner))?
            } else {
                seed(owner, store, state, indexes, applied)?.take_writes()
            };
            store.write_batch(&writes)?;
        }
        return Ok(false);
    };
    let progress = base.rebuild().expect("partial manifest");
    if progress.finished() {
        base.status = StructuredStatus::Current;
        store.write_batch(&[base.write()?])?;
        return Ok(may_replace);
    }
    let _workspace = store
        .plaintext_memory_owner()
        .clone()
        .reserve_installed((WINDOW_BYTES + (WINDOW_ROWS + 2) * (2 * MAX_KEY_BYTES + 256)) as u64)?;
    let mut window = Window {
        rows: BTreeMap::new(),
        lookups: 0,
        fields: 0,
        bytes: 0,
        large: None,
        store,
        reader: TreeReader::new(&**store, &base.page_space, base.records, None)?,
    };
    let next = advance(state, indexes, resolver, progress, &mut window)?;
    ensure!(
        next.cursor > progress.cursor,
        "structured rebuild window did not advance"
    );
    base.status = StructuredStatus::Rebuilding(Box::new(next));
    if window.rows.is_empty() {
        store.write_batch(&[base.write()?])?;
        return Ok(false);
    }
    let edits: Vec<_> = window.rows.iter().map(|(k, v)| Edit::Put(k, v)).collect();
    owner.recovery_pending.store(true, Ordering::Release);
    let edit = ordered_pages::edit_tree_staged_batches(
        store,
        &base.page_space,
        &base.records,
        MAX_BATCHES,
        |apply| apply(&edits),
    )?;
    let (root, mut writes, _edit_workspace) = edit.into_parts();
    base.records = root;
    writes.push(base.write()?);
    store.write_batch(&writes)?;
    Ok(false)
}
