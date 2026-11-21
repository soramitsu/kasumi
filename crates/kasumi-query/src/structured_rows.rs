//! Logical rows of the ordinary structured directory, and the exact set of
//! rows that differ between two generations' indexes.
//!
//! A field is named by its ordinal among the collection's indexed paths, the
//! same sorted path map the planner uses. A changed collection definition can
//! renumber fields, so its rows are replaced as a whole. Otherwise the
//! persistent maps of both generations share every untouched node, and the
//! difference visits only the entries a mutation changed: no document body is
//! opened and no collection-sized pass runs for an ordinary write.
use crate::scalar::Scalar;
use crate::structured::{FieldIndex, IdSet};
use crate::{CollectionIndexes, FieldValue, QueryIndexes};
use imbl::{ordmap, ordset};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// One row of a collection's structured directory.
#[derive(Clone, Copy)]
pub enum StructuredRow<'a> {
    /// An order-preserving, complete compound tuple and its unique owner.
    Compound {
        index: usize,
        key: &'a [u8],
        id: &'a str,
    },
    /// The document has a value at the field's path, null and arrays included.
    Present { field: usize, id: &'a str },
    /// The field has at least one posting under this distinct scalar.
    Value {
        field: usize,
        value: &'a FieldValue<'a>,
    },
    /// The document is indexed under this scalar. A missing path is the
    /// scalar with tag zero, so absence needs no separate row.
    Posting {
        field: usize,
        value: &'a FieldValue<'a>,
        id: &'a str,
    },
}

/// One indexed field's resident postings.
#[derive(Clone, Copy)]
pub struct StructuredField<'a> {
    index: &'a FieldIndex,
}
impl<'a> StructuredField<'a> {
    /// Documents with a value at the path, in ID order.
    pub fn present(&self) -> impl Iterator<Item = &'a str> + use<'a> {
        self.index.present.iter().map(String::as_str)
    }
    /// Distinct scalars in canonical scalar order with their postings.
    pub fn values(&self) -> impl Iterator<Item = StructuredPostings<'a>> + use<'a> {
        self.index
            .entries
            .iter()
            .map(|(key, ids)| StructuredPostings {
                value: FieldValue::from_scalar(key),
                ids,
            })
    }
}

/// One distinct scalar and the documents indexed under it.
pub struct StructuredPostings<'a> {
    pub value: FieldValue<'a>,
    ids: &'a IdSet,
}
impl<'a> StructuredPostings<'a> {
    /// Document IDs in ID order.
    pub fn ids(&self) -> impl Iterator<Item = &'a str> + use<'a> {
        self.ids.iter().map(String::as_str)
    }
}

fn postings<E>(
    field: usize,
    key: &Scalar,
    ids: &IdSet,
    emit: &mut impl FnMut(StructuredRow<'_>) -> Result<bool, E>,
) -> Result<bool, E> {
    let value = FieldValue::from_scalar(key);
    if !emit(StructuredRow::Value {
        field,
        value: &value,
    })? {
        return Ok(false);
    }
    for id in ids {
        if !emit(StructuredRow::Posting {
            field,
            value: &value,
            id,
        })? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn field_rows<E>(
    field: usize,
    index: &FieldIndex,
    emit: &mut impl FnMut(StructuredRow<'_>) -> Result<bool, E>,
) -> Result<bool, E> {
    for id in &index.present {
        if !emit(StructuredRow::Present { field, id })? {
            return Ok(false);
        }
    }
    for (key, ids) in &index.entries {
        if !postings(field, key, ids, emit)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn collection_rows<E>(
    indexes: &CollectionIndexes,
    emit: &mut impl FnMut(StructuredRow<'_>) -> Result<bool, E>,
) -> Result<bool, E> {
    for (field, index) in indexes.structured.fields.values().enumerate() {
        if !field_rows(field, index, emit)? {
            return Ok(false);
        }
    }
    compound_rows(indexes, emit)
}

fn compound_rows<E>(
    indexes: &CollectionIndexes,
    emit: &mut impl FnMut(StructuredRow<'_>) -> Result<bool, E>,
) -> Result<bool, E> {
    for (index, unique) in indexes
        .structured
        .unique
        .values()
        .filter(|u| u.fields.len() > 1)
        .enumerate()
    {
        for (tuple, id) in unique.entries.as_ref().expect("compound root") {
            if let Some(key) = crate::ordered_tuple::encode(tuple)
                && !emit(StructuredRow::Compound {
                    index,
                    key: &key,
                    id,
                })?
            {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

fn compound_changes<E>(
    old: &CollectionIndexes,
    new: &CollectionIndexes,
    mut emit: impl FnMut(bool, StructuredRow<'_>) -> Result<bool, E>,
) -> Result<bool, E> {
    let indexes = old
        .structured
        .unique
        .values()
        .zip(new.structured.unique.values())
        .filter(|(old, _)| old.fields.len() > 1);
    for (index, (old, new)) in indexes.enumerate() {
        let old = old.entries.as_ref().expect("compound root");
        let new = new.entries.as_ref().expect("compound root");
        if old.ptr_eq(new) {
            continue;
        }
        for difference in old.diff(new) {
            let (key, removed, added) = match difference {
                ordmap::DiffItem::Add(key, id) => (key, None, Some(id)),
                ordmap::DiffItem::Remove(key, id) => (key, Some(id), None),
                ordmap::DiffItem::Update {
                    old: (key, prior),
                    new: (_, next),
                } => (key, Some(prior), Some(next)),
            };
            let Some(key) = crate::ordered_tuple::encode(key) else {
                continue;
            };
            for (added, id) in [(false, removed), (true, added)] {
                if let Some(id) = id
                    && !emit(
                        added,
                        StructuredRow::Compound {
                            index,
                            key: &key,
                            id,
                        },
                    )?
                {
                    return Ok(false);
                }
            }
        }
    }
    Ok(true)
}

fn field_changes<E>(
    field: usize,
    old: &FieldIndex,
    new: &FieldIndex,
    emit: &mut impl FnMut(bool, StructuredRow<'_>) -> Result<bool, E>,
) -> Result<bool, E> {
    if !old.present.ptr_eq(&new.present) {
        for item in old.present.diff(&new.present) {
            let (added, id) = match item {
                ordset::DiffItem::Add(id) => (true, id),
                ordset::DiffItem::Remove(id) => (false, id),
            };
            if !emit(added, StructuredRow::Present { field, id })? {
                return Ok(false);
            }
        }
    }
    if old.entries.ptr_eq(&new.entries) {
        return Ok(true);
    }
    for item in old.entries.diff(&new.entries) {
        let more = match item {
            ordmap::DiffItem::Add(key, ids) => {
                postings(field, key, ids, &mut |row| emit(true, row))?
            }
            ordmap::DiffItem::Remove(key, ids) => {
                postings(field, key, ids, &mut |row| emit(false, row))?
            }
            ordmap::DiffItem::Update {
                old: (key, before),
                new: (_, after),
            } => {
                let value = FieldValue::from_scalar(key);
                let mut more = true;
                for item in before.diff(after) {
                    let (added, id) = match item {
                        ordset::DiffItem::Add(id) => (true, id),
                        ordset::DiffItem::Remove(id) => (false, id),
                    };
                    more = emit(
                        added,
                        StructuredRow::Posting {
                            field,
                            value: &value,
                            id,
                        },
                    )?;
                    if !more {
                        break;
                    }
                }
                more
            }
        };
        if !more {
            return Ok(false);
        }
    }
    Ok(true)
}

impl QueryIndexes {
    /// Emit all representable compound rows in native key order. Stops as soon
    /// as the consumer refuses a row.
    pub fn visit_compound_rows<E>(
        &self,
        mut emit: impl FnMut(&str, usize, &[u8], &str) -> Result<bool, E>,
    ) -> Result<bool, E> {
        for (name, collection) in &self.collections {
            if !compound_rows(collection, &mut |row| match row {
                StructuredRow::Compound { index, key, id } => emit(name, index, key, id),
                _ => unreachable!("compound row producer"),
            })? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    pub fn compound_ordinal(&self, collection: &str, name: &str) -> Option<usize> {
        self.collections
            .get(collection)?
            .structured
            .unique
            .iter()
            .filter(|(_, unique)| unique.fields.len() > 1)
            .position(|(key, _)| key == name)
    }

    pub fn compound_order_complete(&self, collection: &str, ordinal: usize) -> bool {
        self.collections
            .get(collection)
            .and_then(|indexes| {
                indexes
                    .structured
                    .unique
                    .values()
                    .filter(|u| u.fields.len() > 1)
                    .nth(ordinal)
            })
            .is_some_and(|u| u.overflow.is_empty())
    }

    pub fn compound_count(&self, collection: &str) -> usize {
        self.collections.get(collection).map_or(0, |c| {
            c.structured
                .unique
                .values()
                .filter(|u| u.fields.len() > 1)
                .count()
        })
    }

    pub fn compound_fields(
        &self,
        collection: &str,
        ordinal: usize,
    ) -> Option<&[kasumi_types::IndexField]> {
        Some(
            &self
                .collections
                .get(collection)?
                .structured
                .unique
                .values()
                .filter(|u| u.fields.len() > 1)
                .nth(ordinal)?
                .fields,
        )
    }

    /// Binds every collection's name and complete definition in name order.
    /// Rows written under one layout are never read under another.
    pub fn structured_layout_sha256(&self) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(b"kasumi.structured.layout.v1");
        hash.update((self.collections.len() as u64).to_be_bytes());
        for (name, indexes) in &self.collections {
            hash.update((name.len() as u64).to_be_bytes());
            hash.update(name.as_bytes());
            hash.update(indexes.definition_sha256);
        }
        hash.finalize().into()
    }

    /// The number of indexed fields of `collection`, if it exists.
    pub fn structured_field_count(&self, collection: &str) -> Option<usize> {
        self.collections
            .get(collection)
            .map(|indexes| indexes.structured.fields.len())
    }

    /// The ordinal used by the selected native presence and posting keys.
    pub fn structured_field_ordinal(&self, collection: &str, path: &str) -> Option<usize> {
        self.collections
            .get(collection)?
            .structured
            .fields
            .keys()
            .position(|key| key == path)
    }

    /// The field value used to build the resident presence and scalar postings.
    /// Archived rows lend their authenticated stored projection.
    pub fn structured_field_value<'a>(
        &self,
        collection: &str,
        ordinal: usize,
        record: crate::Record<'a>,
    ) -> Option<(kasumi_types::ScalarType, Option<&'a serde_json::Value>)> {
        let (path, field) = self
            .collections
            .get(collection)?
            .structured
            .fields
            .iter()
            .nth(ordinal)?;
        Some((field.kind, crate::structured::record_value(record, path)))
    }

    /// Every collection's indexed fields in name order, each collection's
    /// fields in ordinal order. The borrowed postings stay in the resident
    /// persistent maps; nothing is copied until a caller encodes a row.
    pub fn structured_collections(
        &self,
    ) -> impl Iterator<Item = (&str, impl Iterator<Item = StructuredField<'_>>)> {
        self.collections.iter().map(|(name, indexes)| {
            (
                name.as_str(),
                indexes
                    .structured
                    .fields
                    .values()
                    .map(|index| StructuredField { index }),
            )
        })
    }

    /// Whether no collection has any structured row.
    pub fn structured_is_empty(&self) -> bool {
        self.collections.values().all(|indexes| {
            indexes
                .structured
                .fields
                .values()
                .all(|index| index.present.is_empty() && index.entries.is_empty())
        })
    }

    /// Whether the directory holds at most `limit` presence and posting rows.
    /// The count stops at the limit, so the check costs at most `limit`
    /// distinct scalars however large the indexes are.
    pub fn structured_rows_within(&self, limit: usize) -> bool {
        let mut rows = 0usize;
        for indexes in self.collections.values() {
            for index in indexes
                .structured
                .unique
                .values()
                .filter(|u| u.fields.len() > 1)
            {
                rows = rows.saturating_add(index.entries.as_ref().expect("compound root").len());
                if rows > limit {
                    return false;
                }
            }
            for index in indexes.structured.fields.values() {
                rows = rows.saturating_add(index.present.len());
                if rows > limit {
                    return false;
                }
                for ids in index.entries.values() {
                    rows = rows.saturating_add(ids.len());
                    if rows > limit {
                        return false;
                    }
                }
            }
        }
        true
    }

    /// The rows that differ from `previous` to `self`: `emit(collection,
    /// added, row)`. A collection whose definition changed, appeared or
    /// disappeared contributes all of its previous rows as removals and then
    /// all of its rows as additions, so a later addition of the same row
    /// supersedes its removal. `emit` returns false to stop; the result is
    /// false when it did.
    pub fn visit_structured_changes<E>(
        &self,
        previous: &Self,
        mut emit: impl FnMut(&str, bool, StructuredRow<'_>) -> Result<bool, E>,
    ) -> Result<bool, E> {
        if std::ptr::eq(self, previous) {
            return Ok(true);
        }
        for (name, old) in &previous.collections {
            let new = self.collections.get(name);
            if new.is_some_and(|new| Arc::ptr_eq(old, new)) {
                continue;
            }
            match new {
                Some(new) if new.definition_sha256 == old.definition_sha256 => {
                    let fields = old
                        .structured
                        .fields
                        .values()
                        .zip(new.structured.fields.values());
                    for (field, (before, after)) in fields.enumerate() {
                        if !field_changes(field, before, after, &mut |added, row| {
                            emit(name, added, row)
                        })? {
                            return Ok(false);
                        }
                    }
                    if !compound_changes(old, new, |added, row| emit(name, added, row))? {
                        return Ok(false);
                    }
                }
                _ => {
                    if !collection_rows(old, &mut |row| emit(name, false, row))? {
                        return Ok(false);
                    }
                    if let Some(new) = new
                        && !collection_rows(new, &mut |row| emit(name, true, row))?
                    {
                        return Ok(false);
                    }
                }
            }
        }
        for (name, new) in &self.collections {
            if !previous.collections.contains_key(name)
                && !collection_rows(new, &mut |row| emit(name, true, row))?
            {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_test_utils::{FixtureQueries, pending};
    use kasumi_types::{
        CollectionDefinition, CollectionRetentionClass, CollectionState, CollectionWriteMode,
        Document, IndexDefinition, IndexField, ScalarType,
    };
    use serde_json::{Value, json};
    use std::collections::{BTreeMap, BTreeSet};

    type Row = (String, u8, usize, u8, Vec<u8>, String);

    fn row(collection: &str, row: StructuredRow<'_>) -> Row {
        match row {
            StructuredRow::Compound { index, key, id } => {
                (collection.into(), b'U', index, 0, key.to_vec(), id.into())
            }
            StructuredRow::Present { field, id } => {
                (collection.into(), b'P', field, 0, Vec::new(), id.into())
            }
            StructuredRow::Value { field, value } => (
                collection.into(),
                b'D',
                field,
                value.tag,
                value.bytes.to_vec(),
                String::new(),
            ),
            StructuredRow::Posting { field, value, id } => (
                collection.into(),
                b'V',
                field,
                value.tag,
                value.bytes.to_vec(),
                id.into(),
            ),
        }
    }

    fn all(indexes: &QueryIndexes) -> BTreeSet<Row> {
        let mut rows = BTreeSet::new();
        for (name, fields) in indexes.structured_collections() {
            for (field, index) in fields.enumerate() {
                for id in index.present() {
                    assert!(rows.insert(row(name, StructuredRow::Present { field, id })));
                }
                for postings in index.values() {
                    let value = &postings.value;
                    assert!(rows.insert(row(name, StructuredRow::Value { field, value })));
                    for id in postings.ids() {
                        assert!(
                            rows.insert(row(name, StructuredRow::Posting { field, value, id }))
                        );
                    }
                }
            }
        }
        rows
    }

    /// Apply the reported changes to `before` in order and return the result
    /// with the number of changes.
    fn applied(before: &QueryIndexes, after: &QueryIndexes) -> (BTreeSet<Row>, usize) {
        let mut rows = all(before);
        let mut changes = 0;
        let complete = after
            .visit_structured_changes(before, |name, added, change| {
                changes += 1;
                let change = row(name, change);
                if added {
                    assert!(rows.insert(change), "added row was present");
                } else {
                    assert!(rows.remove(&change), "removed row was absent");
                }
                Ok::<_, std::convert::Infallible>(true)
            })
            .unwrap();
        assert!(complete);
        (rows, changes)
    }

    fn collection(name: &str, paths: &[(&str, ScalarType)]) -> CollectionState {
        CollectionState {
            definition: std::sync::Arc::new(CollectionDefinition {
                name: name.into(),
                write_mode: CollectionWriteMode::Mutable,
                retention_class: CollectionRetentionClass::Operational,
                schema: json!({"type": "object"}),
                indexes: paths
                    .iter()
                    .map(|(path, kind)| IndexDefinition {
                        name: path.trim_start_matches('/').into(),
                        fields: vec![IndexField {
                            path: (*path).into(),
                            kind: *kind,
                        }],
                        unique: false,
                        text: None,
                    })
                    .collect(),
                strict_read_audit: false,
            }),
            data_epoch: 1,
            documents: Default::default(),
            archived_documents: Default::default(),
            archived_document_bytes: 0,
        }
    }

    fn put(collection: &mut CollectionState, id: &str, version: u64, body: Value) {
        collection.documents.insert(
            id.into(),
            pending(Document {
                id: id.into(),
                version,
                body,
            }),
        );
    }

    #[test]
    fn the_change_set_is_exactly_the_difference_between_two_generations() {
        const PATHS: [(&str, ScalarType); 3] = [
            ("/n", ScalarType::Number),
            ("/s", ScalarType::String),
            ("/tags", ScalarType::StringArray),
        ];
        let mut docs = collection("docs", &PATHS);
        for n in 0..200u64 {
            let body = match n % 4 {
                0 => {
                    json!({"s": format!("v{}", n % 9), "n": n, "tags": ["a", format!("t{}", n % 5)]})
                }
                1 => json!({"s": null, "tags": []}),
                2 => json!({"n": n % 7}),
                _ => json!({"s": format!("v{}", n % 3)}),
            };
            put(&mut docs, &format!("d{n:03}"), 1, body);
        }
        let mut other = collection("other", &[("/s", ScalarType::String)]);
        put(&mut other, "o1", 1, json!({"s": "kept"}));
        let first: BTreeMap<String, CollectionState> =
            [("docs".to_owned(), docs), ("other".to_owned(), other)].into();
        let empty = QueryIndexes::default();
        assert!(empty.structured_is_empty());
        let built = QueryIndexes::build_fixture(&first).unwrap();
        assert!(!built.structured_is_empty());
        let rows = all(&built);
        assert!(built.structured_rows_within(rows.len()));
        // Distinct-scalar rows are not counted: they are not tree postings.
        let scalars = rows.iter().filter(|row| row.1 == b'D').count();
        assert!(!built.structured_rows_within(rows.len() - scalars - 1));
        // New collections contribute every row as an addition.
        assert_eq!(applied(&empty, &built), (rows.clone(), rows.len()));
        assert_eq!(applied(&built, &built).1, 0);

        // An ordinary delta: updates, a deletion and an insertion. Only the
        // rows that differ are reported, and the untouched collection none.
        let mut second = first.clone();
        let mut changed = BTreeSet::new();
        {
            let docs = second.get_mut("docs").unwrap();
            put(
                docs,
                "d000",
                2,
                json!({"s": "moved", "n": 0, "tags": ["a", "new"]}),
            );
            put(docs, "d001", 2, json!({"s": "v1", "tags": ["only"]}));
            put(docs, "d500", 2, json!({"s": "v2", "n": 500}));
            docs.documents.remove("d002");
            docs.data_epoch = 2;
            changed.extend(["d000", "d001", "d500", "d002"].map(String::from));
        }
        let delta = BTreeMap::from([("docs".to_owned(), changed)]);
        let updated = built.update_fixture(&first, &second, &delta).unwrap();
        let (after, changes) = applied(&built, &updated);
        assert_eq!(after, all(&updated));
        assert!(
            changes < 40,
            "a four-document delta reported {changes} rows"
        );
        assert_eq!(
            built.structured_layout_sha256(),
            updated.structured_layout_sha256()
        );

        // A changed definition renumbers fields: every old row is removed
        // before the new rows are added. A dropped collection removes its rows.
        let mut third = second.clone();
        third.remove("other");
        let redefined = collection(
            "docs",
            &[("/a", ScalarType::String), ("/s", ScalarType::String)],
        );
        let documents = third["docs"].documents.clone();
        third.insert(
            "docs".into(),
            CollectionState {
                documents,
                ..redefined
            },
        );
        let rebuilt = updated
            .update_fixture(&second, &third, &BTreeMap::new())
            .unwrap();
        assert_ne!(
            updated.structured_layout_sha256(),
            rebuilt.structured_layout_sha256()
        );
        let mut removals_done = false;
        let mut rows = all(&updated);
        rebuilt
            .visit_structured_changes(&updated, |name, added, change| {
                let change = row(name, change);
                if added {
                    removals_done |= name == "docs";
                    rows.insert(change);
                } else {
                    assert!(
                        name != "docs" || !removals_done,
                        "a rebuilt collection removed a row after adding one"
                    );
                    assert!(rows.remove(&change));
                }
                Ok::<_, std::convert::Infallible>(true)
            })
            .unwrap();
        assert_eq!(rows, all(&rebuilt));

        // A visitor that stops is reported as incomplete.
        let mut seen = 0;
        assert!(
            !rebuilt
                .visit_structured_changes(&updated, |_, _, _| {
                    seen += 1;
                    Ok::<_, std::convert::Infallible>(seen < 3)
                })
                .unwrap()
        );
        assert_eq!(seen, 3);
    }
}
