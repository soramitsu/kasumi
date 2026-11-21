use crate::scalar::{
    IndexString, Scalar, exhausted, indexed_values, invalid, scalar, validate_pointer,
};
use crate::{
    CollectionRecords, DocumentChanges, DocumentSource, QueryCancellation, ReadResult, Record,
    document_source,
};
use imbl::{OrdMap, OrdSet};
use kasumi_types::*;
use serde_json::Value;
use std::cell::LazyCell;
use std::collections::{BTreeMap, BTreeSet};
use std::ops::{Bound, RangeBounds};
use std::sync::Arc;

pub(crate) type IdSet = OrdSet<Arc<str>>;
/// Every compound index of one document can retain the same immutable ID.
pub(crate) type TupleMap = OrdMap<Vec<Scalar>, Arc<str>>;

/// Sharing lasts only for the current document. Correlated fields can grow
/// or shrink the same immutable ID root even when their scalar keys differ.
struct DocumentPostings<'a> {
    id: &'a Arc<str>,
    singleton: Option<IdSet>,
    insertions: Vec<(IdSet, IdSet)>,
    removals: Vec<(IdSet, IdSet)>,
    limit: usize,
}

impl<'a> DocumentPostings<'a> {
    fn new(id: &'a Arc<str>, fields: usize) -> Self {
        Self {
            id,
            singleton: None,
            insertions: Vec::new(),
            removals: Vec::new(),
            // A wide array may visit many values. Bound the old/new roots
            // kept beyond the immediate edit, independently of array length.
            limit: if fields > 1 { fields.min(16) } else { 0 },
        }
    }

    fn singleton(&mut self) -> IdSet {
        self.singleton
            .get_or_insert_with(|| IdSet::unit(Arc::clone(self.id)))
            .clone()
    }

    fn change(&mut self, ids: &mut IdSet, insert: bool) {
        let changes = if insert {
            &mut self.insertions
        } else {
            &mut self.removals
        };
        if let Some((_, next)) = changes.iter().find(|(old, _)| old.ptr_eq(ids)) {
            *ids = next.clone();
            return;
        }
        let old = (changes.len() < self.limit).then(|| ids.clone());
        if insert {
            ids.insert(Arc::clone(self.id));
        } else {
            ids.remove(self.id.as_ref());
        }
        if let Some(old) = old {
            changes.push((old, ids.clone()));
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct FieldIndex {
    pub kind: ScalarType,
    pub(crate) share_strings: bool,
    pub entries: OrdMap<Scalar, IdSet>,
    pub present: IdSet,
}

impl FieldIndex {
    fn share_complete_posting(&mut self, ids: &IdSet) {
        if self.entries.len() != 1 {
            return;
        }
        let (_, posting) = self.entries.get_min().expect("single field posting");
        if posting.len() != ids.len() || posting.ptr_eq(ids) {
            return;
        }
        self.set_only_posting(ids);
    }

    fn set_only_posting(&mut self, ids: &IdSet) {
        debug_assert_eq!(self.entries.len(), 1);
        // All postings are subsets of the collection IDs. Move the sole
        // scalar out of this private root, including an oversized string.
        let (key, _) = std::mem::take(&mut self.entries)
            .into_iter()
            .next()
            .expect("single field posting");
        self.entries = OrdMap::unit(key, ids.clone());
    }

    fn insert(&mut self, key: Scalar, row: &mut DocumentPostings<'_>) {
        if !self.share_strings {
            match self.entries.entry(key) {
                imbl::ordmap::Entry::Occupied(mut entry) => row.change(entry.get_mut(), true),
                imbl::ordmap::Entry::Vacant(entry) => {
                    entry.insert(row.singleton());
                }
            }
            return;
        }
        // Preserve the stored field key when other indexes share its string.
        if let Some(ids) = self.entries.get_mut(&key) {
            row.change(ids, true);
            return;
        }
        let key = match key {
            Scalar::String(IndexString::Owned(text)) => {
                Scalar::String(IndexString::Shared(text.into()))
            }
            key => key,
        };
        self.entries.insert(key, row.singleton());
    }
}

struct BuildingField {
    complete_presence: bool,
    uniform_posting: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct Structured {
    pub fields: BTreeMap<String, FieldIndex>,
    pub ids: IdSet,
    pub(crate) unique: BTreeMap<String, UniqueIndex>,
}

#[derive(Debug, Clone)]
pub(crate) struct UniqueIndex {
    pub(crate) fields: Vec<IndexField>,
    // A one-field generation uses its already selected scalar posting tree
    // for both uniqueness and ordered seek. A standalone validation pass
    // has no field tree and therefore builds its temporary tuple map.
    pub(crate) entries: Option<TupleMap>,
    // Only keys longer than a native page key live here. A mixed index can
    // walk the published directory and merge these exceptions in tuple order.
    pub(crate) overflow: TupleMap,
}

pub(crate) fn record_value<'a>(record: Record<'a>, path: &str) -> Option<&'a Value> {
    match record {
        Record::Live(document) => document.body.pointer(path),
        Record::Archived(document) => document.indexed_fields.get(path),
    }
}
impl UniqueIndex {
    fn same_fields(&self, old: Record<'_>, new: Record<'_>) -> bool {
        self.fields
            .iter()
            .all(|field| record_value(old, &field.path) == record_value(new, &field.path))
    }

    fn key(&self, record: Record<'_>) -> Result<Option<Vec<Scalar>>> {
        let key = self
            .fields
            .iter()
            .map(|field| scalar(record_value(record, &field.path), Some(field.kind)))
            .collect::<Result<Vec<_>>>()?;
        Ok((!key.contains(&Scalar::Missing)).then_some(key))
    }
    fn owned_entries(&mut self, key: &[Scalar]) -> &mut TupleMap {
        if self.fields.len() > 1 && crate::ordered_tuple::encode(key).is_none() {
            &mut self.overflow
        } else {
            self.entries.as_mut().expect("private unique tuple tree")
        }
    }

    fn share_components(&self, key: &mut [Scalar], fields: &BTreeMap<String, FieldIndex>) {
        for (part, field) in key.iter_mut().zip(&self.fields) {
            if let Scalar::String(_) = part
                && let Some((stored @ Scalar::String(IndexString::Shared(_)), _)) =
                    fields[&field.path].entries.get_key_value(part)
            {
                *part = stored.clone();
            }
        }
    }

    fn insert_tuple(
        &mut self,
        name: &str,
        owner: impl FnOnce() -> Arc<str>,
        record: Record<'_>,
        fields: Option<&BTreeMap<String, FieldIndex>>,
    ) -> Result<()> {
        if let Some(mut key) = self.key(record)? {
            if let Some(fields) = fields
                && self.fields.len() > 1
            {
                self.share_components(&mut key, fields);
            }
            if self.owned_entries(&key).insert(key, owner()).is_some() {
                return Err(unique_conflict(name));
            }
        }
        Ok(())
    }

    /// The earlier unique pass sees the predecessor's field roots. Bind newly
    /// introduced strings to the candidate's final postings before publication.
    fn bind_new_components(
        &mut self,
        id: &str,
        record: Record<'_>,
        fields: &BTreeMap<String, FieldIndex>,
    ) -> Result<()> {
        if self.fields.len() < 2 {
            return Ok(());
        }
        let Some(mut key) = self.key(record)? else {
            return Ok(());
        };
        self.share_components(&mut key, fields);
        let entries = self.owned_entries(&key);
        let (previous, owner) = entries.get_key_value(&key).ok_or_else(old_owner_mismatch)?;
        if owner.as_ref() != id {
            return Err(old_owner_mismatch());
        }
        let needs_binding =
            previous
                .iter()
                .zip(&key)
                .any(|(prior, selected)| match (prior, selected) {
                    (
                        Scalar::String(IndexString::Shared(a)),
                        Scalar::String(IndexString::Shared(b)),
                    ) => !std::sync::Arc::ptr_eq(a, b),
                    (
                        Scalar::String(IndexString::Owned(_)),
                        Scalar::String(IndexString::Shared(_)),
                    ) => true,
                    _ => false,
                });
        if needs_binding {
            let owner = entries.remove(&key).expect("validated unique owner");
            entries.insert(key, owner);
        }
        Ok(())
    }
}

/// The deterministic rejection shared by resident and durable uniqueness owners.
pub fn unique_conflict(name: &str) -> Error {
    Error::new(
        ErrorCode::Conflict,
        format!("unique index {name} conflicts"),
    )
}

// New constraints, field postings and the collection share one immutable ID.
// A replacement can reuse its predecessor's allocation across both generations.
fn logical_owner(ids: &mut IdSet, id: &str, insert: bool) -> Arc<str> {
    if let Some(owner) = ids.get(id) {
        return Arc::clone(owner);
    }
    let owner: Arc<str> = id.into();
    if insert {
        ids.insert(Arc::clone(&owner));
    }
    owner
}

fn old_owner_mismatch() -> Error {
    Error::new(
        ErrorCode::Corruption,
        "old unique mapping differs from delta",
    )
}

impl Structured {
    pub fn update<D: DocumentChanges + ?Sized>(&self, changes: &D) -> ReadResult<Self, D::Failure> {
        let mut next = self.clone();
        next.unique = self.unique_delta(changes, |id, is_new| {
            logical_owner(&mut next.ids, id, is_new)
        })?;
        changes.visit_changes(|delta| {
            let previous = delta.old;
            let current = delta.new;
            let id = delta.id;
            if previous.is_none() && current.is_none() {
                return Ok(());
            }
            let owner = if current.is_none() {
                next.ids.remove(id).unwrap_or_else(|| Arc::from(id))
            } else {
                logical_owner(&mut next.ids, id, previous.is_none())
            };
            let mut changed_shared_text = false;
            let mut postings = DocumentPostings::new(&owner, next.fields.len());
            for (path, index) in &mut next.fields {
                let old_value = previous.and_then(|record| record_value(record, path));
                let new_value = current.and_then(|record| record_value(record, path));
                if previous.is_some() && current.is_some() && old_value == new_value {
                    continue;
                }
                match (old_value.is_some(), new_value.is_some()) {
                    (false, true) => {
                        postings.change(&mut index.present, true);
                    }
                    (true, false) => {
                        postings.change(&mut index.present, false);
                    }
                    _ => {}
                }
                if previous.is_some() {
                    for key in indexed_values(old_value, index.kind)? {
                        if let imbl::ordmap::Entry::Occupied(mut entry) = index.entries.entry(key) {
                            if entry.get().len() == 1 && entry.get().contains(id) {
                                postings.singleton.get_or_insert(entry.remove());
                            } else {
                                postings.change(entry.get_mut(), false);
                            }
                        }
                    }
                }
                if current.is_some() {
                    for key in indexed_values(new_value, index.kind)? {
                        changed_shared_text |=
                            index.share_strings && matches!(key, Scalar::String(_));
                        index.insert(key, &mut postings);
                    }
                }
            }
            if changed_shared_text && let Some(record) = current {
                for index in next.unique.values_mut() {
                    index.bind_new_components(id, record, &next.fields)?;
                }
            }
            Ok(())
        })?;
        // Presence is a subset of this collection's IDs. A sparse field
        // can become complete when its last missing document is deleted.
        for (field, previous) in next.fields.values_mut().zip(self.fields.values()) {
            if field.present.len() == next.ids.len() {
                field.present = next.ids.clone();
            }
            if !field.entries.ptr_eq(&previous.entries) {
                field.share_complete_posting(&next.ids);
            }
        }
        Ok(next)
    }
    fn unique_delta<D: DocumentChanges + ?Sized>(
        &self,
        changes: &D,
        mut document_owner: impl FnMut(&str, bool) -> Arc<str>,
    ) -> ReadResult<BTreeMap<String, UniqueIndex>, D::Failure> {
        let mut unique = self.unique.clone();
        if unique.is_empty() {
            // No constraint consumes these bodies. Schema/ID/field updates
            // retain their checked passes; avoid two otherwise empty replays.
            return Ok(unique);
        }
        // One-field constraints borrow the field tree's COW root. Only
        // changed paths enter this validation pass, and no duplicate
        // dictionary survives in the resulting generation.
        let mut singles: BTreeMap<_, _> = unique
            .iter()
            .filter(|(_, index)| index.entries.is_none())
            .map(|(name, index)| {
                (
                    name.clone(),
                    self.fields[&index.fields[0].path].entries.clone(),
                )
            })
            .collect();
        // Remove every old mapping across the batch before inserting any new one.
        changes.visit_changes(|delta| {
            if let Some(old) = delta.old {
                for (name, index) in &mut unique {
                    if let Some(mut key) = index.key(old)? {
                        // Always verify the old owner, including a payload-only edit.
                        let unchanged = delta.new.is_some_and(|new| index.same_fields(old, new));
                        if index.entries.is_some() {
                            let entries = index.owned_entries(&key);
                            if entries
                                .get(&key)
                                .is_none_or(|owner| owner.as_ref() != delta.id)
                            {
                                return Err(old_owner_mismatch());
                            }
                            if !unchanged {
                                entries.remove(&key);
                            }
                        } else {
                            let scalar = key.pop().expect("one-field unique key");
                            let entries = singles.get_mut(name).expect("shared unique posting");
                            let ids = entries.get(&scalar).ok_or_else(old_owner_mismatch)?;
                            if ids.len() != 1 || !ids.contains(delta.id) {
                                return Err(old_owner_mismatch());
                            }
                            if !unchanged {
                                entries.remove(&scalar);
                            }
                        }
                    }
                }
            }
            Ok(())
        })?;
        changes.visit_changes(|delta| {
            if let Some(new) = delta.new {
                let owner = LazyCell::new(|| document_owner(delta.id, delta.old.is_none()));
                for (name, index) in &mut unique {
                    if delta.old.is_some_and(|old| index.same_fields(old, new)) {
                        continue;
                    }
                    if index.entries.is_some() {
                        index.insert_tuple(name, || Arc::clone(&owner), new, Some(&self.fields))?;
                    } else if let Some(mut key) = index.key(new)? {
                        let entries = singles.get_mut(name).expect("shared unique posting");
                        let scalar = key.pop().expect("one-field unique key");
                        if entries.contains_key(&scalar) {
                            return Err(unique_conflict(name));
                        }
                        // Only occupied/vacant is consulted after all removals.
                        entries.insert(scalar, IdSet::new());
                    }
                }
            }
            Ok(())
        })?;
        Ok(unique)
    }
    pub fn validate_unique_changes<D: DocumentChanges + ?Sized>(
        &self,
        changes: &D,
    ) -> ReadResult<(), D::Failure> {
        self.unique_delta(changes, |id, _| {
            self.ids.get(id).cloned().unwrap_or_else(|| Arc::from(id))
        })
        .map(|_| ())
    }

    fn empty_unique(
        definition: &CollectionDefinition,
        share_fields: bool,
    ) -> BTreeMap<String, UniqueIndex> {
        definition
            .indexes
            .iter()
            .filter(|index| index.unique)
            .map(|index| {
                (
                    index.name.clone(),
                    UniqueIndex {
                        fields: index.fields.clone(),
                        overflow: OrdMap::new(),
                        entries: (!share_fields || index.fields.len() != 1).then(OrdMap::new),
                    },
                )
            })
            .collect()
    }
    pub(crate) fn build_unique<R: CollectionRecords + ?Sized>(
        source: &R,
    ) -> ReadResult<BTreeMap<String, UniqueIndex>, R::Failure> {
        let mut unique = Self::empty_unique(source.definition(), false);
        if unique.is_empty() {
            return Ok(unique);
        }
        source.visit_records(|id, record| {
            let owner = LazyCell::new(|| Arc::<str>::from(id));
            for (name, index) in &mut unique {
                index.insert_tuple(name, || Arc::clone(&owner), record, None)?;
            }
            Ok(())
        })?;
        Ok(unique)
    }
    pub(crate) fn empty(definition: &CollectionDefinition) -> Self {
        let mut fields = BTreeMap::new();
        for index in &definition.indexes {
            for field in &index.fields {
                let entry = fields
                    .entry(field.path.clone())
                    .or_insert_with(|| FieldIndex {
                        kind: field.kind,
                        share_strings: false,
                        entries: OrdMap::new(),
                        present: IdSet::new(),
                    });
                entry.share_strings |=
                    index.unique && index.fields.len() > 1 && field.kind == ScalarType::String;
            }
        }
        Self {
            ids: IdSet::new(),
            unique: Self::empty_unique(definition, true),
            fields,
        }
    }

    pub fn build<R: CollectionRecords + ?Sized>(
        &mut self,
        source: &R,
        validator: &jsonschema::Validator,
    ) -> ReadResult<(), R::Failure> {
        let definition = source.definition();
        let mut index_failure = None;
        // A one-field unique validator reads posting counts during insertion.
        // Other fields can defer their first posting until a second value or
        // an empty array appears. Field order stays fixed throughout the build.
        let mut building = {
            let singles: BTreeSet<_> = self
                .unique
                .values()
                .filter(|index| index.entries.is_none())
                .map(|index| &index.fields[0].path)
                .collect();
            self.fields
                .keys()
                .map(|path| BuildingField {
                    complete_presence: true,
                    uniform_posting: !singles.contains(path),
                })
                .collect::<Vec<_>>()
        };
        source.visit_records(|id, record| {
            if let Record::Live(document) = record {
                crate::validation::validate_document_with_validator(
                    definition,
                    &document.body,
                    validator,
                )?;
            }
            // A later schema or source failure has always taken precedence
            // over a conflict in these unpublished roots. Keep checking rows
            // under their original loan even after the first index failure.
            if index_failure.is_none() {
                index_failure = self.insert_record(id, record, &mut building).err();
            }
            Ok(())
        })?;
        if let Some(error) = index_failure {
            return Err(error.into());
        }
        for (field, state) in self.fields.values_mut().zip(building) {
            if state.complete_presence {
                field.present = self.ids.clone();
            }
            if state.uniform_posting && !field.entries.is_empty() {
                field.set_only_posting(&self.ids);
            } else {
                field.share_complete_posting(&self.ids);
            }
        }
        Ok(())
    }

    fn insert_record(
        &mut self,
        id: &str,
        record: Record<'_>,
        building: &mut [BuildingField],
    ) -> Result<()> {
        let owner: Arc<str> = id.into();
        let mut postings = DocumentPostings::new(&owner, self.fields.len());
        for ((path, index), state) in self.fields.iter_mut().zip(building) {
            let value = record_value(record, path);
            if state.complete_presence && value.is_none() {
                index.present = self.ids.clone();
                state.complete_presence = false;
            } else if !state.complete_presence && value.is_some() {
                postings.change(&mut index.present, true);
            }
            let keys = indexed_values(value, index.kind)?;
            if state.uniform_posting {
                if let [key] = keys.as_slice()
                    && index.entries.contains_key(key)
                {
                    continue;
                }
                if keys.len() != 1 || !index.entries.is_empty() {
                    state.uniform_posting = false;
                    if !index.entries.is_empty() {
                        index.set_only_posting(&self.ids);
                    }
                }
            }
            for key in keys {
                index.insert(key, &mut postings);
            }
        }
        self.ids.insert(Arc::clone(&owner));
        for (name, index) in &mut self.unique {
            if index.entries.is_some() {
                index.insert_tuple(name, || Arc::clone(&owner), record, Some(&self.fields))?;
            } else if let Some(mut key) = index.key(record)? {
                let scalar = key.pop().expect("one-field unique key");
                if self.fields[&index.fields[0].path].entries[&scalar].len() != 1 {
                    return Err(unique_conflict(name));
                }
            }
        }
        Ok(())
    }

    pub fn field_kind(&self, path: &str, allow_scan: bool) -> Result<Option<ScalarType>> {
        validate_pointer(path)?;
        match self.fields.get(path) {
            Some(index) => Ok(Some(index.kind)),
            None if allow_scan => Ok(None),
            None => Err(Error::new(
                ErrorCode::IndexRequired,
                format!("declare an index for {path} or explicitly allow_scan"),
            )),
        }
    }
}

pub(crate) fn check_size(size: usize, limit: usize) -> Result<()> {
    if size > limit {
        Err(exhausted("query candidate budget exceeded"))
    } else {
        Ok(())
    }
}

const MAX_FILTER_DEPTH: usize = 16;
const MAX_FILTER_NODES: usize = 256;
/// Index entries a range estimate may visit before it is ranked as broad.
const RANGE_ESTIMATE_BUDGET: usize = 4096;

/// A filter normalized to one node per test. A field's bounds form a single
/// range, so `{"gte": a, "lt": b}` is one ordered index walk.
#[derive(Debug)]
pub(crate) enum Node<'a> {
    All,
    Leaf { path: &'a str, test: Test<'a> },
    And(Vec<Node<'a>>),
    Or(Vec<Node<'a>>),
    Not(Box<Node<'a>>),
}

#[derive(Debug)]
pub(crate) enum Test<'a> {
    Eq(&'a Value),
    In(&'a [Value]),
    Range {
        lower: Bound<&'a Value>,
        upper: Bound<&'a Value>,
    },
    Exists(bool),
    Contains(&'a Value),
}

/// Shape checks and normalization, independent of indexes and documents, so
/// empty collections and short-circuiting cannot accept malformed filters.
pub(crate) fn plan(filter: &Filter) -> Result<Node<'_>> {
    plan_filter(filter, 0, &mut 0)
}

fn count(nodes: &mut usize) -> Result<()> {
    *nodes += 1;
    if *nodes > MAX_FILTER_NODES {
        return Err(invalid("filter exceeds 256 conditions"));
    }
    Ok(())
}

fn plan_filter<'a>(filter: &'a Filter, depth: usize, nodes: &mut usize) -> Result<Node<'a>> {
    if depth > MAX_FILTER_DEPTH {
        return Err(invalid("filter exceeds 16 nesting levels"));
    }
    let mut children = Vec::new();
    for (path, condition) in &filter.fields {
        validate_pointer(path)?;
        plan_condition(path, condition, nodes, &mut children)?;
    }
    for nested in &filter.and {
        count(nodes)?;
        children.push(plan_filter(nested, depth + 1, nodes)?);
    }
    if !filter.or.is_empty() {
        count(nodes)?;
        let alternatives = filter
            .or
            .iter()
            .map(|alternative| plan_filter(alternative, depth + 1, nodes))
            .collect::<Result<_>>()?;
        children.push(Node::Or(alternatives));
    }
    if let Some(negated) = &filter.not {
        count(nodes)?;
        children.push(Node::Not(Box::new(plan_filter(negated, depth + 1, nodes)?)));
    }
    Ok(match children.len() {
        0 => Node::All,
        1 => children.pop().expect("one child"),
        _ => Node::And(children),
    })
}

fn plan_condition<'a>(
    path: &'a str,
    condition: &'a Condition,
    nodes: &mut usize,
    out: &mut Vec<Node<'a>>,
) -> Result<()> {
    if condition.is_empty() {
        return Err(invalid(format!("{path}: empty field condition")));
    }
    if condition.gt.is_some() && condition.gte.is_some() {
        return Err(invalid(format!("{path}: use either gt or gte")));
    }
    if condition.lt.is_some() && condition.lte.is_some() {
        return Err(invalid(format!("{path}: use either lt or lte")));
    }
    let leaf = |test| Node::Leaf { path, test };
    let mut push = |node| -> Result<()> {
        count(nodes)?;
        out.push(node);
        Ok(())
    };
    if let Some(value) = &condition.eq {
        push(leaf(Test::Eq(value)))?;
    }
    if let Some(value) = &condition.ne {
        push(Node::Not(Box::new(leaf(Test::Eq(value)))))?;
    }
    let lower = match (&condition.gt, &condition.gte) {
        (Some(value), _) => Bound::Excluded(value),
        (_, Some(value)) => Bound::Included(value),
        _ => Bound::Unbounded,
    };
    let upper = match (&condition.lt, &condition.lte) {
        (Some(value), _) => Bound::Excluded(value),
        (_, Some(value)) => Bound::Included(value),
        _ => Bound::Unbounded,
    };
    if !matches!((lower, upper), (Bound::Unbounded, Bound::Unbounded)) {
        push(leaf(Test::Range { lower, upper }))?;
    }
    for (values, negated) in [(&condition.r#in, false), (&condition.nin, true)] {
        if let Some(values) = values {
            if values.len() > MAX_FILTER_IN_VALUES {
                return Err(invalid("in/nin are limited to 256 values"));
            }
            let node = leaf(Test::In(values));
            push(if negated {
                Node::Not(Box::new(node))
            } else {
                node
            })?;
        }
    }
    if let Some(exists) = condition.exists {
        push(leaf(Test::Exists(exists)))?;
    }
    if let Some(value) = &condition.contains {
        push(leaf(Test::Contains(value)))?;
    }
    Ok(())
}

fn bound_value<'a>(bound: &Bound<&'a Value>) -> Option<&'a Value> {
    match bound {
        Bound::Included(value) | Bound::Excluded(value) => Some(value),
        Bound::Unbounded => None,
    }
}

fn scalar_bound(bound: Bound<&Value>, kind: Option<ScalarType>) -> Result<Bound<Scalar>> {
    Ok(match bound {
        Bound::Included(value) => Bound::Included(scalar(Some(value), kind)?),
        Bound::Excluded(value) => Bound::Excluded(scalar(Some(value), kind)?),
        Bound::Unbounded => Bound::Unbounded,
    })
}

/// Index range for a validated test. Absent and null entries sort first and
/// never satisfy a range, so an open lower bound starts after them.
fn index_range(
    lower: Bound<&Value>,
    upper: Bound<&Value>,
    kind: Option<ScalarType>,
) -> Result<(Bound<Scalar>, Bound<Scalar>)> {
    let lower = match scalar_bound(lower, kind)? {
        Bound::Unbounded => Bound::Excluded(Scalar::Null),
        bound => bound,
    };
    Ok((lower, scalar_bound(upper, kind)?))
}

fn empty_range(range: &(Bound<Scalar>, Bound<Scalar>)) -> bool {
    use Bound::{Excluded, Included};
    match range {
        (Included(lower), Included(upper)) => lower > upper,
        (Included(lower) | Excluded(lower), Included(upper) | Excluded(upper)) => lower >= upper,
        _ => false,
    }
}

fn validate_test(path: &str, test: &Test<'_>, kind: Option<ScalarType>) -> Result<()> {
    let array = matches!(
        kind,
        Some(ScalarType::StringArray | ScalarType::NumberArray)
    );
    let array_error = || {
        invalid(format!(
            "{path} is an array field; use contains to match its elements"
        ))
    };
    match test {
        Test::Exists(_) => Ok(()),
        Test::Contains(value) => {
            if kind.is_some() && !array {
                return Err(invalid(format!("{path}: contains requires an array field")));
            }
            if value.is_null() {
                return Err(invalid("array membership requires a non-null scalar"));
            }
            scalar(Some(value), kind).map(drop)
        }
        Test::Eq(value) => {
            if array && !value.is_null() {
                return Err(array_error());
            }
            scalar(Some(value), kind).map(drop)
        }
        Test::In(values) => {
            if array {
                return Err(array_error());
            }
            values
                .iter()
                .try_for_each(|value| scalar(Some(value), kind).map(drop))
        }
        Test::Range { lower, upper } => {
            if array {
                return Err(array_error());
            }
            let mut first: Option<Scalar> = None;
            for value in [bound_value(lower), bound_value(upper)]
                .into_iter()
                .flatten()
            {
                let key = scalar(Some(value), kind)?;
                if key == Scalar::Null {
                    return Err(invalid("ordered comparison requires a non-null scalar"));
                }
                if let Some(first) = &first
                    && std::mem::discriminant(first) != std::mem::discriminant(&key)
                {
                    return Err(invalid(format!("{path}: range bounds must have one type")));
                }
                first = Some(key);
            }
            Ok(())
        }
    }
}

/// Unindexed values that cannot be compared never match a scanned leaf.
fn scanned_scalar(value: Option<&Value>, kind: Option<ScalarType>) -> Option<Scalar> {
    scalar(value, kind).ok()
}

/// Constants belong to the plan, so decimal parsing and string allocation
/// happen once per leaf rather than once per visited document.
#[derive(Debug)]
enum PreparedTest {
    Eq(Scalar),
    In(BTreeSet<Scalar>),
    Range {
        lower: Bound<Scalar>,
        upper: Bound<Scalar>,
    },
    Exists(bool),
    Contains(Scalar),
}
impl PreparedTest {
    fn new(test: &Test<'_>, kind: Option<ScalarType>) -> Result<Self> {
        #[cfg(test)]
        PREPARED_LEAVES.with(|count| count.set(count.get() + 1));
        Ok(match test {
            Test::Eq(value) => Self::Eq(scalar(Some(value), kind)?),
            Test::Contains(value) => Self::Contains(scalar(Some(value), kind)?),
            Test::In(values) => Self::In(
                values
                    .iter()
                    .map(|v| scalar(Some(v), kind))
                    .collect::<Result<_>>()?,
            ),
            Test::Range { lower, upper } => Self::Range {
                lower: scalar_bound(*lower, kind)?,
                upper: scalar_bound(*upper, kind)?,
            },
            Test::Exists(value) => Self::Exists(*value),
        })
    }
    fn evaluate(
        &self,
        actual: Option<&Value>,
        kind: Option<ScalarType>,
        cancellation: &QueryCancellation,
    ) -> Result<bool> {
        cancellation.check()?;
        if let Self::Exists(exists) = self {
            return Ok(actual.is_some() == *exists);
        }
        if let Self::Contains(expected) = self {
            let Some(Value::Array(elements)) = actual else {
                return Ok(false);
            };
            for element in elements {
                cancellation.check()?;
                if scanned_scalar(Some(element), kind).as_ref() == Some(expected) {
                    return Ok(true);
                }
            }
            return Ok(false);
        }
        if actual.is_none() {
            return Ok(false);
        }
        let Some(actual) = scanned_scalar(actual, kind) else {
            return Ok(false);
        };
        Ok(match self {
            Self::Eq(expected) => actual == *expected,
            Self::In(expected) => expected.contains(&actual),
            Self::Range { lower, upper } => {
                if matches!(actual, Scalar::Missing | Scalar::Null) {
                    return Ok(false);
                }
                for bound in [lower, upper] {
                    if let Bound::Included(key) | Bound::Excluded(key) = bound
                        && std::mem::discriminant(key) != std::mem::discriminant(&actual)
                    {
                        return Ok(false);
                    }
                }
                (lower.as_ref(), upper.as_ref()).contains(&actual)
            }
            Self::Exists(_) | Self::Contains(_) => unreachable!("handled above"),
        })
    }
}
#[cfg(test)]
thread_local! { static PREPARED_LEAVES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) }; }

#[cfg(test)]
pub(crate) fn prepared_leaves_for_test() -> usize {
    PREPARED_LEAVES.with(|count| count.get())
}

/// A subtree containing only scanned fields can borrow each body once even
/// when several OR/NOT leaves inspect it. Indexed conjuncts still narrow the
/// input before this plan runs, retaining the existing candidate budget.
enum Scan<'a> {
    All,
    Leaf(&'a str, PreparedTest),
    And(Vec<Self>),
    Or(Vec<Self>),
    Not(Box<Self>),
}
impl<'a> Scan<'a> {
    fn prepare(node: &Node<'a>, fields: &BTreeMap<String, FieldIndex>) -> Result<Option<Self>> {
        Ok(match node {
            Node::All => Some(Self::All),
            Node::Leaf { path, test } if !fields.contains_key(*path) => {
                Some(Self::Leaf(path, PreparedTest::new(test, None)?))
            }
            Node::Leaf { .. } => None,
            Node::Not(child) => {
                Self::prepare(child, fields)?.map(|child| Self::Not(Box::new(child)))
            }
            Node::And(children) | Node::Or(children) => {
                let mut prepared = Vec::with_capacity(children.len());
                for child in children {
                    let Some(child) = Self::prepare(child, fields)? else {
                        return Ok(None);
                    };
                    prepared.push(child);
                }
                Some(if matches!(node, Node::And(_)) {
                    Self::And(prepared)
                } else {
                    Self::Or(prepared)
                })
            }
        })
    }
    fn has_leaf(&self) -> bool {
        match self {
            Self::All => false,
            Self::Leaf(..) => true,
            Self::Not(child) => child.has_leaf(),
            Self::And(children) | Self::Or(children) => children.iter().any(Self::has_leaf),
        }
    }
    fn evaluate(&self, document: &Value, cancellation: &QueryCancellation) -> Result<bool> {
        cancellation.check()?;
        match self {
            Self::All => Ok(true),
            Self::Leaf(path, test) => test.evaluate(
                crate::allocation::pointer(document, path),
                None,
                cancellation,
            ),
            Self::Not(child) => Ok(!child.evaluate(document, cancellation)?),
            Self::And(children) => {
                for child in children {
                    if !child.evaluate(document, cancellation)? {
                        return Ok(false);
                    }
                }
                Ok(true)
            }
            Self::Or(children) => {
                for child in children {
                    if child.evaluate(document, cancellation)? {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
        }
    }
}

impl Structured {
    /// Extra owned constants and plan nodes retained by prepared scans. This
    /// is admitted before preparing them; decimal internals keep the existing
    /// explicit provisional allowance used by sorted query scalars.
    pub(crate) fn prepared_bytes(&self, node: &Node<'_>) -> Result<u64> {
        use crate::allocation::{add, object_entry_bytes, string_clone_bytes, vec_bytes};
        let value_bytes = |value: &Value, kind: Option<ScalarType>| -> Result<u64> {
            match value {
                Value::Number(_) => Ok(crate::scalar::PROVISIONAL_DECIMAL_KEY_BYTES),
                Value::String(_) if kind == Some(ScalarType::Decimal) => {
                    Ok(crate::scalar::PROVISIONAL_DECIMAL_KEY_BYTES)
                }
                Value::String(text) => string_clone_bytes(text),
                _ => Ok(0),
            }
        };
        match node {
            Node::All => Ok(0),
            Node::And(children) | Node::Or(children) => {
                let mut bytes = vec_bytes::<Scan<'_>>(children.len())?;
                for child in children {
                    bytes = add(bytes, self.prepared_bytes(child)?)?;
                }
                Ok(bytes)
            }
            Node::Not(child) => add(vec_bytes::<Scan<'_>>(1)?, self.prepared_bytes(child)?),
            Node::Leaf { path, test } => {
                let kind = self.fields.get(*path).map(|index| index.kind);
                if kind.is_some() && !matches!(test, Test::Range { .. }) {
                    return Ok(0);
                }
                let bytes = match test {
                    Test::Eq(value) | Test::Contains(value) => value_bytes(value, kind)?,
                    Test::In(values) => {
                        let mut bytes = 0;
                        for value in *values {
                            // One complete BTree node per value bounds unused
                            // slots as in the JSON object allocation policy.
                            bytes = add(
                                bytes,
                                add(object_entry_bytes()?, value_bytes(value, kind)?)?,
                            )?;
                        }
                        bytes
                    }
                    Test::Range { lower, upper } => {
                        let mut bytes = 0;
                        for value in [bound_value(lower), bound_value(upper)]
                            .into_iter()
                            .flatten()
                        {
                            bytes = add(bytes, value_bytes(value, kind)?)?;
                        }
                        bytes
                    }
                    Test::Exists(_) => 0,
                };
                add(bytes, crate::scalar::PROVISIONAL_DECIMAL_SCRATCH_BYTES)
            }
        }
    }

    /// Type-check every leaf against declared indexes before any evaluation.
    pub(crate) fn validate(&self, node: &Node<'_>, allow_scan: bool) -> Result<()> {
        match node {
            Node::All => Ok(()),
            Node::And(children) | Node::Or(children) => children
                .iter()
                .try_for_each(|child| self.validate(child, allow_scan)),
            Node::Not(child) => self.validate(child, allow_scan),
            Node::Leaf { path, test } => {
                validate_test(path, test, self.field_kind(path, allow_scan)?)
            }
        }
    }

    /// Upper bound on matching IDs, read from index cardinalities without
    /// touching documents. `None` means the node needs document scans or a
    /// complement over its input; such nodes are evaluated last.
    fn estimate(&self, node: &Node<'_>, universe: usize, budget: usize) -> Result<Option<usize>> {
        Ok(match node {
            Node::All => Some(universe),
            // A complement depends on its input, except that of every document.
            Node::Not(child) => matches!(**child, Node::All).then_some(0),
            Node::And(children) => {
                let mut best = None;
                for child in children {
                    if let Some(estimate) = self.estimate(child, universe, budget)? {
                        best = Some(best.map_or(estimate, |best: usize| best.min(estimate)));
                    }
                }
                best
            }
            Node::Or(children) => {
                let mut total = 0usize;
                for child in children {
                    match self.estimate(child, universe, budget)? {
                        Some(estimate) => total = total.saturating_add(estimate),
                        None => return Ok(None),
                    }
                }
                Some(total.min(universe))
            }
            Node::Leaf { path, test } => {
                let Some(index) = self.fields.get(*path) else {
                    return Ok(None);
                };
                let kind = Some(index.kind);
                let ids = |value: &Value| -> Result<usize> {
                    Ok(index
                        .entries
                        .get(&scalar(Some(value), kind)?)
                        .map_or(0, IdSet::len))
                };
                Some(match test {
                    Test::Eq(value) | Test::Contains(value) => ids(value)?,
                    Test::In(values) => values.iter().try_fold(0usize, |total, value| {
                        ids(value).map(|count| total.saturating_add(count))
                    })?,
                    Test::Exists(true) => index.present.len(),
                    Test::Exists(false) => universe.saturating_sub(index.present.len()),
                    Test::Range { lower, upper } => {
                        let range = index_range(*lower, *upper, kind)?;
                        if empty_range(&range) {
                            return Ok(Some(0));
                        }
                        let limit = budget.min(RANGE_ESTIMATE_BUDGET);
                        let mut total = 0usize;
                        for (visited, (_, ids)) in index.entries.range(range).enumerate() {
                            total = total.saturating_add(ids.len());
                            if total > limit || visited >= limit {
                                return Ok(Some(universe.max(total)));
                            }
                        }
                        total
                    }
                })
            }
        })
    }

    /// Conjuncts run from the most selective indexed test to scans and
    /// complements, each over the survivors of the previous ones.
    fn conjunct_order(&self, children: &[Node<'_>], universe: usize) -> Result<Vec<usize>> {
        let mut ranked = Vec::with_capacity(children.len());
        let mut budget = universe;
        // Exact posting sizes first, so range walks stop at the best of them.
        let range = |node: &Node<'_>| {
            matches!(
                node,
                Node::Leaf {
                    test: Test::Range { .. },
                    ..
                }
            )
        };
        for pass in [false, true] {
            for (position, child) in children.iter().enumerate() {
                if range(child) != pass {
                    continue;
                }
                let estimate = self.estimate(child, universe, budget)?;
                if let Some(estimate) = estimate {
                    budget = budget.min(estimate);
                }
                ranked.push((estimate.is_none(), estimate.unwrap_or(usize::MAX), position));
            }
        }
        ranked.sort_unstable();
        Ok(ranked
            .into_iter()
            .map(|(_, _, position)| position)
            .collect())
    }

    /// Evaluate supported boolean filters from the same selected generation.
    /// Each conjunction streams its later postings through the surviving IDs.
    /// A source without the complete layout returns control to the normal planner.
    pub(crate) fn stored_posting<S: DocumentSource + ?Sized, W: crate::QueryWorkspace>(
        &self,
        source: &S,
        node: &Node<'_>,
        cap: usize,
        cancellation: &QueryCancellation,
        memory: &mut crate::QueryMemory<W>,
    ) -> ReadResult<Option<IdSet>, S::Failure> {
        self.stored_candidates(source, node, None, cap, cancellation, memory)
    }

    #[allow(clippy::too_many_arguments)]
    fn stored_candidates<S: DocumentSource + ?Sized, W: crate::QueryWorkspace>(
        &self,
        source: &S,
        node: &Node<'_>,
        restrict: Option<&IdSet>,
        cap: usize,
        cancellation: &QueryCancellation,
        memory: &mut crate::QueryMemory<W>,
    ) -> ReadResult<Option<IdSet>, S::Failure> {
        cancellation.check()?;
        memory.scope(|memory| {
            let baseline = memory.live_bytes();
            let result = match node {
                Node::And(children) if !children.is_empty() => {
                    let mut survivors = None;
                    let mut survivor_bytes = 0;
                    for i in self.conjunct_order(children, restrict.unwrap_or(&self.ids).len())? {
                        let before = memory.live_bytes();
                        let input = survivors.as_ref().or(restrict);
                        let Some(next) = self.stored_candidates(
                            source,
                            &children[i],
                            input,
                            cap,
                            cancellation,
                            memory,
                        )?
                        else {
                            return Ok((None, 0));
                        };
                        let next_bytes = memory.live_bytes() - before;
                        survivors = Some(next);
                        memory.release(survivor_bytes)?;
                        survivor_bytes = next_bytes;
                        if survivors.as_ref().is_some_and(IdSet::is_empty) {
                            break;
                        }
                    }
                    survivors
                }
                Node::Or(children) if !children.is_empty() => {
                    let mut union = IdSet::new();
                    for child in children {
                        let before = memory.live_bytes();
                        let Some(posting) = self.stored_candidates(
                            source,
                            child,
                            restrict,
                            cap,
                            cancellation,
                            memory,
                        )?
                        else {
                            return Ok((None, 0));
                        };
                        let posting_bytes = memory.live_bytes() - before;
                        if union.is_empty() {
                            union = posting;
                            continue;
                        }
                        for id in &posting {
                            cancellation.check()?;
                            if !union.contains(id) {
                                check_size(union.len() + 1, cap)?;
                                reserve_posting_id(memory, id)?;
                                union.insert(id.clone());
                            }
                        }
                        drop(posting);
                        memory.release(posting_bytes)?;
                    }
                    Some(union)
                }
                Node::Leaf { .. } => {
                    self.stored_leaf(source, node, restrict, cap, cancellation, memory)?
                }
                _ => None,
            };
            let retained = if result.is_some() {
                memory.live_bytes() - baseline
            } else {
                0
            };
            Ok((result, retained))
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn stored_leaf<S: DocumentSource + ?Sized, W: crate::QueryWorkspace>(
        &self,
        source: &S,
        node: &Node<'_>,
        restrict: Option<&IdSet>,
        cap: usize,
        cancellation: &QueryCancellation,
        memory: &mut crate::QueryMemory<W>,
    ) -> ReadResult<Option<IdSet>, S::Failure> {
        let Node::Leaf { path, test } = node else {
            return Ok(None);
        };
        let Some((field, (_, index))) = self
            .fields
            .iter()
            .enumerate()
            .find(|(_, (key, _))| key.as_str() == *path)
        else {
            return Ok(None);
        };
        let predicate = match test {
            Test::Exists(present) => crate::FieldPredicate::Exists(*present),
            Test::Eq(value) | Test::Contains(value) => crate::FieldPredicate::Equals {
                value,
                kind: index.kind,
            },
            Test::Range { lower, upper } => crate::FieldPredicate::Range {
                lower: *lower,
                upper: *upper,
                kind: index.kind,
            },
            Test::In(values) => crate::FieldPredicate::In {
                values,
                kind: index.kind,
            },
        };
        let ordered_by_value = matches!(
            predicate,
            crate::FieldPredicate::Range { .. } | crate::FieldPredicate::In { .. }
        );
        let mut ids = IdSet::new();
        let mut visited = false;
        let available = source.visit_field_posting(field, predicate, cancellation, |id| {
            cancellation.check()?;
            visited = true;
            if restrict.is_some_and(|ids| !ids.contains(id)) {
                return Ok(());
            }
            check_size(ids.len() + 1, cap)?;
            reserve_posting_id(memory, id)?;
            // Range and membership visit one ID-ordered posting per distinct scalar. A
            // non-array field can contribute an ID to only one such posting.
            let invalid_order = if ordered_by_value {
                ids.contains(id)
            } else {
                ids.get_max()
                    .is_some_and(|previous: &Arc<str>| previous.as_ref() >= id)
            };
            if invalid_order {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "unordered field postings",
                ));
            }
            ids.insert(self.ids.get(id).cloned().unwrap_or_else(|| Arc::from(id)));
            Ok(())
        })?;
        if !available && visited {
            return Err(Error::new(ErrorCode::Corruption, "partial field postings").into());
        }
        Ok(available.then_some(ids))
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn candidates<S: DocumentSource + ?Sized>(
        &self,
        source: &S,
        node: &Node<'_>,
        universe: &IdSet,
        allow_scan: bool,
        allow_index_reads: bool,
        cap: usize,
        cancellation: &QueryCancellation,
    ) -> ReadResult<IdSet, S::Failure> {
        cancellation.check()?;
        if allow_scan
            && matches!(node, Node::And(_) | Node::Or(_) | Node::Not(_))
            && let Some(scan) = Scan::prepare(node, &self.fields)?
            && scan.has_leaf()
        {
            check_size(universe.len(), cap)?;
            let mut selected = IdSet::new();
            for id in universe {
                let matched =
                    document_source::with_live(source, id, None, cancellation, |document| {
                        scan.evaluate(&document.body, cancellation)
                    })?;
                if matched {
                    selected.insert(id.clone());
                }
            }
            return Ok(selected);
        }
        match node {
            Node::All => {
                check_size(universe.len(), cap)?;
                Ok(universe.clone())
            }
            Node::And(children) => {
                let mut survivors: Option<IdSet> = None;
                for position in self.conjunct_order(children, universe.len())? {
                    let input = survivors.as_ref().unwrap_or(universe);
                    let next = self.candidates(
                        source,
                        &children[position],
                        input,
                        allow_scan,
                        allow_index_reads,
                        cap,
                        cancellation,
                    )?;
                    let empty = next.is_empty();
                    survivors = Some(next);
                    if empty {
                        break;
                    }
                }
                Ok(survivors.unwrap_or_else(|| universe.clone()))
            }
            Node::Or(children) => {
                let mut candidates = IdSet::new();
                for child in children {
                    for id in self.candidates(
                        source,
                        child,
                        universe,
                        allow_scan,
                        allow_index_reads,
                        cap,
                        cancellation,
                    )? {
                        cancellation.check()?;
                        candidates.insert(id);
                    }
                    check_size(candidates.len(), cap)?;
                }
                Ok(candidates)
            }
            Node::Not(child) => {
                // The canonical never-matching filter needs no candidates.
                if matches!(**child, Node::All) {
                    return Ok(IdSet::new());
                }
                // The child bounds its own candidates and any documents it
                // scans. Excluded IDs are a subset of the universe, so the
                // complement's size is known before it is built.
                let excluded = self.candidates(
                    source,
                    child,
                    universe,
                    allow_scan,
                    allow_index_reads,
                    cap,
                    cancellation,
                )?;
                check_size(universe.len().saturating_sub(excluded.len()), cap)?;
                Ok(complement(universe, &excluded, cancellation)?)
            }
            Node::Leaf { path, test } => {
                let kind = self.field_kind(path, allow_scan)?;
                // A selective preceding conjunct is cheaper to test directly
                // than walking a broad range's every posting. Archived rows
                // already retain their indexed scalar, so no archive fetch is
                // introduced. The outer BoundSource verifies each loan.
                if allow_index_reads
                    && kind.is_some()
                    && matches!(test, Test::Range { .. })
                    && !universe.ptr_eq(&self.ids)
                    && universe.len().saturating_mul(8) < self.ids.len()
                    && self
                        .estimate(node, self.ids.len(), universe.len())?
                        .is_some_and(|size| size > universe.len())
                {
                    let prepared = PreparedTest::new(test, kind)?;
                    let mut selected = IdSet::new();
                    for id in universe {
                        let matched = source.with_record(id, None, cancellation, |record| {
                            cancellation.check()?;
                            let record = record.ok_or_else(|| {
                                Error::new(
                                    ErrorCode::Corruption,
                                    "index/document generation mismatch",
                                )
                            })?;
                            if matches!(record, Record::Live(document) if document.id != id.as_ref()) {
                                return Err(Error::new(
                                    ErrorCode::Corruption,
                                    "source document identity/version differs",
                                ));
                            }
                            prepared.evaluate(record_value(record, path), kind, cancellation)
                        })?;
                        if matched {
                            selected.insert(id.clone());
                        }
                    }
                    return Ok(selected);
                }
                match self.fields.get(*path) {
                    Some(index) => Ok(index.candidates(
                        test,
                        universe,
                        universe.ptr_eq(&self.ids),
                        cap,
                        cancellation,
                    )?),
                    None => {
                        check_size(universe.len(), cap)?;
                        let prepared = PreparedTest::new(test, kind)?;
                        let mut selected = IdSet::new();
                        for id in universe {
                            let matched = document_source::with_live(
                                source,
                                id,
                                None,
                                cancellation,
                                |document| {
                                    prepared.evaluate(
                                        crate::allocation::pointer(&document.body, path),
                                        kind,
                                        cancellation,
                                    )
                                },
                            )?;
                            if matched {
                                selected.insert(id.clone());
                            }
                        }
                        Ok(selected)
                    }
                }
            }
        }
    }
}

// Each inserted ID may allocate a 16-slot persistent tree node and its edges,
// as well as the string backing. Admit these before mutating the private set.
fn reserve_posting_id<W: crate::QueryWorkspace>(
    memory: &mut crate::QueryMemory<W>,
    id: &str,
) -> Result<()> {
    memory.reserve(crate::allocation::add(
        2048 + (2 * size_of::<usize>()) as u64,
        crate::allocation::string_clone_bytes(id)?,
    )?)
}

/// `universe` without `excluded` (a subset of it). A small exclusion shares
/// the universe's persistent nodes instead of copying every surviving ID.
fn complement(
    universe: &IdSet,
    excluded: &IdSet,
    cancellation: &QueryCancellation,
) -> Result<IdSet> {
    if excluded.len() <= universe.len() / 2 {
        let mut candidates = universe.clone();
        for id in excluded {
            cancellation.check()?;
            candidates.remove(id);
        }
        return Ok(candidates);
    }
    let mut candidates = IdSet::new();
    for id in universe {
        cancellation.check()?;
        if !excluded.contains(id) {
            candidates.insert(id.clone());
        }
    }
    Ok(candidates)
}

impl FieldIndex {
    /// `whole` means `universe` is the collection's complete ID set, so every
    /// index entry is already a subset of it and can be shared in O(1).
    fn candidates(
        &self,
        test: &Test<'_>,
        universe: &IdSet,
        whole: bool,
        cap: usize,
        cancellation: &QueryCancellation,
    ) -> Result<IdSet> {
        let kind = Some(self.kind);
        let mut candidates = IdSet::new();
        let mut add = |ids: &IdSet| -> Result<()> {
            if whole {
                check_size(
                    candidates
                        .len()
                        .saturating_add(ids.len())
                        .min(universe.len()),
                    cap,
                )?;
                if candidates.len() < ids.len() {
                    let previous = std::mem::replace(&mut candidates, ids.clone());
                    for id in previous {
                        cancellation.check()?;
                        candidates.insert(id);
                    }
                } else {
                    for id in ids {
                        cancellation.check()?;
                        candidates.insert(id.clone());
                    }
                }
                return check_size(candidates.len(), cap);
            }
            let (shorter, longer) = if ids.len() <= universe.len() {
                (ids, universe)
            } else {
                (universe, ids)
            };
            for id in shorter {
                cancellation.check()?;
                if longer.contains(id) {
                    candidates.insert(id.clone());
                    check_size(candidates.len(), cap)?;
                }
            }
            Ok(())
        };
        match test {
            Test::Exists(true) => add(&self.present)?,
            Test::Exists(false) if whole => {
                candidates = complement(universe, &self.present, cancellation)?;
                check_size(candidates.len(), cap)?;
            }
            Test::Exists(false) => {
                for id in universe {
                    cancellation.check()?;
                    if !self.present.contains(id) {
                        candidates.insert(id.clone());
                        check_size(candidates.len(), cap)?;
                    }
                }
            }
            Test::Eq(value) | Test::Contains(value) => {
                if let Some(ids) = self.entries.get(&scalar(Some(value), kind)?) {
                    add(ids)?;
                }
            }
            Test::In(values) => {
                // Equal values, including decimal spellings that normalize
                // alike, share one posting: add and charge it only once.
                let mut keys = BTreeSet::new();
                for value in *values {
                    cancellation.check()?;
                    keys.insert(scalar(Some(value), kind)?);
                }
                for key in &keys {
                    cancellation.check()?;
                    if let Some(ids) = self.entries.get(key) {
                        add(ids)?;
                    }
                }
            }
            Test::Range { lower, upper } => {
                let range = index_range(*lower, *upper, kind)?;
                if !empty_range(&range) {
                    for (visited, (key, ids)) in self.entries.range(range).enumerate() {
                        cancellation.check()?;
                        // Survivors of an earlier conjunct already passed the
                        // candidate budget, and only they can be added here.
                        if whole {
                            check_size(visited + 1, cap)?;
                        }
                        if !matches!(key, Scalar::Missing | Scalar::Null) {
                            add(ids)?;
                        }
                    }
                }
            }
        }
        Ok(candidates)
    }
}
