use crate::scalar::{Scalar, exhausted, indexed_values, invalid, scalar, validate_pointer};
use crate::{
    CollectionRecords, DocumentChanges, DocumentSource, QueryCancellation, ReadResult, Record,
    document_source,
};
use imbl::{OrdMap, OrdSet};
use kasumi_types::*;
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) type IdSet = OrdSet<String>;

#[derive(Debug, Clone)]
pub(crate) struct FieldIndex {
    pub kind: ScalarType,
    pub entries: OrdMap<Scalar, IdSet>,
    pub present: IdSet,
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
    pub(crate) entries: OrdMap<Vec<Scalar>, String>,
}

pub(crate) fn record_value<'a>(record: Record<'a>, path: &str) -> Option<&'a Value> {
    match record {
        Record::Live(document) => document.body.pointer(path),
        Record::Archived(document) => document.indexed_fields.get(path),
    }
}
impl UniqueIndex {
    fn key(&self, record: Record<'_>) -> Result<Option<Vec<Scalar>>> {
        let key = self
            .fields
            .iter()
            .map(|field| scalar(record_value(record, &field.path), Some(field.kind)))
            .collect::<Result<Vec<_>>>()?;
        Ok((!key.contains(&Scalar::Missing)).then_some(key))
    }
    fn insert(&mut self, name: &str, id: &str, record: Record<'_>) -> Result<()> {
        if let Some(key) = self.key(record)?
            && self.entries.insert(key, id.to_owned()).is_some()
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!("unique index {name} conflicts"),
            ));
        }
        Ok(())
    }
}

impl Structured {
    pub fn update<D: DocumentChanges + ?Sized>(&self, changes: &D) -> ReadResult<Self, D::Failure> {
        let mut next = self.clone();
        next.unique = self.unique_delta(changes)?;
        changes.visit_changes(|delta| {
            let previous = delta.old;
            let current = delta.new;
            let id = delta.id;
            if previous.is_none() && current.is_none() {
                return Ok(());
            }
            if current.is_none() {
                next.ids.remove(id);
            } else if previous.is_none() {
                next.ids.insert(id.to_owned());
            }
            for (path, index) in &mut next.fields {
                let old_value = previous.and_then(|record| record_value(record, path));
                let new_value = current.and_then(|record| record_value(record, path));
                if previous.is_some() && current.is_some() && old_value == new_value {
                    continue;
                }
                if previous.is_some() {
                    index.present.remove(id);
                    for key in indexed_values(old_value, index.kind)? {
                        if let Some(ids) = index.entries.get_mut(&key) {
                            ids.remove(id);
                            if ids.is_empty() {
                                index.entries.remove(&key);
                            }
                        }
                    }
                }
                if current.is_some() {
                    if new_value.is_some() {
                        index.present.insert(id.to_owned());
                    }
                    for key in indexed_values(new_value, index.kind)? {
                        index.entries.entry(key).or_default().insert(id.to_owned());
                    }
                }
            }
            Ok(())
        })?;
        Ok(next)
    }
    fn unique_delta<D: DocumentChanges + ?Sized>(
        &self,
        changes: &D,
    ) -> ReadResult<BTreeMap<String, UniqueIndex>, D::Failure> {
        let mut unique = self.unique.clone();
        // Remove every old mapping across the batch before adding any new one.
        // Private COW roots are discarded on rejection; published roots stay intact.
        changes.visit_changes(|delta| {
            if let Some(old) = delta.old {
                for index in unique.values_mut() {
                    if let Some(key) = index.key(old)? {
                        if index
                            .entries
                            .get(&key)
                            .is_none_or(|owner| owner != delta.id)
                        {
                            return Err(Error::new(
                                ErrorCode::Corruption,
                                "old unique mapping differs from delta",
                            ));
                        }
                        index.entries.remove(&key);
                    }
                }
            }
            Ok(())
        })?;
        changes.visit_changes(|delta| {
            if let Some(new) = delta.new {
                for (name, index) in &mut unique {
                    index.insert(name, delta.id, new)?;
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
        self.unique_delta(changes).map(|_| ())
    }

    /// Validate independently of hits, so empty collections and short-circuiting
    /// cannot turn malformed queries into successful responses.
    pub fn validate(&self, predicate: &Predicate, allow_scan: bool) -> Result<()> {
        match predicate {
            Predicate::All => Ok(()),
            Predicate::And { predicates } | Predicate::Or { predicates } => {
                for predicate in predicates {
                    self.validate(predicate, allow_scan)?;
                }
                Ok(())
            }
            Predicate::Not { predicate } => self.validate(predicate, allow_scan),
            _ => {
                let kind =
                    self.field_kind(predicate_path(predicate).expect("leaf field"), allow_scan)?;
                let check = |value: &Value| -> Result<()> {
                    if let Some(kind) = kind {
                        check_operator_type(predicate, kind, value)?;
                    }
                    if matches!(predicate, Predicate::Contains { .. }) && value.is_null() {
                        return Err(invalid("array membership requires a non-null scalar"));
                    }
                    let value = scalar(Some(value), kind)?;
                    if matches!(predicate, Predicate::Compare { .. }) && value == Scalar::Null {
                        return Err(invalid("ordered comparison requires a non-null scalar"));
                    }
                    Ok(())
                };
                match predicate {
                    Predicate::Eq { value, .. }
                    | Predicate::Contains { value, .. }
                    | Predicate::Compare { value, .. } => check(value),
                    Predicate::In { values, .. } => {
                        if matches!(
                            kind,
                            Some(ScalarType::StringArray | ScalarType::NumberArray)
                        ) {
                            return Err(invalid("array fields require the contains operator"));
                        }
                        for value in values {
                            check(value)?;
                        }
                        Ok(())
                    }
                    Predicate::Exists { .. } => Ok(()),
                    _ => unreachable!(),
                }
            }
        }
    }

    fn empty_unique(definition: &CollectionDefinition) -> BTreeMap<String, UniqueIndex> {
        definition
            .indexes
            .iter()
            .filter(|index| index.unique)
            .map(|index| {
                (
                    index.name.clone(),
                    UniqueIndex {
                        fields: index.fields.clone(),
                        entries: OrdMap::new(),
                    },
                )
            })
            .collect()
    }
    pub(crate) fn build_unique<R: CollectionRecords + ?Sized>(
        source: &R,
    ) -> ReadResult<BTreeMap<String, UniqueIndex>, R::Failure> {
        let mut unique = Self::empty_unique(source.definition());
        source.visit_records(|id, record| {
            for (name, index) in &mut unique {
                index.insert(name, id, record)?;
            }
            Ok(())
        })?;
        Ok(unique)
    }
    pub fn build<R: CollectionRecords + ?Sized>(source: &R) -> ReadResult<Self, R::Failure> {
        let mut fields = BTreeMap::new();
        for index in &source.definition().indexes {
            for field in &index.fields {
                fields
                    .entry(field.path.clone())
                    .or_insert_with(|| FieldIndex {
                        kind: field.kind,
                        entries: OrdMap::new(),
                        present: IdSet::new(),
                    });
            }
        }
        let mut ids = IdSet::new();
        let mut unique = Self::empty_unique(source.definition());
        source.visit_records(|id, record| {
            ids.insert(id.to_owned());
            for (path, index) in &mut fields {
                let value = record_value(record, path);
                if value.is_some() {
                    index.present.insert(id.to_owned());
                }
                for key in indexed_values(value, index.kind)? {
                    index.entries.entry(key).or_default().insert(id.to_owned());
                }
            }
            for (name, index) in &mut unique {
                index.insert(name, id, record)?;
            }
            Ok(())
        })?;
        Ok(Self {
            fields,
            ids,
            unique,
        })
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

    pub fn candidates<S: DocumentSource + ?Sized>(
        &self,
        source: &S,
        predicate: &Predicate,
        universe: &IdSet,
        allow_scan: bool,
        cap: usize,
        cancellation: &QueryCancellation,
    ) -> ReadResult<IdSet, S::Failure> {
        cancellation.check()?;
        match predicate {
            Predicate::All => {
                check_size(universe.len(), cap)?;
                Ok(universe.clone())
            }
            Predicate::And { predicates } => {
                if predicates.is_empty() {
                    return self.candidates(
                        source,
                        &Predicate::All,
                        universe,
                        allow_scan,
                        cap,
                        cancellation,
                    );
                }
                let mut candidates = self.candidates(
                    source,
                    &predicates[0],
                    universe,
                    allow_scan,
                    cap,
                    cancellation,
                )?;
                for predicate in &predicates[1..] {
                    candidates = self.candidates(
                        source,
                        predicate,
                        &candidates,
                        allow_scan,
                        cap,
                        cancellation,
                    )?;
                }
                Ok(candidates)
            }
            Predicate::Or { predicates } => {
                let mut candidates = IdSet::new();
                for predicate in predicates {
                    for id in
                        self.candidates(source, predicate, universe, allow_scan, cap, cancellation)?
                    {
                        cancellation.check()?;
                        candidates.insert(id);
                    }
                    check_size(candidates.len(), cap)?;
                }
                Ok(candidates)
            }
            Predicate::Not { predicate } => {
                check_size(universe.len(), cap)?;
                let excluded =
                    self.candidates(source, predicate, universe, allow_scan, cap, cancellation)?;
                let mut candidates = IdSet::new();
                for id in universe {
                    cancellation.check()?;
                    if !excluded.contains(id) {
                        candidates.insert(id.clone());
                    }
                }
                Ok(candidates)
            }
            _ => {
                let path = predicate_path(predicate).expect("leaf has a field");
                let kind = self.field_kind(path, allow_scan)?;
                if let Some(index) = self.fields.get(path) {
                    let mut candidates = IdSet::new();
                    let mut add = |ids: &IdSet| -> Result<()> {
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
                    match predicate {
                        Predicate::Exists { exists, .. } => {
                            if *exists {
                                add(&index.present)?;
                            } else {
                                for id in universe {
                                    cancellation.check()?;
                                    if !index.present.contains(id) {
                                        candidates.insert(id.clone());
                                        check_size(candidates.len(), cap)?;
                                    }
                                }
                            }
                        }
                        Predicate::Eq { value, .. } | Predicate::Contains { value, .. } => {
                            check_operator_type(predicate, index.kind, value)?;
                            let key = scalar(Some(value), kind)?;
                            if let Some(ids) = index.entries.get(&key) {
                                add(ids)?;
                            }
                        }
                        Predicate::In { values, .. } => {
                            for value in values {
                                cancellation.check()?;
                                check_operator_type(predicate, index.kind, value)?;
                                if let Some(ids) = index.entries.get(&scalar(Some(value), kind)?) {
                                    add(ids)?;
                                }
                            }
                        }
                        Predicate::Compare {
                            comparison, value, ..
                        } => {
                            check_operator_type(predicate, index.kind, value)?;
                            let key = scalar(Some(value), kind)?;
                            if matches!(key, Scalar::Missing | Scalar::Null) {
                                return Err(invalid(
                                    "ordered comparison requires a non-null scalar",
                                )
                                .into());
                            }
                            use std::ops::Bound::{Excluded, Included, Unbounded};
                            let bounds = match comparison {
                                Comparison::Lt => (Unbounded, Excluded(key)),
                                Comparison::Lte => (Unbounded, Included(key)),
                                Comparison::Gt => (Excluded(key), Unbounded),
                                Comparison::Gte => (Included(key), Unbounded),
                            };
                            for (visited, (key, ids)) in index.entries.range(bounds).enumerate() {
                                cancellation.check()?;
                                check_size(visited + 1, cap)?;
                                if !matches!(key, Scalar::Missing | Scalar::Null) {
                                    add(ids)?;
                                }
                            }
                        }
                        _ => unreachable!(),
                    }
                    Ok(candidates)
                } else {
                    check_size(universe.len(), cap)?;
                    let mut selected = IdSet::new();
                    for id in universe {
                        let matched = document_source::with_live(
                            source,
                            id,
                            None,
                            cancellation,
                            |document| evaluate_leaf(predicate, &document.body, None, cancellation),
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

pub(crate) fn check_size(size: usize, limit: usize) -> Result<()> {
    if size > limit {
        Err(exhausted("query candidate budget exceeded"))
    } else {
        Ok(())
    }
}

fn check_operator_type(predicate: &Predicate, kind: ScalarType, value: &Value) -> Result<()> {
    let array = matches!(kind, ScalarType::StringArray | ScalarType::NumberArray);
    match predicate {
        Predicate::Contains { .. } if !array => Err(invalid("contains requires an array field")),
        Predicate::Contains { .. } if value.is_null() => {
            Err(invalid("array membership requires a non-null scalar"))
        }
        Predicate::Eq { .. } if array && value.is_null() => Ok(()),
        Predicate::Contains { .. } => Ok(()),
        _ if array => Err(invalid("array fields require the contains operator")),
        _ => Ok(()),
    }
}

pub(crate) fn predicate_path(predicate: &Predicate) -> Option<&str> {
    match predicate {
        Predicate::Eq { field, .. }
        | Predicate::In { field, .. }
        | Predicate::Compare { field, .. }
        | Predicate::Exists { field, .. }
        | Predicate::Contains { field, .. } => Some(field),
        _ => None,
    }
}

pub(crate) fn validate_predicate(
    predicate: &Predicate,
    depth: usize,
    nodes: &mut usize,
) -> Result<()> {
    *nodes += 1;
    if depth > 16 || *nodes > 256 {
        return Err(invalid("query predicate exceeds depth/node budget"));
    }
    if let Some(path) = predicate_path(predicate) {
        validate_pointer(path)?;
    }
    match predicate {
        Predicate::And { predicates } | Predicate::Or { predicates } => {
            for predicate in predicates {
                validate_predicate(predicate, depth + 1, nodes)?;
            }
        }
        Predicate::Not { predicate } => validate_predicate(predicate, depth + 1, nodes)?,
        Predicate::In { values, .. } if values.len() > 256 => {
            return Err(invalid("in is limited to 256 values"));
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn evaluate_leaf(
    predicate: &Predicate,
    body: &Value,
    kind: Option<ScalarType>,
    cancellation: &QueryCancellation,
) -> Result<bool> {
    let field = predicate_path(predicate).ok_or_else(|| invalid("not a leaf predicate"))?;
    let actual = body.pointer(field);
    if let Predicate::Exists { exists, .. } = predicate {
        return Ok(actual.is_some() == *exists);
    }
    if let Predicate::Contains { value, .. } = predicate {
        let Some(Value::Array(values)) = actual else {
            return Ok(false);
        };
        let expected = scalar(Some(value), kind)?;
        for value in values {
            cancellation.check()?;
            if scalar(Some(value), kind)? == expected {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    if actual.is_none() {
        return Ok(false);
    }
    let actual = scalar(actual, kind)?;
    match predicate {
        Predicate::Eq { value, .. } => Ok(actual == scalar(Some(value), kind)?),
        Predicate::In { values, .. } => {
            for value in values {
                cancellation.check()?;
                if actual == scalar(Some(value), kind)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Predicate::Compare {
            comparison, value, ..
        } => {
            let expected = scalar(Some(value), kind)?;
            if matches!(expected, Scalar::Missing | Scalar::Null) {
                return Err(invalid("ordered comparison requires a non-null scalar"));
            }
            if matches!(actual, Scalar::Missing | Scalar::Null)
                || std::mem::discriminant(&actual) != std::mem::discriminant(&expected)
            {
                return Ok(false);
            }
            Ok(match comparison {
                Comparison::Lt => actual < expected,
                Comparison::Lte => actual <= expected,
                Comparison::Gt => actual > expected,
                Comparison::Gte => actual >= expected,
            })
        }
        _ => Err(invalid("unsupported predicate")),
    }
}
