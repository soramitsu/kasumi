use crate::QueryCancellation;
use crate::scalar::{Scalar, exhausted, indexed_values, invalid, scalar, validate_pointer};
use imbl::{OrdMap, OrdSet};
use kasumi_types::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

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

impl UniqueIndex {
    fn insert_archived(&mut self, name: &str, id: &str, document: &ArchivedDocument) -> Result<()> {
        let key = self
            .fields
            .iter()
            .map(|field| scalar(document.indexed_fields.get(&field.path), Some(field.kind)))
            .collect::<Result<Vec<_>>>()?;
        if !key.contains(&Scalar::Missing) && self.entries.insert(key, id.into()).is_some() {
            return Err(Error::new(
                ErrorCode::Conflict,
                format!("unique index {name} conflicts"),
            ));
        }
        Ok(())
    }
    fn key(&self, document: &Document) -> Result<Option<Vec<Scalar>>> {
        let key = self
            .fields
            .iter()
            .map(|field| scalar(document.body.pointer(&field.path), Some(field.kind)))
            .collect::<Result<Vec<_>>>()?;
        if key.contains(&Scalar::Missing) {
            Ok(None)
        } else {
            Ok(Some(key))
        }
    }
    fn insert(&mut self, name: &str, document: &Document) -> Result<()> {
        if let Some(key) = self.key(document)?
            && self.entries.insert(key, document.id.clone()).is_some()
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
    pub fn update(
        &self,
        old: &CollectionState,
        new: &CollectionState,
        changed: &BTreeSet<String>,
    ) -> Result<Self> {
        let mut next = self.clone();
        next.unique = self.unique_delta(old, new, changed)?;
        for id in changed {
            let previous = old.documents.get(id);
            let current = new.documents.get(id);
            if previous.is_none() && current.is_none() {
                continue;
            }
            if current.is_none() {
                next.ids.remove(id);
            } else if previous.is_none() {
                next.ids.insert(id.clone());
            }
            for (path, index) in &mut next.fields {
                let old_value = previous.and_then(|document| document.body.pointer(path));
                let new_value = current.and_then(|document| document.body.pointer(path));
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
                        index.present.insert(id.clone());
                    }
                    for key in indexed_values(new_value, index.kind)? {
                        index.entries.entry(key).or_default().insert(id.clone());
                    }
                }
            }
        }
        Ok(next)
    }

    fn unique_delta(
        &self,
        old: &CollectionState,
        new: &CollectionState,
        changed: &BTreeSet<String>,
    ) -> Result<BTreeMap<String, UniqueIndex>> {
        let mut unique = self.unique.clone();
        for (name, index) in &mut unique {
            // Remove the entire batch first, so atomic unique-key swaps work.
            for id in changed {
                if let Some(document) = old.documents.get(id)
                    && let Some(key) = index.key(document)?
                {
                    index.entries.remove(&key);
                }
            }
            for id in changed {
                if let Some(document) = new.documents.get(id) {
                    index.insert(name, document)?;
                }
            }
        }
        Ok(unique)
    }

    pub fn validate_unique_changes(
        &self,
        old: &CollectionState,
        new: &CollectionState,
        changed: &BTreeSet<String>,
    ) -> Result<()> {
        self.unique_delta(old, new, changed).map(|_| ())
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

    pub fn build(collection: &CollectionState) -> Result<Self> {
        let mut fields = BTreeMap::new();
        for index in &collection.definition.indexes {
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
        for (id, document) in &collection.documents {
            ids.insert(id.clone());
            for (path, index) in &mut fields {
                let value = document.body.pointer(path);
                if value.is_some() {
                    index.present.insert(id.clone());
                }
                for key in indexed_values(value, index.kind)? {
                    index.entries.entry(key).or_default().insert(id.clone());
                }
            }
        }
        let mut unique = BTreeMap::new();
        for (id, document) in &collection.archived_documents {
            ids.insert(id.clone());
            for (path, index) in &mut fields {
                let value = document.indexed_fields.get(path);
                if value.is_some() {
                    index.present.insert(id.clone());
                }
                for key in indexed_values(value, index.kind)? {
                    index.entries.entry(key).or_default().insert(id.clone());
                }
            }
        }
        for definition in collection
            .definition
            .indexes
            .iter()
            .filter(|index| index.unique)
        {
            let mut index = UniqueIndex {
                fields: definition.fields.clone(),
                entries: OrdMap::new(),
            };
            for document in collection.documents.values() {
                index.insert(&definition.name, document)?;
            }
            for (id, document) in &collection.archived_documents {
                index.insert_archived(&definition.name, id, document)?;
            }
            unique.insert(definition.name.clone(), index);
        }
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

    pub fn candidates(
        &self,
        collection: &CollectionState,
        predicate: &Predicate,
        universe: &IdSet,
        allow_scan: bool,
        cap: usize,
        cancellation: &QueryCancellation,
    ) -> Result<IdSet> {
        cancellation.check()?;
        match predicate {
            Predicate::All => {
                check_size(universe.len(), cap)?;
                Ok(universe.clone())
            }
            Predicate::And { predicates } => {
                if predicates.is_empty() {
                    return self.candidates(
                        collection,
                        &Predicate::All,
                        universe,
                        allow_scan,
                        cap,
                        cancellation,
                    );
                }
                let mut candidates = self.candidates(
                    collection,
                    &predicates[0],
                    universe,
                    allow_scan,
                    cap,
                    cancellation,
                )?;
                for predicate in &predicates[1..] {
                    candidates = self.candidates(
                        collection,
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
                    for id in self.candidates(
                        collection,
                        predicate,
                        universe,
                        allow_scan,
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
            Predicate::Not { predicate } => {
                check_size(universe.len(), cap)?;
                let excluded = self.candidates(
                    collection,
                    predicate,
                    universe,
                    allow_scan,
                    cap,
                    cancellation,
                )?;
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
                                ));
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
                    universe
                        .iter()
                        .filter_map(|id| {
                            if let Err(error) = cancellation.check() {
                                return Some(Err(error));
                            }
                            let document = &collection.documents[id];
                            match evaluate_leaf(predicate, &document.body, None, cancellation) {
                                Ok(true) => Some(Ok(id.clone())),
                                Ok(false) => None,
                                Err(error) => Some(Err(error)),
                            }
                        })
                        .collect()
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
