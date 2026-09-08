//! Immutable indexes and bounded, exact queries for one published tenant generation.
//!
//! `execute` returns the complete bounded result, in stable order. The engine owns
//! snapshot pagination and fills in the generation revision. Projection produces an
//! object keyed by the requested JSON Pointers; absent values are omitted. Aggregate
//! entries are `{ "group": { pointer: value }, "values": { alias: value } }`.
//! Numbers produced by numeric aggregates are exact decimal strings. `count` is a
//! JSON integer; missing/null inputs are ignored, except fieldless count counts rows.

mod cancellation;
pub use cancellation::QueryCancellation;
mod scalar;
mod search;
mod structured;
mod validation;

pub use validation::{check_unique, unique_index_key, validate_collection, validate_document};

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::Arc;

use bigdecimal::{BigDecimal, Signed, Zero, num_bigint::BigInt};
use kasumi_types::*;
use serde_json::{Map, Value};

use scalar::{Scalar, exhausted, invalid, numeric_value, scalar, validate_pointer};
use search::TextSnapshot;
use structured::{IdSet, Structured, validate_predicate};

#[derive(Debug)]
struct CollectionIndexes {
    _validator: std::sync::Arc<jsonschema::Validator>,
    structured: Structured,
    text: Option<Arc<TextSnapshot>>,
}

/// Publish only after all structured and text indexes have finished construction.
#[derive(Debug, Default)]
pub struct QueryIndexes {
    collections: BTreeMap<String, Arc<CollectionIndexes>>,
}

/// Persistent primary-ID roots for coherent point/scan leases. This intentionally
/// retains no text or field-index generation.
#[derive(Debug, Clone)]
pub struct ReadIds(BTreeMap<String, IdSet>);
impl ReadIds {
    pub fn document_ids_after(
        &self,
        collection: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>> {
        use std::ops::Bound;
        if limit == 0 || limit > 1001 {
            return Err(invalid("ID page limit outside bounds"));
        }
        let ids = self
            .0
            .get(collection)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "collection index not found"))?;
        Ok(ids
            .range::<_, str>((
                after.map_or(Bound::Unbounded, Bound::Excluded),
                Bound::Unbounded,
            ))
            .take(limit)
            .cloned()
            .collect())
    }
}

impl QueryIndexes {
    pub fn read_ids(&self) -> ReadIds {
        ReadIds(
            self.collections
                .iter()
                .map(|(name, indexes)| (name.clone(), indexes.structured.ids.clone()))
                .collect(),
        )
    }
    /// Plan bounded candidates using maintained structured indexes without
    /// reading document bodies. Explicit scans are resolved by the service.
    pub fn indexed_candidate_ids(
        &self,
        collections: &BTreeMap<String, CollectionState>,
        request: &QueryRequest,
        limits: &Limits,
        cancellation: &QueryCancellation,
    ) -> Result<Vec<String>> {
        cancellation.check()?;
        validate_name(&request.collection)?;
        validate_predicate(&request.filter, 0, &mut 0)?;
        let collection = collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "collection not found"))?;
        let indexes = self
            .collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "collection index not ready"))?;
        if request.text.is_some() {
            return Err(Error::new(
                ErrorCode::IndexRequired,
                "cold text queries require a supported archive text index",
            ));
        }
        indexes.structured.validate(&request.filter, false)?;
        Ok(indexes
            .structured
            .candidates(
                collection,
                &request.filter,
                &indexes.structured.ids,
                false,
                limits.max_query_candidates,
                cancellation,
            )?
            .into_iter()
            .collect())
    }
    /// Bounded ID-order continuation over an existing generation's maintained
    /// primary ID index. The caller supplies authorization and snapshot fences.
    pub fn document_ids_after(
        &self,
        collection: &str,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<String>> {
        use std::ops::Bound;
        if limit == 0 || limit > 1001 {
            return Err(invalid("ID page limit outside bounds"));
        }
        let indexes = self
            .collections
            .get(collection)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "collection index not found"))?;
        let start = after.map_or(Bound::Unbounded, Bound::Excluded);
        Ok(indexes
            .structured
            .ids
            .range::<_, str>((start, Bound::Unbounded))
            .take(limit)
            .cloned()
            .collect())
    }
    pub fn build(collections: &BTreeMap<String, CollectionState>) -> Result<Self> {
        let mut indexes = BTreeMap::new();
        for (name, collection) in collections {
            if name != &collection.definition.name {
                return Err(invalid("collection map key differs from its definition"));
            }
            let validator = validation::compile(&collection.definition.schema)?;
            validate_collection(&collection.definition, &collection.documents)?;
            indexes.insert(
                name.clone(),
                Arc::new(CollectionIndexes {
                    _validator: validator,
                    structured: Structured::build(collection)?,
                    text: TextSnapshot::build(collection)?.map(Arc::new),
                }),
            );
        }
        Ok(Self {
            collections: indexes,
        })
    }

    /// Advance from the current generation with the exact changed document IDs
    /// supplied by ordered application. Unchanged collections and text fields
    /// retain their readers. New/changed definitions rebuild before publication.
    /// If a changed collection has no delta entry, rebuild it safely.
    pub fn update(
        &self,
        previous: &BTreeMap<String, CollectionState>,
        next: &BTreeMap<String, CollectionState>,
        changed: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<Self> {
        let mut collections = BTreeMap::new();
        for (name, collection) in next {
            let prior = previous.get(name).zip(self.collections.get(name));
            if let Some((old, indexes)) =
                prior.filter(|(old, _)| old.definition == collection.definition)
            {
                if old.documents.ptr_eq(&collection.documents) {
                    collections.insert(name.clone(), indexes.clone());
                    continue;
                }
                if let Some(ids) = changed.get(name).filter(|ids| !ids.is_empty()) {
                    for id in ids {
                        if let Some(document) = collection.documents.get(id) {
                            validate_name(id)?;
                            if &document.id != id {
                                return Err(invalid("document map key differs from its id"));
                            }
                            validate_document(&collection.definition, &document.body)?;
                        }
                    }
                    let structured = indexes.structured.update(old, collection, ids)?;
                    let text = if let Some(text) = &indexes.text {
                        if text.fields_changed(old, collection, ids) {
                            Some(Arc::new(text.update(collection, ids)?))
                        } else {
                            Some(text.clone())
                        }
                    } else {
                        None
                    };
                    collections.insert(
                        name.clone(),
                        Arc::new(CollectionIndexes {
                            _validator: indexes._validator.clone(),
                            structured,
                            text,
                        }),
                    );
                    continue;
                }
            }
            let built = Self::build(&BTreeMap::from([(name.clone(), collection.clone())]))?;
            collections.insert(name.clone(), built.collections[name].clone());
        }
        Ok(Self { collections })
    }

    /// Deterministic pre-application check for a staged atomic batch. Like update,
    /// changed must contain every modified document ID. Run this before treating
    /// a command as successful; index materialization errors are replica failures.
    pub fn validate_unique_changes(
        &self,
        previous: &BTreeMap<String, CollectionState>,
        next: &BTreeMap<String, CollectionState>,
        changed: &BTreeMap<String, BTreeSet<String>>,
    ) -> Result<()> {
        for (name, ids) in changed {
            let collection = next
                .get(name)
                .ok_or_else(|| invalid("changed collection missing"))?;
            match previous.get(name).zip(self.collections.get(name)) {
                Some((old, indexes)) if old.definition == collection.definition => indexes
                    .structured
                    .validate_unique_changes(old, collection, ids)?,
                _ => check_unique(collection)?,
            }
        }
        Ok(())
    }

    /// The caller must supply collections from the same immutable generation.
    /// A cursor is consumed by the engine and cannot be evaluated here directly.
    pub fn execute(
        &self,
        collections: &BTreeMap<String, CollectionState>,
        request: &QueryRequest,
        limits: &Limits,
    ) -> Result<QueryResponse> {
        self.execute_with_cancellation(collections, request, limits, &QueryCancellation::default())
    }

    pub fn execute_with_cancellation(
        &self,
        collections: &BTreeMap<String, CollectionState>,
        request: &QueryRequest,
        limits: &Limits,
        cancellation: &QueryCancellation,
    ) -> Result<QueryResponse> {
        cancellation.check()?;
        validate_name(&request.collection)?;
        if request.cursor.is_some() {
            return Err(invalid("cursor continuation requires the tenant engine"));
        }
        if request.limit == 0 || request.limit > limits.max_page_size {
            return Err(invalid("page limit outside allowed range"));
        }
        let collection = collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::NotFound, "collection not found"))?;
        let indexes = self
            .collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "collection index is not ready"))?;
        let structured = &indexes.structured;
        validate_predicate(&request.filter, 0, &mut 0)?;
        structured.validate(&request.filter, request.allow_scan)?;
        if request.sort.len() > 8
            || request.projection.len() > 64
            || request.aggregates.len() > 16
            || request.group_by.len() > 8
        {
            return Err(invalid(
                "query exceeds sort/projection/aggregate/group field limits",
            ));
        }
        let scalar_kind = |path: &str| -> Result<Option<ScalarType>> {
            let kind = structured.field_kind(path, request.allow_scan)?;
            if matches!(
                kind,
                Some(ScalarType::StringArray | ScalarType::NumberArray)
            ) {
                return Err(invalid("sorting and grouping require scalar fields"));
            }
            Ok(kind)
        };
        let sort_kinds = request
            .sort
            .iter()
            .map(|sort| scalar_kind(&sort.field))
            .collect::<Result<Vec<_>>>()?;
        let group_kinds = request
            .group_by
            .iter()
            .map(|field| scalar_kind(field))
            .collect::<Result<Vec<_>>>()?;
        let mut projected = BTreeSet::new();
        for path in &request.projection {
            validate_pointer(path)?;
            if !projected.insert(path) {
                return Err(invalid("duplicate projection field"));
            }
        }
        if request.group_by.iter().collect::<BTreeSet<_>>().len() != request.group_by.len() {
            return Err(invalid("duplicate group field"));
        }
        if !request.group_by.is_empty() && request.aggregates.is_empty() {
            return Err(invalid("group_by requires an aggregation"));
        }
        let mut aliases = BTreeSet::new();
        let mut aggregate_kinds = Vec::new();
        for aggregate in &request.aggregates {
            validate_name(&aggregate.alias)?;
            if !aliases.insert(&aggregate.alias) {
                return Err(invalid("duplicate aggregate alias"));
            }
            let kind = aggregate
                .field
                .as_deref()
                .map(scalar_kind)
                .transpose()?
                .flatten();
            match aggregate.function {
                AggregateFunction::Count => {
                    if aggregate.scale.is_some() {
                        return Err(invalid("count does not accept a scale"));
                    }
                }
                AggregateFunction::Avg => {
                    if !aggregate
                        .scale
                        .is_some_and(|scale| (0..=1000).contains(&scale))
                    {
                        return Err(invalid("avg requires an explicit scale between 0 and 1000"));
                    }
                }
                _ if aggregate.scale.is_some() => return Err(invalid("only avg accepts a scale")),
                _ => {}
            }
            if aggregate.function != AggregateFunction::Count {
                if aggregate.field.is_none() {
                    return Err(invalid("numeric aggregate requires a field"));
                }
                if !matches!(kind, None | Some(ScalarType::Number | ScalarType::Decimal)) {
                    return Err(invalid(
                        "sum/min/max/avg require a numeric or decimal field",
                    ));
                }
            }
            aggregate_kinds.push(kind);
        }

        let scores = request
            .text
            .as_ref()
            .map(|text| {
                indexes
                    .text
                    .as_ref()
                    .ok_or_else(|| {
                        Error::new(ErrorCode::IndexRequired, "collection has no text index")
                    })?
                    .search(text, limits.max_query_candidates, cancellation)
            })
            .transpose()?;
        let text_ids = scores
            .as_ref()
            .map(|scores| {
                let mut ids = IdSet::new();
                for id in scores.keys() {
                    cancellation.check()?;
                    ids.insert(id.clone());
                }
                Ok(ids)
            })
            .transpose()?;
        let universe = text_ids.as_ref().unwrap_or(&structured.ids);
        let candidates = structured.candidates(
            collection,
            &request.filter,
            universe,
            request.allow_scan,
            limits.max_query_candidates,
            cancellation,
        )?;
        let mut selected = Vec::with_capacity(candidates.len());
        for id in candidates {
            cancellation.check()?;
            let document = collection.documents.get(&id).ok_or_else(|| {
                Error::new(ErrorCode::Corruption, "index/document generation mismatch")
            })?;
            let keys = request
                .sort
                .iter()
                .zip(&sort_kinds)
                .map(|(sort, kind)| scalar(document.body.pointer(&sort.field), *kind))
                .collect::<Result<Vec<_>>>()?;
            let score = scores.as_ref().and_then(|scores| scores.get(&id)).copied();
            selected.push((document, keys, score));
        }
        // Candidate IDs are already ordered. Preserve that order without an
        // extra sort when no field ordering or text ranking was requested.
        if !request.sort.is_empty() || scores.is_some() {
            cancellation::sort(
                &mut selected,
                cancellation,
                |(left, left_keys, left_score), (right, right_keys, right_score)| {
                    for ((a, b), order) in left_keys.iter().zip(right_keys).zip(&request.sort) {
                        let ordering = a.cmp(b);
                        let ordering = if order.direction == Direction::Desc {
                            ordering.reverse()
                        } else {
                            ordering
                        };
                        if !ordering.is_eq() {
                            return ordering;
                        }
                    }
                    // Explicit field sorting takes precedence. Search defaults to rank.
                    if request.sort.is_empty() {
                        let rank = right_score
                            .unwrap_or_default()
                            .total_cmp(&left_score.unwrap_or_default());
                        if !rank.is_eq() {
                            return rank;
                        }
                    }
                    left.id.cmp(&right.id)
                },
            )?;
        }

        let mut groups: BTreeMap<Vec<Scalar>, Vec<Accumulator>> = BTreeMap::new();
        if !request.aggregates.is_empty() && request.group_by.is_empty() {
            if limits.max_query_groups == 0 {
                return Err(exhausted("query group budget exceeded"));
            }
            groups.insert(
                Vec::new(),
                vec![Accumulator::default(); request.aggregates.len()],
            );
        }
        for (document, _, _) in &selected {
            cancellation.check()?;
            if request.aggregates.is_empty() {
                break;
            }
            let key = request
                .group_by
                .iter()
                .zip(&group_kinds)
                .map(|(path, kind)| scalar(document.body.pointer(path), *kind))
                .collect::<Result<Vec<_>>>()?;
            if !groups.contains_key(&key) && groups.len() >= limits.max_query_groups {
                return Err(exhausted("query group budget exceeded"));
            }
            let values = groups
                .entry(key)
                .or_insert_with(|| vec![Accumulator::default(); request.aggregates.len()]);
            for ((accumulator, aggregate), kind) in values
                .iter_mut()
                .zip(&request.aggregates)
                .zip(&aggregate_kinds)
            {
                accumulator.add(
                    aggregate,
                    aggregate
                        .field
                        .as_deref()
                        .and_then(|path| document.body.pointer(path)),
                    *kind,
                )?;
            }
        }
        let mut aggregates = Vec::with_capacity(groups.len());
        let mut budget = ResultBudget::new(limits.max_result_bytes);
        for (keys, accumulators) in groups {
            cancellation.check()?;
            let mut group = Map::new();
            for ((path, key), kind) in request.group_by.iter().zip(keys).zip(&group_kinds) {
                if let Some(value) = group_value(key, *kind)? {
                    group.insert(path.clone(), value);
                }
            }
            let mut values = Map::new();
            for (accumulator, aggregate) in accumulators.into_iter().zip(&request.aggregates) {
                values.insert(aggregate.alias.clone(), accumulator.finish(aggregate));
            }
            let entry = serde_json::json!({"group": group, "values": values});
            budget.account(&entry)?;
            aggregates.push(entry);
        }
        let mut rows = Vec::with_capacity(selected.len());
        for (document, _, score) in selected {
            cancellation.check()?;
            let body = if request.projection.is_empty() {
                document.body.clone()
            } else {
                let mut body = Map::new();
                for path in &request.projection {
                    if let Some(value) = document.body.pointer(path) {
                        body.insert(path.clone(), value.clone());
                    }
                }
                Value::Object(body)
            };
            let row = QueryRow {
                id: document.id.clone(),
                version: document.version,
                body,
                score,
            };
            budget.account(&row)?;
            rows.push(row);
        }
        let response = QueryResponse {
            revision: 0,
            rows,
            aggregates,
            cursor: None,
        };
        // Include the envelope and separators in the exact wire-size bound too.
        ResultBudget::new(limits.max_result_bytes).account(&response)?;
        cancellation.check()?;
        Ok(response)
    }
}

#[derive(Clone, Default)]
struct Accumulator {
    count: u64,
    sum: BigDecimal,
    min: Option<BigDecimal>,
    max: Option<BigDecimal>,
}

impl Accumulator {
    fn add(
        &mut self,
        aggregate: &Aggregation,
        value: Option<&Value>,
        kind: Option<ScalarType>,
    ) -> Result<()> {
        if aggregate.function == AggregateFunction::Count {
            if aggregate.field.is_none() || value.is_some_and(|value| !value.is_null()) {
                self.count += 1;
            }
            return Ok(());
        }
        match scalar(value, kind)? {
            Scalar::Missing | Scalar::Null => {}
            Scalar::Number(value) => {
                self.count += 1;
                self.sum += &value;
                if self.min.as_ref().is_none_or(|current| value < *current) {
                    self.min = Some(value.clone());
                }
                if self.max.as_ref().is_none_or(|current| value > *current) {
                    self.max = Some(value);
                }
            }
            _ => return Err(invalid("numeric aggregate encountered a nonnumeric value")),
        }
        Ok(())
    }

    fn finish(self, aggregate: &Aggregation) -> Value {
        match aggregate.function {
            AggregateFunction::Count => Value::from(self.count),
            AggregateFunction::Sum => numeric_value(&self.sum),
            AggregateFunction::Min => self.min.as_ref().map(numeric_value).unwrap_or(Value::Null),
            AggregateFunction::Max => self.max.as_ref().map(numeric_value).unwrap_or(Value::Null),
            AggregateFunction::Avg if self.count == 0 => Value::Null,
            AggregateFunction::Avg => numeric_value(&exact_average(
                &self.sum,
                self.count,
                aggregate.scale.expect("validated average scale"),
            )),
        }
    }
}

/// Integer quotient/remainder avoids the decimal library's default precision and
/// double rounding. This remains exact for large integers and scale=1000.
fn exact_average(sum: &BigDecimal, count: u64, scale: i64) -> BigDecimal {
    let (mut numerator, input_scale) = sum.as_bigint_and_exponent();
    let mut denominator = BigInt::from(count);
    let shift = scale - input_scale;
    if shift >= 0 {
        numerator *= BigInt::from(10).pow(shift as u32);
    } else {
        denominator *= BigInt::from(10).pow((-shift) as u32);
    }
    let mut quotient = &numerator / &denominator;
    let remainder = &numerator % &denominator;
    let doubled = remainder.abs() * 2;
    if doubled > denominator || (doubled == denominator && !(&quotient % 2u8).is_zero()) {
        quotient += if numerator.is_negative() { -1 } else { 1 };
    }
    BigDecimal::new(quotient, scale)
}

fn group_value(key: Scalar, kind: Option<ScalarType>) -> Result<Option<Value>> {
    Ok(match key {
        Scalar::Missing => None,
        Scalar::Null => Some(Value::Null),
        Scalar::Boolean(value) => Some(Value::Bool(value)),
        Scalar::String(value) => Some(Value::String(value)),
        Scalar::Number(value) if kind == Some(ScalarType::Decimal) => Some(numeric_value(&value)),
        Scalar::Number(value) => Some(
            serde_json::from_str(&value.normalized().to_string())
                .map_err(|_| invalid("cannot encode exact group number"))?,
        ),
    })
}

/// Count serialization bytes without allocating a second document/result buffer.
struct ResultBudget {
    bytes: usize,
    max: usize,
}
impl ResultBudget {
    fn new(max: usize) -> Self {
        Self { bytes: 0, max }
    }
    fn account(&mut self, value: &impl serde::Serialize) -> Result<()> {
        serde_json::to_writer(self, value)
            .map_err(|_| exhausted("query result byte budget exceeded"))
    }
}
impl io::Write for ResultBudget {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.bytes = self.bytes.saturating_add(buffer.len());
        if self.bytes > self.max {
            return Err(io::Error::other("result budget exceeded"));
        }
        Ok(buffer.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
