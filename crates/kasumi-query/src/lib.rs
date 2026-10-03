//! Immutable indexes and bounded, exact queries for one published tenant generation.
//!
//! `execute` returns the complete bounded result, in stable order. The engine owns
//! snapshot pagination and fills in the generation revision. Projection produces an
//! object keyed by the requested JSON Pointers; absent values are omitted. Aggregate
//! entries are `{ "group": { pointer: value }, "values": { alias: value } }`.
//! Numbers produced by numeric aggregates are exact decimal strings. `count` is a
//! JSON integer; missing/null inputs are ignored, except fieldless count counts rows.

mod index_input;
pub use index_input::{CollectionRecords, DocumentChanges, DocumentDelta, IndexUpdate};
mod document_source;
pub use document_source::{
    DocumentSource, Header, ReadFailure, ReadResult, Record, RecordKind, SourceIdentity,
};
mod cancellation;
pub use cancellation::QueryCancellation;
mod workspace;
pub use workspace::{QueryMemory, QueryWorkspace, query_workspace_estimate};
mod allocation;
pub use allocation::{
    change_event_clone_bytes, change_feed_page_workspace_bytes, document_clone_bytes,
    document_parts_clone_bytes, query_response_clone_bytes,
};
mod ordered_seek;
mod scalar;
mod search;
mod structured;
pub use ordered_seek::{OrderedSeekPage, ordered_seek_request_sha256};
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
    validator: std::sync::Arc<jsonschema::Validator>,
    schema_sha256: [u8; 32],
    definition_sha256: [u8; 32],
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
    /// Reuse this generation's validator only for the exact compiled schema.
    /// A missing collection or changed schema takes the fully checked compiler
    /// path. Index and text constraints always use the supplied definition.
    pub fn validate_document(&self, definition: &CollectionDefinition, body: &Value) -> Result<()> {
        if let Some(indexes) = self.collections.get(&definition.name)
            && indexes.schema_sha256 == validation::schema_sha256(&definition.schema)?
        {
            return validation::validate_document_with_validator(
                definition,
                body,
                &indexes.validator,
            );
        }
        validate_document(definition, body)
    }

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
    pub fn indexed_candidate_ids<S: DocumentSource + ?Sized, W: QueryWorkspace>(
        &self,
        source: &S,
        request: &QueryRequest,
        limits: &Limits,
        cancellation: &QueryCancellation,
        memory: &mut QueryMemory<W>,
    ) -> ReadResult<Vec<String>, S::Failure> {
        memory.scope(|memory| {
            self.indexed_candidate_ids_in(source, request, limits, cancellation, memory)
        })
    }

    fn indexed_candidate_ids_in<S: DocumentSource + ?Sized, W: QueryWorkspace>(
        &self,
        source: &S,
        request: &QueryRequest,
        limits: &Limits,
        cancellation: &QueryCancellation,
        memory: &mut QueryMemory<W>,
    ) -> ReadResult<(Vec<String>, u64), S::Failure> {
        cancellation.check()?;
        document_source::check_source(source, self, &request.collection)?;
        let source = &document_source::BoundSource::new(source);
        validate_name(&request.collection)?;
        validate_predicate(&request.filter, 0, &mut 0)?;
        let indexes = self
            .collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "collection index not ready"))?;
        if request.text.is_some() {
            return Err(Error::new(
                ErrorCode::IndexRequired,
                "cold text queries require a supported archive text index",
            )
            .into());
        }
        // Recursive planner trees and typed predicate validation retain a
        // provisional allowance. The returned Vec and ID clones are separately
        // admitted below, while the planner result still exists.
        memory.reserve(workspace::product(
            workspace::bytes(limits.max_query_candidates)?,
            128,
        )?)?;
        indexes.structured.validate(&request.filter, false)?;
        let candidates = indexes.structured.candidates(
            source,
            &request.filter,
            &indexes.structured.ids,
            false,
            limits.max_query_candidates,
            cancellation,
        )?;
        let mut retained = allocation::vec_bytes::<String>(candidates.len())?;
        memory.reserve(retained)?;
        let mut ids = Vec::with_capacity(candidates.len());
        let iterator_bytes = workspace::imbl_iterator_bytes()?;
        memory.reserve(iterator_bytes)?;
        for id in &candidates {
            cancellation.check()?;
            let bytes = allocation::string_clone_bytes(id)?;
            memory.reserve(bytes)?;
            ids.push(id.clone());
            retained = allocation::add(retained, bytes)?;
        }
        memory.release(iterator_bytes)?;
        Ok((ids, retained))
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
    pub fn build<R: CollectionRecords>(
        sources: impl IntoIterator<Item = R>,
    ) -> ReadResult<Self, R::Failure> {
        let sources: Vec<_> = sources.into_iter().collect();
        let mut prepared = Vec::with_capacity(sources.len());
        let mut names = BTreeSet::new();
        // Complete every deterministic and private construction pass before
        // allocating/materializing any text index.
        for source in &sources {
            let source = index_input::CheckedRecords::new(source)?;
            let name = source.definition().name.clone();
            if !names.insert(name.clone()) {
                return Err(invalid("duplicate index collection source").into());
            }
            let validator = validation::validate_collection_and_compile(&source)?;
            let indexes = CollectionIndexes {
                validator,
                schema_sha256: validation::schema_sha256(&source.definition().schema)?,
                definition_sha256: index_input::definition_sha256(source.definition())?,
                structured: Structured::build(&source)?,
                text: None,
            };
            prepared.push((name, source, indexes));
        }
        let mut collections = BTreeMap::new();
        for (name, source, mut indexes) in prepared {
            indexes.text = TextSnapshot::build(&source)?.map(Arc::new);
            collections.insert(name, Arc::new(indexes));
        }
        Ok(Self { collections })
    }

    /// Explicit catalog actions. Omitted collections retain their captured
    /// indexes; a changed definition requires Rebuild. No missing-delta fallback
    /// can hide an incomplete mutation journal.
    pub fn update<'a, R, D>(
        &self,
        actions: impl IntoIterator<Item = IndexUpdate<'a, R, D>>,
    ) -> ReadResult<Self, R::Failure>
    where
        R: CollectionRecords,
        D: DocumentChanges<Failure = R::Failure>,
    {
        let actions: Vec<_> = actions.into_iter().collect();
        let mut collections = self.collections.clone();
        let mut names = BTreeSet::new();
        let mut prepared = Vec::new();
        let mut claim_name = |name: &str| -> Result<String> {
            validate_name(name)?;
            let name = name.to_owned();
            if !names.insert(name.clone()) {
                return Err(invalid("duplicate index update collection"));
            }
            Ok(name)
        };
        for action in &actions {
            match action {
                IndexUpdate::Remove(name) => {
                    let name = claim_name(name)?;
                    if collections.remove(&name).is_none() {
                        return Err(invalid("removed index collection absent").into());
                    }
                }
                IndexUpdate::Unchanged(name) => {
                    let name = claim_name(name)?;
                    if !collections.contains_key(&name) {
                        return Err(invalid("unchanged index collection absent").into());
                    }
                }
                IndexUpdate::Rebuild(source) => {
                    let source = index_input::CheckedRecords::new(source)?;
                    let name = claim_name(&source.definition().name)?;
                    let indexes = CollectionIndexes {
                        validator: validation::validate_collection_and_compile(&source)?,
                        schema_sha256: validation::schema_sha256(&source.definition().schema)?,
                        definition_sha256: index_input::definition_sha256(source.definition())?,
                        structured: Structured::build(&source)?,
                        text: None,
                    };
                    prepared.push(PreparedIndexCollection {
                        name,
                        indexes,
                        input: PreparedIndexInput::Rebuild(source),
                    });
                }
                IndexUpdate::Delta(source) => {
                    let source = index_input::CheckedChanges::new(source)?;
                    let name = claim_name(&source.new_definition().name)?;
                    let previous = self.delta_indexes(&source)?;
                    source.visit_changes(|delta| {
                        if let Some(Record::Live(document)) = delta.new {
                            validation::validate_document_with_validator(
                                source.new_definition(),
                                &document.body,
                                &previous.validator,
                            )?;
                        }
                        Ok(())
                    })?;
                    let structured = previous.structured.update(&source)?;
                    let text_changed = match &previous.text {
                        Some(text) => text.fields_changed(&source)?,
                        None => false,
                    };
                    let indexes = CollectionIndexes {
                        validator: previous.validator.clone(),
                        schema_sha256: previous.schema_sha256,
                        definition_sha256: previous.definition_sha256,
                        structured,
                        text: previous.text.clone(),
                    };
                    prepared.push(PreparedIndexCollection {
                        name,
                        indexes,
                        input: PreparedIndexInput::Delta {
                            source,
                            text_changed,
                        },
                    });
                }
            }
        }
        // From the first shared text update onward, any failure is an outer
        // application failure. The caller must fence, never publish a rejection.
        for PreparedIndexCollection {
            name,
            mut indexes,
            input,
        } in prepared
        {
            match input {
                PreparedIndexInput::Rebuild(source) => {
                    indexes.text = TextSnapshot::build(&source)?.map(Arc::new);
                }
                PreparedIndexInput::Delta {
                    source,
                    text_changed,
                } => {
                    if text_changed {
                        indexes.text = Some(Arc::new(
                            indexes
                                .text
                                .as_ref()
                                .expect("changed text has prior reader")
                                .update(&source)?,
                        ));
                    }
                }
            }
            collections.insert(name, Arc::new(indexes));
        }
        Ok(Self { collections })
    }

    fn delta_indexes<D: DocumentChanges + ?Sized>(
        &self,
        source: &D,
    ) -> Result<&Arc<CollectionIndexes>> {
        if !std::ptr::eq(self, source.indexes()) {
            return Err(Error::new(
                ErrorCode::Corruption,
                "index delta prior owner differs",
            ));
        }
        let indexes = self
            .collections
            .get(&source.old_definition().name)
            .ok_or_else(|| {
                Error::new(ErrorCode::Corruption, "index delta prior collection absent")
            })?;
        if indexes.definition_sha256 != index_input::definition_sha256(source.old_definition())? {
            return Err(Error::new(
                ErrorCode::Corruption,
                "index delta prior definition differs",
            ));
        }
        Ok(indexes)
    }

    pub fn validate_unique_changes<D: DocumentChanges>(
        &self,
        sources: impl IntoIterator<Item = D>,
    ) -> ReadResult<(), D::Failure> {
        for source in sources {
            let source = index_input::CheckedChanges::new(&source)?;
            self.delta_indexes(&source)?
                .structured
                .validate_unique_changes(&source)?;
        }
        Ok(())
    }

    /// The source must bind these indexes and records to one retained view.
    /// A cursor is consumed by the engine and cannot be evaluated here directly.
    pub fn execute<S: DocumentSource + ?Sized, W: QueryWorkspace>(
        &self,
        source: &S,
        request: &QueryRequest,
        limits: &Limits,
        memory: &mut QueryMemory<W>,
    ) -> ReadResult<QueryResponse, S::Failure> {
        self.execute_with_cancellation(
            source,
            request,
            limits,
            &QueryCancellation::default(),
            memory,
        )
    }

    pub fn execute_with_cancellation<S: DocumentSource + ?Sized, W: QueryWorkspace>(
        &self,
        source: &S,
        request: &QueryRequest,
        limits: &Limits,
        cancellation: &QueryCancellation,
        memory: &mut QueryMemory<W>,
    ) -> ReadResult<QueryResponse, S::Failure> {
        memory.scope(|memory| self.execute_in(source, request, limits, cancellation, memory))
    }

    fn execute_in<S: DocumentSource + ?Sized, W: QueryWorkspace>(
        &self,
        source: &S,
        request: &QueryRequest,
        limits: &Limits,
        cancellation: &QueryCancellation,
        memory: &mut QueryMemory<W>,
    ) -> ReadResult<(QueryResponse, u64), S::Failure> {
        cancellation.check()?;
        document_source::check_source(source, self, &request.collection)?;
        let source = &document_source::BoundSource::new(source);
        validate_name(&request.collection)?;
        if request.cursor.is_some() {
            return Err(invalid("cursor continuation requires the tenant engine").into());
        }
        if request.limit == 0 || request.limit > limits.max_page_size {
            return Err(invalid("page limit outside allowed range").into());
        }
        let indexes = self
            .collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "collection index is not ready"))?;
        let structured = &indexes.structured;
        validate_predicate(&request.filter, 0, &mut 0)?;
        if request.sort.len() > 8
            || request.projection.len() > 64
            || request.aggregates.len() > 16
            || request.group_by.len() > 8
        {
            return Err(
                invalid("query exceeds sort/projection/aggregate/group field limits").into(),
            );
        }
        // Recursive planner/group/search work remains provisional. The concrete
        // metadata, selected rows and output copies below have separate claims.
        memory.reserve(query_workspace_estimate(limits, request)?)?;
        structured.validate(&request.filter, request.allow_scan)?;
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
        memory.reserve(allocation::add(
            allocation::add(
                allocation::vec_bytes::<Option<ScalarType>>(request.sort.len())?,
                allocation::vec_bytes::<Option<ScalarType>>(request.group_by.len())?,
            )?,
            allocation::vec_bytes::<Option<ScalarType>>(request.aggregates.len())?,
        )?)?;
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
        for (index, path) in request.projection.iter().enumerate() {
            validate_pointer(path)?;
            if request.projection[..index].contains(path) {
                return Err(invalid("duplicate projection field").into());
            }
        }
        if request
            .group_by
            .iter()
            .enumerate()
            .any(|(index, path)| request.group_by[..index].contains(path))
        {
            return Err(invalid("duplicate group field").into());
        }
        if !request.group_by.is_empty() && request.aggregates.is_empty() {
            return Err(invalid("group_by requires an aggregation").into());
        }
        let mut aggregate_kinds = Vec::with_capacity(request.aggregates.len());
        for (index, aggregate) in request.aggregates.iter().enumerate() {
            validate_name(&aggregate.alias)?;
            if request.aggregates[..index]
                .iter()
                .any(|previous| previous.alias == aggregate.alias)
            {
                return Err(invalid("duplicate aggregate alias").into());
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
                        return Err(invalid("count does not accept a scale").into());
                    }
                }
                AggregateFunction::Avg => {
                    if !aggregate
                        .scale
                        .is_some_and(|scale| (0..=1000).contains(&scale))
                    {
                        return Err(
                            invalid("avg requires an explicit scale between 0 and 1000").into()
                        );
                    }
                }
                _ if aggregate.scale.is_some() => {
                    return Err(invalid("only avg accepts a scale").into());
                }
                _ => {}
            }
            if aggregate.function != AggregateFunction::Count {
                if aggregate.field.is_none() {
                    return Err(invalid("numeric aggregate requires a field").into());
                }
                if !matches!(kind, None | Some(ScalarType::Number | ScalarType::Decimal)) {
                    return Err(
                        invalid("sum/min/max/avg require a numeric or decimal field").into(),
                    );
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
            .map(|scores| -> Result<IdSet> {
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
            source,
            &request.filter,
            universe,
            request.allow_scan,
            limits.max_query_candidates,
            cancellation,
        )?;
        // Candidate metadata owns no document body or cache guard. Each loan
        // ends before another read, and output reloads the exact selected version.
        let selected_bytes = allocation::vec_bytes::<SelectedRow>(candidates.len())?;
        memory.reserve(selected_bytes)?;
        let mut selected = Vec::with_capacity(candidates.len());
        let mut groups: BTreeMap<Vec<Scalar>, Vec<Accumulator>> = BTreeMap::new();
        if !request.aggregates.is_empty() && request.group_by.is_empty() {
            if limits.max_query_groups == 0 {
                return Err(exhausted("query group budget exceeded").into());
            }
            groups.insert(
                Vec::new(),
                vec![Accumulator::default(); request.aggregates.len()],
            );
        }
        let iterator_bytes = workspace::imbl_iterator_bytes()?;
        memory.reserve(iterator_bytes)?;
        let mut has_numeric_sort_key = false;
        for candidate in &candidates {
            cancellation.check()?;
            let id_bytes = allocation::string_clone_bytes(candidate)?;
            memory.reserve(id_bytes)?;
            let id = candidate.clone();
            let (version, keys, keys_bytes) =
                document_source::with_live(source, &id, None, cancellation, |document| {
                    let mut keys_bytes = allocation::vec_bytes::<Scalar>(request.sort.len())?;
                    memory.reserve(keys_bytes)?;
                    let mut keys = Vec::with_capacity(request.sort.len());
                    for (sort, kind) in request.sort.iter().zip(&sort_kinds) {
                        let (key, bytes) = scalar::query_scalar(
                            allocation::pointer(&document.body, &sort.field),
                            *kind,
                            memory,
                        )?;
                        has_numeric_sort_key |= matches!(key, Scalar::Number(_));
                        keys_bytes = allocation::add(keys_bytes, bytes)?;
                        keys.push(key);
                    }
                    if !request.aggregates.is_empty() {
                        let key = request
                            .group_by
                            .iter()
                            .zip(&group_kinds)
                            .map(|(path, kind)| {
                                scalar(allocation::pointer(&document.body, path), *kind)
                            })
                            .collect::<Result<Vec<_>>>()?;
                        if !groups.contains_key(&key) && groups.len() >= limits.max_query_groups {
                            return Err(exhausted("query group budget exceeded"));
                        }
                        let values = groups.entry(key).or_insert_with(|| {
                            vec![Accumulator::default(); request.aggregates.len()]
                        });
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
                                    .and_then(|path| allocation::pointer(&document.body, path)),
                                *kind,
                            )?;
                        }
                    }
                    Ok((document.version, keys, keys_bytes))
                })?;
            let score = scores.as_ref().and_then(|scores| scores.get(&id)).copied();
            selected.push(SelectedRow {
                id,
                version,
                keys,
                score,
                id_bytes,
                keys_bytes,
            });
        }
        // The borrowed iterator drops at the end of the loop; its candidate
        // root can now go too. Never consume a shared imbl root to obtain IDs.
        memory.release(iterator_bytes)?;
        drop(candidates);
        // Candidate IDs are already ordered. Preserve that order without an
        // extra sort when no field ordering or text ranking was requested.
        if !request.sort.is_empty() || scores.is_some() {
            let decimal_scratch = if has_numeric_sort_key {
                scalar::PROVISIONAL_DECIMAL_SCRATCH_BYTES
            } else {
                0
            };
            memory.reserve(decimal_scratch)?;
            cancellation::sort(&mut selected, cancellation, |left, right| {
                for ((a, b), order) in left.keys.iter().zip(&right.keys).zip(&request.sort) {
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
                    let rank = right
                        .score
                        .unwrap_or_default()
                        .total_cmp(&left.score.unwrap_or_default());
                    if !rank.is_eq() {
                        return rank;
                    }
                }
                left.id.cmp(&right.id)
            })?;
            memory.release(decimal_scratch)?;
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
        let mut retained_rows = allocation::vec_bytes::<QueryRow>(selected.len())?;
        memory.reserve(retained_rows)?;
        let mut rows = Vec::with_capacity(selected.len());
        for SelectedRow {
            id,
            version,
            keys,
            score,
            id_bytes,
            keys_bytes,
        } in selected
        {
            drop(keys);
            memory.release(keys_bytes)?;
            let (row, row_bytes) =
                document_source::with_live(source, &id, Some(version), cancellation, |document| {
                    let borrowed = BorrowedRow {
                        document,
                        projection: &request.projection,
                        score,
                    };
                    budget.account(&borrowed)?;
                    let bytes = borrowed.clone_bytes()?;
                    memory.reserve(bytes)?;
                    Ok((borrowed.into_owned(), bytes))
                })?;
            rows.push(row);
            retained_rows = allocation::add(retained_rows, row_bytes)?;
            drop(id);
            memory.release(id_bytes)?;
        }
        // Vec::IntoIter retains its whole backing allocation until the loop
        // ends, even as individual selected IDs/keys are destroyed above.
        memory.release(selected_bytes)?;
        let retained_aggregates = if aggregates.is_empty() {
            0
        } else {
            let mut aggregate_output = ResultBudget::new(limits.max_result_bytes);
            aggregate_output.account(&aggregates)?;
            workspace::product(workspace::bytes(aggregate_output.bytes)?, 3)?
        };
        let response = QueryResponse {
            revision: 0,
            rows,
            aggregates,
            cursor: None,
        };
        // Include the envelope and separators in the exact wire-size bound too.
        let mut output = ResultBudget::new(limits.max_result_bytes);
        output.account(&response)?;
        cancellation.check()?;
        // Row clones retain their admitted backing, including container slack.
        // Aggregate formatting/group output still use the separate provisional
        // allowance; physical peak custody remains unchanged on all outcomes.
        let retained = allocation::add(retained_rows, retained_aggregates)?;
        Ok((response, retained))
    }
}

struct PreparedIndexCollection<'a, R: CollectionRecords, D: DocumentChanges> {
    name: String,
    indexes: CollectionIndexes,
    input: PreparedIndexInput<'a, R, D>,
}
enum PreparedIndexInput<'a, R: CollectionRecords, D: DocumentChanges> {
    Rebuild(index_input::CheckedRecords<'a, R>),
    Delta {
        source: index_input::CheckedChanges<'a, D>,
        text_changed: bool,
    },
}

struct SelectedRow {
    id: String,
    version: u64,
    keys: Vec<Scalar>,
    score: Option<f32>,
    id_bytes: u64,
    keys_bytes: u64,
}

/// Serializes borrowed values for exact capacity checks before any body clone.
struct BorrowedRow<'a> {
    document: &'a Document,
    projection: &'a [String],
    score: Option<f32>,
}
impl serde::Serialize for BorrowedRow<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut row = serializer.serialize_struct("QueryRow", 4)?;
        row.serialize_field("id", &self.document.id)?;
        row.serialize_field("version", &self.document.version)?;
        row.serialize_field(
            "body",
            &BorrowedProjection {
                body: &self.document.body,
                paths: self.projection,
            },
        )?;
        row.serialize_field("score", &self.score)?;
        row.end()
    }
}
struct BorrowedProjection<'a> {
    body: &'a Value,
    paths: &'a [String],
}
impl serde::Serialize for BorrowedProjection<'_> {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        if self.paths.is_empty() {
            return serde::Serialize::serialize(self.body, serializer);
        }
        let mut map = serializer.serialize_map(None)?;
        for path in self.paths {
            if let Some(value) = allocation::pointer(self.body, path) {
                map.serialize_entry(path, value)?;
            }
        }
        map.end()
    }
}
impl BorrowedRow<'_> {
    fn clone_bytes(&self) -> Result<u64> {
        let mut bytes = allocation::string_clone_bytes(&self.document.id)?;
        if self.projection.is_empty() {
            return allocation::add(bytes, allocation::json_clone_bytes(&self.document.body)?);
        }
        for path in self.projection {
            if let Some(value) = allocation::pointer(&self.document.body, path) {
                // Each pointer is a distinct output key. Overlapping subtrees
                // are copied independently and must each retain a full claim.
                bytes = allocation::add(bytes, allocation::object_entry_bytes()?)?;
                bytes = allocation::add(bytes, allocation::string_clone_bytes(path)?)?;
                bytes = allocation::add(bytes, allocation::json_clone_bytes(value)?)?;
            }
        }
        Ok(bytes)
    }

    fn into_owned(self) -> QueryRow {
        let body = if self.projection.is_empty() {
            self.document.body.clone()
        } else {
            // Avoid Map::from_iter's temporary collector/sort storage. The
            // preflight counts each inserted node, key and cloned subtree.
            let mut projected = Map::new();
            for path in self.projection {
                if let Some(value) = allocation::pointer(&self.document.body, path) {
                    projected.insert(path.clone(), value.clone());
                }
            }
            Value::Object(projected)
        };
        QueryRow {
            id: self.document.id.clone(),
            version: self.document.version,
            body,
            score: self.score,
        }
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
        Scalar::UpperBound => return Err(invalid("internal bound cannot be a stored value")),
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

#[cfg(test)]
mod document_source_tests;
#[cfg(test)]
mod source_test_utils;

#[cfg(test)]
mod index_input_tests;
