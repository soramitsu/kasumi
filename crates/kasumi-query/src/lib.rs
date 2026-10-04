//! Immutable indexes and bounded, exact queries for one published tenant generation.
//!
//! `execute` returns the complete bounded result, in stable order. The engine owns
//! snapshot pagination and fills in the generation revision. `select` keeps the
//! selected members' nesting; absent values are omitted. Aggregate queries return
//! only `{ "group": {...}, "values": { alias: value } }` entries. Numeric results
//! keep the field's declared type (exact numbers, or decimal strings for decimal
//! fields). `count` is a JSON integer; missing/null inputs are ignored, except
//! `count` of `*` counts rows.

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
    document_parts_clone_bytes, query_response_clone_bytes, vec_bytes,
};
mod page;
use page::PageWriter;
pub use page::{PageBound, copy_page};
mod scalar;
mod search;
mod seek;
mod select;
mod structured;
pub use seek::SeekPage;
mod validation;

pub use validation::{check_unique, unique_index_key, validate_collection, validate_document};

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::Arc;

use bigdecimal::{BigDecimal, Signed, Zero, num_bigint::BigInt};
use kasumi_types::*;
use serde_json::{Map, Value};

use scalar::{Scalar, exhausted, invalid, numeric_value, scalar};
use search::TextSnapshot;
use select::Selection;
use structured::{IdSet, Structured};

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
        let filter = structured::plan(&request.filter)?;
        let indexes = self
            .collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "collection index not ready"))?;
        if request.search.is_some() {
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
        indexes.structured.validate(&filter, false)?;
        let candidates = indexes.structured.candidates(
            source,
            &filter,
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

    /// Every matching row, in order, without a cursor: the complete result must
    /// fit in `max_cursor_bytes`. The source must bind these indexes and
    /// records to one retained view. Cursors belong to the tenant engine.
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
        let bound = PageBound {
            rows: usize::MAX,
            bytes: limits.max_cursor_bytes,
        };
        let (response, ()) = self.execute_page(
            source,
            request,
            limits,
            bound,
            cancellation,
            memory,
            |remaining, _| {
                if remaining.len() != 0 {
                    return Err(exhausted(
                        "query result exceeds max_cursor_bytes; narrow the filter or select fewer fields",
                    ));
                }
                Ok(((), 0))
            },
        )?;
        Ok(response)
    }

    /// Evaluate a query but copy only the rows of its first page, at most
    /// `bound`. `retain` then receives the rows after that page in result
    /// order, typically to keep them for a cursor, and returns what it kept
    /// with the bytes it admitted in `memory` for that. Only the first page's
    /// documents are copied; ordering reads sort keys, never whole bodies.
    #[allow(clippy::too_many_arguments)]
    pub fn execute_page<S: DocumentSource + ?Sized, W: QueryWorkspace, T>(
        &self,
        source: &S,
        request: &QueryRequest,
        limits: &Limits,
        bound: PageBound,
        cancellation: &QueryCancellation,
        memory: &mut QueryMemory<W>,
        retain: impl FnOnce(RemainingRows<'_>, &mut QueryMemory<W>) -> Result<(T, u64)>,
    ) -> ReadResult<(QueryResponse, T), S::Failure> {
        memory.scope(|memory| {
            self.execute_in(source, request, limits, bound, cancellation, memory, retain)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn execute_in<S: DocumentSource + ?Sized, W: QueryWorkspace, T>(
        &self,
        source: &S,
        request: &QueryRequest,
        limits: &Limits,
        bound: PageBound,
        cancellation: &QueryCancellation,
        memory: &mut QueryMemory<W>,
        retain: impl FnOnce(RemainingRows<'_>, &mut QueryMemory<W>) -> Result<(T, u64)>,
    ) -> ReadResult<((QueryResponse, T), u64), S::Failure> {
        cancellation.check()?;
        document_source::check_source(source, self, &request.collection)?;
        let source = &document_source::BoundSource::new(source);
        validate_name(&request.collection)?;
        if request.cursor.is_some() {
            return Err(invalid("cursor continuation requires the tenant engine").into());
        }
        if request.paging == kasumi_types::Paging::Seek {
            return Err(invalid("seek paging requires the seek page evaluator").into());
        }
        check_shape(request, limits)?;
        let indexes = self
            .collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "collection index is not ready"))?;
        let structured = &indexes.structured;
        let filter = structured::plan(&request.filter)?;
        let selection = (!request.select.is_empty())
            .then(|| Selection::new(&request.select, "select"))
            .transpose()?;
        Selection::new(&request.group_by, "group_by")?;
        // Recursive planner/group/search work remains provisional. The concrete
        // metadata, selected rows and output copies below have separate claims.
        memory.reserve(query_workspace_estimate(limits, request)?)?;
        structured.validate(&filter, request.allow_scan)?;
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
            allocation::vec_bytes::<Option<ScalarType>>(request.aggregate.len())?,
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
        let mut aggregate_kinds = Vec::with_capacity(request.aggregate.len());
        for (alias, aggregate) in &request.aggregate {
            validate_name(alias)?;
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
            .search
            .as_ref()
            .map(|search| {
                indexes
                    .text
                    .as_ref()
                    .ok_or_else(|| {
                        Error::new(ErrorCode::IndexRequired, "collection has no text index")
                    })?
                    .search(search, limits.max_query_candidates, cancellation)
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
            &filter,
            universe,
            request.allow_scan,
            limits.max_query_candidates,
            cancellation,
        )?;
        if request.is_aggregate() {
            let (response, retained) = aggregate(
                source,
                request,
                &candidates,
                &group_kinds,
                &aggregate_kinds,
                limits,
                cancellation,
                memory,
            )?;
            let (kept, kept_bytes) = retain(RemainingRows::empty(), memory)?;
            return Ok(((response, kept), allocation::add(retained, kept_bytes)?));
        }

        let mut page = PageWriter::new(selection.as_ref(), bound, candidates.len(), memory)?;
        let iterator_bytes = workspace::imbl_iterator_bytes()?;
        memory.reserve(iterator_bytes)?;
        let (kept, kept_bytes) = if request.sort.is_empty() && scores.is_none() {
            // Candidate IDs are already in result order: copy the first page
            // and pass the rest on without reading them.
            let mut ids = candidates.iter().peekable();
            let mut copied = 0;
            while let Some(id) = ids.peek() {
                cancellation.check()?;
                if page.is_full()
                    || !document_source::with_live(source, id, None, cancellation, |document| {
                        page.push(document, None, memory)
                    })?
                {
                    break;
                }
                ids.next();
                copied += 1;
            }
            let remaining = RemainingRows {
                rows: Remaining::Candidates(ids),
                len: candidates.len() - copied,
            };
            retain(remaining, memory)?
        } else {
            let (ordered, ordered_bytes) = order(
                source,
                request,
                &candidates,
                scores.as_ref(),
                &sort_kinds,
                cancellation,
                memory,
            )?;
            let mut copied = 0;
            for row in &ordered {
                cancellation.check()?;
                if page.is_full()
                    || !document_source::with_live(
                        source,
                        row.id,
                        None,
                        cancellation,
                        |document| page.push(document, row.score, memory),
                    )?
                {
                    break;
                }
                copied += 1;
            }
            let remaining = RemainingRows {
                rows: Remaining::Ordered(ordered[copied..].iter()),
                len: ordered.len() - copied,
            };
            let kept = retain(remaining, memory)?;
            drop(ordered);
            memory.release(ordered_bytes)?;
            kept
        };
        memory.release(iterator_bytes)?;
        drop(candidates);
        let (rows, retained) = page.finish();
        let response = QueryResponse {
            revision: 0,
            rows,
            aggregates: Vec::new(),
            cursor: None,
        };
        cancellation.check()?;
        Ok(((response, kept), allocation::add(retained, kept_bytes)?))
    }
}

/// Result order for sorted and ranked queries. Reads only each candidate's
/// sort keys; bodies are copied later for the rows a page actually returns.
/// Returns the ordered rows and their admitted bytes, which stay live.
fn order<'a, S: DocumentSource + ?Sized, W: QueryWorkspace>(
    source: &S,
    request: &QueryRequest,
    candidates: &'a IdSet,
    scores: Option<&BTreeMap<String, f32>>,
    sort_kinds: &[Option<ScalarType>],
    cancellation: &QueryCancellation,
    memory: &mut QueryMemory<W>,
) -> ReadResult<(Vec<OrderedRow<'a>>, u64), S::Failure> {
    let ordered_bytes = allocation::vec_bytes::<OrderedRow<'_>>(candidates.len())?;
    memory.reserve(ordered_bytes)?;
    let mut ordered = Vec::with_capacity(candidates.len());
    let mut keys_bytes = 0u64;
    let mut has_numeric_sort_key = false;
    for id in candidates {
        cancellation.check()?;
        let score = scores.and_then(|scores| scores.get(id)).copied();
        let keys = if request.sort.is_empty() {
            Vec::new()
        } else {
            document_source::with_live(source, id, None, cancellation, |document| {
                let mut bytes = allocation::vec_bytes::<Scalar>(request.sort.len())?;
                memory.reserve(bytes)?;
                let mut keys = Vec::with_capacity(request.sort.len());
                for (sort, kind) in request.sort.iter().zip(sort_kinds) {
                    let (key, key_bytes) = scalar::query_scalar(
                        allocation::pointer(&document.body, &sort.field),
                        *kind,
                        memory,
                    )?;
                    has_numeric_sort_key |= matches!(key, Scalar::Number(_));
                    bytes = allocation::add(bytes, key_bytes)?;
                    keys.push(key);
                }
                keys_bytes = allocation::add(keys_bytes, bytes)?;
                Ok(keys)
            })?
        };
        ordered.push(OrderedRow { id, score, keys });
    }
    let decimal_scratch = if has_numeric_sort_key {
        scalar::PROVISIONAL_DECIMAL_SCRATCH_BYTES
    } else {
        0
    };
    memory.reserve(decimal_scratch)?;
    cancellation::sort(&mut ordered, cancellation, |left, right| {
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
        left.id.cmp(right.id)
    })?;
    memory.release(decimal_scratch)?;
    // Keys are only needed to sort; the rows keep IDs borrowed from candidates.
    for row in &mut ordered {
        drop(std::mem::take(&mut row.keys));
    }
    memory.release(keys_bytes)?;
    Ok((ordered, ordered_bytes))
}

struct OrderedRow<'a> {
    id: &'a str,
    score: Option<f32>,
    keys: Vec<Scalar>,
}

/// The rows after a page, in result order: each item is a document ID and its
/// search score. Borrowed from the query's candidates, so nothing is copied
/// until the caller decides what to keep.
pub struct RemainingRows<'a> {
    rows: Remaining<'a>,
    len: usize,
}
enum Remaining<'a> {
    Candidates(
        std::iter::Peekable<imbl::ordset::Iter<'a, String, imbl::shared_ptr::DefaultSharedPtr>>,
    ),
    Ordered(std::slice::Iter<'a, OrderedRow<'a>>),
}
impl RemainingRows<'_> {
    fn empty() -> Self {
        Self {
            rows: Remaining::Ordered([].iter()),
            len: 0,
        }
    }
}
impl<'a> Iterator for RemainingRows<'a> {
    type Item = (&'a str, Option<f32>);
    fn next(&mut self) -> Option<Self::Item> {
        let row = match &mut self.rows {
            Remaining::Candidates(ids) => ids.next().map(|id| (id.as_str(), None)),
            Remaining::Ordered(rows) => rows.next().map(|row| (row.id, row.score)),
        };
        self.len = self.len.saturating_sub(usize::from(row.is_some()));
        row
    }
    fn size_hint(&self) -> (usize, Option<usize>) {
        (self.len, Some(self.len))
    }
}
impl ExactSizeIterator for RemainingRows<'_> {}

fn check_shape(request: &QueryRequest, limits: &Limits) -> Result<()> {
    if request.sort.len() > 8
        || request.select.len() > 64
        || request.aggregate.len() > 16
        || request.group_by.len() > 8
    {
        return Err(invalid(
            "query exceeds its sort (8), select (64), aggregate (16) or group_by (8) limit",
        ));
    }
    if request.is_aggregate() {
        if !request.sort.is_empty() || !request.select.is_empty() || request.limit.is_some() {
            return Err(invalid(
                "aggregate queries return groups, not rows; remove sort, select and limit",
            ));
        }
    } else {
        if !request.group_by.is_empty() {
            return Err(invalid("group_by requires an aggregate"));
        }
        let limit = request.page_size();
        if limit == 0 || limit > limits.max_page_size {
            return Err(invalid(format!(
                "limit must be between 1 and {}",
                limits.max_page_size
            )));
        }
    }
    if let Some(search) = &request.search
        && search.distance.is_some()
        && search.mode != TextMode::Fuzzy
    {
        return Err(invalid("distance applies only to fuzzy search"));
    }
    Ok(())
}

/// Aggregate queries return only their groups: no row is copied, and counts
/// of matching documents do not read document bodies at all.
#[allow(clippy::too_many_arguments)]
fn aggregate<S: DocumentSource + ?Sized, W: QueryWorkspace>(
    source: &S,
    request: &QueryRequest,
    candidates: &IdSet,
    group_kinds: &[Option<ScalarType>],
    aggregate_kinds: &[Option<ScalarType>],
    limits: &Limits,
    cancellation: &QueryCancellation,
    memory: &mut QueryMemory<W>,
) -> ReadResult<(QueryResponse, u64), S::Failure> {
    let aggregates: Vec<&Aggregation> = request.aggregate.values().collect();
    let mut groups: BTreeMap<Vec<Scalar>, Vec<Accumulator>> = BTreeMap::new();
    if request.group_by.is_empty() {
        if limits.max_query_groups == 0 {
            return Err(exhausted("query group budget exceeded").into());
        }
        groups.insert(Vec::new(), vec![Accumulator::default(); aggregates.len()]);
    }
    let documents_only = request.group_by.is_empty()
        && aggregates.iter().all(|aggregate| {
            aggregate.function == AggregateFunction::Count && aggregate.field.is_none()
        });
    if documents_only {
        let matched = u64::try_from(candidates.len()).map_err(|_| exhausted("count overflow"))?;
        for accumulator in groups.values_mut().flatten() {
            accumulator.count = matched;
        }
    } else {
        let iterator_bytes = workspace::imbl_iterator_bytes()?;
        memory.reserve(iterator_bytes)?;
        for id in candidates {
            cancellation.check()?;
            document_source::with_live(source, id, None, cancellation, |document| {
                let key = request
                    .group_by
                    .iter()
                    .zip(group_kinds)
                    .map(|(path, kind)| scalar(allocation::pointer(&document.body, path), *kind))
                    .collect::<Result<Vec<_>>>()?;
                if !groups.contains_key(&key) && groups.len() >= limits.max_query_groups {
                    return Err(exhausted("query group budget exceeded"));
                }
                let values = groups
                    .entry(key)
                    .or_insert_with(|| vec![Accumulator::default(); aggregates.len()]);
                for ((accumulator, aggregate), kind) in
                    values.iter_mut().zip(&aggregates).zip(aggregate_kinds)
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
                Ok(())
            })?;
        }
        memory.release(iterator_bytes)?;
    }
    let mut output = Vec::with_capacity(groups.len());
    let mut budget = ResultBudget::new(limits.max_result_bytes);
    for (keys, accumulators) in groups {
        cancellation.check()?;
        let mut group = Map::new();
        for ((path, key), kind) in request.group_by.iter().zip(keys).zip(group_kinds) {
            if let Some(value) = group_value(key, *kind)? {
                Selection::insert(&mut group, path, value)?;
            }
        }
        let mut values = Map::new();
        for (((alias, aggregate), accumulator), kind) in request
            .aggregate
            .iter()
            .zip(accumulators)
            .zip(aggregate_kinds)
        {
            values.insert(alias.clone(), accumulator.finish(aggregate, *kind)?);
        }
        let entry = serde_json::json!({"group": group, "values": values});
        budget.account(&entry)?;
        output.push(entry);
    }
    let retained = if output.is_empty() {
        0
    } else {
        let mut bytes = ResultBudget::new(limits.max_result_bytes);
        bytes.account(&output)?;
        workspace::product(workspace::bytes(bytes.bytes)?, 3)?
    };
    cancellation.check()?;
    Ok((
        QueryResponse {
            revision: 0,
            rows: Vec::new(),
            aggregates: output,
            cursor: None,
        },
        retained,
    ))
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

/// Serializes borrowed values for exact capacity checks before any body clone.
struct BorrowedRow<'a> {
    document: &'a Document,
    selection: Option<&'a Selection>,
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
        match self.selection {
            Some(selection) => row.serialize_field("body", &selection.view(&self.document.body))?,
            None => row.serialize_field("body", &self.document.body)?,
        }
        row.serialize_field("score", &self.score)?;
        row.end()
    }
}
impl BorrowedRow<'_> {
    fn clone_bytes(&self) -> Result<u64> {
        let body = match self.selection {
            Some(selection) => selection.clone_bytes(&self.document.body)?,
            None => allocation::json_clone_bytes(&self.document.body)?,
        };
        allocation::add(allocation::string_clone_bytes(&self.document.id)?, body)
    }

    fn into_owned(self) -> QueryRow {
        QueryRow {
            id: self.document.id.clone(),
            version: self.document.version,
            body: match self.selection {
                Some(selection) => selection.project(&self.document.body),
                None => self.document.body.clone(),
            },
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

    /// Results keep the field's declared type: decimal fields produce decimal
    /// strings and number fields exact JSON numbers. Counts are integers.
    fn finish(self, aggregate: &Aggregation, kind: Option<ScalarType>) -> Result<Value> {
        let value = |number: &BigDecimal| numeric_value(number, kind);
        Ok(match aggregate.function {
            AggregateFunction::Count => Value::from(self.count),
            AggregateFunction::Sum => value(&self.sum)?,
            AggregateFunction::Min => self
                .min
                .as_ref()
                .map(value)
                .transpose()?
                .unwrap_or(Value::Null),
            AggregateFunction::Max => self
                .max
                .as_ref()
                .map(value)
                .transpose()?
                .unwrap_or(Value::Null),
            AggregateFunction::Avg if self.count == 0 => Value::Null,
            AggregateFunction::Avg => value(&exact_average(
                &self.sum,
                self.count,
                aggregate.scale.expect("validated average scale"),
            ))?,
        })
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
        Scalar::Number(value) => Some(numeric_value(&value, kind)?),
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

#[cfg(test)]
mod bench_tests;
