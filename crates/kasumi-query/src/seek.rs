//! Seek paging: a query's rows in unique-index order, one page at a time, read
//! straight from the index. There is no candidate set, sort or retained state,
//! so each page costs the same however large the whole result is.
use crate::page::{PageBound, PageWriter};
use crate::scalar::{Scalar, invalid, query_scalar};
use crate::select::Selection;
use crate::structured::{Node, Test, UniqueIndex, plan};
use crate::{
    DocumentSource, QueryCancellation, QueryIndexes, QueryMemory, QueryWorkspace, ReadResult,
    allocation, document_source,
};
use kasumi_types::*;
use serde_json::Value;
use std::collections::BTreeMap;
use std::ops::Bound;

/// One page of a seek-paged query.
#[derive(Debug)]
pub struct SeekPage {
    pub rows: Vec<QueryRow>,
    /// The last row's index key when more rows follow: pass it back as `after`
    /// to read the next page.
    pub last_key: Option<Vec<Value>>,
}

const SHAPE: &str = "seek paging walks a unique index: the filter may only fix its leading \
    fields with equality and bound the next field with one range, and sort lists the \
    remaining fields in one direction";

impl QueryIndexes {
    /// One page of `request` in the order of the unique index that its filter
    /// and sort describe, after `after` (a previous page's `last_key`). The
    /// page's row copies stay admitted in `memory`. `cursor_bytes` measures
    /// the continuation token for a candidate last key, excluding JSON quotes.
    #[allow(clippy::too_many_arguments)]
    pub fn seek_page<S: DocumentSource + ?Sized, W: QueryWorkspace>(
        &self,
        source: &S,
        request: &QueryRequest,
        after: Option<&[Value]>,
        limits: &Limits,
        cursor_bytes: &impl Fn(&[Value]) -> Result<usize>,
        cancellation: &QueryCancellation,
        memory: &mut QueryMemory<W>,
    ) -> ReadResult<SeekPage, S::Failure> {
        memory.scope(|memory| {
            self.seek_in(
                source,
                request,
                after,
                limits,
                cursor_bytes,
                cancellation,
                memory,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn seek_in<S: DocumentSource + ?Sized, W: QueryWorkspace>(
        &self,
        source: &S,
        request: &QueryRequest,
        after: Option<&[Value]>,
        limits: &Limits,
        cursor_bytes: &impl Fn(&[Value]) -> Result<usize>,
        cancellation: &QueryCancellation,
        memory: &mut QueryMemory<W>,
    ) -> ReadResult<(SeekPage, u64), S::Failure> {
        cancellation.check()?;
        document_source::check_source(source, self, &request.collection)?;
        let source = &document_source::BoundSource::new(source);
        validate_name(&request.collection)?;
        crate::check_shape(request, limits)?;
        if request.search.is_some() || request.is_aggregate() {
            return Err(invalid(
                "seek paging returns rows in index order; it cannot rank a search or aggregate",
            )
            .into());
        }
        let indexes = self
            .collections
            .get(&request.collection)
            .ok_or_else(|| Error::new(ErrorCode::Unavailable, "collection index is not ready"))?;
        let filter = plan(&request.filter)?;
        let mut constraints = BTreeMap::new();
        collect(&filter, &mut constraints)?;
        let (index, mut range) = indexes
            .structured
            .unique
            .values()
            .find_map(|index| {
                bounds(index, &constraints, &request.sort, memory)
                    .transpose()
                    .map(|range| range.map(|range| (index, range)))
            })
            .transpose()?
            .ok_or_else(|| Error::new(ErrorCode::IndexRequired, SHAPE))?;
        let descending = request
            .sort
            .first()
            .is_some_and(|sort| sort.direction == Direction::Desc);
        if let Some(after) = after {
            let key = complete_key(after, &index.fields, memory)?;
            if !key.starts_with(&range.prefix) {
                return Err(invalid("seek cursor does not belong to this query").into());
            }
            if descending {
                range.upper = stricter(range.upper, Bound::Excluded(key), true);
            } else {
                range.lower = stricter(range.lower, Bound::Excluded(key), false);
            }
        }
        let selection = (!request.select.is_empty())
            .then(|| Selection::new(&request.select, "select"))
            .transpose()?;
        let bound = PageBound {
            rows: request.page_size(),
            bytes: limits.max_result_bytes,
        };
        let mut page = PageWriter::new(selection.as_ref(), bound, bound.rows, memory)?;
        let mut last_key = None;
        let mut last_key_bytes = 0;
        let mut resume_rows = 0;
        let mut more = false;
        if !empty(&range.lower, &range.upper) {
            let iterator_bytes = crate::workspace::imbl_iterator_bytes()?;
            memory.reserve(iterator_bytes)?;
            {
                let mut range_entries = index
                    .entries
                    .range::<_, Vec<Scalar>>((range.lower.as_ref(), range.upper.as_ref()));
                let mut entries = std::iter::from_fn(|| {
                    if descending {
                        range_entries.next_back()
                    } else {
                        range_entries.next()
                    }
                })
                .peekable();
                while let Some((key, id)) = entries.next() {
                    cancellation.check()?;
                    if page.is_full() {
                        more = true;
                        break;
                    }
                    let has_more = entries.peek().is_some();
                    let copied =
                        document_source::with_live(source, id, None, cancellation, |row| {
                            // Assemble with a terminal null cursor first. A large
                            // key must not reject a page that can finish the walk.
                            if !page.push_with_cursor_bytes(row, None, 2, memory)? {
                                return Ok(None);
                            }
                            raw_key(row, &index.fields, key, memory).map(Some)
                        })?;
                    let Some((raw, bytes)) = copied else {
                        more = true;
                        break;
                    };
                    if has_more && page.fits_cursor_bytes(cursor_bytes(&raw)?) {
                        last_key = Some(raw);
                        memory.release(last_key_bytes)?;
                        last_key_bytes = bytes;
                        resume_rows = page.row_count();
                    } else {
                        drop(raw);
                        memory.release(bytes)?;
                    }
                }
            }
            memory.release(iterator_bytes)?;
        }
        if more {
            if last_key.is_none() {
                return Err(crate::exhausted(
                    "one seek row and its cursor exceed the page byte limit; select fewer fields or increase max_result_bytes",
                ).into());
            }
            // Later rows may fit only without a cursor. Resume from the latest
            // prefix whose actual token fits, without re-reading any documents.
            page.truncate(resume_rows, memory)?;
        }
        let (rows, mut retained) = page.finish();
        let last_key = if more { last_key } else { None };
        if last_key.is_some() {
            retained = allocation::add(retained, last_key_bytes)?;
        }
        cancellation.check()?;
        Ok((SeekPage { rows, last_key }, retained))
    }
}

/// Equality and range constraints by field. Seek paging accepts nothing else.
#[derive(Default)]
struct Constraint<'a> {
    eq: Option<&'a Value>,
    range: Option<(Bound<&'a Value>, Bound<&'a Value>)>,
}

fn collect<'a>(node: &Node<'a>, out: &mut BTreeMap<&'a str, Constraint<'a>>) -> Result<()> {
    match node {
        Node::All => Ok(()),
        Node::And(children) => children.iter().try_for_each(|child| collect(child, out)),
        Node::Leaf { path, test } => {
            let constraint = out.entry(*path).or_default();
            match test {
                Test::Eq(value) if constraint.eq.is_none() && constraint.range.is_none() => {
                    constraint.eq = Some(*value);
                }
                Test::Range { lower, upper }
                    if constraint.eq.is_none() && constraint.range.is_none() =>
                {
                    constraint.range = Some((*lower, *upper));
                }
                _ => return Err(invalid(SHAPE)),
            }
            Ok(())
        }
        Node::Or(_) | Node::Not(_) => Err(invalid(SHAPE)),
    }
}

/// The key range of `index` that the constraints and sort describe, if they
/// describe this index.
struct KeyRange {
    /// Values of the leading fields fixed by equality.
    prefix: Vec<Scalar>,
    lower: Bound<Vec<Scalar>>,
    upper: Bound<Vec<Scalar>>,
}

fn bounds<W: QueryWorkspace>(
    index: &UniqueIndex,
    constraints: &BTreeMap<&str, Constraint<'_>>,
    sort: &[Sort],
    memory: &mut QueryMemory<W>,
) -> Result<Option<KeyRange>> {
    let fields = &index.fields;
    if fields.iter().any(|field| {
        matches!(
            field.kind,
            ScalarType::StringArray | ScalarType::NumberArray
        )
    }) {
        return Ok(None);
    }
    // Equalities fix the leading fields; at most the next one has a range.
    let fixed = fields
        .iter()
        .take_while(|field| {
            constraints
                .get(field.path.as_str())
                .is_some_and(|c| c.eq.is_some())
        })
        .count();
    let ranged = fields
        .get(fixed)
        .and_then(|field| constraints.get(field.path.as_str()))
        .and_then(|constraint| constraint.range);
    if constraints.len() != fixed + usize::from(ranged.is_some()) {
        return Ok(None);
    }
    // The sort lists the fields after some fixed ones, through the last field.
    let Some(first) = sort.first() else {
        return Ok(None);
    };
    let start = fields.len().saturating_sub(sort.len());
    if sort.len() > fields.len()
        || start > fixed
        || sort
            .iter()
            .zip(&fields[start..])
            .any(|(sort, field)| sort.field != field.path || sort.direction != first.direction)
    {
        return Ok(None);
    }
    memory.reserve(allocation::vec_bytes::<Scalar>(fixed)?)?;
    let prefix = fields[..fixed]
        .iter()
        .map(|field| {
            let value = constraints[field.path.as_str()]
                .eq
                .expect("fixed by equality");
            key_scalar(value, field, memory)
        })
        .collect::<Result<Vec<_>>>()?;
    let mut lower = Bound::Included(extend_key(&prefix, [], memory)?);
    let mut upper = Bound::Excluded(extend_key(&prefix, [Scalar::UpperBound], memory)?);
    if let Some((low, high)) = ranged {
        let field = &fields[fixed];
        let value = |value: &Value, memory: &mut QueryMemory<W>| -> Result<Scalar> {
            let key = key_scalar(value, field, memory)?;
            if key == Scalar::Null {
                return Err(invalid("ordered comparison requires a non-null scalar"));
            }
            Ok(key)
        };
        // Absent and null values never satisfy a range.
        lower = match low {
            Bound::Included(v) => {
                Bound::Included(extend_key(&prefix, [value(v, memory)?], memory)?)
            }
            Bound::Excluded(v) => Bound::Excluded(extend_key(
                &prefix,
                [value(v, memory)?, Scalar::UpperBound],
                memory,
            )?),
            Bound::Unbounded => Bound::Excluded(extend_key(
                &prefix,
                [Scalar::Null, Scalar::UpperBound],
                memory,
            )?),
        };
        upper = match high {
            Bound::Included(v) => Bound::Included(extend_key(
                &prefix,
                [value(v, memory)?, Scalar::UpperBound],
                memory,
            )?),
            Bound::Excluded(v) => {
                Bound::Excluded(extend_key(&prefix, [value(v, memory)?], memory)?)
            }
            Bound::Unbounded => upper,
        };
    }
    Ok(Some(KeyRange {
        prefix,
        lower,
        upper,
    }))
}

/// Copy a prefix into a bound only after admitting the vector and its keys.
fn extend_key<W: QueryWorkspace, const N: usize>(
    prefix: &[Scalar],
    suffix: [Scalar; N],
    memory: &mut QueryMemory<W>,
) -> Result<Vec<Scalar>> {
    let mut bytes = allocation::vec_bytes::<Scalar>(prefix.len() + N)?;
    for scalar in prefix {
        bytes = allocation::add(
            bytes,
            match scalar {
                Scalar::String(value) => allocation::string_clone_bytes(value)?,
                // Decimal ownership remains provisional, as in query_scalar.
                Scalar::Number(_) => crate::scalar::PROVISIONAL_DECIMAL_SCRATCH_BYTES,
                _ => 0,
            },
        )?;
    }
    memory.reserve(bytes)?;
    let mut key = Vec::with_capacity(prefix.len() + N);
    key.extend_from_slice(prefix);
    key.extend(suffix);
    Ok(key)
}

fn key_scalar<W: QueryWorkspace>(
    value: &Value,
    field: &IndexField,
    memory: &mut QueryMemory<W>,
) -> Result<Scalar> {
    // Indexed strings can be as large as a document. Continuations must accept
    // every key that a successful first page can emit.
    query_scalar(Some(value), Some(field.kind), memory).map(|(key, _)| key)
}

/// A cursor's key: one value per index field.
fn complete_key<W: QueryWorkspace>(
    values: &[Value],
    fields: &[IndexField],
    memory: &mut QueryMemory<W>,
) -> Result<Vec<Scalar>> {
    if values.len() != fields.len() {
        return Err(invalid("seek cursor does not belong to this query"));
    }
    memory.reserve(allocation::vec_bytes::<Scalar>(values.len())?)?;
    values
        .iter()
        .zip(fields)
        .map(|(value, field)| key_scalar(value, field, memory))
        .collect()
}

/// The stricter of two lower (or, with `upper`, two upper) bounds.
fn stricter(a: Bound<Vec<Scalar>>, b: Bound<Vec<Scalar>>, upper: bool) -> Bound<Vec<Scalar>> {
    let (Bound::Included(x) | Bound::Excluded(x)) = &a else {
        return b;
    };
    let (Bound::Included(y) | Bound::Excluded(y)) = &b else {
        return a;
    };
    match x.cmp(y) {
        std::cmp::Ordering::Equal if matches!(a, Bound::Excluded(_)) => a,
        std::cmp::Ordering::Equal => b,
        std::cmp::Ordering::Less if upper => a,
        std::cmp::Ordering::Less => b,
        std::cmp::Ordering::Greater if upper => b,
        std::cmp::Ordering::Greater => a,
    }
}

fn empty(lower: &Bound<Vec<Scalar>>, upper: &Bound<Vec<Scalar>>) -> bool {
    match (lower, upper) {
        (Bound::Included(lower), Bound::Included(upper)) => lower > upper,
        (
            Bound::Included(lower) | Bound::Excluded(lower),
            Bound::Included(upper) | Bound::Excluded(upper),
        ) => lower >= upper,
        _ => false,
    }
}

/// The row's index values as stored, checked against the index entry, with
/// the bytes admitted for the copy.
fn raw_key<W: QueryWorkspace>(
    document: &Document,
    fields: &[IndexField],
    expected: &[Scalar],
    memory: &mut QueryMemory<W>,
) -> Result<(Vec<Value>, u64)> {
    let value = |field: &IndexField| {
        allocation::pointer(&document.body, &field.path).ok_or_else(|| {
            Error::new(
                ErrorCode::Corruption,
                "seek index field absent from document",
            )
        })
    };
    let mut bytes = allocation::vec_bytes::<Value>(fields.len())?;
    for (field, expected) in fields.iter().zip(expected) {
        let value = value(field)?;
        let matches = memory.scope::<_, Error>(|memory| {
            let (actual, _) = query_scalar(Some(value), Some(field.kind), memory)?;
            Ok((actual == *expected, 0))
        })?;
        if !matches {
            return Err(Error::new(
                ErrorCode::Corruption,
                "seek index entry differs from document",
            ));
        }
        bytes = allocation::add(bytes, allocation::json_clone_bytes(value)?)?;
    }
    memory.reserve(bytes)?;
    let values = fields
        .iter()
        .map(|field| value(field).cloned())
        .collect::<Result<_>>()?;
    Ok((values, bytes))
}

#[cfg(test)]
#[path = "seek_tests.rs"]
mod tests;
