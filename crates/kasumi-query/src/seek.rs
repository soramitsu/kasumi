//! Seek paging: a query's rows in unique-index order, one page at a time, read
//! straight from the index. There is no candidate set, sort or retained state,
//! so each page costs the same however large the whole result is.
#[path = "seek_ranked.rs"]
mod ranked;
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

type TupleMap = imbl::OrdMap<Vec<Scalar>, String>;

#[derive(Debug)]
pub(crate) struct Projection {
    // The worker exclusively owns this projection. Keep the original captured
    // fallback until its actual planned native read has returned successfully.
    fallback: std::sync::Mutex<Option<Vec<TupleMap>>>,
    // A registered Engine worker executes exactly one page. Move its wide
    // fallback into that page only after the request has resolved its range.
    worker_wide: Option<std::sync::Mutex<Option<Vec<TupleMap>>>>,
    wide_indexes: Vec<bool>,
}

impl QueryIndexes {
    /// Retain only the fallback rows needed by a registered seek worker after
    /// its first successful physical tuple window for this collection.
    /// Its ordinary tuples are owned by that captured directory. Single-field
    /// postings and oversized tuples keep their canonical fallback.
    #[doc(hidden)]
    pub fn published_seek_projection(&self, collection: &str) -> Option<Self> {
        self.seek_projection_for(collection, false)
    }

    /// A registered worker serves exactly one request, including its decoded
    /// continuation. Oversized keys outside its page can be released.
    #[doc(hidden)]
    pub fn published_seek_worker_projection(&self, collection: &str) -> Option<Self> {
        self.seek_projection_for(collection, true)
    }

    fn seek_projection_for(&self, collection: &str, worker: bool) -> Option<Self> {
        if self.seek_projection.is_some() {
            return None;
        }
        let source = self.collections.get(collection)?;
        let mut selected = crate::CollectionIndexes::clone(source);
        selected.text = None;
        selected.structured.ids.clear();
        selected.structured.fields.retain(|path, _| {
            selected
                .structured
                .unique
                .values()
                .any(|index| index.fields.len() == 1 && index.fields[0].path == *path)
        });
        for field in selected.structured.fields.values_mut() {
            field.present.clear();
        }
        let fallback = selected
            .structured
            .unique
            .values_mut()
            .filter(|index| index.fields.len() > 1)
            .map(|index| std::mem::take(index.entries.as_mut().expect("compound tuple root")))
            .collect();
        let wide_indexes = selected
            .structured
            .unique
            .values()
            .filter(|index| index.fields.len() > 1)
            .map(|index| !index.overflow.is_empty())
            .collect();
        let worker_wide = worker.then(|| {
            let roots = selected
                .structured
                .unique
                .values_mut()
                .filter(|index| index.fields.len() > 1)
                .map(|index| std::mem::take(&mut index.overflow))
                .collect();
            std::sync::Mutex::new(Some(roots))
        });
        Some(Self {
            collections: BTreeMap::from([(collection.to_owned(), std::sync::Arc::new(selected))]),
            text_residency: crate::TextResidency::Directory,
            seek_projection: Some(Projection {
                fallback: std::sync::Mutex::new(Some(fallback)),
                worker_wide,
                wide_indexes,
            }),
            structured_layout: std::sync::OnceLock::from(self.structured_layout_sha256()),
        })
    }

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
            let worker_wide = self
                .seek_projection
                .as_ref()
                .and_then(|r| r.worker_wide.as_ref());
            let iterator_bytes = if index.overflow.is_empty() && worker_wide.is_none() {
                iterator_bytes
            } else {
                allocation::add(iterator_bytes, iterator_bytes)?
            };
            memory.reserve(iterator_bytes)?;
            {
                // Acquire a bounded native tuple window before opening a document
                // loan: page and document readers may share the same native handle.
                let mut native_workspace = 0;
                let mut native = None;
                let mut ranked = None;
                if source.has_ordered_unique_source() && index.fields.len() > 1 {
                    let workspace = ((crate::ORDERED_TUPLE_WINDOW + 3)
                        * (crate::MAX_ORDERED_TUPLE_BYTES
                            + 256
                            + std::mem::size_of::<(Vec<u8>, String)>())
                        + 6 * crate::MAX_ORDERED_TUPLE_BYTES)
                        as u64;
                    memory.reserve(workspace)?;
                    let ordinal = indexes
                        .structured
                        .unique
                        .values()
                        .filter(|u| u.fields.len() > 1)
                        .position(|candidate| std::ptr::eq(candidate, index))
                        .expect("selected compound index");
                    let wide = self
                        .seek_projection
                        .as_ref()
                        .map_or(!index.overflow.is_empty(), |projection| {
                            projection.wide_indexes[ordinal]
                        });
                    if wide {
                        ranked = ranked::Walk::open(
                            source,
                            ordinal,
                            &index.fields,
                            &range,
                            descending,
                            cancellation,
                        )?;
                    }
                    if ranked.is_none() {
                        let lower = crate::ordered_tuple::range_bound(&range.lower, true);
                        let upper = crate::ordered_tuple::range_bound(&range.upper, false);
                        if let Some(rows) = source.ordered_unique_window(
                            ordinal,
                            bytes_bound(&lower),
                            bytes_bound(&upper),
                            descending,
                            cancellation,
                        )? {
                            native = Some(NativeWalk::new(ordinal, lower, upper, rows, descending));
                        }
                    }
                    if ranked.is_some() || native.is_some() {
                        native_workspace = workspace;
                    } else {
                        memory.release(workspace)?;
                    }
                }
                let projected_fallback = if let Some(read) = &self.seek_projection
                    && index.fields.len() > 1
                {
                    let mut fallback = read.fallback.lock().map_err(|_| {
                        Error::new(ErrorCode::Unavailable, "captured seek fallback poisoned")
                    })?;
                    if native.is_some() || ranked.is_some() {
                        // The exact physical root now owns this immutable walk.
                        fallback.take();
                        None
                    } else {
                        let ordinal = indexes
                            .structured
                            .unique
                            .values()
                            .filter(|i| i.fields.len() > 1)
                            .position(|i| std::ptr::eq(i, index))
                            .expect("selected compound index");
                        Some(
                            fallback
                                .as_ref()
                                .and_then(|roots| roots.get(ordinal))
                                .ok_or_else(|| {
                                    Error::new(
                                        ErrorCode::Corruption,
                                        "captured physical seek directory disappeared",
                                    )
                                })?
                                .clone(),
                        )
                    }
                } else {
                    None
                };
                let mut tuples = if native.is_none() && ranked.is_none() {
                    projected_fallback
                        .as_ref()
                        .or(index.entries.as_ref())
                        .map(|entries| {
                            entries.range::<_, Vec<Scalar>>((
                                range.lower.as_ref(),
                                range.upper.as_ref(),
                            ))
                        })
                } else {
                    None
                };
                let mut posting = if tuples.is_none() && native.is_none() && ranked.is_none() {
                    let field = indexes
                        .structured
                        .fields
                        .get(&index.fields[0].path)
                        .ok_or_else(|| {
                            Error::new(ErrorCode::Corruption, "unique field tree absent")
                        })?;
                    Some(field.entries.range::<_, Scalar>((
                        field_bound(&range.lower, true),
                        field_bound(&range.upper, false),
                    )))
                } else {
                    None
                };
                let ranked_order = ranked.is_some();
                let mut ordinary = std::iter::from_fn(|| {
                    if let Some(walk) = &mut ranked {
                        return walk
                            .next(source, cancellation)
                            .transpose()
                            .map(|r| r.map(SeekEntry::Ranked));
                    }
                    if let Some(walk) = &mut native {
                        return walk
                            .next(source, cancellation)
                            .transpose()
                            .map(|r| r.map(|(key, id)| SeekEntry::Native(key, id)));
                    }
                    if let Some(tuples) = &mut tuples {
                        return directed_next(tuples, descending)
                            .map(|(key, id)| Ok(SeekEntry::Resident(key.as_slice(), id)));
                    }
                    let posting = posting.as_mut()?;
                    loop {
                        let (scalar, ids) = directed_next(posting, descending)?;
                        if *scalar == Scalar::Missing {
                            continue;
                        }
                        return Some(if ids.len() == 1 {
                            Ok(SeekEntry::Resident(
                                std::slice::from_ref(scalar),
                                ids.get_min().expect("singleton posting"),
                            ))
                        } else {
                            Err(Error::new(
                                ErrorCode::Corruption,
                                "unique seek posting has multiple or missing owners",
                            )
                            .into())
                        });
                    }
                })
                .peekable();
                let mut overflow_charge = 0;
                let selected_wide = if let Some(captured) = worker_wide {
                    let mut roots = captured
                        .lock()
                        .map_err(|_| {
                            Error::new(
                                ErrorCode::Unavailable,
                                "captured wide seek fallback poisoned",
                            )
                        })?
                        .take()
                        .ok_or_else(|| {
                            Error::new(
                                ErrorCode::Unavailable,
                                "registered seek worker already consumed its page",
                            )
                        })?;
                    let selected = indexes
                        .structured
                        .unique
                        .values()
                        .filter(|u| u.fields.len() > 1)
                        .position(|u| std::ptr::eq(u, index))
                        .map(|ordinal| roots.swap_remove(ordinal));
                    drop(roots);
                    if let Some(root) = selected.filter(|_| !ranked_order) {
                        let (rows, charge) = WideRows::for_page(
                            root,
                            &range,
                            descending,
                            bound.rows,
                            cancellation,
                            memory,
                        )?;
                        overflow_charge = charge;
                        Some(rows)
                    } else {
                        None
                    }
                } else {
                    None
                };
                let root = match &selected_wide {
                    _ if ranked_order => None,
                    Some(WideRows::Page(_)) => None,
                    Some(WideRows::Full(root)) => Some(root),
                    None => Some(&index.overflow),
                };
                let mut tree = root.filter(|root| !root.is_empty()).map(|root| {
                    root.range::<_, Vec<Scalar>>((range.lower.as_ref(), range.upper.as_ref()))
                });
                let mut selected = match &selected_wide {
                    Some(WideRows::Page(rows)) => Some(rows.iter()),
                    _ => None,
                };
                let mut wide = std::iter::from_fn(|| {
                    if let Some(rows) = &mut selected {
                        return rows.next().map(|(key, id)| (key, id));
                    }
                    directed_next(tree.as_mut()?, descending)
                })
                .peekable();
                let mut entries = std::iter::from_fn(|| {
                    let Some((key, _)) = wide.peek() else {
                        return ordinary.next();
                    };
                    let first = match ordinary.peek() {
                        Some(Ok(SeekEntry::Ranked(_))) => {
                            unreachable!("ranked order owns all tuple widths")
                        }
                        Some(Ok(SeekEntry::Native(bytes, _))) => {
                            crate::ordered_tuple::compare_overflow(bytes, key)
                        }
                        Some(Ok(SeekEntry::Resident(other, _))) => other.cmp(&key.as_slice()),
                        Some(Err(_)) => return ordinary.next(),
                        None => return wide.next().map(|(k, id)| Ok(SeekEntry::Resident(k, id))),
                    };
                    let take_ordinary = if descending {
                        first.is_gt()
                    } else {
                        first.is_lt()
                    };
                    if take_ordinary {
                        ordinary.next()
                    } else {
                        wide.next().map(|(k, id)| Ok(SeekEntry::Resident(k, id)))
                    }
                })
                .peekable();
                while let Some(entry) = entries.next() {
                    let entry = entry?;
                    let id = match &entry {
                        SeekEntry::Resident(_, id) => *id,
                        SeekEntry::Native(_, id) => id,
                        SeekEntry::Ranked(row) => &row.id,
                    };
                    cancellation.check()?;
                    if page.is_full() {
                        more = true;
                        break;
                    }
                    if matches!(entries.peek(), Some(Err(_)))
                        && let Some(Err(failure)) = entries.next()
                    {
                        return Err(failure);
                    }
                    let has_more = entries.peek().is_some();
                    let copied =
                        document_source::with_live(source, id, None, cancellation, |row| {
                            // Assemble with a terminal null cursor first. A large
                            // key must not reject a page that can finish the walk.
                            if !page.push_with_cursor_bytes(row, None, 2, memory)? {
                                return Ok(None);
                            }
                            let expected = match &entry {
                                SeekEntry::Ranked(selected) => {
                                    if crate::ranked_record_digest(
                                        &index.fields,
                                        crate::Record::Live(row),
                                    )? != selected.digest
                                    {
                                        return Err(Error::new(
                                            ErrorCode::Corruption,
                                            "ranked compound owner differs from projected document",
                                        ));
                                    }
                                    None
                                }
                                SeekEntry::Resident(key, _) => Some(*key),
                                SeekEntry::Native(key, _) => {
                                    if crate::ordered_record_tuple(
                                        &index.fields,
                                        crate::Record::Live(row),
                                    )?
                                    .as_ref()
                                        != Some(key)
                                    {
                                        return Err(Error::new(
                                            ErrorCode::Corruption,
                                            "native seek entry differs from document",
                                        ));
                                    }
                                    None
                                }
                            };
                            raw_key(row, &index.fields, expected, memory).map(Some)
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
                drop(entries);
                drop(selected_wide);
                memory.release(overflow_charge)?;
                memory.release(native_workspace)?;
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

enum WideRows {
    Full(TupleMap),
    Page(Vec<(Vec<Scalar>, String)>),
}

impl WideRows {
    fn for_page<W: QueryWorkspace>(
        root: TupleMap,
        range: &KeyRange,
        descending: bool,
        rows: usize,
        cancel: &QueryCancellation,
        memory: &mut QueryMemory<W>,
    ) -> Result<(Self, u64)> {
        // One lookahead decides whether a continuation is needed. Limit
        // optional copying even when a request asks for a very large page.
        let limit = rows.saturating_add(1);
        if limit > 256 || root.len() <= limit {
            return Ok((Self::Full(root), 0));
        }
        let window = || {
            let mut entries =
                root.range::<_, Vec<Scalar>>((range.lower.as_ref(), range.upper.as_ref()));
            std::iter::from_fn(move || directed_next(&mut entries, descending)).take(limit)
        };
        let mut bytes = 0;
        let mut count = 0usize;
        for (key, id) in window() {
            cancel.check()?;
            count += 1;
            bytes = allocation::add(bytes, allocation::vec_bytes::<Scalar>(key.len())?)?;
            bytes = allocation::add(bytes, allocation::string_clone_bytes(id)?)?;
            for part in key {
                let part_bytes = match part {
                    Scalar::String(value) => allocation::string_clone_bytes(value)?,
                    Scalar::Number(_) => crate::scalar::PROVISIONAL_DECIMAL_KEY_BYTES,
                    _ => 0,
                };
                bytes = allocation::add(bytes, part_bytes)?;
            }
        }
        bytes = allocation::add(
            bytes,
            allocation::vec_bytes::<(Vec<Scalar>, String)>(count)?,
        )?;
        if bytes > 1 << 20 {
            return Ok((Self::Full(root), 0));
        }
        if let Err(error) = memory.reserve(bytes) {
            if error.code == ErrorCode::ResourceExhausted {
                return Ok((Self::Full(root), 0));
            }
            return Err(error);
        }
        let mut rows = Vec::with_capacity(count);
        for (key, id) in window() {
            cancel.check()?;
            rows.push((key.clone(), id.clone()));
        }
        Ok((Self::Page(rows), bytes))
    }
}

enum SeekEntry<'a> {
    Resident(&'a [Scalar], &'a str),
    Native(Vec<u8>, String),
    Ranked(crate::RankedOwner),
}
fn bytes_bound(bound: &Bound<Vec<u8>>) -> Bound<&[u8]> {
    bound.as_ref().map(Vec::as_slice)
}

struct NativeWalk {
    ordinal: usize,
    lower: Bound<Vec<u8>>,
    upper: Bound<Vec<u8>>,
    descending: bool,
    rows: std::vec::IntoIter<(Vec<u8>, String)>,
    more: bool,
}
impl NativeWalk {
    fn new(
        ordinal: usize,
        lower: Bound<Vec<u8>>,
        upper: Bound<Vec<u8>>,
        rows: crate::OrderedTupleWindow,
        descending: bool,
    ) -> Self {
        let more = rows.len() == crate::ORDERED_TUPLE_WINDOW;
        Self {
            ordinal,
            lower,
            upper,
            descending,
            more,
            rows: rows.into_iter(),
        }
    }
    fn next<S: DocumentSource + ?Sized>(
        &mut self,
        source: &S,
        cancellation: &QueryCancellation,
    ) -> ReadResult<Option<(Vec<u8>, String)>, S::Failure> {
        if self.rows.len() == 0 && self.more {
            let rows = source
                .ordered_unique_window(
                    self.ordinal,
                    bytes_bound(&self.lower),
                    bytes_bound(&self.upper),
                    self.descending,
                    cancellation,
                )?
                .ok_or_else(|| {
                    Error::new(
                        ErrorCode::Corruption,
                        "compound directory disappeared during seek",
                    )
                })?;
            self.more = rows.len() == crate::ORDERED_TUPLE_WINDOW;
            self.rows = rows.into_iter();
        }
        let next = self.rows.next();
        if self.rows.len() == 0
            && self.more
            && let Some((key, _)) = &next
        {
            let resumed = Bound::Excluded(key.clone());
            if self.descending {
                self.upper = resumed;
            } else {
                self.lower = resumed;
            }
        }
        Ok(next)
    }
}
fn directed_next<I: DoubleEndedIterator>(iter: &mut I, descending: bool) -> Option<I::Item> {
    if descending {
        iter.next_back()
    } else {
        iter.next()
    }
}

/// Compare a one-element stored tuple against the planner's complete or
/// sentinel-extended bound. [v] sorts strictly before [v, UpperBound].
fn field_bound(bound: &Bound<Vec<Scalar>>, lower: bool) -> Bound<&Scalar> {
    let (key, inclusive) = match bound {
        Bound::Included(key) => (key, true),
        Bound::Excluded(key) => (key, false),
        Bound::Unbounded => return Bound::Unbounded,
    };
    match key.as_slice() {
        [] if lower => Bound::Unbounded,
        [] => Bound::Excluded(&Scalar::Missing),
        [scalar] if inclusive => Bound::Included(scalar),
        [scalar] => Bound::Excluded(scalar),
        [scalar, ..] if lower => Bound::Excluded(scalar),
        [scalar, ..] => Bound::Included(scalar),
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
    expected: Option<&[Scalar]>,
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
    for (ordinal, field) in fields.iter().enumerate() {
        let value = value(field)?;
        if let Some(expected) = expected {
            let matches = memory.scope::<_, Error>(|memory| {
                let (actual, _) = query_scalar(Some(value), Some(field.kind), memory)?;
                Ok((actual == expected[ordinal], 0))
            })?;
            if !matches {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "seek index entry differs from document",
                ));
            }
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
