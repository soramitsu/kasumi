//! Page assembly. A query copies only its first page; the rows after it stay
//! uncopied in the query's generation until a continuation asks for them.
use crate::select::Selection;
use crate::{
    BorrowedRow, QueryCancellation, QueryMemory, QueryWorkspace, ResultBudget, allocation,
};
use kasumi_types::{Document, QueryResponse, QueryRow, Result};

/// At most `rows` rows and `bytes` of encoded response per page. A row that
/// cannot fit by itself fails explicitly instead of exceeding the byte bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageBound {
    pub rows: usize,
    pub bytes: usize,
}

/// Snapshot cursors are UUID strings.
const CURSOR_SIZED_TOKEN: &str = "00000000-0000-0000-0000-000000000000";

pub(crate) fn encoded_len(value: &impl serde::Serialize) -> Result<usize> {
    let mut budget = ResultBudget::new(usize::MAX);
    budget.account(value)?;
    Ok(budget.bytes)
}

/// Copies rows into one page until either bound is reached. Every row clone is
/// admitted before allocation; the row vector is sized once up front.
pub(crate) struct PageWriter<'a> {
    selection: Option<&'a Selection>,
    bound: PageBound,
    /// Rows this page can hold: the bound, or fewer when fewer can arrive.
    limit: usize,
    bytes: usize,
    cursor_bytes: usize,
    rows: Vec<QueryRow>,
    retained: u64,
}

impl<'a> PageWriter<'a> {
    /// `available` caps the row vector at the rows that can actually arrive.
    pub(crate) fn new<W: QueryWorkspace>(
        selection: Option<&'a Selection>,
        bound: PageBound,
        available: usize,
        memory: &mut QueryMemory<W>,
    ) -> Result<Self> {
        let envelope = encoded_len(&QueryResponse {
            revision: u64::MAX,
            rows: Vec::new(),
            aggregates: Vec::new(),
            cursor: None,
        })?;
        if envelope > bound.bytes {
            return Err(crate::exhausted(
                "query page envelope exceeds its byte limit",
            ));
        }
        let limit = bound.rows.min(available);
        let retained = allocation::vec_bytes::<QueryRow>(limit)?;
        memory.reserve(retained)?;
        Ok(Self {
            selection,
            bound,
            limit,
            bytes: envelope,
            // A JSON null is two bytes longer than an empty quoted string.
            cursor_bytes: 2,
            rows: Vec::with_capacity(limit),
            retained,
        })
    }

    pub(crate) fn is_full(&self) -> bool {
        self.rows.len() >= self.limit
    }

    pub(crate) fn row_count(&self) -> usize {
        self.rows.len()
    }

    pub(crate) fn fits_cursor_bytes(&self, cursor_bytes: usize) -> bool {
        self.bytes
            .checked_sub(self.cursor_bytes)
            .and_then(|bytes| bytes.checked_add(cursor_bytes))
            .is_some_and(|bytes| bytes <= self.bound.bytes)
    }

    /// Discard a suffix after discovering that a continuation needs more
    /// space. The vector keeps its original capacity and its admitted charge.
    pub(crate) fn truncate<W: QueryWorkspace>(
        &mut self,
        rows: usize,
        memory: &mut QueryMemory<W>,
    ) -> Result<()> {
        let mut released = 0;
        let mut removed_bytes = 0usize;
        for (index, row) in self.rows.iter().enumerate().skip(rows) {
            released = allocation::add(
                released,
                allocation::document_parts_clone_bytes(&row.id, &row.body)?,
            )?;
            removed_bytes = removed_bytes
                .saturating_add(encoded_len(row)?)
                .saturating_add(usize::from(index != 0));
        }
        self.rows.truncate(rows);
        self.retained -= released;
        self.bytes -= removed_bytes;
        memory.release(released)
    }

    /// Copy `document` as the next row. Returns false, copying nothing, when
    /// the page is full or this row would exceed the byte bound.
    pub(crate) fn push<W: QueryWorkspace>(
        &mut self,
        document: &Document,
        score: Option<f32>,
        memory: &mut QueryMemory<W>,
    ) -> Result<bool> {
        self.push_with_cursor_bytes(document, score, CURSOR_SIZED_TOKEN.len(), memory)
    }

    /// Like `push`, with the encoded cursor's string payload length. Seek
    /// cursors include an index key, so their allowance varies with each row.
    pub(crate) fn push_with_cursor_bytes<W: QueryWorkspace>(
        &mut self,
        document: &Document,
        score: Option<f32>,
        cursor_bytes: usize,
        memory: &mut QueryMemory<W>,
    ) -> Result<bool> {
        if self.is_full() {
            return Ok(false);
        }
        let row = BorrowedRow {
            document,
            selection: self.selection,
            score,
        };
        // The row plus its separator in the response's row array.
        let bytes = self
            .bytes
            .saturating_sub(self.cursor_bytes)
            .saturating_add(cursor_bytes)
            .saturating_add(encoded_len(&row)?)
            .saturating_add(usize::from(!self.rows.is_empty()));
        if bytes > self.bound.bytes {
            if self.rows.is_empty() {
                return Err(crate::exhausted(
                    "one query row and its cursor exceed the page byte limit; select fewer fields or increase max_result_bytes",
                ));
            }
            return Ok(false);
        }
        let clone = row.clone_bytes()?;
        memory.reserve(clone)?;
        self.rows.push(row.into_owned());
        self.bytes = bytes;
        self.cursor_bytes = cursor_bytes;
        self.retained = allocation::add(self.retained, clone)?;
        Ok(true)
    }

    pub(crate) fn finish(self) -> (Vec<QueryRow>, u64) {
        (self.rows, self.retained)
    }
}

/// Copy the next page from rows a query already selected and ordered, such as
/// the documents a cursor retains. The page's clones stay admitted in `memory`;
/// `rows.len()` of the result is how many inputs the page used.
pub fn copy_page<'a, W: QueryWorkspace>(
    rows: impl ExactSizeIterator<Item = (&'a Document, Option<f32>)>,
    select: &[String],
    bound: PageBound,
    cancellation: &QueryCancellation,
    memory: &mut QueryMemory<W>,
) -> Result<Vec<QueryRow>> {
    memory.scope(|memory| {
        let selection = (!select.is_empty())
            .then(|| Selection::new(select, "select"))
            .transpose()?;
        let mut writer = PageWriter::new(selection.as_ref(), bound, rows.len(), memory)?;
        for (document, score) in rows {
            cancellation.check()?;
            if !writer.push(document, score, memory)? {
                break;
            }
        }
        cancellation.check()?;
        Ok(writer.finish())
    })
}
