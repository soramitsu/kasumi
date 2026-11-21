//! Full tuple order in an immutable checkpoint: ranks are scoped to the
//! selected source. Binary searches borrow one owning document at a time.
use super::*;
use crate::{FieldValue, RankedOwner, ordered_tuple};

pub(super) struct Walk {
    index: usize,
    start: u64,
    end: u64,
    descending: bool,
    rows: std::vec::IntoIter<RankedOwner>,
}

fn corrupt() -> Error {
    Error::new(
        ErrorCode::Corruption,
        "ranked compound directory differs from selected document",
    )
}

fn partition<S: DocumentSource + ?Sized>(
    source: &S,
    index: usize,
    fields: &[IndexField],
    count: u64,
    bound: Bound<Vec<FieldValue<'_>>>,
    lower: bool,
    cancel: &QueryCancellation,
) -> ReadResult<u64, S::Failure> {
    let (key, skip_equal) = match bound {
        Bound::Unbounded => return Ok(if lower { 0 } else { count }),
        Bound::Included(key) => (key, !lower),
        Bound::Excluded(key) => (key, lower),
    };
    let (mut start, mut end) = (0, count);
    while start < end {
        cancel.check()?;
        let mid = start + (end - start) / 2;
        let point = source
            .ranked_compound_window(index, mid, mid + 1, false, cancel)?
            .and_then(|mut rows| rows.pop())
            .ok_or_else(corrupt)?;
        let order = source.with_record(&point.id, None, cancel, |record| {
            let record = record.ok_or_else(corrupt)?;
            if ordered_tuple::ranked_record_digest(fields, record)? != point.digest {
                return Err(corrupt());
            }
            ordered_tuple::compare_ranked_record(fields, record, &key)
        })?;
        if order.is_lt() || (skip_equal && order.is_eq()) {
            start = mid + 1;
        } else {
            end = mid;
        }
    }
    Ok(start)
}

impl Walk {
    pub(super) fn open<S: DocumentSource + ?Sized>(
        source: &S,
        index: usize,
        fields: &[IndexField],
        range: &KeyRange,
        descending: bool,
        cancel: &QueryCancellation,
    ) -> ReadResult<Option<Self>, S::Failure> {
        let Some(count) = source.ranked_compound_count(index, cancel)? else {
            return Ok(None);
        };
        let start = partition(
            source,
            index,
            fields,
            count,
            ordered_tuple::ranked_bound(&range.lower),
            true,
            cancel,
        )?;
        let end = partition(
            source,
            index,
            fields,
            count,
            ordered_tuple::ranked_bound(&range.upper),
            false,
            cancel,
        )?;
        if start > end {
            return Err(corrupt().into());
        }
        let mut walk = Self {
            index,
            start,
            end,
            descending,
            rows: Vec::new().into_iter(),
        };
        walk.refill(source, cancel)?;
        Ok(Some(walk))
    }

    fn refill<S: DocumentSource + ?Sized>(
        &mut self,
        source: &S,
        cancel: &QueryCancellation,
    ) -> ReadResult<(), S::Failure> {
        if self.start == self.end {
            return Ok(());
        }
        let rows = source
            .ranked_compound_window(self.index, self.start, self.end, self.descending, cancel)?
            .ok_or_else(corrupt)?;
        if rows.is_empty() {
            return Err(corrupt().into());
        }
        if self.descending {
            self.end -= rows.len() as u64;
        } else {
            self.start += rows.len() as u64;
        }
        self.rows = rows.into_iter();
        Ok(())
    }

    pub(super) fn next<S: DocumentSource + ?Sized>(
        &mut self,
        source: &S,
        cancel: &QueryCancellation,
    ) -> ReadResult<Option<RankedOwner>, S::Failure> {
        if self.rows.len() == 0 {
            self.refill(source, cancel)?;
        }
        Ok(self.rows.next())
    }
}
