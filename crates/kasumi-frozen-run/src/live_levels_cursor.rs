//! Pull one bounded row from a frozen run for a multi-run merge.
use super::*;
use std::ops::Range;

pub(crate) struct RunCursor {
    blocks: Range<usize>,
    rows: Range<usize>,
    block: usize,
    reverse: bool,
}

fn below(key: &[u8], lower: Bound<&[u8]>) -> bool {
    match lower {
        Bound::Included(k) => key < k,
        Bound::Excluded(k) => key <= k,
        Bound::Unbounded => false,
    }
}

fn above(key: &[u8], upper: Bound<&[u8]>) -> bool {
    match upper {
        Bound::Included(k) => key > k,
        Bound::Excluded(k) => key >= k,
        Bound::Unbounded => false,
    }
}

impl RunCursor {
    pub(crate) fn new(
        run: &FrozenRun,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
        reverse: bool,
    ) -> Self {
        let start = run.blocks.partition_point(|b| below(&b.last, lower));
        let stop = run.blocks.partition_point(|b| !above(&b.first, upper));
        Self {
            blocks: start..stop,
            rows: 0..0,
            block: 0,
            reverse,
        }
    }

    pub(crate) fn next(
        &mut self,
        run: &mut FrozenRun,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
    ) -> io::Result<Option<(usize, u32)>> {
        loop {
            let row = if self.reverse {
                self.rows.next_back()
            } else {
                self.rows.next()
            };
            if let Some(row) = row {
                return Ok(Some((self.block, run.block(self.block)?.offsets[row])));
            }
            let block = if self.reverse {
                self.blocks.next_back()
            } else {
                self.blocks.next()
            };
            let Some(block) = block else { return Ok(None) };
            self.block = block;
            let cut_low = below(&run.blocks[block].first, lower);
            let cut_high = above(&run.blocks[block].last, upper);
            let decoded = run.block(block)?;
            let lo = if cut_low {
                decoded
                    .offsets
                    .partition_point(|&o| below(decoded.row(o).0, lower))
            } else {
                0
            };
            let hi = if cut_high {
                decoded
                    .offsets
                    .partition_point(|&o| !above(decoded.row(o).0, upper))
            } else {
                decoded.offsets.len()
            };
            self.rows = lo..hi;
        }
    }
}

impl FrozenRun {
    pub(crate) fn cursor_row(&mut self, at: (usize, u32)) -> io::Result<(&[u8], &[u8])> {
        Ok(self.block(at.0)?.row(at.1))
    }

    pub(crate) fn extent_bounds(&self) -> Option<(&[u8], &[u8])> {
        Some((&self.blocks.first()?.first, &self.blocks.last()?.last))
    }
}
