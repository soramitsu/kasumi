//! Authenticated, immutable runs for the mutable store. The manifest supplies
//! levels in descending age order (newest first). Only a newly produced run and
//! its bounded merge inputs participate in a flush.
use crate::{
    FrozenRun, invalid, live_bulk_filter::BulkFilter, live_merge::Delta, read::RunCursor, write,
};
use std::{
    cmp::Ordering,
    collections::VecDeque,
    fs::File,
    io::{self, Seek},
    ops::Bound,
};

#[path = "live_levels_index.rs"]
mod index;
use index::{Leaf, Link, Node};

const PIECE_TARGET: usize = 4 << 20;

struct Loaded {
    descriptor: Leaf,
    rows: FrozenRun,
    deletes: Option<FrozenRun>,
}

pub(super) struct Level {
    file: File,
    root: Option<Link>,
    loaded: Option<Loaded>,
    only_piece: bool,
    cache_bulk_pieces: bool,
    recent: VecDeque<Loaded>,
    membership: Option<BulkFilter>,
}

impl Level {
    pub(super) fn open(mut file: File, expected_root: [u8; 32], bulk: bool) -> io::Result<Self> {
        let mut root = index::open(&mut file, expected_root)?;
        let mut membership = None;
        let mut first = None;
        if let Some(link) = root {
            let mut node = index::read(&mut file, link)?;
            if let Node::BulkRoot { tree, filter } = node {
                if !bulk {
                    return Err(invalid("membership filter outside the bulk tier"));
                }
                membership = Some(index::read_filter(&mut file, filter)?);
                root = Some(tree);
                node = index::read(&mut file, tree)?;
            }
            match node {
                Node::Leaf(leaf) => first = Some(leaf),
                Node::Branch { .. } => {}
                Node::BulkRoot { .. } => return Err(invalid("nested bulk membership root")),
            }
        }
        let mut out = Self {
            file,
            root,
            loaded: None,
            only_piece: false,
            cache_bulk_pieces: bulk,
            recent: VecDeque::new(),
            membership,
        };
        if let Some(leaf) = first {
            out.load(leaf)?;
            out.only_piece = true;
        }
        Ok(out)
    }

    fn activate(&mut self, piece: Loaded) {
        if let Some(mut previous) = self.loaded.replace(piece)
            && self.cache_bulk_pieces
        {
            // Keep at most three old pieces; a large single-value buffer must
            // not multiply with the number of cached pieces.
            previous.rows.forget_oversized();
            if let Some(deletes) = &mut previous.deletes {
                deletes.forget_oversized();
            }
            if self.recent.len() == 3 {
                self.recent.pop_back();
            }
            self.recent.push_front(previous);
        }
    }

    fn reuse(&mut self, position: usize) {
        let piece = self.recent.remove(position).expect("recent piece position");
        self.activate(piece);
    }

    fn load(&mut self, descriptor: Leaf) -> io::Result<()> {
        if self
            .loaded
            .as_ref()
            .is_some_and(|s| s.descriptor.rows == descriptor.rows)
        {
            return Ok(());
        }
        if let Some(position) = self
            .recent
            .iter()
            .position(|s| s.descriptor.rows == descriptor.rows)
        {
            self.reuse(position);
            return Ok(());
        }
        let open = |link: Link| {
            FrozenRun::from_extent(
                self.file.try_clone()?,
                link.at,
                link.at + link.len,
                link.root,
            )
        };
        let rows = open(descriptor.rows)?;
        if rows.extent_bounds() != Some((descriptor.first.as_slice(), descriptor.last.as_slice())) {
            return Err(invalid("live piece key bounds differ"));
        }
        let deletes = descriptor.deleted.map(open).transpose()?;
        self.activate(Loaded {
            descriptor,
            rows,
            deletes,
        });
        Ok(())
    }

    /// Find the first leaf intersecting the chosen start bound, recording later
    /// siblings on the path for a range traversal.
    fn descend(
        &mut self,
        mut link: Link,
        start: Bound<&[u8]>,
        reverse: bool,
        siblings: &mut Vec<Link>,
    ) -> io::Result<()> {
        for _ in 0..=index::HEIGHT {
            match index::read(&mut self.file, link)? {
                Node::Leaf(leaf) => return self.load(leaf),
                Node::BulkRoot { .. } => return Err(invalid("nested bulk membership root")),
                Node::Branch { split, left, right } => {
                    let right_first = match start {
                        Bound::Included(key) => key >= split.as_slice(),
                        Bound::Excluded(key) if reverse => key > split.as_slice(),
                        Bound::Excluded(key) => key >= split.as_slice(),
                        Bound::Unbounded => reverse,
                    };
                    if right_first == reverse {
                        if siblings.len() >= index::HEIGHT {
                            return Err(invalid("live level tree is too deep"));
                        }
                        siblings.push(if reverse { left } else { right });
                    }
                    link = if right_first { right } else { left };
                }
            }
        }
        Err(invalid("live level tree is too deep"))
    }

    fn lookup(&mut self, key: &[u8]) -> io::Result<Option<Option<Vec<u8>>>> {
        let Some(root) = self.root else {
            return Ok(None);
        };
        if self
            .membership
            .as_ref()
            .is_some_and(|filter| !filter.may_contain(key))
        {
            return Ok(None);
        }
        let contains = |s: &Loaded| {
            s.descriptor.first.as_slice() <= key && key <= s.descriptor.last.as_slice()
        };
        if !self.only_piece && !self.loaded.as_ref().is_some_and(contains) {
            if let Some(position) = self.recent.iter().position(contains) {
                self.reuse(position);
            } else {
                self.descend(root, Bound::Included(key), false, &mut Vec::new())?;
            }
        }
        let shard = self.loaded.as_mut().unwrap();
        let Some(v) = shard.rows.get(key)? else {
            return Ok(None);
        };
        if v.is_empty() && is_deleted(&mut shard.deletes, key)? {
            return Ok(Some(None));
        }
        Ok(Some(Some(v)))
    }
}

fn is_deleted(deletes: &mut Option<FrozenRun>, key: &[u8]) -> io::Result<bool> {
    match deletes {
        Some(run) => Ok(run.get(key)?.is_some()),
        None => Ok(false),
    }
}

pub(super) fn get(
    levels: &mut [&mut Level],
    delta: &Delta,
    key: &[u8],
) -> io::Result<Option<Vec<u8>>> {
    if let Some(change) = delta.get(key) {
        return Ok(change.clone());
    }
    for level in levels {
        if let Some(change) = level.lookup(key)? {
            return Ok(change);
        }
    }
    Ok(None)
}

struct Cursor {
    later: Vec<Link>,
    scan: Option<RunCursor>,
    pos: Option<(usize, u32)>,
    key: Vec<u8>,
    verify_membership: bool,
}

impl Cursor {
    fn start(
        level: &mut Level,
        lo: Bound<&[u8]>,
        hi: Bound<&[u8]>,
        rev: bool,
        verify_membership: bool,
    ) -> io::Result<Self> {
        let mut c = Self {
            later: Vec::new(),
            scan: None,
            pos: None,
            key: Vec::new(),
            verify_membership,
        };
        if let Some(root) = level.root {
            if !level.only_piece {
                level.descend(root, if rev { hi } else { lo }, rev, &mut c.later)?;
            }
            c.scan = Some(RunCursor::new(
                &level.loaded.as_ref().unwrap().rows,
                lo,
                hi,
                rev,
            ));
            c.advance(level, lo, hi, rev)?;
        }
        Ok(c)
    }
    fn advance(
        &mut self,
        level: &mut Level,
        lo: Bound<&[u8]>,
        hi: Bound<&[u8]>,
        rev: bool,
    ) -> io::Result<()> {
        self.pos = None;
        loop {
            let Some(scan) = &mut self.scan else {
                return Ok(());
            };
            let shard = level.loaded.as_mut().unwrap();
            if let Some(row) = scan.next(&mut shard.rows, lo, hi)? {
                self.key.clear();
                self.key.extend_from_slice(shard.rows.cursor_row(row)?.0);
                if self.verify_membership
                    && level
                        .membership
                        .as_ref()
                        .is_some_and(|filter| !filter.may_contain(&self.key))
                {
                    return Err(invalid("bulk filter omits a stored key"));
                }
                self.pos = Some(row);
                return Ok(());
            }
            // Ascending/descending pieces are disjoint. The opposite bound
            // can terminate the scan before loading the next piece.
            let finished = if rev {
                match lo {
                    Bound::Included(k) | Bound::Excluded(k) => {
                        k >= shard.descriptor.first.as_slice()
                    }
                    Bound::Unbounded => false,
                }
            } else {
                match hi {
                    Bound::Included(k) | Bound::Excluded(k) => {
                        k <= shard.descriptor.last.as_slice()
                    }
                    Bound::Unbounded => false,
                }
            };
            let Some(next) = self.later.pop().filter(|_| !finished) else {
                self.scan = None;
                return Ok(());
            };
            level.descend(next, Bound::Unbounded, rev, &mut self.later)?;
            self.scan = Some(RunCursor::new(
                &level.loaded.as_ref().unwrap().rows,
                lo,
                hi,
                rev,
            ));
        }
    }
    fn value<'a>(&self, level: &'a mut Level) -> io::Result<Option<&'a [u8]>> {
        let shard = level.loaded.as_mut().unwrap();
        let (key, value) = shard.rows.cursor_row(self.pos.unwrap())?;
        Ok(
            if value.is_empty() && is_deleted(&mut shard.deletes, key)? {
                None
            } else {
                Some(value)
            },
        )
    }
}

fn empty(lo: Bound<&[u8]>, hi: Bound<&[u8]>) -> bool {
    use Bound::*;
    match (lo, hi) {
        (Unbounded, _) | (_, Unbounded) => false,
        (Included(a), Included(b)) => a > b,
        (Included(a) | Excluded(a), Included(b) | Excluded(b)) => a >= b,
    }
}

/// Emit the newest operation for each key. The callback stops a limited scan
/// without advancing or decoding any later row.
fn merge(
    levels: &mut [&mut Level],
    delta: &Delta,
    lo: Bound<&[u8]>,
    hi: Bound<&[u8]>,
    rev: bool,
    verify_membership: bool,
    mut emit: impl FnMut(&[u8], Option<&[u8]>) -> io::Result<bool>,
) -> io::Result<()> {
    if empty(lo, hi) {
        return Ok(());
    }
    let mut cursors = levels
        .iter_mut()
        .map(|l| Cursor::start(l, lo, hi, rev, verify_membership))
        .collect::<io::Result<Vec<_>>>()?;
    let mut changes = delta.range::<[u8], _>((lo, hi));
    let mut take_change = || {
        if rev {
            changes.next_back()
        } else {
            changes.next()
        }
    };
    let mut change = take_change();
    let mut key = Vec::new();
    loop {
        let mut chosen = None;
        let mut smallest = change.map(|(k, _)| k.as_slice());
        for (i, cursor) in cursors.iter().enumerate() {
            if cursor.pos.is_some()
                && smallest.is_none_or(|other| {
                    let cmp = cursor.key.as_slice().cmp(other);
                    cmp == if rev {
                        Ordering::Greater
                    } else {
                        Ordering::Less
                    }
                })
            {
                chosen = Some(i);
                smallest = Some(&cursor.key);
            }
        }
        let Some(selected_key) = smallest else {
            return Ok(());
        };
        let value = match chosen {
            Some(i) => cursors[i].value(levels[i])?,
            None => change.unwrap().1.as_deref(),
        };
        if !emit(selected_key, value)? {
            return Ok(());
        }
        key.clear();
        key.extend_from_slice(selected_key);
        if change.is_some_and(|(k, _)| k == &key) {
            change = take_change();
        }
        for (level, cursor) in levels.iter_mut().zip(&mut cursors) {
            if cursor.pos.is_some() && cursor.key == key {
                cursor.advance(level, lo, hi, rev)?;
            }
        }
    }
}

pub(super) fn visit(
    levels: &mut [&mut Level],
    delta: &Delta,
    lo: Bound<&[u8]>,
    hi: Bound<&[u8]>,
    limit: usize,
    rev: bool,
    mut emit: impl FnMut(&[u8], &[u8]) -> io::Result<()>,
) -> io::Result<usize> {
    if limit == 0 || empty(lo, hi) {
        return Ok(0);
    }
    if delta.is_empty()
        && let [one] = levels
        && one.only_piece
    {
        let shard = one.loaded.as_mut().unwrap();
        if shard.deletes.is_none() {
            return if rev {
                shard.rows.visit_reverse(lo, hi, limit, emit)
            } else {
                shard.rows.visit_forward(lo, hi, limit, emit)
            };
        }
    }
    let mut count = 0;
    merge(levels, delta, lo, hi, rev, false, |key, value| {
        if let Some(row) = value {
            emit(key, row)?;
            count += 1;
        }
        Ok(count < limit)
    })?;
    Ok(count)
}

/// The full merge visits keys in every input, including tombstones and values
/// shadowed by newer writes. Validate the Bloom bits on that same traversal.
pub(super) fn visit_verified(
    levels: &mut [&mut Level],
    delta: &Delta,
    mut emit: impl FnMut(&[u8], &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    if !levels.iter().any(|level| level.membership.is_some()) {
        return visit(
            levels,
            delta,
            Bound::Unbounded,
            Bound::Unbounded,
            usize::MAX,
            false,
            emit,
        )
        .map(|_| ());
    }
    merge(
        levels,
        delta,
        Bound::Unbounded,
        Bound::Unbounded,
        false,
        true,
        |key, value| {
            if let Some(value) = value {
                emit(key, value)?;
            }
            Ok(true)
        },
    )
}

type Buffered = (Vec<u8>, Option<Vec<u8>>);

fn flush_piece(
    file: &mut File,
    index: &mut index::Builder,
    rows: &mut Vec<Buffered>,
) -> io::Result<()> {
    if rows.is_empty() {
        return Ok(());
    }
    let at = file.stream_position()?;
    let root = write::write_rows(file, |put| {
        for (key, value) in rows.iter() {
            put(key, value.as_deref().unwrap_or_default())?;
        }
        Ok(())
    })?;
    let end = file.stream_position()?;
    let data = Link {
        at,
        len: end - at,
        root,
    };
    let deleted = if rows.iter().any(|(_, v)| v.is_none()) {
        let root = write::write_rows(file, |put| {
            for (key, v) in rows.iter() {
                if v.is_none() {
                    put(key, &[])?;
                }
            }
            Ok(())
        })?;
        Some(Link {
            at: end,
            len: file.stream_position()? - end,
            root,
        })
    } else {
        None
    };
    index.push(
        file,
        Leaf {
            first: rows.first().unwrap().0.clone(),
            last: rows.last().unwrap().0.clone(),
            rows: data,
            deleted,
        },
    )?;
    rows.clear();
    Ok(())
}

/// File synchronization and publication are owned by the manifest writer.
pub(super) fn write_level(
    file: &mut File,
    delta: &Delta,
    older: &mut [&mut Level],
    drop_tombstones: bool,
) -> io::Result<[u8; 32]> {
    write_pieces(file, delta, older, drop_tombstones, PIECE_TARGET)
}

fn write_pieces(
    file: &mut File,
    delta: &Delta,
    older: &mut [&mut Level],
    drop_tombstones: bool,
    target: usize,
) -> io::Result<[u8; 32]> {
    if file.stream_position()? != 0 || file.metadata()?.len() != 0 {
        return Err(invalid("live level output must be empty"));
    }
    let mut rows = Vec::new();
    let mut size = 0;
    let mut index = index::Builder::default();
    // A full compaction may grow or shrink the immutable base substantially.
    // Count the actual survivors before allocating the replacement filter.
    let mut membership = None;
    if older.iter().any(|level| level.membership.is_some()) {
        let mut count = 0u64;
        merge(
            older,
            delta,
            Bound::Unbounded,
            Bound::Unbounded,
            false,
            true,
            |_, value| {
                if !drop_tombstones || value.is_some() {
                    count = count
                        .checked_add(1)
                        .ok_or_else(|| invalid("compacted row count overflow"))?;
                }
                Ok(true)
            },
        )?;
        if count != 0 {
            membership = Some(BulkFilter::for_rows(count)?);
        }
    }
    merge(
        older,
        delta,
        Bound::Unbounded,
        Bound::Unbounded,
        false,
        false,
        |key, value| {
            if value.is_none() && drop_tombstones {
                return Ok(true);
            }
            if let Some(filter) = &mut membership {
                filter.insert(key);
            }
            // Charge row metadata as well as payload bytes so tiny records cannot
            // overrun the shard buffer. One legal oversized row occupies its own shard.
            let bytes = 64 + key.len() + value.map_or(0, <[u8]>::len);
            if !rows.is_empty() && size + bytes > target {
                flush_piece(file, &mut index, &mut rows)?;
                size = 0;
            }
            rows.push((key.to_vec(), value.map(<[u8]>::to_vec)));
            size += bytes;
            Ok(true)
        },
    )?;
    flush_piece(file, &mut index, &mut rows)?;
    index.finish(file, membership.as_ref())
}

#[cfg(test)]
#[path = "live_levels_tests.rs"]
mod tests;

/// Stream sorted live rows into the normal piece and sparse-index format. At
/// most one piece and the logarithmic index-builder stack are resident.
pub(super) fn write_sorted(
    file: &mut File,
    source: impl IntoIterator<Item = io::Result<(Vec<u8>, Vec<u8>)>>,
    expected_filter_rows: Option<u64>,
) -> io::Result<([u8; 32], u64)> {
    let mut index = index::Builder::default();
    let mut membership = expected_filter_rows.map(BulkFilter::for_rows).transpose()?;
    let mut rows: Vec<Buffered> = Vec::new();
    let mut size = 0;
    let mut count = 0u64;
    for row in source {
        let (key, value) = row?;
        if expected_filter_rows.is_some_and(|limit| count >= limit) {
            return Err(invalid("filtered import exceeds expected row count"));
        }
        if key.len() > crate::MAX_KEY || value.len() > crate::MAX_VALUE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "row exceeds live storage limits",
            ));
        }
        // Check the join to the previous piece *before* we flush its rows.
        if rows.last().is_some_and(|last| key <= last.0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bulk keys must strictly increase",
            ));
        }
        let charge = 64 + key.len() + value.len();
        if !rows.is_empty() && size + charge > PIECE_TARGET {
            flush_piece(file, &mut index, &mut rows)?;
            size = 0;
        }
        if let Some(filter) = &mut membership {
            filter.insert(&key);
        }
        rows.push((key, Some(value)));
        size += charge;
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid("bulk row count overflow"))?;
    }
    flush_piece(file, &mut index, &mut rows)?;
    if expected_filter_rows.is_some_and(|expected| expected != count) {
        return Err(invalid("filtered import row count differs"));
    }
    Ok((index.finish(file, membership.as_ref())?, count))
}
