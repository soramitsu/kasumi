//! Point reads and bounded traversal of one selected root.
//!
//! A reader observes exactly the root it was given through a source pinned
//! at that root. Traversal keeps only its ancestor path: there are no leaf
//! sibling links, so a copy-on-write split never rewrites a neighbour.
use super::*;
use std::ops::Bound;

/// Copied keys and values of one page of entries.
#[cfg(test)]
pub(super) type Entries = Vec<(Vec<u8>, Vec<u8>)>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Forward,
    Reverse,
}

pub struct TreeReader<'s> {
    source: &'s dyn PageSource,
    space: &'s str,
    root: TreeRoot,
    cache: Option<&'s PageCache>,
    // Ancestor path and one overflow chunk, admitted before any page loads.
    _workspace: DiskMemoryLease,
}

struct Frame {
    page: Arc<Page>,
    // Forward: the next entry to visit. Reverse: entries left before the cursor.
    index: usize,
    high: Option<Vec<u8>>,
}

impl<'s> TreeReader<'s> {
    pub fn new(
        source: &'s dyn PageSource,
        space: &'s str,
        root: TreeRoot,
        cache: Option<&'s PageCache>,
    ) -> Result<Self> {
        source.check_access()?;
        let workspace = source
            .memory()
            .reserve_installed(path_workspace(root.height()))?;
        Ok(Self {
            source,
            space,
            root,
            cache,
            _workspace: workspace,
        })
    }

    pub fn root(&self) -> &TreeRoot {
        &self.root
    }

    fn load(&self, page: &PageRef, low: Option<&[u8]>, high: Option<&[u8]>) -> Result<Arc<Page>> {
        self.source.check_access()?;
        let key = self
            .cache
            .map(|_| PageCache::key(self.source.domain(), self.space, &self.root.tree, page));
        if let (Some(cache), Some(key)) = (self.cache, key.as_ref())
            && let Some(hit) = cache.get(key)
        {
            // The hash binds bytes, tree and level; aggregates and bounds
            // belong to this parent.
            hit.check_reference(page)?;
            hit.check_bounds(low, high)?;
            return Ok(hit);
        }
        let row = self
            .source
            .read_row(self.space, &page.id.row_key(), MAX_PAGE_BYTES)?
            .context("ordered page missing")?;
        let decoded = Arc::new(Page::decode(row.as_bytes(), &self.root.tree, page)?);
        drop(row);
        decoded.check_bounds(low, high)?;
        if let (Some(cache), Some(key)) = (self.cache, key) {
            cache.insert(key, &decoded, true);
        }
        Ok(decoded)
    }

    /// Check row presence without decoding its overflow value.
    pub fn contains_key(&self, key: &[u8]) -> Result<bool> {
        let present = self.find(key, |value| Ok(value.is_some()))?;
        self.source.check_access()?;
        Ok(present)
    }

    /// Copy the value at `key` into `out`, overflow included.
    pub fn get(&self, key: &[u8], out: &mut Vec<u8>) -> Result<bool> {
        self.find(key, |value| match value {
            Some(value) => {
                self.read_value(&value, out)?;
                Ok(true)
            }
            None => Ok(false),
        })
    }

    /// Lend a point's value only after enforcing the caller's decoded-input
    /// bound. An overflow copy has its own installed lease until the visitor
    /// returns; an inline value borrows the already admitted page.
    pub fn with_value<T>(
        &self,
        key: &[u8],
        max: usize,
        visit: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T> {
        let result = self.find(key, |value| {
            let Some(value) = value else {
                return visit(None);
            };
            ensure!(
                value.len() <= max as u64,
                "ordered point exceeds caller's value bound"
            );
            match value {
                ValueRef::Inline(bytes) => visit(Some(bytes)),
                ValueRef::Overflow(overflow) => {
                    let _lease = self
                        .source
                        .memory()
                        .reserve_installed(crate::disk_memory::allocation::<u8>(value.len())?)?;
                    let mut bytes = zeroize::Zeroizing::new(Vec::new());
                    bytes.try_reserve_exact(usize::try_from(value.len())?)?;
                    visit_overflow(self.source, self.space, &overflow, |chunk| {
                        bytes.extend_from_slice(chunk)
                    })?;
                    visit(Some(&bytes))
                }
            }
        })?;
        self.source.check_access()?;
        Ok(result)
    }

    /// Compare a stored value in byte order, authenticating every overflow
    /// chunk even when its first bytes already determine the ordering.
    pub fn compare_value_at(
        &self,
        key: &[u8],
        target: &[u8],
        max: usize,
    ) -> Result<Option<std::cmp::Ordering>> {
        use std::cmp::Ordering;
        let result = self.find(key, |value| {
            let Some(value) = value else { return Ok(None) };
            ensure!(
                value.len() <= max as u64,
                "ordered point exceeds caller's value bound"
            );
            match value {
                ValueRef::Inline(bytes) => Ok(Some(bytes.cmp(target))),
                ValueRef::Overflow(overflow) => {
                    let mut order = Ordering::Equal;
                    let mut remaining = target;
                    visit_overflow(self.source, self.space, &overflow, |chunk| {
                        if order == Ordering::Equal {
                            let common = chunk.len().min(remaining.len());
                            order = chunk[..common].cmp(&remaining[..common]);
                            if order == Ordering::Equal && common < chunk.len() {
                                order = Ordering::Greater;
                            }
                            remaining = &remaining[common..];
                        }
                    })?;
                    Ok(Some(
                        order.then_with(|| overflow.len.cmp(&(target.len() as u64))),
                    ))
                }
            }
        })?;
        self.source.check_access()?;
        Ok(result)
    }

    fn find<T>(
        &self,
        key: &[u8],
        found: impl FnOnce(Option<ValueRef<'_>>) -> Result<T>,
    ) -> Result<T> {
        self.source.check_access()?;
        let Some(mut page_ref) = self.root.root else {
            return found(None);
        };
        let mut low: Option<Vec<u8>> = None;
        let mut high: Option<Vec<u8>> = None;
        loop {
            let page = self.load(&page_ref, low.as_deref(), high.as_deref())?;
            if page.is_leaf() {
                let index = page.lower_bound(key);
                if index == page.len() || page.key(index) != key {
                    return found(None);
                }
                return found(Some(page.value(index)));
            }
            if key < page.key(0) {
                return found(None);
            }
            let index = page.child_index(key);
            page_ref = page.child(index);
            low = Some(page.key(index).to_vec());
            if index + 1 < page.len() {
                high = Some(page.key(index + 1).to_vec());
            }
        }
    }

    pub fn read_value(&self, value: &ValueRef<'_>, out: &mut Vec<u8>) -> Result<()> {
        self.source.check_access()?;
        match value {
            ValueRef::Inline(bytes) => {
                out.clear();
                out.try_reserve_exact(bytes.len())?;
                out.extend_from_slice(bytes);
                Ok(())
            }
            ValueRef::Overflow(overflow) => {
                let len = usize::try_from(overflow.len)?;
                ensure!(len <= MAX_VALUE_BYTES, "overflow value exceeds bound");
                out.clear();
                out.try_reserve_exact(len)?;
                let result = visit_overflow(self.source, self.space, overflow, |bytes| {
                    out.extend_from_slice(bytes)
                });
                if result.is_err() {
                    out.clear();
                }
                result
            }
        }
    }

    /// Verify the entire value while retaining at most one overflow chunk.
    pub fn value_sha256(&self, value: &ValueRef<'_>) -> Result<[u8; 32]> {
        self.source.check_access()?;
        match value {
            ValueRef::Inline(bytes) => Ok(Sha256::digest(bytes).into()),
            ValueRef::Overflow(overflow) => {
                visit_overflow(self.source, self.space, overflow, |_| {})?;
                Ok(overflow.sha256)
            }
        }
    }

    /// Visit entries from `start` in `direction` until `visit` returns false.
    /// An entry's overflow value is read only if the visitor asks for it.
    pub fn scan(
        &self,
        start: Bound<&[u8]>,
        direction: Direction,
        visit: &mut dyn FnMut(&[u8], ValueRef<'_>) -> Result<bool>,
    ) -> Result<()> {
        self.source.check_access()?;
        let Some(root) = self.root.root else {
            return Ok(());
        };
        let mut stack = Vec::with_capacity(self.root.height());
        let mut page_ref = root;
        let mut low: Option<Vec<u8>> = None;
        let mut high: Option<Vec<u8>> = None;
        loop {
            let page = self.load(&page_ref, low.as_deref(), high.as_deref())?;
            if page.is_leaf() {
                let index = match (direction, start) {
                    (Direction::Forward, Bound::Unbounded) => 0,
                    (Direction::Forward, Bound::Included(key)) => page.lower_bound(key),
                    (Direction::Forward, Bound::Excluded(key))
                    | (Direction::Reverse, Bound::Included(key)) => page.upper_bound(key),
                    (Direction::Reverse, Bound::Excluded(key)) => page.lower_bound(key),
                    (Direction::Reverse, Bound::Unbounded) => page.len(),
                };
                stack.push(Frame { page, index, high });
                break;
            }
            let index = match start {
                Bound::Included(key) | Bound::Excluded(key) => page.child_index(key),
                Bound::Unbounded if direction == Direction::Forward => 0,
                Bound::Unbounded => page.len() - 1,
            };
            page_ref = page.child(index);
            low = Some(page.key(index).to_vec());
            let child_high = if index + 1 < page.len() {
                Some(page.key(index + 1).to_vec())
            } else {
                high.clone()
            };
            stack.push(Frame { page, index, high });
            high = child_high;
        }
        loop {
            let leaf = stack.last_mut().expect("leaf frame");
            match direction {
                Direction::Forward => {
                    while leaf.index < leaf.page.len() {
                        let index = leaf.index;
                        leaf.index += 1;
                        if !visit(leaf.page.key(index), leaf.page.value(index))? {
                            return Ok(());
                        }
                    }
                }
                Direction::Reverse => {
                    while leaf.index > 0 {
                        leaf.index -= 1;
                        let index = leaf.index;
                        if !visit(leaf.page.key(index), leaf.page.value(index))? {
                            return Ok(());
                        }
                    }
                }
            }
            stack.pop();
            // Climb to the nearest ancestor with another child this way.
            loop {
                let Some(parent) = stack.last_mut() else {
                    return Ok(());
                };
                match direction {
                    Direction::Forward if parent.index + 1 < parent.page.len() => {
                        parent.index += 1;
                        break;
                    }
                    Direction::Reverse if parent.index > 0 => {
                        parent.index -= 1;
                        break;
                    }
                    _ => {
                        stack.pop();
                    }
                }
            }
            // Descend along the near edge to the next leaf.
            loop {
                let parent = stack.last().expect("parent frame");
                let index = parent.index;
                let child = parent.page.child(index);
                let low = parent.page.key(index).to_vec();
                let high = if index + 1 < parent.page.len() {
                    Some(parent.page.key(index + 1).to_vec())
                } else {
                    parent.high.clone()
                };
                let page = self.load(&child, Some(&low), high.as_deref())?;
                let index = match direction {
                    Direction::Forward => 0,
                    Direction::Reverse if page.is_leaf() => page.len(),
                    Direction::Reverse => page.len() - 1,
                };
                let leaf = page.is_leaf();
                stack.push(Frame { page, index, high });
                if leaf {
                    break;
                }
            }
        }
    }

    /// Up to `limit` entries after (or before) `start`, copying overflow
    /// values. Returns the entries and whether the range continues.
    #[cfg(test)]
    pub(super) fn page(
        &self,
        start: Bound<&[u8]>,
        direction: Direction,
        limit: usize,
    ) -> Result<(Entries, bool)> {
        let mut entries = Vec::new();
        let mut more = false;
        self.scan(start, direction, &mut |key, value| {
            if entries.len() == limit {
                more = true;
                return Ok(false);
            }
            let mut bytes = Vec::new();
            self.read_value(&value, &mut bytes)?;
            entries.push((key.to_vec(), bytes));
            Ok(true)
        })?;
        Ok((entries, more))
    }

    /// Warm the cache from the root without evicting what it has already
    /// warmed. Returns true when every page of this root is resident; above
    /// budget it stops retaining and later reads go through bounded loads.
    pub fn preload(&self) -> Result<bool> {
        let (Some(cache), Some(root)) = (self.cache, self.root.root) else {
            return Ok(false);
        };
        let mut pending = vec![(root, None::<Vec<u8>>, None::<Vec<u8>>)];
        while let Some((page_ref, low, high)) = pending.pop() {
            self.source.check_access()?;
            let key = PageCache::key(self.source.domain(), self.space, &self.root.tree, &page_ref);
            let page = match cache.get(&key) {
                Some(page) => page,
                None => {
                    let row = self
                        .source
                        .read_row(self.space, &page_ref.id.row_key(), MAX_PAGE_BYTES)?
                        .context("ordered page missing")?;
                    let page = Arc::new(Page::decode(row.as_bytes(), &self.root.tree, &page_ref)?);
                    if !cache.insert(key, &page, false) {
                        return Ok(false);
                    }
                    page
                }
            };
            page.check_reference(&page_ref)?;
            page.check_bounds(low.as_deref(), high.as_deref())?;
            if !page.is_leaf() {
                for index in (0..page.len()).rev() {
                    let child_high = if index + 1 < page.len() {
                        Some(page.key(index + 1).to_vec())
                    } else {
                        high.clone()
                    };
                    pending.push((
                        page.child(index),
                        Some(page.key(index).to_vec()),
                        child_high,
                    ));
                }
            }
        }
        Ok(true)
    }

    /// Authenticate every page and overflow value reachable from the root.
    /// Returns the number of pages.
    pub fn verify(&self) -> Result<u64> {
        let Some(root) = self.root.root else {
            return Ok(0);
        };
        let mut pages = 0u64;
        let mut pending = vec![(root, None::<Vec<u8>>, None::<Vec<u8>>)];
        while let Some((page_ref, low, high)) = pending.pop() {
            let page = self.load(&page_ref, low.as_deref(), high.as_deref())?;
            pages += 1;
            if page.is_leaf() {
                for index in 0..page.len() {
                    if let overflow @ ValueRef::Overflow(_) = page.value(index) {
                        self.value_sha256(&overflow)?;
                    }
                }
                continue;
            }
            for index in 0..page.len() {
                let child_high = if index + 1 < page.len() {
                    Some(page.key(index + 1).to_vec())
                } else {
                    high.clone()
                };
                pending.push((
                    page.child(index),
                    Some(page.key(index).to_vec()),
                    child_high,
                ));
            }
        }
        Ok(pages)
    }
}

impl Page {
    /// The first index whose key is above `key`.
    fn upper_bound(&self, key: &[u8]) -> usize {
        let mut low = 0;
        let mut high = self.len();
        while low < high {
            let middle = (low + high) / 2;
            if self.key(middle) <= key {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        low
    }
}
