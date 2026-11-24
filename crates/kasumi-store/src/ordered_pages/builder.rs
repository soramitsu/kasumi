//! Sorted bulk construction for snapshot installation and migration.
//!
//! Entries stream in key order; each level keeps one page in progress and one
//! finished page held back so the last two can be rebalanced. Rows (pages and
//! overflow chunks) leave through the caller's sink as soon as they are
//! final, so memory is bounded by the tree height, never by its size.
use super::*;

#[derive(Default)]
struct Level {
    current: Vec<Vec<u8>>,
    bytes: usize,
    held: Option<Vec<Vec<u8>>>,
    emitted: u64,
}

/// Receives each finished row: a page or an overflow chunk.
pub type RowSink<'a> = dyn FnMut(&[u8], &[u8]) -> Result<()> + 'a;

pub struct BulkBuilder<'e> {
    tree: [u8; 16],
    emit: &'e mut RowSink<'e>,
    levels: Vec<Level>,
    last: Option<Vec<u8>>,
    // Two pages per level plus one overflow value's chunk copies.
    _workspace: DiskMemoryLease,
}

const BUILDER_WORKSPACE: u64 =
    (MAX_HEIGHT as u64) * 3 * MAX_PAGE_BYTES as u64 + 4 * OVERFLOW_CHUNK_BYTES as u64;

impl<'e> BulkBuilder<'e> {
    pub fn new(
        tree: [u8; 16],
        memory: Arc<dyn NodeDiskMemoryAdmission>,
        emit: &'e mut RowSink<'e>,
    ) -> Result<Self> {
        Ok(Self {
            tree,
            emit,
            levels: Vec::new(),
            last: None,
            _workspace: memory.reserve_installed(BUILDER_WORKSPACE)?,
        })
    }

    pub fn push(&mut self, key: &[u8], value: &[u8]) -> Result<()> {
        ensure!(key.len() <= MAX_KEY_BYTES, "ordered key exceeds bound");
        ensure!(
            self.last.as_deref().is_none_or(|last| last < key),
            "bulk entries are not strictly increasing"
        );
        let emit = &mut *self.emit;
        let entry = encode_value(key, value, |row, bytes| emit(&row, &bytes))?;
        self.last = Some(key.to_vec());
        self.add(0, entry)
    }

    fn add(&mut self, level: usize, entry: Vec<u8>) -> Result<()> {
        ensure!(level < MAX_HEIGHT, "ordered tree exceeds its height bound");
        if self.levels.len() <= level {
            self.levels.push(Level::default());
        }
        let current = &mut self.levels[level];
        let mut finished = None;
        if !current.current.is_empty()
            && (current.bytes + entry.len() > BULK_FILL_BYTES
                || current.current.len() == MAX_PAGE_ENTRIES)
        {
            let full = std::mem::take(&mut current.current);
            current.bytes = 0;
            finished = current.held.replace(full);
        }
        current.bytes += entry.len();
        current.current.push(entry);
        if let Some(held) = finished {
            self.levels[level].emitted += 1;
            let (key, page) = self.emit_page(level as u8, &held)?;
            self.add(level + 1, encode_child_entry(&key, &page)?)?;
        }
        Ok(())
    }

    fn emit_page(&mut self, level: u8, entries: &[Vec<u8>]) -> Result<(Vec<u8>, PageRef)> {
        let slices: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
        let bytes = encode_page(&self.tree, level, &slices);
        ensure!(
            bytes.len() <= MAX_PAGE_BYTES,
            "ordered page exceeds its bound"
        );
        let (count, logical) = entries
            .iter()
            .fold((0u64, 0u64), |(count, logical), entry| {
                let (entries, bytes) = entry_aggregates(level, entry);
                (count + entries, logical + bytes)
            });
        let page = PageRef {
            id: PageId::fresh(),
            sha256: Sha256::digest(&bytes).into(),
            level,
            count,
            bytes: logical,
        };
        (self.emit)(&page.id.row_key(), &bytes)?;
        Ok((entry_key(&entries[0]).to_vec(), page))
    }

    pub fn finish(mut self) -> Result<TreeRoot> {
        let mut level = 0;
        loop {
            if level == self.levels.len() {
                return Ok(TreeRoot::empty(self.tree));
            }
            let Level {
                current,
                held,
                emitted,
                ..
            } = std::mem::take(&mut self.levels[level]);
            let top = level + 1 == self.levels.len();
            if top && emitted == 0 && held.is_none() {
                if current.is_empty() {
                    return Ok(TreeRoot::empty(self.tree));
                }
                let (_, root) = self.emit_page(level as u8, &current)?;
                return Ok(TreeRoot {
                    tree: self.tree,
                    root: Some(root),
                });
            }
            // Rebalance the held page with a short last page.
            let mut entries = held.unwrap_or_default();
            entries.extend(current);
            for range in pack(&entries, BULK_FILL_BYTES) {
                let (key, page) = self.emit_page(level as u8, &entries[range])?;
                self.add(level + 1, encode_child_entry(&key, &page)?)?;
            }
            level += 1;
        }
    }
}

/// Stream sorted entries into a fresh staged page space and seal it. The
/// caller selects the returned root together with the stage's owner.
pub fn stage_tree(
    stage: &NamespaceStage,
    tree: [u8; 16],
    entries: impl FnOnce(&mut BulkBuilder<'_>) -> Result<()>,
) -> Result<TreeRoot> {
    let memory = stage.memory();
    let mut root = None;
    stage.write_rows(|emit| {
        let mut builder = BulkBuilder::new(tree, memory, emit)?;
        entries(&mut builder)?;
        root = Some(builder.finish()?);
        Ok(())
    })?;
    root.context("staged tree did not finish")
}
