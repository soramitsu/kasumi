//! Incremental copy-on-write edits.
//!
//! One sorted edit batch descends once, rewrites only the pages on changed
//! paths and copies untouched entries' encodings unchanged, so overflow values
//! of untouched entries are shared rather than rewritten. Rewritten pages
//! below the minimum fill merge with a sibling; a root with one child
//! collapses.
//!
//! Everything an edit replaces is deleted by its publication: the tree's
//! single live history owns those rows exclusively, and readers of older
//! roots keep their pinned native view. A large edit stages its new rows in
//! bounded batches before publication, each batch with a journal row naming
//! what it wrote. The publication deletes the journal rows with the replaced
//! rows, so a journal row that survives belongs to an edit that never
//! published, and recovery deletes exactly the rows it names.
use super::*;
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug)]
pub enum Edit<'a> {
    Put(&'a [u8], &'a [u8]),
    Delete(&'a [u8]),
}
impl Edit<'_> {
    pub fn key(&self) -> &[u8] {
        match self {
            Self::Put(key, _) | Self::Delete(key) => key,
        }
    }
}

/// Journal rows of staged, unpublished edits, across every page space of the
/// encryption domain. Small: an edit's publication removes its rows.
pub const EDIT_JOURNAL: &str = "kasumi.app.edit-journal";
// One of a staged batch's sixteen native puts is its journal row.
const STAGE_ROWS: usize = 15;
const STAGE_BYTES: usize = 3 << 20;
const MAX_JOURNAL_BYTES: usize = 64 << 10;

/// The new root and the native writes that publish it. Unstaged, they are
/// every new page and chunk plus deletions of what the edit replaced; staged,
/// the new rows are already durable and the writes delete the replaced rows
/// and the edit's journal. Either way they commit in one transaction with
/// whatever names the new root, and their admitted workspace stays with this
/// owner.
pub struct TreeEdit {
    pub root: TreeRoot,
    writes: Vec<WriteOp>,
    put_bytes: u64,
    staged_batches: u32,
    _workspace: EditWorkspace,
}
impl TreeEdit {
    pub fn writes(&self) -> &[WriteOp] {
        &self.writes
    }
    /// Namespace, key and value bytes of every put in `writes`.
    pub fn put_bytes(&self) -> u64 {
        self.put_bytes
    }
    /// Batches written ahead of publication.
    pub fn staged_batches(&self) -> u32 {
        self.staged_batches
    }
    /// The writes and the workspace that funds them; drop the writes first.
    pub fn into_parts(self) -> (TreeRoot, Vec<WriteOp>, EditWorkspace) {
        (self.root, self.writes, self._workspace)
    }
}

const WORKSPACE_BLOCK: u64 = 1 << 20;

/// Installed resident credit for an edit's loaded pages and unstaged rows,
/// grown in fixed blocks so one ledger entry covers many pages.
pub struct EditWorkspace {
    memory: Arc<dyn NodeDiskMemoryAdmission>,
    leases: Vec<DiskMemoryLease>,
    reserved: u64,
    used: u64,
}
impl EditWorkspace {
    fn new(memory: Arc<dyn NodeDiskMemoryAdmission>, initial: u64) -> Result<Self> {
        let mut workspace = Self {
            memory,
            leases: Vec::new(),
            reserved: 0,
            used: 0,
        };
        workspace.charge(initial)?;
        Ok(workspace)
    }
    fn charge(&mut self, bytes: u64) -> Result<()> {
        self.used = self
            .used
            .checked_add(bytes)
            .context("ordered edit workspace overflow")?;
        while self.used > self.reserved {
            let block = (self.used - self.reserved).max(WORKSPACE_BLOCK);
            self.leases
                .push(self.memory.clone().reserve_installed(block)?);
            self.reserved += block;
        }
        Ok(())
    }
    /// Staged rows no longer occupy the workspace; its credit is reused.
    fn release(&mut self, bytes: u64) {
        self.used = self.used.saturating_sub(bytes);
    }
}

struct Child {
    key: Vec<u8>,
    page: PageRef,
    /// Payload bytes and entries when written by this edit; untouched pages
    /// are not candidates for merging.
    fresh: Option<(usize, usize)>,
}

struct Staging<'a> {
    store: &'a TenantStore,
    edit: [u8; 16],
    journal: Vec<Vec<u8>>,
}

struct Editor<'a> {
    source: &'a dyn PageSource,
    space: &'a str,
    tree: [u8; 16],
    // New rows not yet staged.
    pending: BTreeMap<Vec<u8>, Vec<u8>>,
    pending_bytes: usize,
    // Selected rows, or rows this edit staged, that the new root no longer uses.
    obsolete: BTreeSet<Vec<u8>>,
    staging: Option<Staging<'a>>,
    workspace: EditWorkspace,
}

fn check_edits(edits: &[Edit<'_>]) -> Result<()> {
    for (index, edit) in edits.iter().enumerate() {
        ensure!(
            edit.key().len() <= MAX_KEY_BYTES,
            "ordered key exceeds bound"
        );
        if let Edit::Put(_, value) = edit {
            ensure!(
                value.len() <= MAX_VALUE_BYTES,
                "ordered value exceeds bound"
            );
        }
        ensure!(
            index == 0 || edits[index - 1].key() < edit.key(),
            "ordered edits are not strictly increasing"
        );
    }
    Ok(())
}

/// Apply `edits`, sorted by strictly increasing key, to `base`, keeping every
/// new row in the returned writes. Pages are read through `source`, which
/// must observe `base` exactly: the caller holds the publication gate under
/// which `base` is the selected root.
pub fn edit_tree(
    source: &dyn PageSource,
    space: &str,
    base: &TreeRoot,
    edits: &[Edit<'_>],
) -> Result<TreeEdit> {
    run(source, space, base, edits, None)
}

/// `edit_tree` whose publication stays small whatever the edit's size: once
/// its new rows exceed one staging batch they are written to `store` in
/// bounded journaled batches before returning. The caller must publish or
/// abandon the edit before editing again, and recover abandoned edits under
/// the same gate before its first edit.
pub fn edit_tree_staged(
    store: &TenantStore,
    space: &str,
    base: &TreeRoot,
    edits: &[Edit<'_>],
) -> Result<TreeEdit> {
    let staging = Staging {
        store,
        edit: *Uuid::new_v4().as_bytes(),
        journal: Vec::new(),
    };
    run(store, space, base, edits, Some(staging))
}

fn run<'a>(
    source: &'a dyn PageSource,
    space: &'a str,
    base: &TreeRoot,
    edits: &[Edit<'_>],
    staging: Option<Staging<'a>>,
) -> Result<TreeEdit> {
    check_edits(edits)?;
    validate_record(space, &[], 0)?;
    let workspace = EditWorkspace::new(source.memory(), path_workspace(base.height() + 1))?;
    let mut editor = Editor {
        source,
        space,
        tree: base.tree,
        pending: BTreeMap::new(),
        pending_bytes: 0,
        obsolete: BTreeSet::new(),
        staging,
        workspace,
    };
    let root = editor.edit_root(base, edits)?;
    let staged = editor
        .staging
        .as_ref()
        .is_some_and(|staging| !staging.journal.is_empty());
    if staged {
        editor.flush()?;
    }
    let mut put_bytes = 0u64;
    let journal = editor
        .staging
        .take()
        .map(|staging| staging.journal)
        .unwrap_or_default();
    let mut writes = Vec::new();
    writes.try_reserve_exact(editor.pending.len() + editor.obsolete.len() + journal.len())?;
    for (key, value) in std::mem::take(&mut editor.pending) {
        put_bytes += (space.len() + key.len() + value.len()) as u64;
        writes.push(WriteOp::Put {
            namespace: space.into(),
            key,
            value,
        });
    }
    for key in std::mem::take(&mut editor.obsolete) {
        writes.push(WriteOp::Delete {
            namespace: space.into(),
            key,
        });
    }
    let staged_batches = journal.len() as u32;
    for key in journal {
        writes.push(WriteOp::Delete {
            namespace: EDIT_JOURNAL.into(),
            key,
        });
    }
    Ok(TreeEdit {
        root,
        writes,
        put_bytes,
        staged_batches,
        _workspace: editor.workspace,
    })
}

fn journal_key(space: &str, edit: &[u8; 16], batch: u32) -> Vec<u8> {
    let mut key = Vec::with_capacity(2 + space.len() + 20);
    key.extend_from_slice(&(space.len() as u16).to_be_bytes());
    key.extend_from_slice(space.as_bytes());
    key.extend_from_slice(edit);
    key.extend_from_slice(&batch.to_be_bytes());
    key
}

/// Delete the rows of every staged edit that never published, one bounded
/// transaction per journal row. Run under the publication gate before the
/// first edit; returns the number of abandoned batches removed.
pub fn recover_abandoned_edits(store: &Arc<TenantStore>) -> Result<u64> {
    let view = store.read_view()?;
    let mut journal = Vec::new();
    view.visit(EDIT_JOURNAL, MAX_JOURNAL_BYTES, |key, value| {
        journal.push((key.to_vec(), value.to_vec()));
        Ok(())
    })?;
    view.close()?;
    let mut removed = 0;
    for (key, value) in journal {
        let mut reader = Reader {
            bytes: &key,
            offset: 0,
        };
        let space_len = usize::from(reader.u16()?);
        let space = std::str::from_utf8(reader.take(space_len)?)?;
        let _edit = reader.array::<16>()?;
        let _batch = reader.u32()?;
        ensure!(reader.offset == key.len(), "invalid edit journal key");
        let mut rows = Reader {
            bytes: &value,
            offset: 0,
        };
        let mut operations = Vec::new();
        while rows.offset < value.len() {
            let len = usize::from(rows.u16()?);
            let row = rows.take(len)?;
            ensure!(
                matches!(row.first(), Some(&PAGE_ROW | &CHUNK_ROW))
                    && operations.len() < STAGE_ROWS,
                "invalid edit journal row"
            );
            operations.push(WriteOp::delete(space, row));
        }
        operations.push(WriteOp::delete(EDIT_JOURNAL, key));
        store.write_batch(&operations)?;
        removed += 1;
    }
    Ok(removed)
}

impl Editor<'_> {
    fn edit_root(&mut self, base: &TreeRoot, edits: &[Edit<'_>]) -> Result<TreeRoot> {
        let children = match &base.root {
            None => {
                let mut entries = Vec::new();
                for edit in edits {
                    if let Edit::Put(key, value) = edit {
                        entries.push(self.encode_value(key, value)?);
                    }
                }
                self.write_level(0, &entries)?
            }
            Some(root) => match self.edit_node(root, None, None, edits)? {
                None => return Ok(*base),
                Some(children) => children,
            },
        };
        let mut level = children;
        loop {
            match level.len() {
                0 => return Ok(TreeRoot::empty(self.tree)),
                1 => {
                    let mut root = level.remove(0).page;
                    // Deletions can leave a chain of single children.
                    while root.level > 0 {
                        let page = self.load(&root, None, None)?;
                        if page.len() > 1 {
                            break;
                        }
                        self.obsolete_page(&root);
                        root = page.child(0);
                    }
                    return Ok(TreeRoot {
                        tree: self.tree,
                        root: Some(root),
                    });
                }
                _ => {
                    let parent = level[0].page.level + 1;
                    ensure!(
                        usize::from(parent) < MAX_HEIGHT,
                        "ordered tree exceeds its height bound"
                    );
                    let entries = level
                        .iter()
                        .map(|child| encode_child_entry(&child.key, &child.page))
                        .collect::<Result<Vec<_>>>()?;
                    level = self.write_level(parent, &entries)?;
                }
            }
        }
    }

    /// `None` when nothing under `page` changed; otherwise its replacement
    /// pages at the same level, possibly none.
    fn edit_node(
        &mut self,
        page_ref: &PageRef,
        low: Option<&[u8]>,
        high: Option<&[u8]>,
        edits: &[Edit<'_>],
    ) -> Result<Option<Vec<Child>>> {
        let page = self.load(page_ref, low, high)?;
        if page.is_leaf() {
            return self.edit_leaf(page_ref, &page, edits);
        }
        let mut children = Vec::with_capacity(page.len() + 2);
        let mut changed = false;
        let mut start = 0;
        for index in 0..page.len() {
            let next = if index + 1 < page.len() {
                let separator = page.key(index + 1);
                start + edits[start..].partition_point(|edit| edit.key() < separator)
            } else {
                edits.len()
            };
            let child = page.child(index);
            let key = page.key(index);
            let replaced = if next > start {
                let child_high = if index + 1 < page.len() {
                    Some(page.key(index + 1))
                } else {
                    high
                };
                self.edit_node(&child, Some(key), child_high, &edits[start..next])?
            } else {
                None
            };
            match replaced {
                None => children.push(Child {
                    key: key.to_vec(),
                    page: child,
                    fresh: None,
                }),
                Some(list) => {
                    changed = true;
                    children.extend(list);
                }
            }
            start = next;
        }
        if !changed {
            return Ok(None);
        }
        self.merge_underfull(&mut children)?;
        self.obsolete_page(page_ref);
        if children.is_empty() {
            return Ok(Some(Vec::new()));
        }
        let entries = children
            .iter()
            .map(|child| encode_child_entry(&child.key, &child.page))
            .collect::<Result<Vec<_>>>()?;
        Ok(Some(self.write_level(page.level, &entries)?))
    }

    fn edit_leaf(
        &mut self,
        page_ref: &PageRef,
        page: &Page,
        edits: &[Edit<'_>],
    ) -> Result<Option<Vec<Child>>> {
        let mut entries = Vec::with_capacity(page.len() + edits.len());
        let mut changed = false;
        let mut next = 0;
        for index in 0..page.len() {
            let key = page.key(index);
            while next < edits.len() && edits[next].key() < key {
                if let Edit::Put(key, value) = edits[next] {
                    entries.push(self.encode_value(key, value)?);
                    changed = true;
                }
                next += 1;
            }
            let existing = page.value(index);
            if next < edits.len() && edits[next].key() == key {
                match edits[next] {
                    Edit::Put(_, value) if same_value(&existing, value) => {
                        entries.push(page.entry_bytes(index).to_vec());
                    }
                    Edit::Put(key, value) => {
                        self.obsolete_value(&existing);
                        entries.push(self.encode_value(key, value)?);
                        changed = true;
                    }
                    Edit::Delete(_) => {
                        self.obsolete_value(&existing);
                        changed = true;
                    }
                }
                next += 1;
            } else {
                entries.push(page.entry_bytes(index).to_vec());
            }
        }
        for edit in &edits[next..] {
            if let Edit::Put(key, value) = edit {
                entries.push(self.encode_value(key, value)?);
                changed = true;
            }
        }
        if !changed {
            return Ok(None);
        }
        self.obsolete_page(page_ref);
        Ok(Some(self.write_level(0, &entries)?))
    }

    /// Merge each underfull rewritten child with a neighbour and repack. Two
    /// underfull pages fit one page; an underfull page and a sufficient one
    /// repack into one page or two balanced pages above the minimum fill.
    fn merge_underfull(&mut self, children: &mut Vec<Child>) -> Result<()> {
        let mut index = 0;
        while index < children.len() {
            let underfull = children[index]
                .fresh
                .is_some_and(|(bytes, entries)| underfull(bytes, entries));
            if !underfull || children.len() == 1 {
                index += 1;
                continue;
            }
            let left = if index + 1 < children.len() {
                index
            } else {
                index - 1
            };
            let level = children[left].page.level;
            let mut entries = Vec::new();
            for child in &children[left..left + 2] {
                let page = self.load(&child.page, None, None)?;
                for entry in 0..page.len() {
                    entries.push(page.entry_bytes(entry).to_vec());
                }
            }
            let (first, second) = (children[left].page, children[left + 1].page);
            self.obsolete_page(&first);
            self.obsolete_page(&second);
            let merged = self.write_level(level, &entries)?;
            children.splice(left..left + 2, merged);
            index = left;
        }
        Ok(())
    }

    fn write_level(&mut self, level: u8, entries: &[Vec<u8>]) -> Result<Vec<Child>> {
        let mut children = Vec::new();
        for range in pack(entries, MAX_PAYLOAD_BYTES) {
            let slices: Vec<&[u8]> = entries[range].iter().map(Vec::as_slice).collect();
            children.push(self.write_page(level, &slices)?);
        }
        Ok(children)
    }

    fn write_page(&mut self, level: u8, entries: &[&[u8]]) -> Result<Child> {
        let bytes = encode_page(&self.tree, level, entries);
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
        let fresh = (bytes.len() - HEADER_BYTES, entries.len());
        self.put_row(page.id.row_key().to_vec(), bytes)?;
        Ok(Child {
            key: entry_key(entries[0]).to_vec(),
            page,
            fresh: Some(fresh),
        })
    }

    fn encode_value(&mut self, key: &[u8], value: &[u8]) -> Result<Vec<u8>> {
        ensure!(
            value.len() <= MAX_VALUE_BYTES,
            "ordered value exceeds bound"
        );
        if value.len() <= MAX_INLINE_VALUE {
            return encode_inline_entry(key, value);
        }
        let overflow = OverflowRef {
            id: *Uuid::new_v4().as_bytes(),
            len: value.len() as u64,
            sha256: Sha256::digest(value).into(),
        };
        for (chunk, bytes) in value.chunks(OVERFLOW_CHUNK_BYTES).enumerate() {
            self.put_row(overflow.chunk_key(chunk as u32).to_vec(), bytes.to_vec())?;
        }
        encode_overflow_entry(key, &overflow)
    }

    fn put_row(&mut self, key: Vec<u8>, value: Vec<u8>) -> Result<()> {
        let bytes = key.len() + value.len();
        self.workspace.charge(bytes as u64 + 64)?;
        self.pending_bytes += bytes;
        self.pending.insert(key, value);
        if self.staging.is_some()
            && (self.pending.len() >= STAGE_ROWS || self.pending_bytes >= STAGE_BYTES)
        {
            self.flush()?;
        }
        Ok(())
    }

    /// Stage every pending row with one journal row naming them.
    fn flush(&mut self) -> Result<()> {
        let Some(staging) = self.staging.as_mut() else {
            return Ok(());
        };
        if self.pending.is_empty() {
            return Ok(());
        }
        let key = journal_key(
            self.space,
            &staging.edit,
            u32::try_from(staging.journal.len())?,
        );
        let mut names = Vec::new();
        let mut operations = Vec::with_capacity(self.pending.len() + 1);
        for (row, value) in std::mem::take(&mut self.pending) {
            names.extend_from_slice(&(row.len() as u16).to_be_bytes());
            names.extend_from_slice(&row);
            operations.push(WriteOp::Put {
                namespace: self.space.into(),
                key: row,
                value,
            });
        }
        operations.push(WriteOp::put(EDIT_JOURNAL, key.clone(), names));
        // The journal row commits with the rows it names.
        staging.journal.push(key);
        staging.store.write_batch(&operations)?;
        let released = self.pending_bytes as u64 + 64 * (operations.len() as u64 - 1);
        self.workspace.release(released);
        self.pending_bytes = 0;
        Ok(())
    }

    fn load(
        &mut self,
        page: &PageRef,
        low: Option<&[u8]>,
        high: Option<&[u8]>,
    ) -> Result<Arc<Page>> {
        self.source.check_access()?;
        let key = page.id.row_key();
        ensure!(
            !self.obsolete.contains(key.as_slice()),
            "ordered page was replaced by this edit"
        );
        // A staged row reads back through the store like any selected row.
        let decoded = match self.pending.get(key.as_slice()) {
            Some(bytes) => Page::decode(bytes, &self.tree, page)?,
            None => {
                let row = self
                    .source
                    .read_row(self.space, &key, MAX_PAGE_BYTES)?
                    .context("ordered page missing")?;
                Page::decode(row.as_bytes(), &self.tree, page)?
            }
        };
        decoded.check_bounds(low, high)?;
        Ok(Arc::new(decoded))
    }

    fn obsolete_row(&mut self, key: Vec<u8>) {
        // A row this edit wrote and never staged simply disappears.
        if let Some(value) = self.pending.remove(&key) {
            self.pending_bytes -= key.len() + value.len();
            self.workspace
                .release((key.len() + value.len()) as u64 + 64);
        } else {
            self.obsolete.insert(key);
        }
    }

    fn obsolete_page(&mut self, page: &PageRef) {
        self.obsolete_row(page.id.row_key().to_vec());
    }

    fn obsolete_value(&mut self, value: &ValueRef<'_>) {
        if let ValueRef::Overflow(overflow) = value {
            for chunk in 0..overflow.chunks() {
                self.obsolete_row(overflow.chunk_key(chunk).to_vec());
            }
        }
    }
}

/// An unchanged value keeps its encoding, overflow chunks included.
fn same_value(existing: &ValueRef<'_>, value: &[u8]) -> bool {
    match existing {
        ValueRef::Inline(bytes) => *bytes == value,
        ValueRef::Overflow(overflow) => {
            overflow.len == value.len() as u64
                && <[u8; 32]>::from(Sha256::digest(value)) == overflow.sha256
        }
    }
}
