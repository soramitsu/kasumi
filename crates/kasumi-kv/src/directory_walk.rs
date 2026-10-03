//! Resumable, bounded traversal of one retained directory root.
//!
//! The caller keeps the physical root pinned and supplies the uncached arena
//! backend. Only a fixed reference/index path, two separator keys, and one
//! admitted page buffer survive between steps. Restoring a parent rereads its
//! immediate separator source pages and the parent, never a whole root path.

use super::*;

#[derive(Clone, Copy)]
struct KeySource {
    page: DirectoryPageRef,
    at: usize,
    len: usize,
}

#[derive(Clone, Copy)]
struct Frame {
    reference: DirectoryPageRef,
    info: PageInfo,
    ceiling_generation: u64,
    lower: Option<KeySource>,
    upper: Option<KeySource>,
    next_at: usize,
    next_index: usize,
}

#[derive(Clone, Copy)]
struct Pending {
    reference: DirectoryPageRef,
    lower: Option<KeySource>,
    upper: Option<KeySource>,
}

#[derive(Clone, Copy)]
enum Action {
    Enter(Pending),
    Entries,
    RestoreLower,
    RestoreUpper,
    RestorePage,
    Complete,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DirectoryWalkProgress {
    /// Physical page loads plus visited directory entries in this step.
    pub(crate) work: usize,
    /// Newly visited pages; ancestor reloads consume work but no callback.
    pub(crate) pages: usize,
    /// Both table/row leaf entries and child entries consume work.
    pub(crate) entries: usize,
    pub(crate) complete: bool,
}

pub(crate) struct DirectoryWalker {
    root: DirectoryRoot,
    admission: Arc<dyn StorageAdmission>,
    frames: [Option<Frame>; MAX_HEIGHT],
    depth: usize,
    bounds: Bounds,
    buffer: Option<PageBuffer>,
    loaded: Option<DirectoryPageRef>,
    action: Action,
    failed: bool,
    _lease: Box<dyn ResidentLease>,
}

impl DirectoryWalker {
    /// Reserve all traversal backing before any page read or callback. An
    /// error here leaves the root untouched and can be retried independently.
    pub(crate) fn new(
        root: DirectoryRoot,
        admission: Arc<dyn StorageAdmission>,
    ) -> Result<Self, CoreError> {
        admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        root.validate()?;
        let lease = reserve(
            &admission,
            std::mem::size_of::<Self>()
                + std::mem::size_of::<Frame>()
                + std::mem::size_of::<DirectoryReader<'_>>()
                + 2 * std::mem::size_of::<KeySource>(),
        )?;
        let buffer = root.page.map(|_| PageBuffer::new(&admission)).transpose()?;
        admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)?;
        Ok(Self {
            root,
            admission,
            frames: [None; MAX_HEIGHT],
            depth: 0,
            bounds: Bounds {
                lower: [0; MAX_ENCODED_KEY],
                lower_len: 0,
                upper: [0; MAX_ENCODED_KEY],
                upper_len: 0,
                entries: root.entries,
                level: root.height.saturating_sub(1),
                generation: root.generation,
            },
            buffer,
            loaded: None,
            action: root.page.map_or(Action::Complete, |reference| {
                Action::Enter(Pending {
                    reference,
                    lower: None,
                    upper: None,
                })
            }),
            failed: false,
            _lease: lease,
        })
    }

    pub(crate) fn root(&self) -> DirectoryRoot {
        self.root
    }

    /// Visit new pages and row value locations under one hard work ceiling.
    /// Each successful callback runs exactly once during this traversal.
    /// The caller must discard its accumulated proof after any error; this
    /// walker is poisoned, including on callback or admission failure. Drop
    /// releases all scratch without requiring another successful step.
    pub(crate) fn step(
        &mut self,
        backend: &dyn DirectoryBackend,
        work_limit: usize,
        mut page: impl FnMut(DirectoryPageRef) -> Result<(), CoreError>,
        mut value: impl FnMut(ValueLocation) -> Result<(), CoreError>,
    ) -> Result<DirectoryWalkProgress, CoreError> {
        if self.failed {
            return Err(CoreError::OwnerFailed);
        }
        let result = self.step_inner(backend, work_limit, &mut page, &mut value);
        if result.is_err() {
            self.failed = true;
        }
        result
    }

    fn check_owner(&self) -> Result<(), CoreError> {
        self.admission
            .check_owner()
            .map_err(|_| CoreError::OwnerFailed)
    }

    fn step_inner(
        &mut self,
        backend: &dyn DirectoryBackend,
        work_limit: usize,
        page: &mut impl FnMut(DirectoryPageRef) -> Result<(), CoreError>,
        value: &mut impl FnMut(ValueLocation) -> Result<(), CoreError>,
    ) -> Result<DirectoryWalkProgress, CoreError> {
        self.check_owner()?;
        let mut progress = DirectoryWalkProgress::default();
        while progress.work < work_limit {
            self.check_owner()?;
            match self.action {
                Action::Complete => break,
                Action::Enter(pending) => {
                    let reader = DirectoryReader::new(backend, self.admission.clone());
                    let info = reader.load(
                        self.buffer.as_mut().expect("nonempty root"),
                        self.root,
                        pending.reference,
                        &self.bounds,
                    )?;
                    progress.work += 1;
                    self.loaded = Some(pending.reference);
                    page(pending.reference)?;
                    self.check_owner()?;
                    self.frames[self.depth] = Some(Frame {
                        reference: pending.reference,
                        info,
                        ceiling_generation: self.bounds.generation,
                        lower: pending.lower,
                        upper: pending.upper,
                        next_at: HEADER_BYTES,
                        next_index: 0,
                    });
                    self.depth += 1;
                    self.action = Action::Entries;
                    progress.pages += 1;
                }
                Action::Entries => {
                    let frame = self.frames[self.depth - 1].expect("loaded page");
                    if frame.next_index == frame.info.count {
                        self.depth -= 1;
                        self.frames[self.depth] = None;
                        if self.depth == 0 {
                            self.action = Action::Complete;
                        } else {
                            let parent = self.frames[self.depth - 1].expect("parent");
                            if parent.next_index == parent.info.count {
                                // Its final child just completed. Pop this
                                // already-validated parent without rereading
                                // a page that has no remaining entries.
                                self.action = Action::Entries;
                            } else {
                                self.bounds.lower_len = 0;
                                self.bounds.upper_len = 0;
                                self.bounds.level = parent.info.level;
                                self.bounds.entries = parent.info.entries;
                                self.bounds.generation = parent.ceiling_generation;
                                self.action = Action::RestoreLower;
                            }
                        }
                        continue;
                    }
                    let bytes = &self.buffer.as_ref().expect("loaded page").bytes;
                    let (entry, end) = page_entry(bytes, frame.next_at, frame.info.used)?;
                    if frame.info.level == 0 {
                        if let DirectoryValue::Row {
                            value: location, ..
                        } =
                            DirectoryValue::decode(entry.key, entry.value, frame.info.generation)?
                        {
                            value(location)?;
                        }
                    } else {
                        let lower = KeySource {
                            page: frame.reference,
                            at: frame.next_at,
                            len: entry.key_bytes.len(),
                        };
                        let upper = if frame.next_index + 1 < frame.info.count {
                            let (next, _) = page_entry(bytes, end, frame.info.used)?;
                            self.bounds.upper_len = next.key_bytes.len();
                            self.bounds.upper[..self.bounds.upper_len]
                                .copy_from_slice(next.key_bytes);
                            Some(KeySource {
                                page: frame.reference,
                                at: end,
                                len: next.key_bytes.len(),
                            })
                        } else {
                            frame.upper
                        };
                        self.bounds.lower_len = entry.key_bytes.len();
                        self.bounds.lower[..self.bounds.lower_len].copy_from_slice(entry.key_bytes);
                        self.bounds.entries = le_u64(&entry.value[PAGE_REF_BYTES..]);
                        self.bounds.level = frame.info.level - 1;
                        self.bounds.generation = frame.info.generation;
                        self.action = Action::Enter(Pending {
                            reference: DirectoryPageRef::decode(&entry.value[..PAGE_REF_BYTES])?,
                            lower: Some(lower),
                            upper,
                        });
                    }
                    let parent = self.frames[self.depth - 1].as_mut().expect("loaded page");
                    parent.next_at = end;
                    parent.next_index += 1;
                    self.check_owner()?;
                    progress.work += 1;
                    progress.entries += 1;
                }
                Action::RestoreLower => {
                    let frame = self.frames[self.depth - 1].expect("parent");
                    if let Some(key) = frame.lower {
                        self.restore_key(backend, key, true, &mut progress)?;
                    }
                    self.action = Action::RestoreUpper;
                }
                Action::RestoreUpper => {
                    let frame = self.frames[self.depth - 1].expect("parent");
                    if let Some(key) = frame.upper {
                        self.restore_key(backend, key, false, &mut progress)?;
                    }
                    self.action = Action::RestorePage;
                }
                Action::RestorePage => {
                    let frame = self.frames[self.depth - 1].expect("parent");
                    let reader = DirectoryReader::new(backend, self.admission.clone());
                    let info = reader.load(
                        self.buffer.as_mut().expect("nonempty root"),
                        self.root,
                        frame.reference,
                        &self.bounds,
                    )?;
                    progress.work += 1;
                    if info != frame.info {
                        return Err(CoreError::Corrupt("directory changed during traversal"));
                    }
                    self.loaded = Some(frame.reference);
                    self.action = Action::Entries;
                }
            }
        }
        self.check_owner()?;
        progress.complete = matches!(self.action, Action::Complete);
        Ok(progress)
    }

    fn restore_key(
        &mut self,
        backend: &dyn DirectoryBackend,
        key: KeySource,
        lower: bool,
        progress: &mut DirectoryWalkProgress,
    ) -> Result<(), CoreError> {
        self.check_owner()?;
        let buffer = self.buffer.as_mut().expect("nonempty root");
        if self.loaded != Some(key.page) {
            backend.read_page(key.page, &mut buffer.bytes)?;
            self.admission
                .check_owner()
                .map_err(|_| CoreError::OwnerFailed)?;
            progress.work += 1;
            self.loaded = Some(key.page);
        }
        // This separator source was already fully validated on descent. Its
        // complete SHA reference certifies those same parent bounds on reuse;
        // canonical validation here rejects substitution or changed bytes.
        let info = validate_page(&buffer.bytes, self.root, key.page)?;
        let (entry, _) = page_entry(&buffer.bytes, key.at, info.used)?;
        if entry.key_bytes.len() != key.len {
            return Err(CoreError::Corrupt(
                "directory separator changed during traversal",
            ));
        }
        if lower {
            self.bounds.lower_len = key.len;
            self.bounds.lower[..key.len].copy_from_slice(entry.key_bytes);
        } else {
            self.bounds.upper_len = key.len;
            self.bounds.upper[..key.len].copy_from_slice(entry.key_bytes);
        }
        self.check_owner()
    }
}
