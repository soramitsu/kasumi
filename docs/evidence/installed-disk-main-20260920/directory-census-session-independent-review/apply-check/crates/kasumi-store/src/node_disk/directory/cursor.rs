//! Bounded, enrolled directory reads. No mutation or implicit adoption.
use super::super::{AccountedFile, CensusCancellation, extent};
use super::*;
use std::{
    ffi::CStr,
    os::fd::{FromRawFd, IntoRawFd},
    ptr::NonNull,
    sync::atomic::Ordering,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeDiskEntryKind {
    File,
    Directory,
}
/// Exact inline close outcome retained independently of a preceding read error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeDiskDirectoryCloseError {
    pub kind: io::ErrorKind,
    pub raw_os_error: Option<i32>,
}
impl NodeDiskDirectoryCloseError {
    fn error(self) -> io::Error {
        self.raw_os_error
            .map_or_else(|| self.kind.into(), io::Error::from_raw_os_error)
    }
}
/// A name borrows the native stream and cannot survive its next read or Drop.
/// Entry metadata grants no raw descriptor or mutation permission.
#[derive(Debug)]
pub struct NodeDiskDirectoryEntry<'cursor> {
    name: &'cursor CStr,
    kind: NodeDiskEntryKind,
}
impl NodeDiskDirectoryEntry<'_> {
    pub fn name(&self) -> &CStr {
        self.name
    }
    pub fn kind(&self) -> NodeDiskEntryKind {
        self.kind
    }
}

struct Stream {
    disk: Arc<NodeDisk>,
    pointer: Option<NonNull<libc::DIR>>,
    #[cfg(test)]
    after_close: Option<ClosePause>,
    #[cfg(test)]
    force_close_error: bool,
}
impl Stream {
    fn retire(&mut self) -> io::Result<()> {
        let Some(pointer) = self.pointer.take() else {
            return Ok(());
        };
        // SAFETY: this sole owner consumes the live DIR exactly once. The
        // independent stream FD and libc buffer retire before slot credit.
        let result = unsafe { libc::closedir(pointer.as_ptr()) };
        let error = (result != 0).then(io::Error::last_os_error);
        #[cfg(test)]
        let error = if self.force_close_error {
            Some(io::ErrorKind::Other.into())
        } else {
            error
        };
        #[cfg(test)]
        if let Some(pause) = self.after_close.take() {
            pause.entered.send(()).unwrap();
            pause
                .release
                .recv_timeout(std::time::Duration::from_secs(5))
                .expect("release cursor retirement");
        }
        let mut state = self.disk.lock_state();
        if let Some(error) = error {
            // An uncertain close retains the stream count and installed memory
            // owner. Reconciliation cannot manufacture a completed drain.
            self.disk.fail_locked(&mut state);
            // A count alone cannot keep the installed owner alive once all
            // external Arcs drop. Retain one existing strong reference for
            // this uncertain native resource until process exit. Never retry
            // closedir on a possibly consumed pointer. No allocation/callback.
            let _ = Arc::into_raw(self.disk.clone());
            return Err(error);
        }
        let Some(next) = state.open_directory_cursors.checked_sub(1) else {
            self.disk.fail_locked(&mut state);
            return Err(io::ErrorKind::InvalidData.into());
        };
        state.open_directory_cursors = next;
        Ok(())
    }
    fn close(mut self) -> io::Result<()> {
        self.retire()
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        let _ = self.retire();
    }
}

/// An exclusive stream, intentionally not Send/Sync. It borrows no naked fd and
/// retains its counted directory until stream/buffer destruction has completed.
/// At most max_depth streams share the census workspace reservation;
/// every one prevents reconciliation through its actual directory registration.
pub struct NodeDiskDirectoryCursor {
    stream: Option<Stream>,
    directory: Option<NodeDiskDirectory>,
    generation: u64,
    expected_children: u64,
    work: u64,
    children: u64,
    finished: bool,
    failure: Option<io::ErrorKind>,
    close_error: Option<NodeDiskDirectoryCloseError>,
}
impl std::fmt::Debug for NodeDiskDirectoryCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeDiskDirectoryCursor")
            .field("work", &self.work)
            .field("children", &self.children)
            .field("finished", &self.finished)
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}
impl NodeDiskDirectory {
    pub fn cursor(mut self, cancel: &CensusCancellation) -> io::Result<NodeDiskDirectoryCursor> {
        if cancel.cancelled.load(Ordering::Acquire) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        if Arc::get_mut(self.0.as_mut().expect("live directory custody")).is_none() {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let disk = self.owner().disk.clone();
        // If construction unwinds after stream publication, State unlocks
        // before the registered stream and the input directory retire.
        let stream;
        let mut state = disk.lock_state();
        if state.phase != NodeDiskPhase::Open || !disk.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        if state.open_directory_cursors >= disk.config.max_depth {
            return Err(io::ErrorKind::StorageFull.into());
        }
        self.verify(&state)
            .inspect_err(|_| disk.fail_locked(&mut state))?;
        let entry = *state.accounted[&self.owner().identity]
            .directory()
            .expect("verified directory");
        let generation = state.namespace_generation;
        let next = state
            .open_directory_cursors
            .checked_add(1)
            .ok_or(io::ErrorKind::StorageFull)?;
        // dup shares a directory offset. openat(".") owns an independent file
        // description, exactly as the existing census stream does.
        let file = census::open_at(
            self.owner().file.as_ref().expect("live directory"),
            c".",
            libc::O_RDONLY | libc::O_DIRECTORY,
        )
        .inspect_err(|_| disk.fail_locked(&mut state))?;
        checked_entry(&state, &file, entry.binding, entry.parent)
            .map(|_| ())
            .inspect_err(|_| disk.fail_locked(&mut state))?;
        let fd = file.into_raw_fd();
        // SAFETY: fdopendir takes sole fd ownership only on success.
        let pointer = unsafe { libc::fdopendir(fd) };
        let Some(pointer) = NonNull::new(pointer) else {
            let error = io::Error::last_os_error();
            drop(unsafe { File::from_raw_fd(fd) });
            return Err(error);
        };
        state.open_directory_cursors = next;
        stream = Stream {
            disk: disk.clone(),
            pointer: Some(pointer),
            #[cfg(test)]
            after_close: None,
            #[cfg(test)]
            force_close_error: false,
        };
        drop(state);
        Ok(NodeDiskDirectoryCursor {
            stream: Some(stream),
            directory: Some(self),
            generation,
            expected_children: entry.children,
            work: 0,
            children: 0,
            finished: false,
            failure: None,
            close_error: None,
        })
    }
}
impl NodeDiskDirectoryCursor {
    fn finish(&mut self) -> io::Result<()> {
        self.finished = true;
        if let Some(error) = self.close_error {
            return Err(error.error());
        }
        let result = self.stream.take().map_or(Ok(()), Stream::close);
        if let Err(error) = &result {
            self.close_error = Some(NodeDiskDirectoryCloseError {
                kind: error.kind(),
                raw_os_error: error.raw_os_error(),
            });
        }
        result
    }
    /// Explicit retirement is required before publishing a partial page.
    /// The retained directory remains counted until this cursor drops.
    pub fn close(&mut self) -> io::Result<()> {
        self.finish()
    }
    /// A primary read/cancellation error never overwrites an independent close
    /// failure. This inline observation survives repeated next/close calls.
    pub fn close_error(&self) -> Option<NodeDiskDirectoryCloseError> {
        self.close_error
    }
    fn stop(&mut self, kind: io::ErrorKind) {
        self.failure = Some(kind);
        let _ = self.finish();
    }
    pub fn next(
        &mut self,
        cancel: &CensusCancellation,
    ) -> io::Result<Option<NodeDiskDirectoryEntry<'_>>> {
        if let Some(kind) = self.failure {
            return Err(kind.into());
        }
        if let Some(error) = self.close_error {
            return Err(error.error());
        }
        if self.finished {
            return Ok(None);
        }
        let disk = self
            .directory
            .as_ref()
            .expect("retained directory")
            .owner()
            .disk
            .clone();
        loop {
            if cancel.cancelled.load(Ordering::Acquire) {
                self.stop(io::ErrorKind::Interrupted);
                return Err(io::ErrorKind::Interrupted.into());
            }
            let mut state = disk.lock_state();
            if state.phase == NodeDiskPhase::Failed || !disk.device.lock().admission_ready() {
                drop(state);
                self.stop(io::ErrorKind::Other);
                return Err(io::ErrorKind::Other.into());
            }
            if state.namespace_generation != self.generation {
                // A managed mutation makes this scan incomplete, even a rename
                // that preserved length/blocks/count. It does not corrupt disk.
                drop(state);
                self.stop(io::ErrorKind::WouldBlock);
                return Err(io::ErrorKind::WouldBlock.into());
            }
            let directory = self.directory.as_ref().expect("retained directory");
            let result = (|| -> io::Result<Option<(*const libc::c_char, NodeDiskEntryKind)>> {
                directory.verify(&state)?;
                #[cfg(target_os = "macos")]
                unsafe {
                    *libc::__error() = 0;
                }
                #[cfg(target_os = "linux")]
                unsafe {
                    *libc::__errno_location() = 0;
                }
                // SAFETY: this cursor owns the only reference to its DIR. &mut
                // self excludes another read and any previous borrowed entry.
                let item = unsafe {
                    libc::readdir(
                        self.stream
                            .as_ref()
                            .expect("active stream")
                            .pointer
                            .expect("live stream")
                            .as_ptr(),
                    )
                };
                if item.is_null() {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(0) {
                        return Err(error);
                    }
                    directory.verify(&state)?;
                    if self.children != self.expected_children {
                        return Err(io::ErrorKind::InvalidData.into());
                    }
                    return Ok(None);
                }
                self.work = self.work.checked_add(1).ok_or(io::ErrorKind::StorageFull)?;
                // This operational scan visits one enrolled directory. Its complete
                // returned-entry bound is the retained child count plus dots;
                // census_work_per_step is not a lifetime limit for this cursor.
                if self.work > self.expected_children.checked_add(2).ok_or(io::ErrorKind::InvalidData)? {
                    return Err(io::ErrorKind::StorageFull.into());
                }
                let name = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) };
                if name.to_bytes().len() > disk.config.max_name_bytes as usize {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                if name.to_bytes() == b"." || name.to_bytes() == b".." {
                    return Ok(Some((std::ptr::null(), NodeDiskEntryKind::Directory)));
                }
                self.children = self
                    .children
                    .checked_add(1)
                    .ok_or(io::ErrorKind::InvalidData)?;
                if self.children > self.expected_children {
                    return Err(io::ErrorKind::InvalidData.into());
                }
                let parent = directory.owner();
                let parent_entry = state.accounted[&parent.identity]
                    .directory()
                    .expect("verified parent");
                let binding = parent_entry.binding.child(name);
                let file = census::open_at(
                    parent.file.as_ref().expect("retained parent"),
                    name,
                    libc::O_RDONLY | libc::O_NONBLOCK,
                )?;
                let metadata = file.metadata()?;
                let identity = Identity::of(&metadata);
                let kind = match state.accounted.get(&identity) {
                    Some(AccountedInode::File(entry)) if entry.binding == binding => {
                        census::regular_nonallocating(&metadata, parent.identity.0)?;
                        // Same enrollment predicate as exclusive file open:
                        // stable EOF alone cannot detect sparse materialization.
                        let (bytes, pending) = extent(&metadata, disk.unit)?;
                        if metadata.len() != entry.actual_len
                            || entry.actual_len > entry.reserved_len
                            || bytes > entry.bytes
                            || (entry.settled
                                && *entry
                                    != AccountedFile::durable(
                                        binding,
                                        bytes,
                                        pending,
                                        metadata.len(),
                                    ))
                        {
                            return Err(io::ErrorKind::InvalidData.into());
                        }
                        NodeDiskEntryKind::File
                    }
                    Some(AccountedInode::Directory(_)) => {
                        checked_entry(&state, &file, binding, Some(parent.identity))?;
                        NodeDiskEntryKind::Directory
                    }
                    _ => return Err(io::ErrorKind::InvalidData.into()),
                };
                directory.verify(&state)?;
                Ok(Some((name.as_ptr(), kind)))
            })();
            match result {
                Err(error) => {
                    if error.kind() != io::ErrorKind::StorageFull {
                        disk.fail_locked(&mut state);
                    }
                    drop(state);
                    self.stop(error.kind());
                    return Err(error);
                }
                Ok(None) => {
                    drop(state);
                    if let Err(error) = self.finish() {
                        self.failure = Some(error.kind());
                        return Err(error);
                    }
                    if cancel.cancelled.load(Ordering::Acquire) {
                        self.stop(io::ErrorKind::Interrupted);
                        return Err(io::ErrorKind::Interrupted.into());
                    }
                    return Ok(None);
                }
                Ok(Some((name, kind))) => {
                    drop(state);
                    if name.is_null() {
                        continue;
                    }
                    if cancel.cancelled.load(Ordering::Acquire) {
                        self.stop(io::ErrorKind::Interrupted);
                        return Err(io::ErrorKind::Interrupted.into());
                    }
                    // SAFETY: validation above has not advanced or closed DIR.
                    // The returned borrow is tied to &mut self, preventing both.
                    return Ok(Some(NodeDiskDirectoryEntry {
                        name: unsafe { CStr::from_ptr(name) },
                        kind,
                    }));
                }
            }
        }
    }
}
impl Drop for NodeDiskDirectoryCursor {
    fn drop(&mut self) {
        let _ = self.finish();
        drop(self.directory.take());
    }
}

#[cfg(test)]
mod tests;
