from pathlib import Path
r=Path('target/installed-disk-validation/file-owner-custody-revision1')
p=r/'proposed/crates/kasumi-store/src/node_disk/file.rs';s=p.read_text()
s=s.replace('original_error: Mutex<Option<io::Error>>','original_error: Option<Mutex<Option<io::Error>>>')
s=s.replace('provisional_close: None, original_error,','provisional_close: None, original_error: Some(original_error),')
# Checked native leaf stat avoids an additional descriptor and its close obligation.
a=s.index('    let observed = census::open_at(parent, name,');b=s.index('    // An unsettled live target',a)
s=s[:a]+'''    let metadata = stat_leaf(parent, name, device)?;
    let length = u64::try_from(metadata.st_size).map_err(|_| io::ErrorKind::InvalidData)?;
    let allocated = u64::try_from(metadata.st_blocks).map_err(|_| io::ErrorKind::InvalidData)?
        .checked_mul(512).ok_or(io::ErrorKind::InvalidData)?;
    let bytes = rounded(length.max(allocated), unit)?;
    let pending = bytes - allocated;
    if metadata.st_ino != identity.1 || length != enrolled.actual_len
        || enrolled.actual_len > enrolled.reserved_len || bytes > enrolled.bytes
        || (enrolled.settled && *enrolled != AccountedFile::durable(binding, bytes, pending, length))
    { return Err(io::ErrorKind::InvalidData.into()); }
''' + s[b:]
a=s.index('fn verify_parent(')
s=s[:a]+'''// A single validated C-string component plus NOFOLLOW never follows an
// intermediate symlink. All ancestors have already been checked by custody.
fn stat_leaf(parent: &File, name: &std::ffi::CStr, device: u64) -> io::Result<libc::stat> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: parent is retained, name is NUL-terminated, and stat is writable.
    if unsafe { libc::fstatat(parent.as_raw_fd(), name.as_ptr(), stat.as_mut_ptr(), libc::AT_SYMLINK_NOFOLLOW) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful fstatat initializes the complete native structure.
    let stat = unsafe { stat.assume_init() };
    let observed_device = u64::try_from(stat.st_dev).map_err(|_| io::ErrorKind::InvalidData)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG || stat.st_nlink != 1 || observed_device != device {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(stat)
}

''' + s[a:]
a=s.index('    fn verify(&self, file: &File)');b=s.index('\n    fn check(&self',a)
s=s[:a]+'''    fn verify(&self, file: &File) -> io::Result<()> {
        let result = (|| {
            verify_parent(&self.disk.roots[&self.root], &self.parent_names, self.parent_custody())?;
            let metadata = stat_leaf(self.parent(), self.name(), self.identity.0)?;
            if metadata.st_ino != self.identity.1 || Identity::of(&file.metadata()?) != self.identity {
                return Err(io::ErrorKind::InvalidData.into());
            }
            Ok(())
        })();
        result.map_err(|error| self.record_error(error))
    }
''' + s[b:]
a=s.index('    // This value is outside its original Arc.');b=s.index('    #[cfg(test)]\n    fn close_checkpoint',a)
s=s[:a]+'''    // This value is outside its original Arc. The map's Weak keeps that exact
    // allocation admitted while data/parent descriptors and heap backing retire.
    fn retire_resources(&mut self) -> io::Result<()> {
        if let Some(mutex) = &mut self.resources.budget {
            let budget = mutex.get_mut().unwrap_or_else(|poison| poison.into_inner());
            super::native_file::close(&mut budget.file, &mut budget.close_outcome)?;
        }
        #[cfg(test)]
        self.close_checkpoint(CloseStage::DataClosed);
        self.resources.close_descriptors()?;
        if self.resources.has_failure() { return Err(io::ErrorKind::InvalidData.into()); }
        for parent in [self.resources.parent.take(), self.resources.retiring_parent.take()]
            .into_iter().flatten()
        {
            if let Some(identity) = parent.retire_drained() {
                assert!(self.resources.retired_parent.replace(identity).is_none(), "one parent registration");
            }
        }
        drop(std::mem::take(&mut self.resources.root));
        drop(std::mem::take(&mut self.resources.relative));
        drop(std::mem::replace(&mut self.resources.parent_names, Box::new([])));
        drop(self.resources.name.take());
        drop(self.resources.budget.take());
        drop(self.resources.original_error.take());
        #[cfg(test)]
        self.close_checkpoint(CloseStage::ResourcesClosed);
        Ok(())
    }
    fn retain_locked(&mut self, state: &mut State) {
        let resources = std::mem::replace(&mut self.resources, FileResources::empty());
        self.disk.fail_locked(state);
        state.file_custody.retain(resources);
    }

''' + s[b:]
s=s.replace('''        state.open_files = next;
        true''','''        state.open_files = next;
        state.file_custody.release(self.custody_slot);
        self.custody_slot = usize::MAX;
        true''')
a=s.index('impl Drop for FileOwner {')
s=s[:a]+'''// If a retirement checkpoint or another destructor unwinds, the actual
// unfinished payload moves into its reserved slot before field destruction.
struct Retirement<'a> { owner: &'a mut FileOwner, armed: bool }
impl Drop for Retirement<'_> {
    fn drop(&mut self) {
        if self.armed {
            let disk = self.owner.disk.clone();
            let mut state = disk.lock_state();
            self.owner.retain_locked(&mut state);
        }
    }
}
impl Drop for FileOwner {
    fn drop(&mut self) {
        if self.resources.custody_slot == usize::MAX { return; }
        let mut retirement = Retirement { owner: self, armed: true };
        let owner = &mut *retirement.owner;
        let settled = owner.resources.budget.as_mut().is_some_and(|mutex| {
            let poisoned = mutex.is_poisoned();
            let budget = mutex.get_mut().unwrap_or_else(|poison| poison.into_inner());
            !poisoned && budget.settled
        });
        let result = if settled && !owner.resources.has_failure() {
            owner.retire_resources()
        } else { Err(io::ErrorKind::InvalidData.into()) };
        let disk = owner.disk.clone();
        let mut state = disk.lock_state();
        if !settled {
            if let Some(enrolled) = state.accounted.get_mut(&owner.identity).and_then(AccountedInode::file_mut) {
                enrolled.settled = false;
            }
        }
        if result.is_err() || !owner.retire_registration(&mut state) {
            owner.retain_locked(&mut state);
        }
        retirement.armed = false;
    }
}
'''
p.write_text(s)
p=r/'proposed/crates/kasumi-store/src/node_disk/file/custody.rs';s=p.read_text()
s=s.replace('    fn empty() -> Self {','    pub(super) fn empty() -> Self {').replace('original_error: Mutex::new(None)','original_error: None')
s=s.replace('self.original_error.lock()', 'self.original_error.as_ref().expect("retained outcome mutex").lock()')
a=s.index('        self.original_error.is_poisoned()');b=s.index('            || self.provisional_close',a)
s=s[:a]+'''        self.original_error.as_ref().is_some_and(|mutex| mutex.is_poisoned()
            || mutex.lock().unwrap_or_else(|poison| poison.into_inner()).is_some())
''' + s[b:]
p.write_text(s)
