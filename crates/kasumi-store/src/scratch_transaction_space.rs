//! Aggregate promises transferred into exact anonymous-file Charges. No Drop
//! path returns rights; only explicit finish/cancel does so after caller proof.
use super::*;

/// Only explicit pre-effect arithmetic and admission paths mint a refusal.
/// Native observation errors keep their original value, irrespective of kind.
#[derive(Debug)]
pub(crate) enum ReserveFailure {
    Capacity,
    Failed(io::Error),
}
impl ReserveFailure {
    pub(crate) fn memory(error: io::Error) -> Self {
        if error.kind() == io::ErrorKind::OutOfMemory {
            Self::Capacity
        } else {
            Self::Failed(error)
        }
    }
}
impl From<io::Error> for ReserveFailure {
    fn from(error: io::Error) -> Self {
        Self::Failed(error)
    }
}
impl From<io::ErrorKind> for ReserveFailure {
    fn from(kind: io::ErrorKind) -> Self {
        Self::Failed(kind.into())
    }
}
impl From<ReserveFailure> for kasumi_kv::TransactionReserveError {
    fn from(failure: ReserveFailure) -> Self {
        match failure {
            ReserveFailure::Capacity => Self::CapacityDenied,
            ReserveFailure::Failed(error) => Self::Failed(error),
        }
    }
}

pub(crate) struct TransactionSpace {
    disk: Arc<ScratchDisk>,
    bytes: u64,
    files: u64,
    active: bool,
}
impl ScratchDisk {
    pub(crate) fn reserve_transaction_space(
        self: &Arc<Self>,
        bytes: u64,
        files: u64,
    ) -> Result<TransactionSpace, ReserveFailure> {
        let mut state = self.lock_state();
        let mut pending = self.device.lock();
        if !pending.admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        let next = state
            .bytes
            .checked_add(bytes)
            .filter(|next| *next <= self.config.max_bytes)
            .ok_or(ReserveFailure::Capacity)?;
        let promised = pending.checked_add(bytes).ok_or(ReserveFailure::Capacity)?;
        let required = promised
            .checked_add(pending.minimum_free_bytes())
            .ok_or(ReserveFailure::Capacity)?;
        let reserved_files = state
            .reserved_files
            .checked_add(files)
            .filter(|reserved| state.files.checked_add(*reserved).is_some())
            .ok_or(ReserveFailure::Capacity)?;
        let available = self.available().inspect_err(|_| pending.fail_owner())?;
        if available < required {
            return Err(ReserveFailure::Capacity);
        }
        pending.set_pending(promised)?;
        state.bytes = next;
        state.reserved_files = reserved_files;
        Ok(TransactionSpace {
            disk: self.clone(),
            bytes,
            files,
            active: true,
        })
    }
    pub(crate) fn transaction_rounded(&self, ciphertext_len: u64) -> io::Result<u64> {
        self.rounded(ciphertext_len)
    }
    pub(crate) fn transaction_allocation_unit(&self) -> u64 {
        self.allocation_unit
    }
    pub(crate) fn transaction_ready(&self) -> bool {
        self.device.lock().admission_ready()
    }
}
impl TransactionSpace {
    fn check(&self, disk: &Arc<ScratchDisk>) -> io::Result<()> {
        if !self.active || !Arc::ptr_eq(&self.disk, disk) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        if !self.disk.device.lock().admission_ready() {
            return Err(io::ErrorKind::Other.into());
        }
        Ok(())
    }
    pub(crate) fn transfer_growth(
        &mut self,
        charge: &mut Charge,
        ciphertext_len: u64,
    ) -> io::Result<()> {
        self.check(&charge.disk)?;
        let bytes = self.disk.rounded(ciphertext_len)?;
        if bytes <= charge.bytes {
            return Ok(());
        }
        let delta = bytes - charge.bytes;
        let remaining = self
            .bytes
            .checked_sub(delta)
            .ok_or(io::ErrorKind::InvalidData)?;
        // All bytes remain in the same aggregate quota/pending totals. Their
        // owner changes from this unassigned promise to the exact file Charge.
        self.bytes = remaining;
        charge.bytes = bytes;
        Ok(())
    }
    fn consume_file(&mut self, disk: &Arc<ScratchDisk>) -> io::Result<()> {
        self.check(disk)?;
        let mut state = disk.lock_state();
        let free = self
            .files
            .checked_sub(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        let reserved = state
            .reserved_files
            .checked_sub(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        let files = state
            .files
            .checked_add(1)
            .ok_or(io::ErrorKind::InvalidData)?;
        self.files = free;
        state.reserved_files = reserved;
        state.files = files;
        Ok(())
    }
    pub(crate) fn finish(&mut self) -> io::Result<()> {
        self.check(&self.disk)?;
        let mut state = self.disk.lock_state();
        let mut pending = self.disk.device.lock();
        let bytes = state
            .bytes
            .checked_sub(self.bytes)
            .ok_or(io::ErrorKind::InvalidData)?;
        let files = state
            .reserved_files
            .checked_sub(self.files)
            .ok_or(io::ErrorKind::InvalidData)?;
        let promised = pending
            .checked_sub(self.bytes)
            .ok_or(io::ErrorKind::InvalidData)?;
        pending.set_pending(promised)?;
        state.bytes = bytes;
        state.reserved_files = files;
        self.bytes = 0;
        self.files = 0;
        self.active = false;
        Ok(())
    }
}
impl Drop for TransactionSpace {
    fn drop(&mut self) {
        if self.active {
            self.disk.device.lock().fail_owner();
        }
    }
}
impl Charge {
    pub(crate) fn transaction_bytes(&self) -> u64 {
        self.bytes
    }
    pub(crate) fn grow_claimed(
        &mut self,
        space: &mut TransactionSpace,
        ciphertext_len: u64,
    ) -> io::Result<()> {
        space.transfer_growth(self, ciphertext_len)
    }
}

const CLAIM_FILE_PREFIX: &[u8] = b"kasumi-scratch-";

/// Stored in the registered group before openat. No later unlink/metadata error
/// can discard an acquired descriptor or its exact randomized pending name.
pub(crate) struct FileAttempt {
    disk: Arc<ScratchDisk>,
    name: [u8; CLAIM_FILE_PREFIX.len() + 32 + 1],
    file: Option<File>,
    counted: bool,
    unlinked: bool,
    identity: Option<(u64, u64)>,
    #[cfg(test)]
    after_open_error: Option<io::Error>,
}
impl FileAttempt {
    pub(crate) fn new(disk: &Arc<ScratchDisk>) -> Self {
        let mut name = [0; CLAIM_FILE_PREFIX.len() + 32 + 1];
        name[..CLAIM_FILE_PREFIX.len()].copy_from_slice(CLAIM_FILE_PREFIX);
        for (index, byte) in uuid::Uuid::new_v4().as_bytes().iter().enumerate() {
            name[CLAIM_FILE_PREFIX.len() + index * 2] = b"0123456789abcdef"[(byte >> 4) as usize];
            name[CLAIM_FILE_PREFIX.len() + index * 2 + 1] =
                b"0123456789abcdef"[(byte & 15) as usize];
        }
        Self {
            disk: disk.clone(),
            name,
            file: None,
            counted: false,
            unlinked: false,
            identity: None,
            #[cfg(test)]
            after_open_error: None,
        }
    }
    pub(crate) fn acquire(&mut self, space: &mut TransactionSpace) -> io::Result<()> {
        space.check(&self.disk)?;
        if self.file.is_some() || self.counted {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        check_directory(&self.disk.directory.metadata()?).map_err(io::Error::other)?;
        // The NUL-terminated name and descriptor owner are already retained.
        let descriptor = unsafe {
            libc::openat(
                self.disk.directory.as_raw_fd(),
                self.name.as_ptr().cast(),
                libc::O_RDWR | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful openat returned a new owned descriptor. Publish it
        // before the next fallible action, while caller still owns this attempt.
        self.file = Some(unsafe { File::from_raw_fd(descriptor) });
        space.consume_file(&self.disk)?;
        self.counted = true;
        #[cfg(test)]
        if let Some(error) = self.after_open_error.take() {
            return Err(error);
        }
        if unsafe {
            libc::unlinkat(
                self.disk.directory.as_raw_fd(),
                self.name.as_ptr().cast(),
                0,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        self.unlinked = true;
        let metadata = self
            .file
            .as_ref()
            .expect("retained descriptor")
            .metadata()?;
        if !metadata.is_file()
            || metadata.nlink() != 0
            || metadata.mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.len() != 0
            || metadata.blocks() != 0
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        self.identity = Some((metadata.dev(), metadata.ino()));
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn fail_after_open(&mut self, error: io::Error) {
        self.after_open_error = Some(error);
    }
    pub(crate) fn acquired(&self) -> bool {
        self.file.is_some()
    }
    pub(crate) fn finish(&mut self) -> (File, Charge) {
        let identity = self.identity.take().expect("validated anonymous identity");
        assert!(self.counted && self.unlinked);
        self.counted = false;
        (
            self.file.take().expect("validated anonymous descriptor"),
            Charge {
                disk: self.disk.clone(),
                identity,
                bytes: 0,
                allocated: 0,
                release_on_drop: true,
            },
        )
    }
}
