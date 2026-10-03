//! Pre-effect crypto ownership and retained claimed descriptor acquisition.
use super::*;
use crate::scratch_disk::transaction::{FileAttempt, ReserveFailure, TransactionSpace};

struct Buffers {
    key: SecretKey,
    id: [u8; 16],
    cached: Zeroizing<Vec<u8>>,
    ciphertext: Zeroizing<Vec<u8>>,
}
pub(crate) struct PreparedSpool {
    attempt: FileAttempt,
    buffers: Option<Buffers>,
    limit: u64,
}
impl PreparedSpool {
    /// Caller owns its real installed crypto-memory lease before this call.
    pub(crate) fn new(disk: &Arc<ScratchDisk>, limit: u64) -> Result<Self, ReserveFailure> {
        if EncryptedSpool::transaction_ciphertext_len(limit)? > i64::MAX as u64 {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        fn buffer(bytes: usize) -> Result<Zeroizing<Vec<u8>>, ReserveFailure> {
            let mut out = Vec::new();
            out.try_reserve_exact(bytes)
                .map_err(|_| ReserveFailure::Capacity)?;
            if out.capacity() != bytes {
                return Err(ReserveFailure::Capacity);
            }
            out.resize(bytes, 0);
            Ok(Zeroizing::new(out))
        }
        Ok(Self {
            attempt: FileAttempt::new(disk),
            buffers: Some(Buffers {
                key: SecretKey::random().map_err(io::Error::other)?,
                id: *uuid::Uuid::new_v4().as_bytes(),
                cached: buffer(NATIVE_BLOCK)?,
                ciphertext: buffer(NATIVE_SLOT as usize)?,
            }),
            limit,
        })
    }
    #[cfg(test)]
    pub(crate) fn fail_after_open(&mut self, error: io::Error) {
        self.attempt.fail_after_open(error);
    }
    pub(crate) fn acquired(&self) -> bool {
        self.attempt.acquired()
    }
    pub(crate) fn acquire(&mut self, space: &mut TransactionSpace) -> io::Result<EncryptedSpool> {
        self.attempt.acquire(space)?;
        // All fallible physical work has succeeded while ownership remained
        // here. Only infallible moves assemble the actual anonymous spool.
        let (file, charge) = self.attempt.finish();
        let Buffers {
            key,
            id,
            cached,
            ciphertext,
        } = self.buffers.take().expect("prepared crypto buffers");
        Ok(EncryptedSpool {
            file: NativeFile(Some(file)),
            native_close: NativeClosePhase::Open,
            #[cfg(test)]
            close_entered: false,
            key,
            id,
            length: 0,
            position: 0,
            limit: self.limit,
            layout: SpoolLayout::Native,
            #[cfg(test)]
            authenticated_bytes_read: 0,
            cached_index: None,
            cached,
            ciphertext,
            dirty: false,
            append_digest: Some(Sha256::new()),
            charge,
        })
    }
}
impl EncryptedSpool {
    pub(crate) fn transaction_ciphertext_len(length: u64) -> io::Result<u64> {
        SpoolLayout::Native.ciphertext_len(length)
    }
    pub(crate) fn transaction_charged_bytes(&self) -> u64 {
        self.charge.transaction_bytes()
    }
    pub(crate) fn reserve_claimed_growth(
        &mut self,
        space: &mut TransactionSpace,
        requested: u64,
    ) -> io::Result<()> {
        self.check_owner()?;
        if requested < self.length || requested > self.limit {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.charge
            .grow_claimed(space, self.layout.ciphertext_len(requested)?)
    }
    pub(crate) fn transaction_clean(&self) -> io::Result<()> {
        self.check_owner()?;
        if self.dirty {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(())
    }
}
