//! Scalar space bounds for the installed arena writer's actual append position.
use super::*;
use crate::group::{ExistingFileSpace, FileSpaceRange};

fn overflow() -> CoreError {
    CoreError::InvalidInput("arena transaction-space arithmetic overflow")
}

fn file_length(pages: u64) -> Result<u64, CoreError> {
    pages
        .checked_mul(DIRECTORY_PAGE_BYTES as u64)
        .and_then(|n| n.checked_add(HEADER_BYTES as u64))
        .ok_or_else(overflow)
}

impl DirectoryArenaBackend {
    /// Borrow this writer's current position; do not publish an ID, reserve
    /// memory, read a backend or append a page. The caller must serialize this
    /// observation with the transaction that consumes the returned bound.
    pub(crate) fn transaction_space(
        &self,
        first_fresh: u64,
        additional_pages: u64,
    ) -> Result<(Option<ExistingFileSpace>, FileSpaceRange), CoreError> {
        check_owner(&self.admission)?;
        let writer = self.writer.lock().map_err(|_| CoreError::OwnerFailed)?;
        if writer.poisoned {
            return Err(CoreError::OwnerFailed);
        }
        if first_fresh == 0
            || first_fresh == u64::MAX
            || self.max_pages == 0
            || self.max_pages > MAX_PAGES
            || writer
                .active
                .as_ref()
                .is_some_and(|a| a.id == 0 || a.id >= first_fresh || a.pages > self.max_pages)
        {
            return Err(CoreError::InvalidInput(
                "invalid arena transaction-space start",
            ));
        }
        let mut remaining = additional_pages;
        let existing = writer
            .active
            .as_ref()
            .map(|active| -> Result<ExistingFileSpace, CoreError> {
                let add = remaining.min(self.max_pages - active.pages);
                remaining -= add;
                Ok(ExistingFileSpace {
                    file: GroupFile::directory(active.id),
                    initial_len: file_length(active.pages)?,
                    maximum_len: file_length(active.pages + add)?,
                })
            })
            .transpose()?;
        let new = if remaining == 0 {
            FileSpaceRange {
                first_id: 0,
                count: 0,
                full_len: 0,
                minimum_len: 0,
                last_len: 0,
                total_len: 0,
            }
        } else {
            let count = remaining.div_ceil(self.max_pages);
            first_fresh
                .checked_add(count)
                .filter(|next| *next != u64::MAX)
                .ok_or_else(overflow)?;
            let last_pages = (remaining - 1) % self.max_pages + 1;
            FileSpaceRange {
                first_id: first_fresh,
                count,
                full_len: file_length(self.max_pages)?,
                minimum_len: HEADER_BYTES as u64,
                last_len: file_length(last_pages)?,
                total_len: remaining
                    .checked_mul(DIRECTORY_PAGE_BYTES as u64)
                    .and_then(|bytes| {
                        count
                            .checked_mul(HEADER_BYTES as u64)
                            .and_then(|headers| bytes.checked_add(headers))
                    })
                    .ok_or_else(overflow)?,
            }
        };
        check_owner(&self.admission)?;
        Ok((existing, new))
    }
}
