//! Admitted public outputs and directory-only decisions for the Core facade.
use super::*;
use crate::core::{AdmittedValue, CommittedPosition, ScanDirection};
use std::ops::{Bound, RangeBounds};

impl DiskState {
    pub(crate) fn generation(&self) -> Result<u64, CoreError> {
        self.owner.check()?;
        Ok(self.selected.generation)
    }

    pub(crate) fn committed_position(&self) -> Result<Option<CommittedPosition>, CoreError> {
        self.owner.check()?;
        Ok(self
            .owner
            .lock()?
            .directory()
            .map(|commit| CommittedPosition {
                segment_id: commit.start.position.segment_id,
                offset: commit.start.position.offset,
            }))
    }

    pub(crate) fn get_admitted(
        &mut self,
        pin: &SnapshotPin,
        table: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<Option<AdmittedValue>, CoreError> {
        self.run(|state| {
            let root = state.check_snapshot(pin)?;
            let reader = DirectoryReader::new(&state.pages, state.owner.admission.clone());
            if reader.get(root, DirectoryKey::table(table))?.is_none() {
                return Err(CoreError::new(crate::CoreErrorCause::MissingTable));
            }
            match reader.get(root, DirectoryKey::row(table, key))? {
                None => Ok(None),
                Some(DirectoryValue::Row { value, .. }) => state
                    .value_admitted(value, table, key, max_value_bytes)
                    .map(Some),
                Some(DirectoryValue::Table { .. }) => Err(CoreError::new(
                    crate::CoreErrorCause::Corrupt("row lookup returned a table"),
                )),
            }
        })
    }

    fn table_at_prepared(
        &self,
        root: DirectoryRoot,
        table: &str,
        workspace: &mut crate::core::PreparedPointRead,
    ) -> Result<bool, CoreError> {
        let reader = DirectoryReader::new(&self.pages, self.owner.admission.clone());
        Ok(reader
            .get_with_workspace(root, DirectoryKey::table(table), &mut workspace.directory)?
            .is_some())
    }

    pub(crate) fn table_exists_prepared(
        &mut self,
        pin: &SnapshotPin,
        table: &str,
        workspace: &mut crate::core::PreparedPointRead,
    ) -> Result<bool, CoreError> {
        self.run(|state| state.table_at_prepared(state.check_snapshot(pin)?, table, workspace))
    }

    /// Both reads and size preflight validate the table at this same pinned
    /// root, then reuse the caller's real admitted directory workspace.
    fn point_location_prepared(
        &self,
        pin: &SnapshotPin,
        table: &str,
        key: &[u8],
        workspace: &mut crate::core::PreparedPointRead,
    ) -> Result<Option<ValueLocation>, CoreError> {
        let root = self.check_snapshot(pin)?;
        if !self.table_at_prepared(root, table, workspace)? {
            return Err(CoreError::new(crate::CoreErrorCause::MissingTable));
        }
        let reader = DirectoryReader::new(&self.pages, self.owner.admission.clone());
        match reader.get_with_workspace(
            root,
            DirectoryKey::row(table, key),
            &mut workspace.directory,
        )? {
            None => Ok(None),
            Some(DirectoryValue::Row { value, .. }) => Ok(Some(value)),
            Some(DirectoryValue::Table { .. }) => Err(CoreError::new(
                crate::CoreErrorCause::Corrupt("row lookup returned a table"),
            )),
        }
    }

    pub(crate) fn point_length_prepared(
        &mut self,
        pin: &SnapshotPin,
        table: &str,
        key: &[u8],
        workspace: &mut crate::core::PreparedPointRead,
    ) -> Result<Option<usize>, CoreError> {
        self.run(|state| {
            state
                .point_location_prepared(pin, table, key, workspace)
                .map(|value| value.map(|value| value.len as usize))
        })
    }

    pub(crate) fn get_prepared(
        &mut self,
        pin: &SnapshotPin,
        table: &str,
        key: &[u8],
        max_value_bytes: usize,
        workspace: &mut crate::core::PreparedPointRead,
    ) -> Result<Option<usize>, CoreError> {
        self.run(|state| {
            let Some(value) = state.point_location_prepared(pin, table, key, workspace)? else {
                return Ok(None);
            };
            let length = value.len as usize;
            if length > max_value_bytes || length > workspace.output.bytes.len() {
                return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "value exceeds the caller's read bound",
                )));
            }
            state.value_into(value, table, key, &mut workspace.output.bytes[..length])?;
            Ok(Some(length))
        })
    }

    pub(crate) fn key_exists(
        &mut self,
        pin: &SnapshotPin,
        table: &str,
        key: &[u8],
    ) -> Result<bool, CoreError> {
        self.run(|state| {
            let root = state.check_snapshot(pin)?;
            let reader = DirectoryReader::new(&state.pages, state.owner.admission.clone());
            if reader.get(root, DirectoryKey::table(table))?.is_none() {
                return Err(CoreError::new(crate::CoreErrorCause::MissingTable));
            }
            match reader.get(root, DirectoryKey::row(table, key))? {
                None => Ok(false),
                Some(DirectoryValue::Row { .. }) => Ok(true),
                Some(DirectoryValue::Table { .. }) => Err(CoreError::new(
                    crate::CoreErrorCause::Corrupt("row lookup returned a table"),
                )),
            }
        })
    }

    // Called inside run, which checks the owner before and after the read.
    fn bounded_record(
        &self,
        pin: &SnapshotPin,
        table: &str,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
        direction: ScanDirection,
    ) -> Result<Option<DirectoryRecord>, CoreError> {
        use Bound::{Excluded, Included, Unbounded};
        for bound in [lower, upper] {
            if matches!(bound, Included(key) | Excluded(key) if key.len() > crate::MAX_KEY_BYTES) {
                return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                    "range key exceeds storage limit",
                )));
            }
        }
        let root = self.check_snapshot(pin)?;
        let reader = DirectoryReader::new(&self.pages, self.owner.admission.clone());
        if reader.get(root, DirectoryKey::table(table))?.is_none() {
            return Err(CoreError::new(crate::CoreErrorCause::MissingTable));
        }
        let record = match direction {
            ScanDirection::Ascending => {
                let key = match lower {
                    Included(key) | Excluded(key) => key,
                    Unbounded => &[],
                };
                reader.next(
                    root,
                    DirectoryKey::row(table, key),
                    matches!(lower, Excluded(_)),
                )?
            }
            ScanDirection::Descending => {
                // The largest permitted byte key belongs to the interval, including
                // when that exact all-FF key is itself stored in the table.
                const LAST: &[u8] = &[0xff; crate::MAX_KEY_BYTES];
                let key = match upper {
                    Included(key) | Excluded(key) => key,
                    Unbounded => LAST,
                };
                reader.previous(
                    root,
                    DirectoryKey::row(table, key),
                    matches!(upper, Excluded(_)),
                )?
            }
        };
        Ok(record.filter(|record| {
            let key = record.key();
            key.table == table && key.row.is_some_and(|row| (lower, upper).contains(row))
        }))
    }

    pub(crate) fn seek_key_admitted(
        &mut self,
        pin: &SnapshotPin,
        table: &str,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
        direction: ScanDirection,
    ) -> Result<Option<AdmittedValue>, CoreError> {
        self.run(|state| {
            let Some(record) = state.bounded_record(pin, table, lower, upper, direction)? else {
                return Ok(None);
            };
            let key = record.key().row.expect("bounded record is a row");
            AdmittedValue::copy(&state.owner.admission, key).map(Some)
        })
    }

    pub(crate) fn seek_admitted(
        &mut self,
        pin: &SnapshotPin,
        table: &str,
        lower: Bound<&[u8]>,
        upper: Bound<&[u8]>,
        direction: ScanDirection,
        max_value_bytes: usize,
    ) -> Result<Option<(AdmittedValue, AdmittedValue)>, CoreError> {
        self.run(|state| {
            let Some(record) = state.bounded_record(pin, table, lower, upper, direction)? else {
                return Ok(None);
            };
            state.admit_record(record, table, max_value_bytes).map(Some)
        })
    }

    pub(crate) fn next_admitted(
        &mut self,
        pin: &SnapshotPin,
        table: &str,
        prefix: &[u8],
        after: Option<&[u8]>,
        max_value_bytes: usize,
    ) -> Result<Option<(AdmittedValue, AdmittedValue)>, CoreError> {
        self.run(|state| {
            let Some(record) = state.next_record(pin, table, prefix, after)? else {
                return Ok(None);
            };
            state.admit_record(record, table, max_value_bytes).map(Some)
        })
    }

    fn admit_record(
        &self,
        record: DirectoryRecord,
        table: &str,
        max_value_bytes: usize,
    ) -> Result<(AdmittedValue, AdmittedValue), CoreError> {
        let (Some(key), DirectoryValue::Row { value, .. }) = (record.key().row, record.value)
        else {
            return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                "row seek returned a table",
            )));
        };
        let output_key = AdmittedValue::copy(&self.owner.admission, key)?;
        let output_value = self.value_admitted(value, table, key, max_value_bytes)?;
        Ok((output_key, output_value))
    }

    // Called only inside `run`, which verifies the owner around the whole read.
    fn value_admitted(
        &self,
        value: ValueLocation,
        table: &str,
        key: &[u8],
        max_value_bytes: usize,
    ) -> Result<AdmittedValue, CoreError> {
        self.owner.check_live()?;
        value.validate()?;
        if value.len as usize > max_value_bytes {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "value exceeds the caller's read bound",
            )));
        }
        // Reserve the required output first. Optional caching cannot turn a
        // readable value into an allocation failure by consuming its headroom.
        let mut output = AdmittedValue::allocate(&self.owner.admission, value.len as usize)?;
        self.value_into(value, table, key, &mut output.bytes)?;
        Ok(output)
    }

    // Shared authenticated/cached physical read for owned outputs and prepared
    // loans. Optional retention retains its normal-demand full-fit policy.
    // Called only inside `run`, like `value_admitted`. A cold value is read
    // through the segment's own verified descriptor and checked by CRC.
    fn value_into(
        &self,
        value: ValueLocation,
        table: &str,
        key: &[u8],
        output: &mut [u8],
    ) -> Result<(), CoreError> {
        self.owner.check_live()?;
        value.validate()?;
        if output.len() != value.len as usize {
            return Err(CoreError::new(crate::CoreErrorCause::InvalidInput(
                "value output length differs",
            )));
        }
        let identity = NativeIdentity::value(self.owner.group_id, value, table, key)?;
        let cached = self
            .cache
            .lock()
            .map_err(|_| CoreError::new(crate::CoreErrorCause::OwnerFailed))?
            .load_or_read_into(identity, output, |out| {
                self.owner.check_live()?;
                self.owner
                    .backend
                    .read(GroupFile::segment(value.segment_id), value.offset, out)?;
                self.owner.check_live()?;
                if crc32c(out) != value.crc {
                    return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                        "value checksum differs",
                    )));
                }
                Ok(())
            })
            .map_err(|error| match error {
                CacheLoadError::Admission(error) => error.into(),
                CacheLoadError::Load(error) => error,
            })?;
        self.owner.check_live()?;
        if let Some(cached) = cached {
            if cached.as_bytes().len() != value.len as usize
                || crc32c(cached.as_bytes()) != value.crc
            {
                return Err(CoreError::new(crate::CoreErrorCause::Corrupt(
                    "cached value identity differs",
                )));
            }
            output.copy_from_slice(cached.as_bytes());
        }
        self.owner.check_live()?;
        Ok(())
    }
}
