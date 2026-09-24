use crate::transaction_tracker::{SavepointId, TransactionId, TransactionTracker};
use crate::tree_store::page_store::page_manager::FILE_FORMAT_VERSION4;
use crate::tree_store::{BtreeHeader, TransactionalMemory};
use crate::{Result, StorageError, TypeName, Value};
use alloc::format;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::mem::size_of;

// on-disk format:
// * 1 byte: version
// * 8 bytes: savepoint id
// * 8 bytes: transaction id
// * 1 byte: user root not-null
// * 8 bytes: user root page
// * 8 bytes: user root checksum
/// A database savepoint
///
/// May be used with [`WriteTransaction::restore_savepoint`] to restore the database to the state
/// when this savepoint was created
///
/// [`WriteTransaction::restore_savepoint`]: crate::WriteTransaction::restore_savepoint
pub struct Savepoint {
    version: u8,
    id: SavepointId,
    // Each savepoint has an associated read transaction id to ensure that any pages it references
    // are not freed
    transaction_id: TransactionId,
    user_root: Option<BtreeHeader>,
    transaction_tracker: Arc<TransactionTracker>,
    ephemeral: bool,
}

impl Savepoint {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new_ephemeral(
        mem: &TransactionalMemory,
        transaction_tracker: Arc<TransactionTracker>,
        id: SavepointId,
        transaction_id: TransactionId,
        user_root: Option<BtreeHeader>,
    ) -> Self {
        Self {
            id,
            transaction_id,
            version: mem.get_version(),
            user_root,
            transaction_tracker,
            ephemeral: true,
        }
    }

    pub(crate) fn get_version(&self) -> u8 {
        self.version
    }

    pub(crate) fn get_id(&self) -> SavepointId {
        self.id
    }

    pub(crate) fn get_transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    pub(crate) fn get_user_root(&self) -> Option<BtreeHeader> {
        self.user_root
    }

    pub(crate) fn db_address(&self) -> *const TransactionTracker {
        core::ptr::from_ref(self.transaction_tracker.as_ref())
    }

    pub(crate) fn set_persistent(&mut self) {
        self.ephemeral = false;
    }
}

impl Drop for Savepoint {
    fn drop(&mut self) {
        if self.ephemeral {
            self.transaction_tracker
                .deallocate_savepoint(self.get_id(), self.get_transaction_id());
        }
    }
}

#[derive(Debug)]
pub(crate) enum SerializedSavepoint<'a> {
    Ref(&'a [u8]),
    Owned(Vec<u8>),
}

impl SerializedSavepoint<'_> {
    pub(crate) fn from_savepoint(savepoint: &Savepoint) -> Self {
        assert_eq!(savepoint.version, FILE_FORMAT_VERSION4);
        let mut result = vec![savepoint.version];
        result.extend(savepoint.id.0.to_le_bytes());
        result.extend(savepoint.transaction_id.raw_id().to_le_bytes());

        if let Some(header) = savepoint.user_root {
            result.push(1);
            result.extend(header.to_le_bytes());
        } else {
            result.push(0);
            result.extend([0; BtreeHeader::serialized_size()]);
        }

        Self::Owned(result)
    }

    fn data(&self) -> &[u8] {
        match self {
            SerializedSavepoint::Ref(x) => x,
            SerializedSavepoint::Owned(x) => x.as_slice(),
        }
    }

    pub(crate) fn to_savepoint(
        &self,
        transaction_tracker: Arc<TransactionTracker>,
    ) -> Result<Savepoint> {
        let data = self.data();
        let serialized_len =
            2 * size_of::<u8>() + 2 * size_of::<u64>() + BtreeHeader::serialized_size();
        if data.len() != serialized_len {
            return Err(StorageError::Corrupted(
                "Corrupted savepoint record".to_string(),
            ));
        }
        let mut offset = 0;
        let version = data[offset];
        if version != FILE_FORMAT_VERSION4 {
            return Err(StorageError::Corrupted(format!(
                "Unsupported savepoint version: {version}"
            )));
        }
        offset += size_of::<u8>();

        let id = u64::from_le_bytes(
            data[offset..(offset + size_of::<u64>())]
                .try_into()
                .unwrap(),
        );
        offset += size_of::<u64>();

        let transaction_id = u64::from_le_bytes(
            data[offset..(offset + size_of::<u64>())]
                .try_into()
                .unwrap(),
        );
        offset += size_of::<u64>();

        let not_null = data[offset];
        if not_null > 1 {
            return Err(StorageError::Corrupted(
                "Corrupted savepoint record".to_string(),
            ));
        }
        offset += 1;
        let user_root = if not_null == 1 {
            Some(BtreeHeader::from_le_bytes(
                data[offset..(offset + BtreeHeader::serialized_size())]
                    .try_into()
                    .unwrap(),
            )?)
        } else {
            None
        };
        offset += BtreeHeader::serialized_size();
        debug_assert_eq!(offset, data.len());

        Ok(Savepoint {
            version,
            id: SavepointId(id),
            transaction_id: TransactionId::new(transaction_id),
            user_root,
            transaction_tracker,
            ephemeral: false,
        })
    }
}

impl Value for SerializedSavepoint<'_> {
    type SelfType<'a>
        = SerializedSavepoint<'a>
    where
        Self: 'a;
    type AsBytes<'a>
        = &'a [u8]
    where
        Self: 'a;

    fn fixed_width() -> Option<usize> {
        None
    }

    fn from_bytes<'a>(data: &'a [u8]) -> Self::SelfType<'a>
    where
        Self: 'a,
    {
        SerializedSavepoint::Ref(data)
    }

    fn as_bytes<'a, 'b: 'a>(value: &'a Self::SelfType<'b>) -> Self::AsBytes<'a>
    where
        Self: 'b,
    {
        value.data()
    }

    fn type_name() -> TypeName {
        TypeName::internal("redb::SerializedSavepoint")
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transaction_tracker::{TransactionId, TransactionTracker};
    use alloc::sync::Arc;

    #[test]
    fn corrupted_record_errors() {
        let tracker = Arc::new(TransactionTracker::new(TransactionId::new(1)));

        let mut record = vec![FILE_FORMAT_VERSION4];
        record.extend(1u64.to_le_bytes());
        record.extend(1u64.to_le_bytes());
        record.push(0);
        record.extend([0; BtreeHeader::serialized_size()]);
        assert!(
            SerializedSavepoint::Ref(&record)
                .to_savepoint(tracker.clone())
                .is_ok()
        );

        let truncated = &record[..record.len() - 1];
        assert!(matches!(
            SerializedSavepoint::Ref(truncated).to_savepoint(tracker.clone()),
            Err(StorageError::Corrupted(_))
        ));

        for version in [0, 1, 2, 3, 5, 9, u8::MAX] {
            let mut bad_version = record.clone();
            bad_version[0] = version;
            assert!(matches!(
                SerializedSavepoint::Ref(&bad_version).to_savepoint(tracker.clone()),
                Err(StorageError::Corrupted(_))
            ));
        }

        let mut bad_null_marker = record.clone();
        bad_null_marker[17] = 2;
        assert!(matches!(
            SerializedSavepoint::Ref(&bad_null_marker).to_savepoint(tracker),
            Err(StorageError::Corrupted(_))
        ));
    }

    #[test]
    fn canonical_savepoint_roots_reject_aliases_before_tracker_publication() {
        use crate::tree_store::page_store::base::{MAX_PAGE_INDEX, MAX_REGIONS, PageNumber};
        let tracker = Arc::new(TransactionTracker::new(TransactionId::new(9)));
        for order in 0..=20 {
            let root = BtreeHeader::new(
                PageNumber::new(MAX_REGIONS - 1, MAX_PAGE_INDEX >> order, order),
                11,
                13,
            );
            let savepoint = Savepoint {
                version: FILE_FORMAT_VERSION4,
                id: SavepointId(7),
                transaction_id: TransactionId::new(8),
                user_root: Some(root),
                transaction_tracker: tracker.clone(),
                ephemeral: false,
            };
            let record = SerializedSavepoint::from_savepoint(&savepoint);
            let decoded = record.to_savepoint(tracker.clone()).unwrap();
            assert_eq!(decoded.get_user_root(), Some(root));
            assert_eq!(decoded.get_id(), SavepointId(7));
            assert_eq!(decoded.get_transaction_id(), TransactionId::new(8));
            assert_eq!(
                SerializedSavepoint::from_savepoint(&decoded).data(),
                record.data()
            );
            drop(decoded);
            let owners = Arc::strong_count(&tracker);
            for bit in (40..59).chain((20 - u32::from(order))..20) {
                let mut bad = record.data().to_vec();
                let offset = 2 * size_of::<u8>() + 2 * size_of::<u64>();
                let raw = u64::from_le_bytes(bad[offset..offset + 8].try_into().unwrap())
                    | (1_u64 << bit);
                bad[offset..offset + 8].copy_from_slice(&raw.to_le_bytes());
                let original = bad.clone();
                assert!(
                    matches!(
                        SerializedSavepoint::Ref(&bad).to_savepoint(tracker.clone()),
                        Err(StorageError::Corrupted(_))
                    ),
                    "order={order}, bit={bit}"
                );
                assert_eq!(bad, original);
                assert_eq!(Arc::strong_count(&tracker), owners);
                assert!(!tracker.any_savepoint_exists());
                assert!(tracker.oldest_live_read_transaction().is_none());
            }
        }
    }
}
