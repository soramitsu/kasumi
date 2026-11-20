//! Dedicated Control pagination for source-owned backup key inventory.
use crate::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const BACKUP_INVENTORY_SCAN_ROWS: u64 = 32;

/// Recovery keys are canonical UUID strings. Public binary prefixes allow a
/// receiver to resume without releasing a different tenant's operation IDs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupInventoryCursor {
    Bindings { after: u64 },
    Recoveries { start: Uuid, bits: u8 },
    Finish,
}
impl BackupInventoryCursor {
    pub const FIRST: Self = Self::Bindings { after: 0 };
    pub const RECOVERIES: Self = Self::Recoveries {
        start: Uuid::nil(),
        bits: 0,
    };
    pub fn recovery_bounds(self) -> Result<(Uuid, Uuid)> {
        let Self::Recoveries { start, bits } = self else {
            return Err(invalid());
        };
        if bits > 128 {
            return Err(invalid());
        }
        let mask = u128::MAX.checked_shr(bits.into()).unwrap_or(0);
        if start.as_u128() & mask != 0 {
            return Err(invalid());
        }
        Ok((start, Uuid::from_u128(start.as_u128() | mask)))
    }
    pub fn split_recoveries(self) -> Result<Self> {
        self.recovery_bounds()?;
        let Self::Recoveries { start, bits } = self else {
            return Err(invalid());
        };
        if bits == 128 {
            return Err(invalid());
        }
        Ok(Self::Recoveries {
            start,
            bits: bits + 1,
        })
    }
    pub fn next_recoveries(self) -> Result<Self> {
        let (_, end) = self.recovery_bounds()?;
        Ok(match end.as_u128().checked_add(1) {
            Some(start) => Self::Recoveries {
                start: Uuid::from_u128(start),
                bits: 128 - start.trailing_zeros() as u8,
            },
            None => Self::Finish,
        })
    }
}
fn invalid() -> Error {
    Error::new(ErrorCode::InvalidArgument, "invalid backup inventory page")
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupInventoryRead {
    pub scan: Uuid,
    pub cursor: BackupInventoryCursor,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub selection: Option<String>,
}
impl BackupInventoryRead {
    pub fn validate(&self) -> Result<()> {
        if self.scan.is_nil()
            || (self.cursor == BackupInventoryCursor::FIRST) != self.selection.is_none()
        {
            return Err(invalid());
        }
        if matches!(self.cursor, BackupInventoryCursor::Recoveries { .. }) {
            self.cursor.recovery_bounds()?;
        }
        if let Some(selection) = &self.selection {
            validate_sha256(selection)?;
        }
        Ok(())
    }
    pub fn digest(&self) -> Result<String> {
        self.validate()?;
        Ok(staged_digest(&("kasumi.backup-retention.inventory.v1", self))?.0)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupInventoryCommand {
    pub reference: RemoteBackupReference,
    pub read: BackupInventoryRead,
}
impl BackupInventoryCommand {
    pub fn validate(&self) -> Result<()> {
        self.reference.validate()?;
        if self.reference.session != self.read.scan
            || self.reference.action_sha256 != self.read.digest()?
        {
            return Err(invalid());
        }
        Ok(())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum BackupInventoryRecord {
    Binding {
        selected: Box<RemoteBackupRecord>,
    },
    Recovery {
        request: Box<RecoveryStart>,
        request_sha256: String,
        updated_revision: u64,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackupInventoryPage {
    pub binding_count: u64,
    pub nonce: Uuid,
    pub selection: String,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub record: Option<BackupInventoryRecord>,
    #[serde(deserialize_with = "crate::require_explicit_option")]
    pub next: Option<BackupInventoryCursor>,
}
impl BackupInventoryPage {
    pub fn validate(&self, command: &BackupInventoryCommand) -> Result<()> {
        command.validate()?;
        validate_sha256(&self.selection)?;
        if self.nonce != command.reference.nonce
            || command
                .read
                .selection
                .as_ref()
                .is_some_and(|s| s != &self.selection)
        {
            return Err(invalid());
        }
        let cursor = command.read.cursor;
        let valid = match (cursor, self.next) {
            (
                BackupInventoryCursor::Bindings { after },
                Some(BackupInventoryCursor::Bindings { after: next }),
            ) => {
                next > after
                    && next < self.binding_count
                    && next - after <= BACKUP_INVENTORY_SCAN_ROWS
            }
            (
                BackupInventoryCursor::Bindings { after },
                Some(BackupInventoryCursor::RECOVERIES),
            ) => {
                after <= self.binding_count
                    && self.binding_count - after <= BACKUP_INVENTORY_SCAN_ROWS
            }
            (BackupInventoryCursor::Recoveries { .. }, Some(next)) => {
                next == cursor.next_recoveries()?
                    || (self.record.is_none() && cursor.split_recoveries().ok() == Some(next))
            }
            (BackupInventoryCursor::Finish, None) => self.record.is_none(),
            _ => false,
        };
        if !valid {
            return Err(invalid());
        }
        match (&self.record, cursor) {
            (None, _) => Ok(()),
            (
                Some(BackupInventoryRecord::Binding { selected }),
                BackupInventoryCursor::Bindings { .. },
            ) if selected.record.claim.tenant == command.reference.tenant => selected.validate(),
            (
                Some(BackupInventoryRecord::Recovery {
                    request,
                    request_sha256,
                    ..
                }),
                BackupInventoryCursor::Recoveries { .. },
            ) => {
                let (first, last) = cursor.recovery_bounds()?;
                if request.tenant != command.reference.tenant
                    || !(first..=last).contains(&request.operation_id)
                    || request.digest()? != *request_sha256
                {
                    return Err(invalid());
                }
                Ok(())
            }
            _ => Err(invalid()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn enumeration_is_bound_to_its_original_source_and_coverage_position() {
        let scan = Uuid::new_v4();
        let read = BackupInventoryRead {
            scan,
            cursor: BackupInventoryCursor::FIRST,
            selection: None,
        };
        let original = BackupInventoryCommand {
            reference: RemoteBackupReference {
                nonce: Uuid::new_v4(),
                control_incarnation: Uuid::new_v4(),
                source_node: 2,
                tenant: "tenant".into(),
                source_incarnation: Uuid::new_v4().to_string(),
                session: scan,
                action_sha256: read.digest().unwrap(),
            },
            read,
        };
        let mut page = BackupInventoryPage {
            binding_count: 33,
            nonce: original.reference.nonce,
            selection: "ab".repeat(32),
            record: None,
            next: Some(BackupInventoryCursor::RECOVERIES),
        };
        assert!(page.validate(&original).is_err());
        page.next = Some(BackupInventoryCursor::Bindings { after: 32 });
        page.validate(&original).unwrap();
        page.nonce = Uuid::new_v4();
        assert!(page.validate(&original).is_err());
        let mut forged = original.clone();
        forged.read.cursor = BackupInventoryCursor::Finish;
        forged.read.selection = Some("cd".repeat(32));
        assert!(forged.validate().is_err());
        forged.reference.action_sha256 =
            staged_digest(&RemoteBackupAction::Read { session_id: scan })
                .unwrap()
                .0;
        assert!(forged.validate().is_err());
    }
    #[test]
    fn recovery_partitions_cover_the_entire_keyspace_through_dense_leaves() {
        let mut cursor = BackupInventoryCursor::RECOVERIES;
        for _ in 0..128 {
            cursor = cursor.split_recoveries().unwrap();
        }
        assert_eq!(
            cursor.recovery_bounds().unwrap(),
            (Uuid::nil(), Uuid::nil())
        );
        assert!(cursor.split_recoveries().is_err());
        let mut last = Uuid::nil();
        for _ in 0..128 {
            cursor = cursor.next_recoveries().unwrap();
            let (start, end) = cursor.recovery_bounds().unwrap();
            assert_eq!(start.as_u128(), last.as_u128() + 1);
            last = end;
        }
        assert_eq!(last.as_u128(), u128::MAX);
        assert_eq!(
            cursor.next_recoveries().unwrap(),
            BackupInventoryCursor::Finish
        );
        assert!(
            BackupInventoryCursor::Recoveries {
                start: Uuid::from_u128(1),
                bits: 0
            }
            .recovery_bounds()
            .is_err()
        );
    }
}
