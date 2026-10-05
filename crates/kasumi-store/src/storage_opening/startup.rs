//! One-use orchestration of the existing registered node opening requests.
//!
//! The coordinator does not own a second engine or expose a raw transaction.
//! Failure keeps the exact opening and unretired child facade for inspection.
//! Once a child retirement consumes its facade, the coordinator keeps its ID
//! and disposition; a progressed census cell may no longer expose a report.
use super::{
    NodeOpeningMode, NodeOpeningPhase, NodeOpeningReport, NodeReadPhase, NodeReadReport,
    NodeStorageConfig, NodeTablesReport, NodeWriterPhase, RegisteredNodeOpening,
    RegisteredNodeRead, RegisteredNodeTables,
};
use crate::storage_census::NativeStartupChildPurpose;
use crate::{NativeConstructorFailure, NodeDisk, StorageCensusDisposition, StorageOwnerId};
use kasumi_kv::DatabaseOpenSettlement;
use std::{io, path::Path, sync::Arc};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeStartupPhase {
    Prepared,
    Opening,
    Tables,
    ExistingVerification,
    Ready,
    Retained,
    Failed,
}

/// The same registered opening owns file acquisition, fixed table work, Ready
/// publication and existing-table verification. `advance` never re-enters work.
pub struct RegisteredNodeStartup {
    opening: RegisteredNodeOpening,
    existing: bool,
    phase: NodeStartupPhase,
    tables: Option<RegisteredNodeTables>,
    verification: Option<RegisteredNodeRead>,
    child_id: Option<StorageOwnerId>,
    child_disposition: Option<StorageCensusDisposition>,
    child_constructor: Option<NativeStartupChildPurpose>,
    local_error: Option<io::Error>,
    close_requested: bool,
}

/// Explicit failed-startup custody after the original opening was stopped.
/// Every field is an existing registered owner or original observation; no
/// database or transaction can escape through this handoff.
pub struct NodeStartupFailureCustody {
    opening: RegisteredNodeOpening,
    tables: Option<RegisteredNodeTables>,
    verification: Option<RegisteredNodeRead>,
    phase: NodeStartupPhase,
    child_id: Option<StorageOwnerId>,
    child_disposition: Option<StorageCensusDisposition>,
    child_constructor: Option<NativeStartupChildPurpose>,
    local_error: Option<io::Error>,
}
impl NodeStartupFailureCustody {
    pub fn phase(&self) -> NodeStartupPhase {
        self.phase
    }
    pub fn opening(&self) -> &RegisteredNodeOpening {
        &self.opening
    }
    pub fn tables(&self) -> Option<&RegisteredNodeTables> {
        self.tables.as_ref()
    }
    pub fn verification(&self) -> Option<&RegisteredNodeRead> {
        self.verification.as_ref()
    }
    pub fn child_id(&self) -> Option<StorageOwnerId> {
        self.child_id
    }
    pub fn child_disposition(&self) -> Option<StorageCensusDisposition> {
        self.child_disposition
    }
    pub fn child_constructor(&self) -> Option<NativeConstructorFailure> {
        self.opening
            .startup_child_constructor(self.child_id?, self.child_constructor?)
    }
    pub fn local_error(&self) -> Option<&io::Error> {
        self.local_error.as_ref()
    }
    /// Hand the stopped exact opening, original child facades, and every
    /// recorded child locator/disposition to the caller. A consumed child has
    /// no facade left, so its ID and disposition must survive this transfer.
    #[allow(clippy::type_complexity)] // Every tuple member is part of the exact custody transfer.
    pub fn into_parts(
        self,
    ) -> (
        RegisteredNodeOpening,
        Option<RegisteredNodeTables>,
        Option<RegisteredNodeRead>,
        NodeStartupPhase,
        Option<StorageOwnerId>,
        Option<StorageCensusDisposition>,
        Option<io::Error>,
        Option<NativeConstructorFailure>,
    ) {
        let child_constructor = self.child_constructor();
        (
            self.opening,
            self.tables,
            self.verification,
            self.phase,
            self.child_id,
            self.child_disposition,
            self.local_error,
            child_constructor,
        )
    }
}
impl RegisteredNodeStartup {
    /// Constructor failures retain their original fixed census receiver. Once
    /// preparation succeeds, `opening_id` identifies the exact opening owner.
    pub fn prepare(
        path: &Path,
        id: Uuid,
        disk: Arc<NodeDisk>,
        mode: NodeOpeningMode,
        config: NodeStorageConfig,
    ) -> Result<Self, NativeConstructorFailure> {
        let existing = matches!(&mode, NodeOpeningMode::Existing);
        Ok(Self {
            opening: RegisteredNodeOpening::prepare(path, id, disk, mode, config)?,
            existing,
            phase: NodeStartupPhase::Prepared,
            tables: None,
            verification: None,
            child_id: None,
            child_disposition: None,
            child_constructor: None,
            local_error: None,
            close_requested: false,
        })
    }

    pub(crate) fn prepare_node(
        path: &Path,
        id: Uuid,
        disk: Arc<NodeDisk>,
        scratch: Arc<crate::ScratchDisk>,
        mode: NodeOpeningMode,
        config: NodeStorageConfig,
    ) -> Result<Self, NativeConstructorFailure> {
        let existing = matches!(&mode, NodeOpeningMode::Existing);
        Ok(Self {
            opening: RegisteredNodeOpening::prepare_node(path, id, disk, scratch, mode, config)?,
            existing,
            phase: NodeStartupPhase::Prepared,
            tables: None,
            verification: None,
            child_id: None,
            child_disposition: None,
            child_constructor: None,
            local_error: None,
            close_requested: false,
        })
    }

    pub(crate) fn node_startup_failed(&self) {
        self.opening.node_body().lifecycle.failed_startup();
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn prepare_fixture<B: kasumi_kv::SegmentGroupBackend + 'static>(
        inputs: &mut Option<crate::NodeFixtureInputs<B>>,
        id: Uuid,
        existing: bool,
        config: NodeStorageConfig,
    ) -> Result<Self, NativeConstructorFailure> {
        Ok(Self {
            opening: RegisteredNodeOpening::prepare_fixture(inputs, id, existing, config)?,
            existing,
            phase: NodeStartupPhase::Prepared,
            tables: None,
            verification: None,
            child_id: None,
            child_disposition: None,
            child_constructor: None,
            local_error: None,
            close_requested: false,
        })
    }

    pub fn opening_id(&self) -> StorageOwnerId {
        self.opening.id()
    }
    pub fn child_id(&self) -> Option<StorageOwnerId> {
        self.child_id
    }
    pub fn phase(&self) -> NodeStartupPhase {
        self.phase
    }
    pub fn child_disposition(&self) -> Option<StorageCensusDisposition> {
        self.child_disposition
    }
    pub fn opening_report(&self) -> NodeOpeningReport<'_> {
        self.opening.report()
    }
    pub fn tables_report(&self) -> Option<NodeTablesReport<'_>> {
        self.tables.as_ref().map(RegisteredNodeTables::report)
    }
    pub fn verification_report(&self) -> Option<NodeReadReport<'_>> {
        self.verification.as_ref().map(RegisteredNodeRead::report)
    }
    pub fn child_constructor(&self) -> Option<NativeConstructorFailure> {
        self.opening
            .startup_child_constructor(self.child_id?, self.child_constructor?)
    }
    pub fn local_error(&self) -> Option<&io::Error> {
        self.local_error.as_ref()
    }

    /// Stop new work on a failed original opening and enter its explicit close.
    /// An active child may make close wait; the same owner and child stay here
    /// until the caller transfers them to failed-startup custody.
    pub fn close_failed(&mut self) -> io::Result<DatabaseOpenSettlement> {
        if !matches!(
            self.phase,
            NodeStartupPhase::Failed | NodeStartupPhase::Retained
        ) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        self.close_requested = true;
        self.opening.close()
    }

    /// Transfer exact opening and child facades only after close has sealed
    /// admission. The caller can inspect, finish/retire children, retry close
    /// on the same opening, or follow its failed-close recovery protocol.
    #[allow(clippy::result_large_err)] // Failure must return the same owned startup for retry.
    pub fn into_failed_custody(self) -> Result<NodeStartupFailureCustody, Self> {
        if !self.close_requested
            || !matches!(
                self.phase,
                NodeStartupPhase::Failed | NodeStartupPhase::Retained
            )
        {
            return Err(self);
        }
        Ok(NodeStartupFailureCustody {
            opening: self.opening,
            tables: self.tables,
            verification: self.verification,
            phase: self.phase,
            child_id: self.child_id,
            child_disposition: self.child_disposition,
            child_constructor: self.child_constructor,
            local_error: self.local_error,
        })
    }

    /// Seal the exact original opening before retaining a coordinator whose
    /// expected transfer could not complete. Every child and original record
    /// survives even when close is waiting or returns an error.
    pub(crate) fn retain_failure(mut self) -> (NodeStartupFailureCustody, Option<io::Error>) {
        let close_error = if self.close_requested {
            None
        } else {
            self.close_requested = true;
            self.opening.close().err()
        };
        (
            NodeStartupFailureCustody {
                opening: self.opening,
                tables: self.tables,
                verification: self.verification,
                phase: self.phase,
                child_id: self.child_id,
                child_disposition: self.child_disposition,
                child_constructor: self.child_constructor,
                local_error: self.local_error,
            },
            close_error,
        )
    }

    /// Drive this original attempt once. A second call only observes its phase;
    /// it cannot reopen a file, rerun a table transaction or republish Ready.
    pub fn advance(&mut self) -> NodeStartupPhase {
        if self.phase != NodeStartupPhase::Prepared {
            return self.phase;
        }
        self.phase = NodeStartupPhase::Opening;
        if self.opening.open() != NodeOpeningPhase::Open {
            self.phase = NodeStartupPhase::Failed;
            return self.phase;
        }
        if self.existing {
            self.phase = NodeStartupPhase::ExistingVerification;
            let verification = match self.opening.queue_startup_verification() {
                Ok(verification) => verification,
                Err(error) => {
                    match error {
                        NativeConstructorFailure::Preclaim(original) => {
                            self.local_error = Some(original)
                        }
                        retained @ NativeConstructorFailure::Retained(_) => {
                            self.child_id = retained.id();
                            self.child_constructor = Some(if self.existing {
                                NativeStartupChildPurpose::Verification
                            } else {
                                NativeStartupChildPurpose::Tables
                            });
                            // Dropping this compact delivery leaves all actual
                            // errors, payloads and grants in its paid receiver.
                            drop(retained);
                        }
                    }
                    self.phase = NodeStartupPhase::Failed;
                    return self.phase;
                }
            };
            self.child_id = Some(verification.id());
            self.verification = Some(verification);
            let reader = self.verification.as_ref().expect("stored verification");
            let _ = reader.begin();
            let verified = self.opening.report().existing_tables_verified();
            if !verified || reader.phase() != NodeReadPhase::Active {
                self.phase = NodeStartupPhase::Failed;
                return self.phase;
            }
            if reader.finish() != NodeReadPhase::Finished {
                self.phase = NodeStartupPhase::Failed;
                return self.phase;
            }
            let reader = self.verification.take().expect("stored verification");
            self.child_disposition = Some(reader.retire());
            match self.child_disposition.expect("recorded reader retirement") {
                StorageCensusDisposition::Retired => {}
                StorageCensusDisposition::Retained => {
                    self.phase = NodeStartupPhase::Retained;
                    return self.phase;
                }
                StorageCensusDisposition::Stale => {
                    self.phase = NodeStartupPhase::Failed;
                    return self.phase;
                }
            }
        } else {
            self.phase = NodeStartupPhase::Tables;
            let tables = match self.opening.queue_startup_tables() {
                Ok(tables) => tables,
                Err(error) => {
                    match error {
                        NativeConstructorFailure::Preclaim(original) => {
                            self.local_error = Some(original)
                        }
                        retained @ NativeConstructorFailure::Retained(_) => {
                            self.child_id = retained.id();
                            self.child_constructor = Some(if self.existing {
                                NativeStartupChildPurpose::Verification
                            } else {
                                NativeStartupChildPurpose::Tables
                            });
                            // Dropping this compact delivery leaves all actual
                            // errors, payloads and grants in its paid receiver.
                            drop(retained);
                        }
                    }
                    self.phase = NodeStartupPhase::Failed;
                    return self.phase;
                }
            };
            self.child_id = Some(tables.id());
            self.tables = Some(tables);
            let tables = self.tables.as_ref().expect("stored table request");
            if tables.run() != NodeWriterPhase::Finished {
                self.phase = NodeStartupPhase::Failed;
                return self.phase;
            }
            if let Err(error) = self.opening.publish_ready_after_tables(tables) {
                self.local_error = Some(error);
                self.phase = NodeStartupPhase::Failed;
                return self.phase;
            }
            let tables = self.tables.take().expect("stored table request");
            self.child_disposition = Some(tables.retire());
            match self.child_disposition.expect("recorded table retirement") {
                StorageCensusDisposition::Retired => {}
                StorageCensusDisposition::Retained => {
                    self.phase = NodeStartupPhase::Retained;
                    return self.phase;
                }
                StorageCensusDisposition::Stale => {
                    self.phase = NodeStartupPhase::Failed;
                    return self.phase;
                }
            }
        }
        self.phase = NodeStartupPhase::Ready;
        self.phase
    }

    /// Only a fully verified opening may become a production node owner.
    /// Failure keeps the opening and any unretired child report handle. A
    /// consumed child retirement remains identified by ID and disposition.
    #[allow(clippy::result_large_err)] // Failure retains the exact opening and child owners.
    pub fn into_opening(self) -> Result<RegisteredNodeOpening, Self> {
        if self.phase == NodeStartupPhase::Ready {
            Ok(self.opening)
        } else {
            Err(self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        NodeDiskMemoryAdmission,
        test_utils::{TestDiskMemory, private_tempdir, retry_disk_registry},
    };
    use kasumi_kv::DatabaseOpenSettlement;

    const ID: Uuid = Uuid::from_u128(0x5825_1c84_5e3b_487b_b998_2ca6_3141_7331);

    #[test]
    fn startup_uses_one_registered_owner_for_create_and_reopen() {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("startup.kv");
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let mut created = RegisteredNodeStartup::prepare(
            &path,
            ID,
            disk.clone(),
            NodeOpeningMode::Create,
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        let create_id = created.opening_id();
        assert_eq!(memory.storage_census().snapshot().databases, 1);
        assert_eq!(created.advance(), NodeStartupPhase::Ready);
        assert_eq!(created.advance(), NodeStartupPhase::Ready);
        assert_eq!(created.opening_id(), create_id);
        assert_eq!(
            created.child_disposition(),
            Some(StorageCensusDisposition::Retired)
        );
        let opening = created.into_opening().ok().unwrap();
        assert_eq!(opening.id(), create_id);
        assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
        assert_eq!(memory.storage_census().snapshot().databases, 0);

        let mut existing = RegisteredNodeStartup::prepare(
            &path,
            ID,
            disk,
            NodeOpeningMode::Existing,
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        let existing_id = existing.opening_id();
        assert_eq!(memory.storage_census().snapshot().databases, 1);
        assert_eq!(existing.advance(), NodeStartupPhase::Ready);
        assert_eq!(existing.advance(), NodeStartupPhase::Ready);
        assert_eq!(
            existing.child_disposition(),
            Some(StorageCensusDisposition::Retired)
        );
        let opening = existing.into_opening().ok().unwrap();
        assert_eq!(opening.id(), existing_id);
        assert_eq!(opening.close().unwrap(), DatabaseOpenSettlement::Closed);
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
        assert_eq!(memory.storage_census().snapshot().databases, 0);
    }
    #[test]
    fn rejected_existing_envelope_transfers_the_original_failed_opening_for_close() {
        use kasumi_kv::TerminalObservation;
        use std::os::unix::fs::OpenOptionsExt;

        let directory = private_tempdir().unwrap();
        let path = directory.path().join("invalid-envelope.kv");
        drop(
            std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&path)
                .unwrap(),
        );
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let mut startup = RegisteredNodeStartup::prepare(
            &path,
            ID,
            disk,
            NodeOpeningMode::Existing,
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        let original_id = startup.opening_id();
        assert_eq!(memory.storage_census().snapshot().databases, 1);
        assert_eq!(startup.advance(), NodeStartupPhase::Failed);
        let original_error = {
            let report = startup.opening_report();
            let TerminalObservation::Returned(Err(error)) = report.acquisition() else {
                panic!("expected original envelope rejection");
            };
            std::ptr::from_ref(error)
        };
        let startup = startup.into_opening().err().unwrap();
        let mut startup = startup.into_failed_custody().err().unwrap();
        assert_eq!(
            startup.close_failed().unwrap(),
            DatabaseOpenSettlement::Closed
        );
        let custody = startup.into_failed_custody().ok().unwrap();
        assert_eq!(custody.opening().id(), original_id);
        assert!(custody.tables().is_none());
        assert!(custody.verification().is_none());
        {
            let report = custody.opening().report();
            let TerminalObservation::Returned(Err(error)) = report.acquisition() else {
                panic!("original envelope rejection lost during close");
            };
            assert_eq!(std::ptr::from_ref(error), original_error);
        }
        let (
            opening,
            tables,
            verification,
            phase,
            child_id,
            child_disposition,
            local_error,
            child_constructor,
        ) = custody.into_parts();
        assert!(tables.is_none());
        assert!(verification.is_none());
        assert_eq!(phase, NodeStartupPhase::Failed);
        assert_eq!(child_id, None);
        assert_eq!(child_disposition, None);
        assert!(local_error.is_none());
        assert!(child_constructor.is_none());
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
        assert_eq!(memory.storage_census().snapshot().databases, 0);
    }

    #[test]
    fn failed_custody_parts_keep_consumed_child_id_and_disposition() {
        let directory = private_tempdir().unwrap();
        let path = directory.path().join("cancelled-tables.kv");
        let memory = TestDiskMemory::new(256 << 20, 4096);
        let disk =
            retry_disk_registry(|| NodeDisk::fixture_for_path(&path, memory.clone())).unwrap();
        let mut startup = RegisteredNodeStartup::prepare(
            &path,
            ID,
            disk,
            NodeOpeningMode::Create,
            crate::test_utils::node_storage_config(),
        )
        .unwrap();
        assert_eq!(startup.opening.open(), NodeOpeningPhase::Open);
        let tables = startup.opening.queue_node_tables().unwrap();
        let original_child_id = tables.id();
        let retained_tables = RegisteredNodeTables::retained(memory.clone(), original_child_id)
            .expect("second facade for the actual registered child");
        assert_eq!(
            startup.opening.close().unwrap(),
            DatabaseOpenSettlement::Closed
        );
        let original_disposition = tables.retire();
        assert_eq!(original_disposition, StorageCensusDisposition::Retained);

        // Model the failure boundary after the first child facade was
        // consumed while another live facade keeps its census cell retained.
        startup.phase = NodeStartupPhase::Retained;
        startup.child_id = Some(original_child_id);
        startup.child_disposition = Some(original_disposition);
        assert_eq!(
            startup.close_failed().unwrap(),
            DatabaseOpenSettlement::Closed
        );
        let custody = startup.into_failed_custody().ok().unwrap();
        assert_eq!(custody.child_id(), Some(original_child_id));
        assert_eq!(custody.child_disposition(), Some(original_disposition));
        let (
            opening,
            tables,
            verification,
            phase,
            child_id,
            child_disposition,
            local_error,
            child_constructor,
        ) = custody.into_parts();
        assert!(tables.is_none());
        assert!(verification.is_none());
        assert_eq!(phase, NodeStartupPhase::Retained);
        assert_eq!(child_id, Some(original_child_id));
        assert_eq!(child_disposition, Some(original_disposition));
        assert!(local_error.is_none());
        assert!(child_constructor.is_none());
        assert_eq!(retained_tables.retire(), StorageCensusDisposition::Retired);
        assert_eq!(opening.retire(), StorageCensusDisposition::Retired);
        assert_eq!(memory.storage_census().snapshot().databases, 0);
    }
}

#[cfg(test)]
#[path = "../native_startup_child_receiver_tests.rs"]
mod native_child_receiver_tests;
