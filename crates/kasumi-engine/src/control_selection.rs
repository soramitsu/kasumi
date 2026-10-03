//! Fixed-role local Control observations. Selection pins one immutable generation;
//! returned source handles own only their selected document and real admission.
use super::{CONTROL_TENANT, ControlPlane};
use crate::admission::Reservation;
use crate::{Database, Generation, LifecycleInstallationMetadata};
use kasumi_query::QueryCancellation;
use kasumi_types::{
    AdmittedDocumentOwner, CollectionDefinition, Document, Error, ErrorCode, SharedDocument,
};
use std::{mem::size_of, sync::Arc};

/// Trusted local management selection. No quorum barrier or read audit occurs.
/// This is not a general document-source API: only the two reserved Control
/// roles are exposed. Borrowed observations always refer to the same generation.
/// Header/schema/lifecycle borrows do not recheck live authority by themselves;
/// a consumer must call `check_access()` after using these observations and
/// before acting on them. Document/decode handoffs perform their own checks.
pub struct LocalControlSelection<'a> {
    database: &'a Database,
    generation: Arc<Generation>,
}
impl ControlPlane {
    pub fn select_local(database: &Database) -> anyhow::Result<LocalControlSelection<'_>> {
        database.raft_group().check_access()?;
        let generation = database.engine().generation()?;
        if generation.tenant() != CONTROL_TENANT {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "control metadata needs its dedicated group",
            )
            .into());
        }
        Ok(LocalControlSelection {
            database,
            generation,
        })
    }
}
impl LocalControlSelection<'_> {
    /// Require the caller's work grant to originate in this installed memory core.
    pub fn check_admission(
        &self,
        admission: &crate::admission::NodeAdmission,
    ) -> kasumi_types::Result<()> {
        if !self.database.admission().shares_memory(admission) {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "local Control work admission differs from installed provider",
            ));
        }
        Ok(())
    }
    pub fn revision(&self) -> u64 {
        self.generation.revision()
    }
    pub fn incarnation(&self) -> &str {
        self.generation.incarnation()
    }
    pub fn topology_version(&self) -> Option<u64> {
        self.generation.local_control_topology_version()
    }
    pub fn enrollment_schema(&self) -> Option<&CollectionDefinition> {
        self.generation
            .collection_metadata("tenant_enrollments")
            .map(|metadata| metadata.definition)
    }
    pub fn lifecycle_installation(&self) -> Option<LifecycleInstallationMetadata<'_>> {
        self.generation.lifecycle_installation()
    }
    /// Check current key/serving authority without replacing selected data.
    pub fn check_access(&self) -> anyhow::Result<()> {
        self.database.raft_group().check_access()?;
        drop(self.database.engine().generation()?);
        Ok(())
    }
    /// The source body is not decoded or semantically validated. This preserves
    /// route-only readiness checks and optional decode-only startup observations.
    pub fn topology_document(&self) -> anyhow::Result<Option<SharedDocument>> {
        self.document("topology", "current")
    }
    /// The exact immutable approval row; its schema/body validation belongs to
    /// the concrete enrollment consumer under its own admitted decode workspace.
    pub fn enrollment_document(&self, tenant: &str) -> anyhow::Result<Option<SharedDocument>> {
        self.document("tenant_enrollments", tenant)
    }
    /// Decode with the legacy optional startup semantics: absence is allowed;
    /// placement and reserved-schema validation are deliberately not performed.
    pub fn decode_topology(
        &self,
    ) -> anyhow::Result<Option<crate::AdmittedOutput<super::VersionedTopology>>> {
        super::memory::selected_topology(self.database, &self.generation, false, false)
    }
    /// Preserve follower-local reserved-schema and placement checks, including
    /// lifecycle enrollment schema, from this exact selected generation.
    pub fn require_installed_topology(
        &self,
    ) -> anyhow::Result<crate::AdmittedOutput<super::VersionedTopology>> {
        super::memory::selected_topology(self.database, &self.generation, true, true)?.ok_or_else(
            || {
                Error::new(
                    ErrorCode::Corruption,
                    "installed Control topology is missing",
                )
                .into()
            },
        )
    }
    fn document(&self, collection: &str, id: &str) -> anyhow::Result<Option<SharedDocument>> {
        self.check_access()?;
        let Some(document) = self
            .generation
            .state
            .collections
            .get(collection)
            .and_then(|collection| collection.documents.get(id))
        else {
            self.check_access()?;
            return Ok(None);
        };
        // Until every runtime producer owns compact admitted backing, retain
        // the same provisional source floor as point reads. Do not interpret
        // this as a measured capacity bound or remove it during this boundary.
        let floor = u64::try_from(self.generation.limits().max_document_bytes)?
            .checked_mul(3)
            .ok_or_else(overflow)?;
        let retained = floor
            .checked_add(arc_bytes::<LocalDocumentOwner>()?)
            .ok_or_else(overflow)?;
        let bytes = retained
            .checked_add(cancellation_bytes()?)
            .ok_or_else(overflow)?;
        let reservation = self.database.admission().reserve(bytes, None)?;
        let mut pending = PendingDocument {
            document: None,
            cancellation: QueryCancellation::default(),
            reservation,
        };
        self.database
            .admission()
            .check_release(&pending.cancellation)?;
        pending.document = Some(document.clone());
        self.check_access()?;
        self.database
            .admission()
            .check_release(&pending.cancellation)?;
        let PendingDocument {
            document,
            cancellation,
            mut reservation,
        } = pending;
        drop(cancellation);
        reservation.retain(retained);
        let owner = Arc::new(LocalDocumentOwner {
            document: document.expect("selected Control row"),
            _reservation: reservation,
        });
        Ok(Some(SharedDocument::from_admitted_owner(owner)))
    }
}
fn overflow() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "local Control source ownership size overflow",
    )
}
fn arc_bytes<T>() -> kasumi_types::Result<u64> {
    allocation_bytes(
        size_of::<T>()
            .checked_add(2 * size_of::<usize>())
            .ok_or_else(overflow)?,
    )
}
fn allocation_bytes(bytes: usize) -> kasumi_types::Result<u64> {
    bytes
        .checked_next_power_of_two()
        .and_then(|n| n.checked_add(64))
        .and_then(|n| u64::try_from(n).ok())
        .ok_or_else(overflow)
}
fn cancellation_bytes() -> kasumi_types::Result<u64> {
    allocation_bytes(
        QueryCancellation::shared_state_bytes()
            .checked_add(2 * size_of::<usize>())
            .ok_or_else(overflow)?,
    )
}
struct PendingDocument {
    document: Option<Arc<Document>>,
    cancellation: QueryCancellation,
    reservation: Reservation,
}
struct LocalDocumentOwner {
    document: Arc<Document>,
    _reservation: Reservation,
}
impl AdmittedDocumentOwner for LocalDocumentOwner {
    fn document(&self) -> &Document {
        &self.document
    }
}
