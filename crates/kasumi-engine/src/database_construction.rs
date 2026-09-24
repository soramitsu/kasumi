//! Checked identity and clock preparation before any Database Raft startup.
//! This owns construction inputs; retained startup children remain owned by
//! SnapshotBufferOwner. It is not a replacement for the runtime startup census.
use super::{Database, DatabaseClocks, SecurityAudit, TenantEngine};
use crate::admission::NodeAdmission;
use kasumi_raft::{RaftGroup, RaftGroupConfig, RaftTransport};
use kasumi_store::TenantStorageSet;
use std::sync::Arc;

pub(crate) struct DatabaseConstruction {
    stores: Arc<TenantStorageSet>,
    audit: Arc<SecurityAudit>,
    clocks: DatabaseClocks,
}

impl DatabaseConstruction {
    pub(crate) fn new(
        stores: Arc<TenantStorageSet>,
        audit: Arc<SecurityAudit>,
    ) -> anyhow::Result<Self> {
        let memory = audit.admission().memory();
        memory.require_store_memory(audit.store())?;
        memory.require_store_memory(stores.application())?;
        memory.require_store_memory(stores.custody().store())?;
        Ok(Self {
            stores,
            audit,
            clocks: DatabaseClocks::default(),
        })
    }

    #[cfg(any(test, feature = "test-utils"))]
    pub(crate) fn with_fixture_clock(
        stores: Arc<TenantStorageSet>,
        audit: Arc<SecurityAudit>,
        clock: Arc<kasumi_clock::EpochClock>,
    ) -> anyhow::Result<Self> {
        let mut construction = Self::new(stores, audit)?;
        anyhow::ensure!(
            matches!(
                construction.stores.application().storage_access().purpose(),
                kasumi_store::StoragePurpose::LocalFixture
            ),
            "fixture clock requires the exact fixture application store"
        );
        clock.now_ms()?;
        construction.clocks = DatabaseClocks {
            elapsed: clock.elapsed_clock(),
            command: Arc::new(super::FixtureCommandClock(clock)),
        };
        Ok(construction)
    }

    pub(crate) fn stores(&self) -> &Arc<TenantStorageSet> {
        &self.stores
    }

    pub(crate) fn admission(&self) -> &Arc<NodeAdmission> {
        self.audit.admission()
    }

    pub(crate) async fn start_local(
        self,
        engine: Arc<TenantEngine>,
        node_id: u64,
        name: String,
    ) -> anyhow::Result<Arc<Database>> {
        let buffers = self.admission().snapshot_buffer_owner()?;
        let group =
            RaftGroup::local(node_id, name, self.stores.clone(), engine.clone(), buffers).await?;
        // No fallible operation or suspension follows the successful transfer
        // of the retained Raft startup outcome into this Database owner.
        Ok(self.finish(engine, group, true))
    }

    pub(crate) async fn start_replicated(
        self,
        engine: Arc<TenantEngine>,
        node_id: u64,
        name: String,
        transport: Arc<dyn RaftTransport>,
        config: RaftGroupConfig,
    ) -> anyhow::Result<Arc<Database>> {
        let buffers = self.admission().snapshot_buffer_owner()?;
        let group = RaftGroup::open(
            node_id,
            name,
            self.stores.clone(),
            engine.clone(),
            transport,
            config,
            buffers,
        )
        .await?;
        Ok(self.finish(engine, group, false))
    }

    fn finish(self, engine: Arc<TenantEngine>, group: RaftGroup, embedded: bool) -> Arc<Database> {
        Database::finish_construction(
            engine,
            group,
            self.stores,
            self.audit,
            self.clocks,
            embedded,
        )
    }
}

#[cfg(test)]
#[path = "database_construction_tests.rs"]
mod tests;
