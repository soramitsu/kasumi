//! Explicit test-only single-domain constructors, including intentionally
//! incomplete application/custody catalogs for storage contract tests.
use super::*;

impl TenantStore {
    pub async fn initialize_catalog_fixture(
        node: Arc<NodeStore>,
        tenant: String,
        provider: Arc<dyn KeyProvider>,
    ) -> Result<Arc<Self>> {
        let access = StorageAccess::fixture_for(&tenant);
        let clock: Arc<dyn LeaseClock> = Arc::new(SystemLeaseClock);
        open(Input {
            node,
            tenant,
            provider,
            access,
            clock,
            renew: true,
            mode: Mode::Initialize,
        })
        .await
    }
    pub async fn initialize_catalog_fixture_with_clock(
        node: Arc<NodeStore>,
        tenant: String,
        provider: Arc<dyn KeyProvider>,
        clock: Arc<dyn LeaseClock>,
    ) -> Result<Arc<Self>> {
        let access = StorageAccess::fixture_for(&tenant);
        open(Input {
            node,
            tenant,
            provider,
            access,
            clock,
            renew: false,
            mode: Mode::Initialize,
        })
        .await
    }
    pub async fn initialize_catalog_fixture_with_access(
        node: Arc<NodeStore>,
        tenant: String,
        provider: Arc<dyn KeyProvider>,
        access: StorageAccess,
    ) -> Result<Arc<Self>> {
        let clock: Arc<dyn LeaseClock> = Arc::new(SystemLeaseClock);
        open(Input {
            node,
            tenant,
            provider,
            access,
            clock,
            renew: true,
            mode: Mode::Initialize,
        })
        .await
    }
    pub async fn initialize_catalog_fixture_with_clock_and_access(
        node: Arc<NodeStore>,
        tenant: String,
        provider: Arc<dyn KeyProvider>,
        clock: Arc<dyn LeaseClock>,
        access: StorageAccess,
    ) -> Result<Arc<Self>> {
        open(Input {
            node,
            tenant,
            provider,
            access,
            clock,
            renew: false,
            mode: Mode::Initialize,
        })
        .await
    }
    pub async fn open_existing_fixture(
        node: Arc<NodeStore>,
        tenant: String,
        provider: Arc<dyn KeyProvider>,
    ) -> Result<Arc<Self>> {
        let access = StorageAccess::fixture_for(&tenant);
        let clock: Arc<dyn LeaseClock> = Arc::new(SystemLeaseClock);
        open(Input {
            node,
            tenant,
            provider,
            access,
            clock,
            renew: true,
            mode: Mode::Existing,
        })
        .await
    }
    pub async fn open_existing_fixture_with_clock(
        node: Arc<NodeStore>,
        tenant: String,
        provider: Arc<dyn KeyProvider>,
        clock: Arc<dyn LeaseClock>,
    ) -> Result<Arc<Self>> {
        let access = StorageAccess::fixture_for(&tenant);
        open(Input {
            node,
            tenant,
            provider,
            access,
            clock,
            renew: false,
            mode: Mode::Existing,
        })
        .await
    }
    pub async fn open_existing_fixture_with_access(
        node: Arc<NodeStore>,
        tenant: String,
        provider: Arc<dyn KeyProvider>,
        access: StorageAccess,
    ) -> Result<Arc<Self>> {
        let clock: Arc<dyn LeaseClock> = Arc::new(SystemLeaseClock);
        open(Input {
            node,
            tenant,
            provider,
            access,
            clock,
            renew: true,
            mode: Mode::Existing,
        })
        .await
    }
    pub async fn open_existing_fixture_with_clock_and_access(
        node: Arc<NodeStore>,
        tenant: String,
        provider: Arc<dyn KeyProvider>,
        clock: Arc<dyn LeaseClock>,
        access: StorageAccess,
    ) -> Result<Arc<Self>> {
        open(Input {
            node,
            tenant,
            provider,
            access,
            clock,
            renew: false,
            mode: Mode::Existing,
        })
        .await
    }
}
