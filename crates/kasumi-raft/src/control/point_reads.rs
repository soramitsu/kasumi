//! Canonical custody validators borrow one operation-owned encrypted snapshot.
//! Directory preflight sizes the actual backing; it is never a content proof.
use super::*;
use kasumi_store::{PreparedTenantPointReads, PreparedTenantPointWorkspace};

pub(crate) trait CustodyRead {
    fn with_point<T>(
        &mut self,
        namespace: &str,
        key: &[u8],
        limit: usize,
        inspect: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T>;

    fn load<T: DeserializeOwned + Serialize>(
        &mut self,
        namespace: &str,
        key: &[u8],
    ) -> Result<Option<T>> {
        self.with_point(namespace, key, 2 << 20, |bytes| {
            bytes.map(decode_canonical).transpose()
        })
    }
}
impl CustodyRead for &TenantStore {
    fn with_point<T>(
        &mut self,
        namespace: &str,
        key: &[u8],
        limit: usize,
        inspect: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T> {
        let bytes = self.get_bounded(namespace, key, limit)?;
        inspect(bytes.as_deref())
    }
}

struct AppliedReads {
    session: PreparedTenantPointReads,
    // Exact phase overlap is included in the eventual immutable selection plan.
    phases: [(usize, usize, usize); 3],
}
impl CustodyRead for AppliedReads {
    fn with_point<T>(
        &mut self,
        namespace: &str,
        key: &[u8],
        limit: usize,
        inspect: impl FnOnce(Option<&[u8]>) -> Result<T>,
    ) -> Result<T> {
        inspect(
            self.session
                .custody_get(namespace, key, limit.min(self.phases[2].2))?,
        )
    }
}
impl AppliedReads {
    fn probe_custody(&mut self, namespace: &str, key: &[u8], maximum: usize) -> Result<bool> {
        let value = self.session.custody_value_bound(namespace, key, maximum)?;
        self.phases[2].2 = self.phases[2].2.max(value.unwrap_or(0));
        Ok(value.is_some())
    }
    fn probe_application(&mut self, namespace: &str, key: &[u8], maximum: usize) -> Result<()> {
        let value = self
            .session
            .application_value_bound(namespace, key, maximum)?;
        self.phases[2].2 = self.phases[2].2.max(value.unwrap_or(0));
        Ok(())
    }
    fn resize(&mut self) -> Result<()> {
        let (namespace, key, value) = self.phases[2];
        self.session.ensure_capacity(namespace, key, value)
    }
    fn new(
        domains: &TenantStorageSet,
        context: &AppliedEntryContext,
        retirement: bool,
        selection: bool,
    ) -> Result<Self> {
        // Only fixed-width identity capacity is known before inspecting the
        // selected directory. The initial output has zero value-byte capacity;
        // its real directory pages perform all size probes without new grants.
        let bounds = (SEEDS.len(), LOCAL_FIRST_ASSOCIATION_KEY.len(), 0);
        let mut reads = Self {
            session: domains
                .read_view()?
                .prepare_point_reads(bounds.0, bounds.1, bounds.2)?,
            phases: [bounds; 3],
        };
        let result = (|| {
            reads.probe_custody(META, b"applied", 2 << 20)?;
            let first = reads.probe_custody(META, b"first_membership", 2 << 20)?;
            reads.probe_custody(META, crate::initialization_association::STATE, 2 << 20)?;
            reads.probe_custody(META, crate::initialization_association::ANCHOR, 2 << 20)?;
            let prebind = reads.probe_custody(META, TARGET_PREBIND_KEY, 2 << 20)?;
            reads.probe_custody(META, LOCAL_FIRST_ASSOCIATION_KEY, 2 << 20)?;
            if prebind {
                reads.probe_custody(META, b"node_id", 2 << 20)?;
                reads.probe_custody(META, b"group", 2 << 20)?;
                reads.probe_custody(META, b"application_bootstrap_sha256", 2 << 20)?;
            }
            if !first && context.membership.log_id().is_some() {
                reads.probe_custody(HEADERS, &context.log_id.index.to_be_bytes(), 2 << 20)?;
            }
            if retirement {
                let prior = reads.probe_custody(META, b"retired_boundary", 2 << 20)?;
                reads.probe_custody(SEEDS, &context.log_id.index.to_be_bytes(), 2 << 20)?;
                reads.probe_custody(META, b"committed", 2 << 20)?;
                reads.probe_custody(META, b"snapshot_coverage", 2 << 20)?;
                reads.probe_custody(META, b"group", 2 << 20)?;
                reads.probe_custody(META, b"application_bootstrap_sha256", 2 << 20)?;
                if prior {
                    reads.probe_custody(
                        META,
                        crate::custody_tables::HEAD,
                        crate::custody_tables::HEAD_BYTES,
                    )?;
                }
            }
            if selection {
                reads.probe_application(
                    "engine.bootstrap",
                    b"manifest",
                    kasumi_store::APPLICATION_BOOTSTRAP_MANIFEST_BYTES,
                )?;
                reads.probe_custody(META, b"application_bootstrap_sha256", 256)?;
            }
            reads.resize()?;
            reads.phases[1] = reads.phases[2];
            Ok(())
        })();
        match result {
            Ok(()) => Ok(reads),
            Err(error) => reads.session.finish(Err(error)),
        }
    }

    fn selection_branch(&mut self, prepared: &PreparedApplied) -> Result<()> {
        if matches!(prepared, PreparedApplied::CoveredReplay { snapshot: true }) {
            // Only this actual branch needs the snapshot proof rows. Ordinary
            // apply does not allocate for stale or unrelated snapshot metadata.
            self.probe_custody(META, b"snapshot_coverage", 2 << 20)?;
            self.probe_application("raft.snapshot", b"current", 2 << 20)?;
            self.resize()?;
        }
        Ok(())
    }
}

pub(crate) fn prepare_applied(
    domains: &TenantStorageSet,
    context: &AppliedEntryContext,
    retirement: Option<&kasumi_types::RetirementReceipt>,
) -> Result<PreparedApplied> {
    let mut reads = AppliedReads::new(domains, context, retirement.is_some(), false)?;
    let result = prepare_applied_at(domains, context, retirement, &mut reads);
    reads.session.finish(result)
}

pub(crate) fn prepare_applied_and_selection(
    domains: &TenantStorageSet,
    context: &AppliedEntryContext,
    retirement: Option<&kasumi_types::RetirementReceipt>,
    application: &[WriteOp],
) -> Result<(
    PreparedApplied,
    crate::PreparedSelectionPlan,
    PreparedTenantPointWorkspace,
)> {
    let mut reads = AppliedReads::new(domains, context, retirement.is_some(), true)?;
    let result = (|| {
        let prepared = prepare_applied_at(domains, context, retirement, &mut reads)?;
        reads.selection_branch(&prepared)?;
        let plan = crate::PreparedSelectionPlan::for_applied_at(
            domains,
            &prepared,
            application,
            &mut reads.session,
            reads.phases,
        )?;
        Ok((prepared, plan))
    })();
    reads
        .session
        .finish_with_workspace(result)
        .map(|((prepared, plan), points)| (prepared, plan, points))
}
