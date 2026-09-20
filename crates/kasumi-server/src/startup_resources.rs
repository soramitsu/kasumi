//! Unpublished owned resources from an exclusive node open or explicit new
//! catalogs or a new custody runtime on an already owned node. A borrowed node
//! is retained only to join its initializers; borrowed serving runtimes, stores
//! and databases never enter this scope.
use kasumi_types::drain::{DrainCompletion, DrainReport, DrainResult};
use std::sync::Arc;

#[derive(Default)]
pub(crate) struct Resources {
    report: tokio::sync::Mutex<DrainReport>,
    pub(crate) nodes: Vec<Arc<kasumi_store::NodeStore>>,
    pub(crate) stores: Vec<Arc<kasumi_store::TenantStore>>,
    pub(crate) audits: Vec<Arc<kasumi_engine::SecurityAudit>>,
    pub(crate) verifiers: Vec<Arc<crate::signer_runtime::InstalledSignerVerifier>>,
    pub(crate) databases: Vec<Arc<kasumi_engine::Database>>,
    pub(crate) custodies: Vec<Arc<kasumi_engine::RetiredCustody>>,
    pub(crate) authorities: Vec<Arc<kasumi_authority::IndependentAuthority>>,
    // Fields drop in declaration order: exclusive installation ownership must
    // outlive every retained worker and physical node handle.
    pub(crate) standalone_lock: Option<kasumi_store::private_files::ExclusiveLock>,
}
impl Resources {
    pub(crate) async fn close(&self) -> DrainResult {
        let mut report = self.report.lock().await;
        let mut retained = None;
        for authority in &self.authorities {
            if let Err(failure) = authority.shutdown().await {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
        }
        for custody in &self.custodies {
            if let Err(failure) = custody.shutdown().await {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
        }
        for database in &self.databases {
            if let Err(failure) = database.shutdown().await {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
        }
        for audit in &self.audits {
            if let Err(failure) = audit.shutdown().await {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
        }
        for store in &self.stores {
            if let Err(failure) = store.shutdown().await {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
        }
        for verifier in &self.verifiers {
            if let Err(failure) = verifier.shutdown().await {
                report.merge(&failure);
                if failure.completion() == DrainCompletion::Retained {
                    retained = Some(failure);
                }
            }
        }
        for (index, node) in self.nodes.iter().enumerate() {
            if let Err(error) = node.drain_initializers().await {
                // This API returns a failure only after all registered handles
                // have actually joined. Preserve it without retrying forever.
                report.record("node initializers", index, error);
            }
        }
        report.outcome(retained)
    }
}

impl crate::startup_owner::Runtime for Resources {
    fn close(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = DrainResult> + Send + '_>> {
        Box::pin(Resources::close(self))
    }
}
