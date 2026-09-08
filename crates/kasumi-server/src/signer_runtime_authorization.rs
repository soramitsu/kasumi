//! A local trust mutation borrows one exact current-quorum administrative
//! invocation. Neither a root certificate nor a serialized receipt can install it.
use anyhow::{Result, ensure};
use kasumi_authority::AuthorityAdministrativeFence;
use kasumi_clock::ElapsedDeadline;
use kasumi_serving::LiveTrustAdministrator;
use kasumi_types::RequestContext;
use std::sync::{Arc, Mutex, OnceLock, Weak};

#[derive(Default)]
pub(super) struct ScopedSignerAdministrator {
    serial: Arc<tokio::sync::Mutex<()>>,
    current: Mutex<Option<Weak<CurrentAuthorization>>>,
}
struct CurrentAuthorization {
    fence: CurrentFence,
    deadline: OnceLock<ElapsedDeadline>,
    directive: OnceLock<Arc<kasumi_authority::CommittedSignerDirective>>,
}
enum CurrentFence {
    Authority(Arc<AuthorityAdministrativeFence>),
    Control {
        fence: Arc<kasumi_engine::ControlAdministrativeFence>,
        issuer: Box<kasumi_client::CurrentControlSignerObservation>,
    },
}
impl CurrentFence {
    fn context(&self) -> &RequestContext {
        match self {
            Self::Authority(fence) => fence.context(),
            Self::Control { fence, .. } => fence.context(),
        }
    }
    fn check(&self) -> Result<()> {
        match self {
            Self::Authority(fence) => Ok(fence.check()?),
            Self::Control { fence, issuer } => {
                issuer.check()?;
                fence.check()?;
                issuer.check()
            }
        }
    }
}
impl CurrentAuthorization {
    fn check(&self) -> Result<()> {
        self.fence.check()?;
        if let Some(deadline) = self.deadline.get() {
            deadline.check()?;
        }
        if let Some(directive) = self.directive.get() {
            directive.check()?;
        }
        Ok(())
    }
}
impl LiveTrustAdministrator for ScopedSignerAdministrator {
    fn authorize(&self, context: &RequestContext) -> Result<()> {
        let current = self
            .current
            .lock()
            .map_err(|_| anyhow::anyhow!("signer authorization poisoned"))?
            .as_ref()
            .and_then(Weak::upgrade)
            .ok_or_else(|| {
                anyhow::anyhow!("current authenticated signer maintenance invocation required")
            })?;
        ensure!(
            current.fence.context() == context
                && current
                    .fence
                    .context()
                    .authorization
                    .same_live_invocation(&context.authorization),
            "signer mutation cannot substitute its original administrative invocation"
        );
        current.check()
    }
}
impl ScopedSignerAdministrator {
    pub(super) async fn bind(
        self: &Arc<Self>,
        fence: Arc<AuthorityAdministrativeFence>,
    ) -> Result<CurrentSignerInvocation> {
        self.bind_current(CurrentFence::Authority(fence)).await
    }
    pub(super) async fn bind_control(
        self: &Arc<Self>,
        fence: Arc<kasumi_engine::ControlAdministrativeFence>,
        issuer: kasumi_client::CurrentControlSignerObservation,
    ) -> Result<CurrentSignerInvocation> {
        self.bind_current(CurrentFence::Control {
            fence,
            issuer: Box::new(issuer),
        })
        .await
    }
    async fn bind_current(
        self: &Arc<Self>,
        fence: CurrentFence,
    ) -> Result<CurrentSignerInvocation> {
        let serial = self.serial.clone().lock_owned().await;
        fence.check()?;
        let current = Arc::new(CurrentAuthorization {
            fence,
            deadline: OnceLock::new(),
            directive: OnceLock::new(),
        });
        *self
            .current
            .lock()
            .map_err(|_| anyhow::anyhow!("signer authorization poisoned"))? =
            Some(Arc::downgrade(&current));
        Ok(CurrentSignerInvocation {
            administrator: self.clone(),
            current,
            _serial: serial,
        })
    }
}
pub(crate) struct CurrentSignerInvocation {
    administrator: Arc<ScopedSignerAdministrator>,
    current: Arc<CurrentAuthorization>,
    _serial: tokio::sync::OwnedMutexGuard<()>,
}
impl CurrentSignerInvocation {
    pub(crate) fn bind_directive(
        &self,
        directive: Arc<kasumi_authority::CommittedSignerDirective>,
    ) -> Result<()> {
        ensure!(
            self.current.fence.context() == directive.context()
                && self
                    .current
                    .fence
                    .context()
                    .authorization
                    .same_live_invocation(&directive.context().authorization),
            "local publication cannot replace its original current source invocation"
        );
        self.current
            .directive
            .set(directive)
            .map_err(|_| anyhow::anyhow!("original signer source permission cannot be replaced"))?;
        self.check()
    }
    pub(crate) fn check(&self) -> Result<()> {
        self.current.check()
    }
    pub(crate) fn bind_deadline(&self, deadline: ElapsedDeadline) -> Result<()> {
        self.current.deadline.set(deadline).map_err(|_| {
            anyhow::anyhow!("original signer admission deadline cannot be replaced")
        })?;
        self.check()
    }
}
impl Drop for CurrentSignerInvocation {
    fn drop(&mut self) {
        if let Ok(mut current) = self.administrator.current.lock() {
            *current = None;
        }
    }
}
