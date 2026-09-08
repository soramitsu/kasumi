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
    fence: Arc<AuthorityAdministrativeFence>,
    deadline: OnceLock<ElapsedDeadline>,
}
impl CurrentAuthorization {
    fn check(&self) -> Result<()> {
        self.fence.check()?;
        if let Some(deadline) = self.deadline.get() {
            deadline.check()?;
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
        let serial = self.serial.clone().lock_owned().await;
        fence.check()?;
        let current = Arc::new(CurrentAuthorization {
            fence,
            deadline: OnceLock::new(),
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
