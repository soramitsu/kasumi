use crate::KasumiLifecycleClient;
use crate::{
    ClientError, KasumiClientConfig,
    installed_pool::{InstalledPool, RoutedClient},
};
use kasumi_serving::{ControlTrust, VerifiedControlChange, VerifiedControlIntent};
use kasumi_transport::credentials::CredentialSource;
use kasumi_types::*;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct KasumiLifecyclePool {
    inner: InstalledPool<KasumiLifecycleClient>,
}
impl RoutedClient for KasumiLifecycleClient {
    type Context = ControlTrust;
    async fn connect(
        config: &KasumiClientConfig,
        context: Self::Context,
    ) -> std::result::Result<Self, ClientError> {
        KasumiLifecycleClient::connect(config, context).await
    }
    fn set_deadline(&mut self, deadline: tokio::time::Instant) {
        KasumiLifecycleClient::set_deadline(self, deadline);
    }
}
impl KasumiLifecyclePool {
    pub fn with_credential(self, credential: Arc<dyn CredentialSource>) -> Self {
        Self {
            inner: self.inner.with_credential(credential),
        }
    }
    pub fn new(
        endpoints: BTreeMap<u64, KasumiClientConfig>,
        trust: ControlTrust,
        credential: Arc<dyn CredentialSource>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            inner: InstalledPool::new(endpoints, trust, credential)?,
        })
    }
    pub async fn execute(
        &mut self,
        request: &LifecycleControlCommand,
        timeout: Duration,
    ) -> std::result::Result<WriteReceipt, ClientError> {
        self.inner
            .request(timeout, false, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.execute(bearer, &request).await })
            })
            .await
    }
    pub async fn observe_intent(
        &mut self,
        id: uuid::Uuid,
        timeout: Duration,
    ) -> std::result::Result<VerifiedControlIntent, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                Box::pin(async move { client.observe_intent(bearer, id).await })
            })
            .await
    }
    pub async fn observe_change(
        &mut self,
        id: uuid::Uuid,
        partition: &str,
        timeout: Duration,
    ) -> std::result::Result<VerifiedControlChange, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                let partition = partition.to_owned();
                Box::pin(async move { client.observe_change(bearer, id, &partition).await })
            })
            .await
    }
    pub async fn read_status(
        &mut self,
        request: &ReadLifecycleStatus,
        timeout: Duration,
    ) -> std::result::Result<LifecycleStatus, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.read_status(bearer, &request).await })
            })
            .await
    }
}
