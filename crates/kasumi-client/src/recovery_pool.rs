use crate::KasumiRecoveryClient;
use crate::{
    ClientError, KasumiClientConfig,
    installed_pool::{InstalledPool, RoutedClient},
};
use kasumi_transport::credentials::CredentialSource;
use kasumi_types::*;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct KasumiRecoveryPool {
    inner: InstalledPool<KasumiRecoveryClient>,
}
impl RoutedClient for KasumiRecoveryClient {
    type Context = ();
    async fn connect(
        config: &KasumiClientConfig,
        _context: Self::Context,
    ) -> std::result::Result<Self, ClientError> {
        KasumiRecoveryClient::connect(config).await
    }
    fn set_deadline(&mut self, deadline: tokio::time::Instant) {
        KasumiRecoveryClient::set_deadline(self, deadline);
    }
}
impl KasumiRecoveryPool {
    pub fn with_credential(self, credential: Arc<dyn CredentialSource>) -> Self {
        Self {
            inner: self.inner.with_credential(credential),
        }
    }
    pub fn new(
        endpoints: BTreeMap<u64, KasumiClientConfig>,
        credential: Arc<dyn CredentialSource>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            inner: InstalledPool::new(endpoints, (), credential)?,
        })
    }
    pub async fn start(
        &mut self,
        request: &RecoveryStart,
        timeout: Duration,
    ) -> std::result::Result<RecoveryRecord, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.start(bearer, &request).await })
            })
            .await
    }
    pub async fn status(
        &mut self,
        request: &RecoveryStatusRequest,
        timeout: Duration,
    ) -> std::result::Result<RecoveryRecord, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.status(bearer, &request).await })
            })
            .await
    }
    pub async fn resume(
        &mut self,
        request: &RecoveryResume,
        timeout: Duration,
    ) -> std::result::Result<RecoveryRecord, ClientError> {
        if !(1..=16).contains(&request.max_steps) {
            return Err(
                anyhow::anyhow!("recovery resume work limit is one to sixteen phases").into(),
            );
        }
        self.inner
            .request_with_probe(
                timeout,
                false,
                |client, bearer| {
                    let status = RecoveryStatusRequest {
                        operation_id: request.operation_id,
                    };
                    Box::pin(async move { client.status(bearer, &status).await.map(|_| ()) })
                },
                |client, bearer| {
                    let request = request.clone();
                    Box::pin(async move { client.resume(bearer, &request).await })
                },
            )
            .await
    }
    pub async fn stop(
        &mut self,
        request: &RecoveryStop,
        timeout: Duration,
    ) -> std::result::Result<RecoveryRecord, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.stop(bearer, &request).await })
            })
            .await
    }
    pub async fn read_phase(
        &mut self,
        request: &RecoveryPhaseRequest,
        timeout: Duration,
    ) -> std::result::Result<RecoveryPhaseRecord, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.read_phase(bearer, &request).await })
            })
            .await
    }
}
