use crate::KasumiAdminClient;
use crate::{
    ClientError, KasumiClientConfig,
    installed_pool::{InstalledPool, RoutedClient},
};
use kasumi_transport::credentials::CredentialSource;
use kasumi_types::*;
use std::{collections::BTreeMap, sync::Arc, time::Duration};

#[derive(Clone)]
pub struct KasumiRetirementPool {
    inner: InstalledPool<KasumiAdminClient>,
}
impl RoutedClient for KasumiAdminClient {
    type Context = ();
    async fn connect(
        config: &KasumiClientConfig,
        _context: Self::Context,
    ) -> std::result::Result<Self, ClientError> {
        KasumiAdminClient::connect(config).await
    }
    fn set_deadline(&mut self, deadline: tokio::time::Instant) {
        KasumiAdminClient::set_deadline(self, deadline);
    }
}
impl KasumiRetirementPool {
    pub fn new(
        endpoints: BTreeMap<u64, KasumiClientConfig>,
        credential: Arc<dyn CredentialSource>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            inner: InstalledPool::new(endpoints, (), credential)?,
        })
    }
    pub async fn read_custody(
        &mut self,
        request: &RetirementRef,
        timeout: Duration,
    ) -> std::result::Result<CustodyStatus, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.read_custody(bearer, &request).await })
            })
            .await
    }
    pub async fn execute_custody(
        &mut self,
        request: &CustodyRequest,
        timeout: Duration,
    ) -> std::result::Result<CustodyReceipt, ClientError> {
        self.inner
            .request_with_resolution(
                timeout,
                |client, bearer| {
                    let request = request.clone();
                    Box::pin(async move { client.read_custody_receipt(bearer, &request).await })
                },
                |client, bearer| {
                    let request = request.clone();
                    Box::pin(async move { client.execute_custody(bearer, &request).await })
                },
            )
            .await
    }
    pub async fn read_custody_receipt(
        &mut self,
        request: &CustodyRequest,
        timeout: Duration,
    ) -> std::result::Result<Option<CustodyReceipt>, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.read_custody_receipt(bearer, &request).await })
            })
            .await
    }
    pub async fn retire_source(
        &mut self,
        request: &RetireSourceRequest,
        timeout: Duration,
    ) -> std::result::Result<crate::VerifiedRetirementReceipt, ClientError> {
        self.inner
            .request(timeout, false, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.retire_source(bearer, &request).await })
            })
            .await
    }
    pub async fn retirement_status(
        &mut self,
        request: &RetirementRef,
        timeout: Duration,
    ) -> std::result::Result<Option<RetirementStatus>, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.retirement_status(bearer, &request).await })
            })
            .await
    }
    pub async fn abort_retirement(
        &mut self,
        request: &RetireSourceRequest,
        timeout: Duration,
    ) -> std::result::Result<crate::VerifiedRetirementResolution, ClientError> {
        self.inner
            .request(timeout, false, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.abort_retirement(bearer, &request).await })
            })
            .await
    }
    pub async fn verify_retirement_receipt(
        &mut self,
        request: &RetirementRef,
        timeout: Duration,
    ) -> std::result::Result<crate::VerifiedRetirementReceipt, ClientError> {
        self.inner
            .request(timeout, true, |client, bearer| {
                let request = request.clone();
                Box::pin(async move { client.verify_retirement_receipt(bearer, &request).await })
            })
            .await
    }
}
