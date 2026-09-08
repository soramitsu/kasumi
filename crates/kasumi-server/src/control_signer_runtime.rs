//! One remote physical receiver. Source permission and local current Control
//! administration remain separate original invocations through final encoding.
use crate::runtime::{parse_certificate_pin, read_bounded};
use crate::serving_runtime::{CredentialSource, ServingAuthorityConfig};
use crate::signer_runtime::InstalledSignerVerifier;
use anyhow::{Context, Result, ensure};
use kasumi_client::{KasumiAuthorityPool, KasumiClientConfig};
use kasumi_serving::*;
use std::{collections::BTreeMap, sync::Arc};

pub(crate) struct ControlSignerRuntime {
    node_id: u64,
    control: Arc<kasumi_engine::Database>,
    verifier: Arc<InstalledSignerVerifier>,
    authorities: BTreeMap<String, ServingAuthorityConfig>,
    trusts: BTreeMap<String, AuthorityTrust>,
    admin_tls: crate::runtime::TlsFiles,
    credential: CredentialSource,
}
impl ControlSignerRuntime {
    pub(crate) fn new(
        node_id: u64,
        control: Arc<kasumi_engine::Database>,
        verifier: Arc<InstalledSignerVerifier>,
        authorities: BTreeMap<String, ServingAuthorityConfig>,
        trusts: BTreeMap<String, AuthorityTrust>,
        admin_tls: crate::runtime::TlsFiles,
        credential: CredentialSource,
    ) -> Result<Arc<Self>> {
        ensure!(
            node_id > 0
                && control.engine().generation()?.state.tenant == crate::runtime::CONTROL_TENANT,
            "remote signer requires the exact installed Control database"
        );
        ensure!(
            authorities.keys().eq(trusts.keys()),
            "installed remote signer authority set differs"
        );
        for (name, config) in &authorities {
            config.validate()?;
            ensure!(
                trusts[name].manifest() == &config.manifest,
                "installed remote signer trust differs from configured issuer"
            );
        }
        Ok(Arc::new(Self {
            node_id,
            control,
            verifier,
            authorities,
            trusts,
            admin_tls,
            credential,
        }))
    }
    pub(crate) fn control(&self) -> &Arc<kasumi_engine::Database> {
        &self.control
    }
    pub(crate) fn route(
        &self,
        request: &ControlSignerRequest,
    ) -> Result<(SigningDomain, AuthorityManifest, KasumiAuthorityPool)> {
        request.digest()?;
        let mut selected = None;
        for (name, config) in &self.authorities {
            for partition in config.manifest.partitions.keys() {
                let domain = config.manifest.signing_domain(*partition)?;
                if domain.digest()? != request.directive.domain_sha256 {
                    continue;
                }
                ensure!(
                    selected.is_none(),
                    "duplicate installed remote signer domain"
                );
                selected = Some((config, &self.trusts[name], *partition, domain));
            }
        }
        let (config, trust, partition, domain) =
            selected.context("remote signer domain is not installed")?;
        let tls = config.tls.load()?;
        let node = NodeIdentity {
            node_id: self.node_id,
            verifier: trust.verifier_identity()?,
            principal: config.principal.clone(),
            certificate_sha256: hex::encode(tls.certificate_pin()),
        };
        ensure!(
            node == request.directive.node,
            "request substituted the installed physical Control receiver"
        );
        let ca = read_bounded(&config.server_ca, 1 << 20)?;
        let connections = config.endpoints[&partition]
            .iter()
            .map(|(id, endpoint)| {
                Ok((
                    *id,
                    KasumiClientConfig {
                        endpoint: endpoint.endpoint.clone(),
                        identity: tls.clone(),
                        trusted_ca_pem: ca.clone(),
                        server_certificate_pins: endpoint
                            .certificate_pins
                            .iter()
                            .map(|pin| parse_certificate_pin(pin))
                            .collect::<Result<_>>()?,
                    },
                ))
            })
            .collect::<Result<_>>()?;
        let path = config.bearer_files[&partition].clone();
        let credential = self.credential.clone();
        let pool = KasumiAuthorityPool::new(
            connections,
            trust.clone(),
            Arc::new(move || credential(&path)),
        )?;
        Ok((domain, config.manifest.clone(), pool))
    }
    pub(crate) async fn authorize(
        &self,
        request: &ControlSignerRequest,
        fence: Arc<kasumi_engine::ControlAdministrativeFence>,
        issuer: kasumi_client::CurrentControlSignerObservation,
        domain: &SigningDomain,
    ) -> Result<(
        Arc<LiveSignerTrust>,
        crate::signer_runtime::authorization::CurrentSignerInvocation,
    )> {
        ensure!(
            issuer
                .observation()
                .registration
                .enrollment
                .certificate_pins
                .contains(&hex::encode(self.admin_tls.load()?.certificate_pin())),
            "current receiver administrative TLS identity differs from its permanent physical registration"
        );
        self.verifier
            .authorize_control(request, fence, issuer, domain)
            .await
    }
}
