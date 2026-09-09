//! Installed current administrative sources for physical publication receivers.
//! The consensus enrollment fixes the destination and pins; configuration adds
//! only explicit local credential/identity sources and never a routing fallback.
use crate::runtime::{TlsFiles, file_secret, parse_certificate_pin, read_bounded};
use anyhow::{Context, Result, ensure};
use kasumi_serving::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
    sync::Arc,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerPublicationReceiver {
    pub verifier: TrustVerifierIdentity,
    pub endpoint: String,
    pub certificate_pins: BTreeSet<String>,
    pub server_ca: PathBuf,
    pub tls: TlsFiles,
    pub bearer_file: PathBuf,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignerPublicationConfig {
    pub receivers: Vec<SignerPublicationReceiver>,
}
impl SignerPublicationConfig {
    pub fn validate(&self) -> Result<()> {
        let mut identities = BTreeSet::new();
        for receiver in &self.receivers {
            SignerVerifierEnrollment {
                verifier: receiver.verifier.clone(),
                endpoint: receiver.endpoint.clone(),
                certificate_pins: receiver.certificate_pins.clone(),
            }
            .validate()?;
            ensure!(
                identities.insert(receiver.verifier.clone()),
                "duplicate physical publication source"
            );
            ensure!(
                receiver.server_ca.is_absolute() && receiver.bearer_file.is_absolute(),
                "publication sources require installed absolute files"
            );
            receiver.tls.validate()?;
        }
        Ok(())
    }
    pub(crate) fn open(
        &self,
        manifest: AuthorityManifest,
    ) -> Result<Arc<dyn kasumi_authority::SignerPublicationTransport>> {
        self.validate()?;
        Ok(Arc::new(InstalledPublicationTransport {
            receivers: self
                .receivers
                .iter()
                .map(|receiver| (receiver.verifier.clone(), receiver.clone()))
                .collect(),
            trust: AuthorityTrust::install(manifest)?,
        }))
    }
}
struct InstalledPublicationTransport {
    receivers: BTreeMap<TrustVerifierIdentity, SignerPublicationReceiver>,
    trust: AuthorityTrust,
}
#[async_trait::async_trait]
impl kasumi_authority::SignerPublicationTransport for InstalledPublicationTransport {
    async fn observe(
        &self,
        dispatch: &SignerCoverageDispatch,
    ) -> Result<kasumi_client::CurrentSignerPublication> {
        let receiver = self
            .receivers
            .get(dispatch.command.publication.verifier())
            .context("physical publication credential source is not installed")?;
        let enrolled = &dispatch.registration.enrollment;
        ensure!(
            receiver.endpoint == enrolled.endpoint
                && receiver.certificate_pins == enrolled.certificate_pins,
            "installed publication route differs from the frozen enrolled endpoint and pins"
        );
        let config = kasumi_client::KasumiClientConfig {
            endpoint: receiver.endpoint.clone(),
            identity: receiver.tls.load()?,
            trusted_ca_pem: read_bounded(&receiver.server_ca, 1 << 20)?,
            server_certificate_pins: receiver
                .certificate_pins
                .iter()
                .map(|pin| parse_certificate_pin(pin))
                .collect::<Result<_>>()?,
        };
        // One atomic private-file snapshot belongs to this whole finite attempt.
        let bearer = file_secret(
            receiver
                .bearer_file
                .to_str()
                .context("signer publication credential path is not UTF-8")?,
        )?;
        Ok(kasumi_client::CurrentSignerPublication::observe(
            &config,
            &bearer,
            self.trust.clone(),
            dispatch,
        )
        .await?)
    }
}
