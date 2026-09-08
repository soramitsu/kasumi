//! Explicit immutable signing fixtures. Production binaries cannot select these
//! owners; durable generation transitions are tested with encrypted stores.
use crate::*;
use anyhow::{Result, ensure};
use ring::signature::{Ed25519KeyPair, KeyPair};
use std::{collections::BTreeMap, sync::Arc};
use uuid::Uuid;

pub struct FixtureSigningRoot(Ed25519KeyPair);
impl FixtureSigningRoot {
    pub fn from_pkcs8(bytes: &[u8]) -> Result<Self> {
        Ok(Self(
            Ed25519KeyPair::from_pkcs8(bytes)
                .map_err(|_| anyhow::anyhow!("invalid fixture root"))?,
        ))
    }
    pub fn public_key(&self) -> String {
        hex::encode(self.0.public_key().as_ref())
    }
    pub fn install(&self, manifest: AuthorityManifest, partition: u16) -> Result<FixtureAuthority> {
        ensure!(
            manifest.partitions.len() == 1,
            "fixture requires one partition"
        );
        let domain = manifest.signing_domain(partition)?;
        ensure!(
            domain.root_public_key == self.public_key(),
            "fixture root differs"
        );
        let operational = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .map_err(|_| anyhow::anyhow!("fixture operational key generation failed"))?;
        let key = Ed25519KeyPair::from_pkcs8(operational.as_ref())
            .map_err(|_| anyhow::anyhow!("fixture key invalid"))?;
        let identity = SigningGeneration {
            domain: domain.clone(),
            generation: 1,
            public_key: hex::encode(key.public_key().as_ref()),
        };
        let certificate = SigningCertificate {
            root_signature: hex::encode(
                self.0
                    .sign(&serde_json::to_vec(&(
                        "kasumi.signing-certificate.v1",
                        &identity,
                    ))?)
                    .as_ref(),
            ),
            identity,
        };
        let verifier = TrustVerifierIdentity {
            installation_id: Uuid::new_v4(),
            node_id: 1,
        };
        let persistence = Arc::new(ImmutableFixture(LocalSignerTrustRecord::initial(
            verifier.clone(),
            certificate.clone(),
        )?));
        let live = LiveSignerTrust::open(
            &verifier,
            domain,
            persistence,
            Arc::new(NoMaintenance),
            Arc::new(kasumi_clock::SystemLeaseClock),
        )?;
        let signer = Arc::new(AuthoritySigner::new(LiveGenerationSigner::install(
            GenerationSigner::from_pkcs8(certificate, operational.as_ref())?,
            live.clone(),
        )?));
        let trust = AuthorityTrust::install(manifest)?
            .with_live_verifiers(BTreeMap::from([(partition, live.clone())]))?;
        Ok(FixtureAuthority {
            signer,
            trust,
            verifier: live,
        })
    }
}
pub struct FixtureAuthority {
    pub signer: Arc<AuthoritySigner>,
    pub trust: AuthorityTrust,
    pub verifier: Arc<LiveSignerTrust>,
}
struct NoMaintenance;
impl LiveTrustAdministrator for NoMaintenance {
    fn authorize(&self, _: &kasumi_types::RequestContext) -> Result<()> {
        anyhow::bail!("immutable fixture")
    }
}
struct ImmutableFixture(LocalSignerTrustRecord);
impl LiveTrustPersistence for ImmutableFixture {
    fn check_access(&self) -> Result<()> {
        Ok(())
    }
    fn load(&self) -> Result<LocalSignerTrustRecord> {
        Ok(self.0.clone())
    }
    fn receipt(&self, _: Uuid) -> Result<Option<SignerTrustReceipt>> {
        Ok(None)
    }
    fn key_use(&self, public_key: &str) -> Result<Option<SignerKeyUse>> {
        if public_key == self.0.active.identity.public_key {
            Ok(Some(SignerKeyUse::for_certificate(&self.0.active)?))
        } else {
            Ok(None)
        }
    }
    fn commit(
        &self,
        _: &LocalSignerTrustRecord,
        _: &LocalSignerTrustRecord,
        _: &SignerTrustReceipt,
    ) -> Result<()> {
        anyhow::bail!("immutable fixture")
    }
}
