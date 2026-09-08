//! Atomic publication of fully validated listener TLS generations.
use crate::{ClientAuthentication, TlsIdentity, server_config};
use anyhow::{Context, Result};
use rustls::ServerConfig;
use std::sync::{Arc, RwLock};

/// Handshakes capture one immutable generation. Certificate, key, CA roots and
/// protocol settings are replaced together; existing connections retain the
/// configuration under which they authenticated until their normal drain.
#[derive(Clone)]
pub struct ReloadableServerConfig {
    current: Arc<RwLock<(u64, Arc<ServerConfig>)>>,
    changed: tokio::sync::watch::Sender<u64>,
}
impl From<Arc<ServerConfig>> for ReloadableServerConfig {
    fn from(config: Arc<ServerConfig>) -> Self {
        Self::new(config)
    }
}
impl ReloadableServerConfig {
    pub fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            current: Arc::new(RwLock::new((1, config))),
            changed: tokio::sync::watch::channel(1).0,
        }
    }
    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changed.subscribe()
    }
    pub fn snapshot_generation(&self) -> Result<(u64, Arc<ServerConfig>)> {
        Ok(self
            .current
            .read()
            .map_err(|_| anyhow::anyhow!("TLS configuration lock poisoned"))?
            .clone())
    }
    pub fn snapshot(&self) -> Result<Arc<ServerConfig>> {
        Ok(self
            .current
            .read()
            .map_err(|_| anyhow::anyhow!("TLS configuration lock poisoned"))?
            .1
            .clone())
    }
    pub fn generation(&self) -> Result<u64> {
        Ok(self
            .current
            .read()
            .map_err(|_| anyhow::anyhow!("TLS configuration lock poisoned"))?
            .0)
    }
    pub fn replace(&self, config: Arc<ServerConfig>) -> Result<u64> {
        let mut current = self
            .current
            .write()
            .map_err(|_| anyhow::anyhow!("TLS configuration lock poisoned"))?;
        let generation = current
            .0
            .checked_add(1)
            .context("TLS generation overflow")?;
        *current = (generation, config);
        self.changed.send_replace(generation);
        Ok(generation)
    }
    /// A malformed certificate, mismatched key, or invalid CA cannot replace
    /// any part of the active configuration.
    pub fn replace_from_pem(
        &self,
        certificates: &[u8],
        private_key: &[u8],
        authentication: ClientAuthentication<'_>,
    ) -> Result<u64> {
        let identity = TlsIdentity::from_pem(certificates, private_key)?;
        self.replace(server_config(&identity, authentication)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn failed_replacement_preserves_complete_previous_generation() {
        let first = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let second = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let identity = TlsIdentity::from_pem(
            first.cert.pem().as_bytes(),
            first.signing_key.serialize_pem().as_bytes(),
        )
        .unwrap();
        let original = server_config(&identity, ClientAuthentication::OAuth).unwrap();
        let reload = ReloadableServerConfig::new(original.clone());
        assert!(
            reload
                .replace_from_pem(
                    second.cert.pem().as_bytes(),
                    first.signing_key.serialize_pem().as_bytes(),
                    ClientAuthentication::OAuth
                )
                .is_err()
        );
        assert_eq!(reload.generation().unwrap(), 1);
        assert!(Arc::ptr_eq(&reload.snapshot().unwrap(), &original));
        assert_eq!(
            reload
                .replace_from_pem(
                    second.cert.pem().as_bytes(),
                    second.signing_key.serialize_pem().as_bytes(),
                    ClientAuthentication::OAuth
                )
                .unwrap(),
            2
        );
        assert!(!Arc::ptr_eq(&reload.snapshot().unwrap(), &original));
        assert!(
            reload
                .replace_from_pem(b"invalid", b"invalid", ClientAuthentication::OAuth)
                .is_err()
        );
        assert_eq!(reload.generation().unwrap(), 2);
    }
}
