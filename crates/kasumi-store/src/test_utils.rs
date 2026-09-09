//! Real authenticated wrapping for tests only. Never selectable in production config.
use std::{
    sync::atomic::{AtomicBool, AtomicU64, Ordering},
    time::Duration,
};

use anyhow::{Result, ensure};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{GeneratedKey, KeyProvider, SecretKey, WrappedKey, decrypt, encrypt};
use kasumi_clock::LeaseClock;

/// Explicit fixture identity; production callers must retain their own installed
/// UUID. Tests of identity mismatch select distinct UUIDs directly.
pub const NODE_STORE_ID: uuid::Uuid =
    uuid::Uuid::from_u128(0x5c8c_7c42_e708_452c_b92f_510a46734f2b);

/// Explicitly install an independent custody provider for a trusted test store.
/// Production configuration must supply both providers through TenantStorageSet.
pub async fn with_custody(
    application: std::sync::Arc<crate::TenantStore>,
    custody_provider: std::sync::Arc<dyn KeyProvider>,
) -> Result<std::sync::Arc<crate::TenantStorageSet>> {
    let control = crate::TenantStore::open(
        application.node.clone(),
        crate::CustodyStore::catalog_name(application.tenant()),
        custody_provider,
        crate::StorageAccess::custody(application.tenant()),
    )
    .await?;
    crate::TenantStorageSet::install(application, control)
}

pub struct LocalKeyProvider {
    key: SecretKey,
    key_ref: String,
    allowed: AtomicBool,
    version: AtomicU64,
    minimum: AtomicU64,
    probes: AtomicU64,
}

impl LocalKeyProvider {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            key: SecretKey::from_bytes(key),
            key_ref: format!("test-only/{}", hex::encode(Sha256::digest(key))),
            allowed: AtomicBool::new(true),
            version: AtomicU64::new(1),
            minimum: AtomicU64::new(1),
            probes: AtomicU64::new(0),
        }
    }
    pub fn revoke(&self) {
        self.allowed.store(false, Ordering::SeqCst);
    }
    pub fn allow(&self) {
        self.allowed.store(true, Ordering::SeqCst);
    }
    pub fn rotate(&self) -> u64 {
        self.version.fetch_add(1, Ordering::SeqCst) + 1
    }
    pub fn set_minimum_version(&self, version: u64) {
        self.minimum.store(version, Ordering::SeqCst);
    }
    pub fn probe_count(&self) -> u64 {
        self.probes.load(Ordering::SeqCst)
    }
    pub fn key_ref(&self) -> &str {
        &self.key_ref
    }
    fn check(&self) -> Result<()> {
        ensure!(self.allowed.load(Ordering::SeqCst), "test key revoked");
        Ok(())
    }
    fn aad(tenant: &str, version: u64) -> Vec<u8> {
        format!("kasumi.test-key/{tenant}/{version}").into_bytes()
    }
    fn wrap(&self, tenant: &str, plaintext: &SecretKey) -> Result<WrappedKey> {
        self.check()?;
        let version = self.version.load(Ordering::SeqCst);
        Ok(WrappedKey {
            provider: "test-only".into(),
            key_ref: self.key_ref.clone(),
            version,
            ciphertext: STANDARD.encode(encrypt(
                &self.key,
                plaintext.as_bytes(),
                &Self::aad(tenant, version),
            )?),
            context: Some(tenant.to_owned()),
        })
    }
}

#[async_trait]
impl KeyProvider for LocalKeyProvider {
    async fn generate_key(&self, tenant: &str) -> Result<GeneratedKey> {
        let plaintext = SecretKey::random()?;
        Ok(GeneratedKey {
            wrapped: self.wrap(tenant, &plaintext)?,
            plaintext,
        })
    }
    async fn unwrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<SecretKey> {
        self.probes.fetch_add(1, Ordering::SeqCst);
        self.check()?;
        ensure!(
            wrapped.provider == "test-only"
                && wrapped.key_ref == self.key_ref
                && wrapped.context.as_deref() == Some(tenant),
            "test key tenant mismatch"
        );
        ensure!(
            wrapped.version >= self.minimum.load(Ordering::SeqCst),
            "test key version revoked"
        );
        let bytes = STANDARD.decode(&wrapped.ciphertext)?;
        let key = Zeroizing::new(decrypt(
            &self.key,
            &bytes,
            &Self::aad(tenant, wrapped.version),
        )?);
        ensure!(key.len() == 32, "invalid test key");
        let mut fixed = Zeroizing::new([0u8; 32]);
        fixed.copy_from_slice(&key);
        Ok(SecretKey::from_bytes(*fixed))
    }
    async fn rewrap_key(&self, tenant: &str, wrapped: &WrappedKey) -> Result<WrappedKey> {
        self.wrap(tenant, &self.unwrap_key(tenant, wrapped).await?)
    }
}

#[derive(Default, Debug)]
pub struct ManualClock(AtomicU64);

impl ManualClock {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn advance(&self, elapsed: Duration) {
        self.0.fetch_add(
            u64::try_from(elapsed.as_nanos()).expect("test clock overflow"),
            Ordering::SeqCst,
        );
    }
}

impl LeaseClock for ManualClock {
    fn now(&self) -> Duration {
        Duration::from_nanos(self.0.load(Ordering::SeqCst))
    }
}

/// Reopenable storage whose synchronized image models what survives power loss.
/// Mutations after `fail_after` operations fail, including fsync, until disarmed.
/// Only the synchronized image is installed by `crash`, without running redb cleanup.
#[derive(Clone, Debug, Default)]
pub struct FaultBackend(std::sync::Arc<parking_lot::Mutex<FaultState>>);

#[derive(Debug, Default)]
struct FaultState {
    volatile: Vec<u8>,
    durable: Vec<u8>,
    remaining: Option<usize>,
    operations: usize,
    syncs: usize,
    advance_on_sync: Option<(std::sync::Arc<ManualClock>, Duration)>,
}

impl FaultBackend {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn fail_after(&self, mutations: usize) {
        self.0.lock().remaining = Some(mutations);
    }
    pub fn disarm(&self) {
        self.0.lock().remaining = None;
    }
    pub fn operations(&self) -> usize {
        self.0.lock().operations
    }
    pub fn syncs(&self) -> usize {
        self.0.lock().syncs
    }
    pub fn advance_clock_on_next_sync(
        &self,
        clock: std::sync::Arc<ManualClock>,
        elapsed: Duration,
    ) {
        self.0.lock().advance_on_sync = Some((clock, elapsed));
    }
    /// Returns a new independent backend, so dropping the old redb database cannot
    /// synchronize anything into the simulated post-crash disk.
    pub fn crash(&self) -> Self {
        let durable = self.0.lock().durable.clone();
        Self(std::sync::Arc::new(parking_lot::Mutex::new(FaultState {
            volatile: durable.clone(),
            durable,
            ..FaultState::default()
        })))
    }
}

impl FaultState {
    fn mutate(&mut self) -> std::io::Result<()> {
        if let Some(remaining) = &mut self.remaining {
            if *remaining == 0 {
                return Err(std::io::Error::other("injected storage failure"));
            }
            *remaining -= 1;
        }
        self.operations += 1;
        Ok(())
    }
}

impl redb::StorageBackend for FaultBackend {
    fn len(&self) -> std::io::Result<u64> {
        Ok(self.0.lock().volatile.len() as u64)
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> std::io::Result<()> {
        let state = self.0.lock();
        let offset = usize::try_from(offset).map_err(std::io::Error::other)?;
        let end = offset
            .checked_add(out.len())
            .ok_or_else(|| std::io::Error::other("read overflow"))?;
        let bytes = state.volatile.get(offset..end).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "read outside storage")
        })?;
        out.copy_from_slice(bytes);
        Ok(())
    }
    fn set_len(&self, len: u64) -> std::io::Result<()> {
        let mut state = self.0.lock();
        state.mutate()?;
        state
            .volatile
            .resize(usize::try_from(len).map_err(std::io::Error::other)?, 0);
        Ok(())
    }
    fn sync_data(&self) -> std::io::Result<()> {
        let mut state = self.0.lock();
        state.mutate()?;
        if let Some((clock, elapsed)) = state.advance_on_sync.take() {
            clock.advance(elapsed);
        }
        state.syncs += 1;
        state.durable = state.volatile.clone();
        Ok(())
    }
    fn write(&self, offset: u64, data: &[u8]) -> std::io::Result<()> {
        let mut state = self.0.lock();
        state.mutate()?;
        let offset = usize::try_from(offset).map_err(std::io::Error::other)?;
        let end = offset
            .checked_add(data.len())
            .ok_or_else(|| std::io::Error::other("write overflow"))?;
        let target = state
            .volatile
            .get_mut(offset..end)
            .ok_or_else(|| std::io::Error::other("write outside storage"))?;
        target.copy_from_slice(data);
        Ok(())
    }
}
