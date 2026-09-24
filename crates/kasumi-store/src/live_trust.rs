//! Encrypted, point-addressed local signer trust and permanent operation receipts.
use super::*;
use kasumi_serving::{
    LiveSignerTrust, LiveTrustAdministrator, LiveTrustPersistence, LocalSignerTrustRecord,
    MAX_SIGNER_TRUST_RECORD_BYTES, SignerKeyUse, SignerTrustReceipt, SigningCertificate,
    SigningCertificateVerification, SigningDomain, TrustVerifierIdentity,
};

const NS: &str = "live.signer.trust";

fn require_current_json<T: serde::Serialize>(
    value: &T,
    original: &[u8],
    diagnostic: &'static str,
) -> Result<()> {
    struct Exact<'a> {
        original: &'a [u8],
        offset: usize,
    }
    impl std::io::Write for Exact<'_> {
        fn write(&mut self, encoded: &[u8]) -> std::io::Result<usize> {
            let end = self
                .offset
                .checked_add(encoded.len())
                .ok_or_else(|| std::io::Error::other("noncanonical live signer trust JSON"))?;
            if self.original.get(self.offset..end) != Some(encoded) {
                return Err(std::io::Error::other("noncanonical live signer trust JSON"));
            }
            self.offset = end;
            Ok(encoded.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut exact = Exact {
        original,
        offset: 0,
    };
    serde_json::to_writer(&mut exact, value).context(diagnostic)?;
    ensure!(exact.offset == original.len(), "{diagnostic}");
    Ok(())
}

struct EncryptedTrust {
    store: Arc<TenantStore>,
    verifier: TrustVerifierIdentity,
    domain: SigningDomain,
    key: String,
}
impl EncryptedTrust {
    fn receipt_key(&self, id: Uuid) -> String {
        format!("receipt/{}/{id}", self.key)
    }
    fn read_record(&self) -> Result<Option<LocalSignerTrustRecord>> {
        let bytes =
            self.store
                .get_bounded(NS, self.key.as_bytes(), MAX_SIGNER_TRUST_RECORD_BYTES)?;
        let record: Option<LocalSignerTrustRecord> =
            bytes.as_deref().map(serde_json::from_slice).transpose()?;
        if let (Some(record), Some(bytes)) = (&record, bytes.as_deref()) {
            record.validate()?;
            ensure!(
                record.verifier == self.verifier && record.active.identity.domain == self.domain,
                "encrypted local trust binding differs"
            );
            require_current_json(record, bytes, "noncanonical local signer trust record")?;
            for certificate in std::iter::once(&record.active)
                .chain(record.staged.as_ref().map(|staged| &staged.certificate))
            {
                ensure!(
                    self.key_use(&certificate.identity.public_key)?
                        == Some(SignerKeyUse::for_certificate(certificate)?),
                    "permanent signer key binding is absent or differs"
                );
            }
        }
        Ok(record)
    }
    fn publish(
        &self,
        expected: Option<&LocalSignerTrustRecord>,
        next: &LocalSignerTrustRecord,
        receipt: Option<&SignerTrustReceipt>,
    ) -> Result<()> {
        let _access = AccessGuard(&self.store);
        next.validate()?;
        ensure!(
            next.verifier == self.verifier && next.active.identity.domain == self.domain,
            "local trust publication binding differs"
        );
        let _mutation = self.store.mutations.lock();
        ensure!(
            self.read_record()?.as_ref() == expected,
            "durable signer trust revision changed"
        );
        let mut operations = vec![WriteOp::put(
            NS,
            self.key.as_bytes(),
            serde_json::to_vec(next)?,
        )];
        let certificate = next
            .staged
            .as_ref()
            .map_or(&next.active, |staged| &staged.certificate);
        let key_use = SignerKeyUse::for_certificate(certificate)?;
        match self.key_use(&certificate.identity.public_key)? {
            Some(previous) => ensure!(
                previous == key_use,
                "operational signing key cannot be reused"
            ),
            None => operations.push(WriteOp::put(
                NS,
                format!("key-use/{}", certificate.identity.public_key).as_bytes(),
                serde_json::to_vec(&key_use)?,
            )),
        }
        if let Some(receipt) = receipt {
            ensure!(
                expected.and_then(|previous| previous.revision.checked_add(1))
                    == Some(next.revision)
                    && receipt.revision == next.revision
                    && receipt.command_sha256 == receipt.command.digest()?
                    && receipt.active_generation == next.active.identity.generation
                    && receipt.active_certificate_sha256 == next.active.digest()?
                    && receipt.retirement_pending == next.retirement.is_some(),
                "local signer receipt differs from committed trust"
            );
            let key = self.receipt_key(receipt.command.operation_id);
            ensure!(
                self.store
                    .get_bounded(NS, key.as_bytes(), MAX_SIGNER_TRUST_RECORD_BYTES)?
                    .is_none(),
                "permanent signer receipt already exists"
            );
            let bytes = serde_json::to_vec(receipt)?;
            ensure!(
                bytes.len() <= MAX_SIGNER_TRUST_RECORD_BYTES,
                "signer receipt exceeds bounded record size"
            );
            operations.push(WriteOp::put(NS, key.as_bytes(), bytes));
        } else {
            ensure!(
                expected.is_none() && next.revision == 0,
                "trust initialization requires an absent record"
            );
        }
        validate_batch(&[&operations])?;
        self.store.check_access()?;
        let state = self.store.state.read();
        self.store.require_access(&state)?;
        let catalog = self.store.catalog.read();
        let tx = self.store.node.db.begin_write()?;
        write_domain(&tx, &self.store, &state, &catalog, &operations)?;
        self.store.require_access(&state)?;
        tx.commit()
            .context("local signer trust commit outcome may be unknown")?;
        self.store
            .require_access(&state)
            .context("local signer trust committed but key access was lost")
    }
}

#[cfg(test)]
#[path = "live_trust_tests.rs"]
mod tests;
impl LiveTrustPersistence for EncryptedTrust {
    fn check_access(&self) -> Result<()> {
        self.store.check_access()
    }
    fn load(&self) -> Result<LocalSignerTrustRecord> {
        self.read_record()?
            .context("local signer trust is not initialized")
    }
    fn receipt(&self, operation_id: Uuid) -> Result<Option<SignerTrustReceipt>> {
        let bytes = self.store.get_bounded(
            NS,
            self.receipt_key(operation_id).as_bytes(),
            MAX_SIGNER_TRUST_RECORD_BYTES,
        )?;
        let receipt: Option<SignerTrustReceipt> =
            bytes.as_deref().map(serde_json::from_slice).transpose()?;
        if let (Some(receipt), Some(bytes)) = (&receipt, bytes.as_deref()) {
            ensure!(
                receipt.command.operation_id == operation_id
                    && receipt.command_sha256 == receipt.command.digest()?
                    && receipt.revision > 0
                    && receipt.active_generation > 0,
                "retained signer receipt identity differs"
            );
            kasumi_types::validate_name(&receipt.principal)?;
            kasumi_types::validate_sha256(&receipt.active_certificate_sha256)?;
            require_current_json(receipt, bytes, "noncanonical signer trust receipt")?;
        }
        Ok(receipt)
    }
    fn key_use(&self, public_key: &str) -> Result<Option<SignerKeyUse>> {
        kasumi_types::validate_sha256(public_key)?;
        let bytes = self
            .store
            .get_bounded(NS, format!("key-use/{public_key}").as_bytes(), 1024)?;
        let key_use: Option<SignerKeyUse> =
            bytes.as_deref().map(serde_json::from_slice).transpose()?;
        if let (Some(key_use), Some(bytes)) = (&key_use, bytes.as_deref()) {
            require_current_json(key_use, bytes, "noncanonical signer key-use record")?;
        }
        Ok(key_use)
    }
    fn commit(
        &self,
        previous: &LocalSignerTrustRecord,
        next: &LocalSignerTrustRecord,
        receipt: &SignerTrustReceipt,
    ) -> Result<()> {
        self.publish(Some(previous), next, Some(receipt))
    }
}
impl TenantStore {
    fn trust_persistence(
        self: &Arc<Self>,
        verifier: &TrustVerifierIdentity,
        domain: &SigningDomain,
    ) -> Result<EncryptedTrust> {
        self.check_access()?;
        verifier.validate()?;
        domain.validate()?;
        ensure!(
            self.access.purpose()
                == &StoragePurpose::LiveSignerTrust {
                    verifier: verifier.clone()
                },
            "live trust needs its exact independent installed storage capability"
        );
        Ok(EncryptedTrust {
            store: self.clone(),
            verifier: verifier.clone(),
            domain: domain.clone(),
            key: domain.digest()?,
        })
    }
    /// Explicit fresh installation. Existing trust is never reset from bootstrap
    /// configuration or a restored application snapshot.
    pub fn initialize_live_signer_trust(
        self: &Arc<Self>,
        verifier: &TrustVerifierIdentity,
        initial: SigningCertificate,
        administrator: Arc<dyn LiveTrustAdministrator>,
        work_budget: kasumi_serving::BackgroundWorkBudget,
    ) -> Result<Arc<LiveSignerTrust>> {
        let domain = initial.identity.domain.clone();
        let persistence = self.trust_persistence(verifier, &domain)?;
        let record = LocalSignerTrustRecord::initial(verifier.clone(), initial)?;
        persistence.publish(None, &record, None)?;
        self.open_live_signer_trust(verifier, domain, administrator, work_budget)
    }
    /// Presence is checked independently from decoding, so an explicit installer
    /// can resume an absent initial record without treating corrupt state as new.
    pub fn has_live_signer_trust(
        self: &Arc<Self>,
        verifier: &TrustVerifierIdentity,
        domain: &SigningDomain,
    ) -> Result<bool> {
        let persistence = self.trust_persistence(verifier, domain)?;
        Ok(self
            .get_bounded(
                NS,
                persistence.key.as_bytes(),
                MAX_SIGNER_TRUST_RECORD_BYTES,
            )?
            .is_some())
    }
    pub fn open_live_signer_trust(
        self: &Arc<Self>,
        verifier: &TrustVerifierIdentity,
        domain: SigningDomain,
        administrator: Arc<dyn LiveTrustAdministrator>,
        work_budget: kasumi_serving::BackgroundWorkBudget,
    ) -> Result<Arc<LiveSignerTrust>> {
        let persistence = self.trust_persistence(verifier, &domain)?;
        let key = domain.digest()?;
        let mut owners = self.live_trust.lock();
        if let Some((prior, scope)) = owners.get(&key) {
            if let Some(owner) = prior.upgrade() {
                ensure!(
                    owner.same_administrator(&administrator),
                    "live trust administrator provider changed"
                );
                ensure!(
                    owner.background_capacity() == work_budget.max_registered(),
                    "cached verifier background capacity changed"
                );
                if !owner.is_closed() {
                    return Ok(owner);
                }
            }
            ensure!(
                scope.drained(),
                "closed verifier has unjoined work or an unreported background failure"
            );
        }
        let owner = LiveSignerTrust::open(
            verifier,
            domain,
            Arc::new(persistence),
            administrator,
            self.clock.clone(),
            work_budget,
        )?;
        owners.insert(key, (Arc::downgrade(&owner), owner.background_scope()));
        Ok(owner)
    }
}
