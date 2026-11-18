//! Rebind one stored issuance during exclusive, journaled client certificate rotation.
use super::*;
use kasumi_client::ClientProfile;

#[derive(Deserialize)]
struct IssuanceIdentity {
    jti: Uuid,
}

/// This untrusted identifier selects a candidate ledger row. Before any change,
/// the complete presented bearer must match the issuer's signature and claims
/// for that original issuance and its enrolled certificate.
fn presented_issuance(bearer: &[u8]) -> Result<Uuid> {
    let payload = bearer
        .split(|byte| *byte == b'.')
        .nth(1)
        .context("installed credential has no payload")?;
    let claims = Zeroizing::new(URL_SAFE_NO_PAD.decode(payload)?);
    Ok(serde_json::from_slice::<IssuanceIdentity>(&claims)?.jti)
}

impl LocalCredentials {
    /// Preserve issuance identity, original expiry and signing generation. The
    /// family cannot gain scopes, change resources, or become current again.
    /// On retry the store and file may independently name either certificate.
    pub(crate) fn rotate_installed_certificate(
        &self,
        path: &Path,
        profile: &ClientProfile,
        old_pin: impl FnOnce() -> Result<[u8; 32]>,
        replacement: [u8; 32],
        after_commit: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("credential writer poisoned"))?;
        let mut status = self.status(profile.family_id)?;
        let spec = &status.specification;
        ensure!(
            spec.family_id == profile.family_id
                && spec.principal == profile.principal
                && spec.resource == profile.resource
                && spec.tenant == profile.tenant,
            "installed profile does not identify its enrolled credential family"
        );
        let Some(current) = spec.certificate_binding() else {
            // Older unbound and MCP families keep their original tokens.
            return Ok(());
        };
        if status.revoked_at_ms.is_some() {
            // Revoked families retain their old binding and receive no token.
            return Ok(());
        }
        ensure!(
            spec.audience.is_native(),
            "an MCP family cannot have a native certificate binding"
        );
        let directory = path
            .parent()
            .context("installed profile directory missing")?;
        ensure!(
            profile.bearer_file.parent() == Some(directory),
            "installed bearer path escapes the profile directory"
        );
        if profile.bearer_file != path.with_extension("token") {
            crate::local_recovery::check_rotation_profile(&self.store, path, profile)?;
        }
        let _watch = private_files::ExclusiveLock::acquire(
            &profile.bearer_file.with_extension("watch.lock"),
        )?;
        let identity = private_files::file_identity(&profile.bearer_file)?;
        let bearer = private_files::read(&profile.bearer_file, 32 << 10)?;
        ensure!(
            private_files::file_identity(&profile.bearer_file)? == identity,
            "installed bearer changed while reading its signed issuance"
        );
        let id = presented_issuance(&bearer)?;
        let row = self
            .store
            .get_bounded(
                ISSUANCES,
                &Self::issuance_key(profile.family_id, id),
                MAX_RECORD,
            )?
            .context("installed bearer has no original credential issuance")?;
        let issuance = Self::issuance(&row)?;
        ensure!(
            issuance.family_id == profile.family_id && issuance.issuance_id == id,
            "credential issuance differs from installed family"
        );
        let mut target = status.clone();
        target.specification.client_certificate_sha256 = Some(hex::encode(replacement));
        let new = Zeroizing::new(self.token(&target, &issuance)?.token);
        if current == replacement && bearer.as_slice() == new.as_bytes() {
            private_files::sync_parent(&profile.bearer_file)?;
            return Ok(());
        }
        let original = old_pin()?;
        ensure!(
            current == original || current == replacement,
            "credential is bound to a different client certificate"
        );
        status.specification.client_certificate_sha256 = Some(hex::encode(original));
        let old = Zeroizing::new(self.token(&status, &issuance)?.token);
        ensure!(
            bearer.as_slice() == old.as_bytes(),
            "installed bearer differs from its original signed issuance"
        );
        if current != replacement {
            let event = CredentialEvent {
                operation: "rotate-client-certificate",
                actor: "offline-certificate-rotation",
                family_id: profile.family_id,
                at_ms: self.clock.now_ms()?,
            };
            self.store.write_batch(&[
                WriteOp::put(FAMILIES, profile.family_id.as_bytes(), encoded(&target)?),
                WriteOp::put(
                    EVENTS,
                    Uuid::new_v4().as_bytes(),
                    serde_json::to_vec(&event)?,
                ),
            ])?;
        }
        after_commit()?;
        private_files::replace(&profile.bearer_file, new.as_bytes())
    }
}
