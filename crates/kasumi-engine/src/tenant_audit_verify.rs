//! Follow authenticated archive links backwards so one request reads at most
//! its declared number of objects from each installed copy. A fresh database
//! instance has a fresh signing key, which expires its predecessor's cursors.
use super::*;
use ring::hmac;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Position {
    caller: String,
    epoch: u64,
    tenant: String,
    incarnation: String,
    stream: uuid::Uuid,
    head: Option<AuditArchiveLink>,
    through: u64,
    remaining: u64,
    next: Option<AuditArchiveLink>,
    expires: Duration,
}

fn expired() -> Error {
    Error::new(
        ErrorCode::CursorExpired,
        "tenant audit continuation expired or its binding changed",
    )
}

impl Position {
    fn sign(&self, key: &hmac::Key) -> Result<String> {
        let bytes = serde_json::to_vec(self).map_err(|_| expired())?;
        let tag = hmac::sign(key, &bytes);
        Ok(hex::encode([tag.as_ref(), &bytes].concat()))
    }

    fn open(token: &str, key: &hmac::Key) -> Result<Self> {
        let bytes = hex::decode(token).map_err(|_| expired())?;
        let (tag, body) = bytes.split_at_checked(32).ok_or_else(expired)?;
        hmac::verify(key, body, tag).map_err(|_| expired())?;
        serde_json::from_slice(body).map_err(|_| expired())
    }
}

fn copy_failure(error: &anyhow::Error) -> AuditObjectCheck {
    if let Some(failure) = error.downcast_ref::<Error>() {
        return match failure.code {
            ErrorCode::Corruption => AuditObjectCheck::Corrupt,
            ErrorCode::NotFound => AuditObjectCheck::Missing,
            _ => AuditObjectCheck::Unavailable,
        };
    }
    if error
        .downcast_ref::<std::io::Error>()
        .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound)
    {
        return AuditObjectCheck::Missing;
    }
    AuditObjectCheck::Unavailable
}

fn check_copy(
    state: &TenantState,
    store: &TenantStore,
    link: &AuditArchiveLink,
    bytes: anyhow::Result<Vec<u8>>,
) -> (AuditObjectCheck, Option<AuditArchiveReference>) {
    let bytes = match bytes {
        Ok(bytes) => bytes,
        Err(failure) => return (copy_failure(&failure), None),
    };
    let Ok(inspected) = kasumi_store::InspectedAuditDependency::from_link(&bytes, link) else {
        return (AuditObjectCheck::Corrupt, None);
    };
    match crate::state::snapshot_bundle::verify_inspected_dependency(
        state,
        store.storage_access().purpose(),
        store,
        &inspected,
    ) {
        Ok(segment) => (
            AuditObjectCheck::Verified,
            Some(segment.reference().clone()),
        ),
        Err(failure) => (copy_failure(&failure), None),
    }
}

impl Database {
    pub(super) fn audit_token_key(&self) -> Result<&hmac::Key> {
        if self.audit_cursor_key.get().is_none() {
            let key = hmac::Key::generate(hmac::HMAC_SHA256, &ring::rand::SystemRandom::new())
                .map_err(|_| Error::new(ErrorCode::Unavailable, "audit cursor key unavailable"))?;
            let _ = self.audit_cursor_key.set(key);
        }
        self.audit_cursor_key.get().ok_or_else(expired)
    }

    pub async fn verify_tenant_audit(
        &self,
        context: &RequestContext,
        request: TenantAuditVerifyRequest,
    ) -> Result<AdmittedOutput<TenantAuditVerificationPage>> {
        let result = self.verify_tenant_audit_inner(context, request).await;
        self.audit_result(context, result).await
    }

    async fn verify_tenant_audit_inner(
        &self,
        context: &RequestContext,
        request: TenantAuditVerifyRequest,
    ) -> Result<AdmittedOutput<TenantAuditVerificationPage>> {
        self.access()?;
        self.engine.authorize(context, None, Action::Audit)?;
        request.validate()?;
        let token = QueryCancellation::default();
        let _cancel = CancelOnDrop(token.clone());
        let registration = self.work.begin(token.clone())?;
        let mut reservation = self.admission().reserve(1 << 20, Some(token.clone()))?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        let state = &generation.state;
        self.engine
            .authorize_release(context, None, Action::Audit, state.policy_epoch)?;
        let caller = staged_digest(&(
            &context.tenant,
            &context.principal,
            &context.scopes,
            &context.authorization,
        ))?
        .0;
        let key = self.audit_token_key()?;
        let retention = &state.audit_retention;
        let mut position = match request.cursor.as_deref() {
            Some(cursor) => Position::open(cursor, key)?,
            None => Position {
                caller: caller.clone(),
                tenant: state.tenant.clone(),
                incarnation: state.incarnation.clone(),
                epoch: state.policy_epoch,
                stream: retention.stream_id,
                head: retention.archive_head.as_ref().map(|r| r.object.clone()),
                through: retention.archive_segments,
                remaining: retention.archive_segments,
                next: retention.archive_head.as_ref().map(|r| r.object.clone()),
                expires: self
                    .clock
                    .now()
                    .checked_add(Duration::from_millis(state.limits.cursor_ttl_ms))
                    .ok_or_else(expired)?,
            },
        };
        if position.caller != caller
            || position.tenant != state.tenant
            || position.incarnation != state.incarnation
            || position.stream != retention.stream_id
            || position.epoch != state.policy_epoch
            || self.clock.now() >= position.expires
            || position.through > retention.archive_segments
            || (position.through == retention.archive_segments
                && position.head.as_ref() != retention.archive_head.as_ref().map(|r| &r.object))
        {
            return Err(expired());
        }
        let (revision, epoch, strict) = (
            state.revision,
            state.policy_epoch,
            state.policy.strict_read_audit,
        );
        let store = self.store.clone();
        let clock = self.clock.clone();
        let limit = request.limit;
        if position.remaining > 0 {
            reservation.reserve_additional(4 * MAX_AUDIT_SEGMENT_BYTES as u64)?;
        }
        let (position, results, mut reservation) = reservation
            .retained_read(token, move |reservation, token| {
                let _registration = registration;
                let mut rows = Vec::with_capacity(usize::from(limit));
                while let Some(link) = position.next.clone() {
                    if rows.len() == usize::from(limit) {
                        break;
                    }
                    token.check()?;
                    if clock.now() >= position.expires {
                        return Err(expired());
                    }
                    let placement = store.tenant_audit_archive().map_err(|_| {
                        Error::new(ErrorCode::Unavailable, "tenant audit placement unavailable")
                    })?;
                    let index = position.remaining.checked_sub(1).ok_or_else(expired)?;
                    let state = &generation.state;
                    let (cache, cached) =
                        check_copy(state, &store, &link, placement.cache().read_blocking(&link));
                    token.check()?;
                    let remote = tokio::runtime::Handle::current()
                        .block_on(placement.read_destination(&link));
                    let (destination, external) = check_copy(state, &store, &link, remote);
                    if cached
                        .as_ref()
                        .zip(external.as_ref())
                        .is_some_and(|(a, b)| a != b)
                    {
                        return Err(Error::new(
                            ErrorCode::Corruption,
                            "verified audit copies differ",
                        ));
                    }
                    let reference = cached.or(external);
                    if let Some(r) = &reference {
                        if r.previous.is_some() != (index > 0)
                            || (index + 1 == state.audit_retention.archive_segments
                                && state.audit_retention.archive_head.as_ref() != Some(r))
                        {
                            return Err(Error::new(
                                ErrorCode::Corruption,
                                "tenant audit archive count or head differs",
                            ));
                        }
                        position.next = r.previous.clone();
                        position.remaining = index;
                    }
                    let blocked = reference.is_none();
                    rows.push(TenantAuditObjectVerification {
                        index,
                        object: link,
                        reference,
                        cache,
                        destination,
                    });
                    if blocked {
                        break;
                    }
                }
                token.check()?;
                Ok::<_, Error>((position, rows, reservation))
            })
            .await?;
        let cursor = position
            .next
            .as_ref()
            .map(|_| position.sign(key))
            .transpose()?;
        let page = TenantAuditVerificationPage {
            tenant: position.tenant,
            incarnation: position.incarnation,
            stream_id: position.stream,
            through_index: position.through,
            snapshot_head: position.head,
            results,
            cursor,
        };
        page.validate(&request)
            .map_err(|error| Error::new(ErrorCode::Corruption, error.message))?;
        self.finish_tenant_audit_read(context, revision, epoch, strict, "tenant_audit_verify")
            .await?;
        if self.clock.now() >= position.expires {
            return Err(expired());
        }
        reservation.retain(MAX_TENANT_AUDIT_PAGE_BYTES as u64);
        Ok(AdmittedOutput::new(page, Arc::new(reservation)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_authenticates_the_exact_position_and_issuer() {
        let key = hmac::Key::new(hmac::HMAC_SHA256, &[1; 32]);
        let other = hmac::Key::new(hmac::HMAC_SHA256, &[2; 32]);
        let cursor = Position {
            caller: "owner".to_owned(),
            epoch: 2,
            tenant: "documents".to_owned(),
            incarnation: "i".to_owned(),
            stream: uuid::Uuid::from_u128(9),
            head: None,
            through: 0,
            remaining: 0,
            next: None,
            expires: Duration::from_secs(60),
        };
        let signed = cursor.sign(&key).unwrap();
        assert_eq!(Position::open(&signed, &key).unwrap().epoch, 2);
        assert!(Position::open(&signed, &other).is_err());
        let mut bytes = hex::decode(signed).unwrap();
        bytes[32] ^= 1;
        assert!(Position::open(&hex::encode(bytes), &key).is_err());
    }
}
