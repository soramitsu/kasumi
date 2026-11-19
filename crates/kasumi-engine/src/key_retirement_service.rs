//! Race-safe retirement of historical wrapping key versions.
//!
//! A retirement is three ordered steps of the scope's own state machine. The
//! fence commits only against complete coverage that names no retired
//! version; from then on every dependency writer refuses a new reference to
//! one. Coverage is then observed again, after every publication that was
//! already in flight has either committed or met the fence, and the decision
//! commits only while the replicated dependency position is still the
//! observed one. A failure after the fence removes it again and is returned
//! unchanged; the completed record, never a page, is what a provider action
//! may rely on.
use super::*;

/// A decision that lost its dependency position to a concurrent publication
/// observes the scope again this many times before giving up.
const DECISION_ATTEMPTS: usize = 3;

/// This owner's own selection of the scope: the entries that follow every
/// reference to a lower key identity. Its first entry is the lowest retained
/// version of the identity, if any reference to the identity exists at all.
fn probe(request: &RetireKeyVersionsRequest) -> Result<ReadKeyRetentionRequest> {
    Ok(ReadKeyRetentionRequest {
        scope: request.scope.clone(),
        cursor: Some(KeyRetentionCursor {
            scope_sha256: request.scope.sha256()?,
            inventory_sha256: "0".repeat(64),
            coverage_revision: 0,
            membership_epoch: 0,
            // No retained version is zero, so this precedes each of them.
            after: KeyRetentionEntry {
                key: KeyVersionRef {
                    provider: request.identity.provider.clone(),
                    key_ref: request.identity.key_ref.clone(),
                    version: 0,
                },
                reference: KeyReference::BackupSession {
                    session_id: uuid::Uuid::nil(),
                },
            },
        }),
        limit: 1,
    })
}

/// The retained record, if any, that still names a version the request retires.
fn retired_reference(
    request: &RetireKeyVersionsRequest,
    observation: &KeyRetentionObservation,
) -> Result<()> {
    let Some(entry) = observation
        .page
        .entries
        .iter()
        .find(|entry| request.retires(&entry.key))
    else {
        return Ok(());
    };
    let record = match entry.reference.kind() {
        KeyReferenceKind::Catalog => "key catalog",
        KeyReferenceKind::BackupSession => "backup session",
        KeyReferenceKind::CompletedBackup => "completed backup",
        KeyReferenceKind::AuditArchive => "audit archive",
        KeyReferenceKind::HistoryArchive => "history archive",
        KeyReferenceKind::RecoveryRecord => "recovery record",
        KeyReferenceKind::TargetJournal => "target journal",
        KeyReferenceKind::LocalRecovery => "local recovery record",
    };
    Err(Error::new(
        ErrorCode::Conflict,
        format!(
            "wrapping key version {} is still referenced by a retained {record}",
            entry.key.version
        ),
    ))
}

fn spent() -> Error {
    Error::new(
        ErrorCode::Conflict,
        "key retirement identity was already used",
    )
}

impl Database {
    /// Retire every version of one wrapping key identity below a bound.
    /// Returns the permanent completed record, or the original failure with
    /// no version retired. Repeating the exact request resumes a retirement
    /// whose reply was lost and returns the same record once it is decided.
    pub async fn retire_key_versions(
        &self,
        context: &RequestContext,
        request: RetireKeyVersionsRequest,
    ) -> Result<KeyRetirementStatus> {
        let result = Box::pin(self.retire_key_versions_inner(context, &request)).await;
        self.audit_write_result(context, result).await
    }

    async fn retire_key_versions_inner(
        &self,
        context: &RequestContext,
        request: &RetireKeyVersionsRequest,
    ) -> Result<KeyRetirementStatus> {
        request.validate()?;
        let request_sha256 = request.request_sha256()?;
        match self
            .retained_key_retirement(context, &request.scope, &request.retirement_id)
            .await?
        {
            Some(KeyRetirementStatus::Completed { record })
                if record.fence.request_sha256 == request_sha256 =>
            {
                return Ok(KeyRetirementStatus::Completed { record });
            }
            // An interrupted retirement or a lost reply left its fence: the
            // decision below is the only step that remains.
            Some(KeyRetirementStatus::Fenced { fence })
                if fence.request_sha256 == request_sha256 => {}
            Some(_) => return Err(spent()),
            None => {
                let (before, _workspace) = self
                    .observe_key_retention(context, &probe(request)?, true)
                    .await?;
                request.require_coverage(&before.page.coverage)?;
                retired_reference(request, &before)?;
                self.submit(
                    context.clone(),
                    Operation::BeginKeyRetirement(BeginKeyRetirement {
                        request: request.clone(),
                        membership_epoch: before.page.coverage.membership_epoch(),
                        expected_dependency_sha256: before.dependency_sha256,
                    }),
                )
                .await?;
            }
        }
        match self
            .decide_key_retirement(context, request, &request_sha256)
            .await
        {
            Ok(record) => Ok(KeyRetirementStatus::Completed { record }),
            Err(original) => {
                // The fence protects nothing once its decision failed. Remove
                // it unless that decision may itself have committed, and keep
                // the failure that the caller has to act on.
                if original.code != ErrorCode::UnknownOutcome
                    && let Err(error) = self
                        .submit(
                            context.clone(),
                            Operation::AbortKeyRetirement(AbortKeyRetirement {
                                retirement_id: request.retirement_id.clone(),
                                request_sha256,
                            }),
                        )
                        .await
                {
                    tracing::warn!(
                        retirement_id = %request.retirement_id,
                        %error,
                        "a failed key retirement kept its fence"
                    );
                }
                Err(original)
            }
        }
    }

    /// Observe the scope after the fence and commit the decision against that
    /// exact observation.
    async fn decide_key_retirement(
        &self,
        context: &RequestContext,
        request: &RetireKeyVersionsRequest,
        request_sha256: &str,
    ) -> Result<KeyRetirementRecord> {
        let probe = probe(request)?;
        let mut moved = None;
        for _ in 0..DECISION_ATTEMPTS {
            self.settle_backup_claims().await?;
            let (after, _workspace) = self.observe_key_retention(context, &probe, true).await?;
            let fence = match after.retirements.status(&request.retirement_id) {
                Some(KeyRetirementStatus::Completed { record })
                    if record.fence.request_sha256 == request_sha256 =>
                {
                    return Ok(record);
                }
                Some(KeyRetirementStatus::Fenced { fence })
                    if fence.request_sha256 == request_sha256 =>
                {
                    fence
                }
                _ => {
                    return Err(Error::new(
                        ErrorCode::Conflict,
                        "key retirement no longer holds its fence",
                    ));
                }
            };
            let KeyRetentionCoverage::Complete {
                membership_epoch,
                coverage_sha256,
                ..
            } = &after.page.coverage
            else {
                return Err(Error::new(
                    ErrorCode::Unavailable,
                    "key retention coverage is incomplete after the fence",
                ));
            };
            // The members that reported are the members the fence was
            // committed for; a changed membership has an unobserved catalog.
            if *membership_epoch != fence.membership_epoch {
                return Err(Error::new(
                    ErrorCode::Conflict,
                    "membership changed after the key retirement fence",
                ));
            }
            retired_reference(request, &after)?;
            let decision = self
                .submit(
                    context.clone(),
                    Operation::CompleteKeyRetirement(CompleteKeyRetirement {
                        retirement_id: request.retirement_id.clone(),
                        request_sha256: request_sha256.to_owned(),
                        completed_coverage_sha256: coverage_sha256.clone(),
                        expected_dependency_sha256: after.dependency_sha256,
                    }),
                )
                .await;
            match decision {
                Ok(_) => {}
                // A publication committed between the observation and the
                // decision. Observe the scope that now includes it.
                Err(error) if error.code == ErrorCode::Conflict => {
                    moved = Some(error);
                    continue;
                }
                Err(error) => return Err(error),
            }
            return match self
                .retained_key_retirement(context, &request.scope, &request.retirement_id)
                .await?
            {
                Some(KeyRetirementStatus::Completed { record })
                    if record.fence.request_sha256 == request_sha256 =>
                {
                    Ok(record)
                }
                _ => Err(Error::new(
                    ErrorCode::UnknownOutcome,
                    "key retirement decision committed without its record",
                )),
            };
        }
        Err(moved.unwrap_or_else(|| {
            Error::new(
                ErrorCode::Conflict,
                "key dependencies changed after their coverage was observed",
            )
        }))
    }

    /// A backup session claim checks its tenant's authority epoch and joins
    /// the Control log under Control's proposal gate. One that passed the
    /// check before the fence finishes while this waits for the gate; one that
    /// takes the gate afterwards meets the epoch the fence advanced.
    async fn settle_backup_claims(&self) -> Result<()> {
        match self.backup_authority() {
            Ok(Some((control, _))) => {
                drop(control.proposal_gate.lock().await);
                Ok(())
            }
            // Without the session owner coverage is incomplete, which the
            // observation that follows reports.
            Ok(None) => Ok(()),
            Err(error) if error.code == ErrorCode::Unavailable => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// The linearizable status this scope retains under the identity.
    async fn retained_key_retirement(
        &self,
        context: &RequestContext,
        scope: &KeyRetentionScope,
        retirement_id: &str,
    ) -> Result<Option<KeyRetirementStatus>> {
        self.access()?;
        self.engine.authorize(context, None, Action::Admin)?;
        let control = self.key_retention_scope(context, scope)?;
        self.barrier().await?;
        let generation = self.engine.generation()?;
        let state = &generation.state;
        if control {
            context.authorization.require_control(&state.incarnation)?;
        }
        self.engine
            .authorize_release(context, None, Action::Admin, state.policy_epoch)?;
        Ok(state
            .key_retirements
            .status(retirement_id)
            .filter(|status| status.request().scope == *scope))
    }

    /// Remove the fence of an undecided retirement. The identity stays spent.
    pub async fn abort_key_retirement(
        &self,
        context: &RequestContext,
        request: RetireKeyVersionsRequest,
    ) -> Result<KeyRetirementStatus> {
        let result = self.abort_key_retirement_inner(context, &request).await;
        self.audit_write_result(context, result).await
    }

    async fn abort_key_retirement_inner(
        &self,
        context: &RequestContext,
        request: &RetireKeyVersionsRequest,
    ) -> Result<KeyRetirementStatus> {
        request.validate()?;
        let request_sha256 = request.request_sha256()?;
        self.access()?;
        self.engine.authorize(context, None, Action::Admin)?;
        self.key_retention_scope(context, &request.scope)?;
        self.submit(
            context.clone(),
            Operation::AbortKeyRetirement(AbortKeyRetirement {
                retirement_id: request.retirement_id.clone(),
                request_sha256,
            }),
        )
        .await?;
        self.retained_key_retirement(context, &request.scope, &request.retirement_id)
            .await?
            .ok_or_else(|| {
                Error::new(
                    ErrorCode::UnknownOutcome,
                    "key retirement abort committed without its record",
                )
            })
    }

    pub async fn key_retirement_status(
        &self,
        context: &RequestContext,
        request: KeyRetirementStatusRequest,
    ) -> Result<KeyRetirementStatusResponse> {
        let result = async {
            request.validate()?;
            let status = self
                .retained_key_retirement(context, &request.scope, &request.retirement_id)
                .await?;
            let response = KeyRetirementStatusResponse { status };
            response.validate(&request)?;
            Ok(response)
        }
        .await;
        self.audit_result(context, result).await
    }

    /// A new encrypted object carries this store's whole application key
    /// catalog. Refuse to publish one while that catalog still wraps under a
    /// version that a fence or a completed retirement names.
    pub(in crate::service) fn require_unfenced_catalog(
        &self,
        retirements: &KeyRetirementState,
    ) -> Result<()> {
        if retirements.is_empty() {
            return Ok(());
        }
        let mut fenced = None;
        self.stores
            .visit_key_retention_catalogs(|custody, _, provider, key_ref, version| {
                if !custody && retirements.rejects_version(provider, key_ref, version) {
                    fenced.get_or_insert(version);
                }
                Ok(())
            })
            .map_err(|_| Error::new(ErrorCode::Unavailable, "key catalog is unavailable"))?;
        match fenced {
            Some(version) => Err(Error::new(
                ErrorCode::Conflict,
                format!("key catalog still wraps under fenced wrapping key version {version}"),
            )),
            None => Ok(()),
        }
    }
}
