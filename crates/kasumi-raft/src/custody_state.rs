//! One deterministic reducer for warm and key-free retired consensus. This
//! state is closed metadata; reading it does not establish current authority.
use crate::RetiredSnapshotState;
use kasumi_types::{
    Action, CustodyAction, CustodyLimits, CustodyReceipt, CustodyRequest, Error, ErrorCode,
    RequestContext, Result, validate_custody_administrators, validate_name,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyState {
    pub origin: RetiredSnapshotState,
    pub revision: u64,
    pub policy_epoch: u64,
    pub administrators: BTreeSet<String>,
    pub limits: CustodyLimits,
    pub commands: BTreeMap<String, CustodyReceipt>,
    pub audit: Vec<CustodyAudit>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyAudit {
    pub principal: String,
    pub request_id: String,
    pub command_id: String,
    pub request_digest: String,
    pub revision: u64,
    pub admitted_at_ms: u64,
    pub policy_epoch: u64,
    pub replay: bool,
    pub accepted: bool,
}

impl CustodyState {
    pub fn new(origin: RetiredSnapshotState, limits: CustodyLimits) -> Result<Self> {
        let state = Self {
            revision: origin.revision,
            administrators: origin.administrators.clone(),
            policy_epoch: 1,
            origin,
            limits,
            commands: BTreeMap::new(),
            audit: Vec::new(),
        };
        state.validate()?;
        Ok(state)
    }

    pub fn authorize(&self, context: &RequestContext) -> Result<()> {
        context
            .authorization
            .require_custody(&self.origin.receipt.source_incarnation)?;
        validate_name(&context.principal)?;
        validate_name(&context.request_id)?;
        if context.tenant != self.origin.receipt.tenant
            || !context.scopes.contains(&Action::Admin)
            || !self.administrators.contains(&context.principal)
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "current custody administrator required",
            ));
        }
        Ok(())
    }

    pub fn apply(
        &self,
        context: &RequestContext,
        request: &CustodyRequest,
        admitted_at_ms: u64,
        revision: u64,
    ) -> Result<(Self, CustodyReceipt)> {
        self.authorize(context)?;
        context.authorization.check_admitted_at(admitted_at_ms)?;
        request.validate()?;
        if request.retirement != self.origin.request.reference()? || revision <= self.revision {
            return Err(Error::new(
                ErrorCode::Conflict,
                "custody source or applied revision differs",
            ));
        }
        let digest = request.digest()?;
        let prior = self.commands.get(&request.command_id);
        if let Some(prior) = prior
            && prior.request_digest != digest
        {
            return Err(Error::new(
                ErrorCode::Conflict,
                "custody command identity differs",
            ));
        }
        // A pure expansion can recover a full configured budget. Its exact
        // candidate still includes this operation's own receipt and audit and
        // cannot exceed the immutable hard ceilings or discard any history.
        let expansion = if prior.is_none()
            && request.expected_policy_epoch == self.policy_epoch
            && admitted_at_ms <= request.not_after_ms
            && let CustodyAction::SetLimits(limits) = &request.action
            && limits.max_commands >= self.limits.max_commands
            && limits.max_audit_records >= self.limits.max_audit_records
            && limits.max_state_bytes >= self.limits.max_state_bytes
        {
            Some(limits)
        } else {
            None
        };
        let admission_limits = expansion.unwrap_or(&self.limits);
        if prior.is_none() && self.commands.len() >= admission_limits.max_commands {
            return Err(Error::new(
                ErrorCode::QuotaExceeded,
                "permanent custody command budget exhausted",
            ));
        }
        let mut next = self.clone();
        next.revision = revision;
        let receipt = if let Some(prior) = prior {
            prior.clone()
        } else {
            let outcome = if admitted_at_ms > request.not_after_ms {
                Err(Error::new(
                    ErrorCode::Conflict,
                    "custody action deadline expired",
                ))
            } else if request.expected_policy_epoch != self.policy_epoch {
                Err(Error::new(ErrorCode::Conflict, "custody policy changed"))
            } else {
                let mut proposed = next.clone();
                match &request.action {
                    CustodyAction::ReplaceAdministrators(administrators) => {
                        proposed.administrators = administrators.clone();
                        proposed.policy_epoch = increment(self.policy_epoch)?;
                    }
                    CustodyAction::SetLimits(limits) => {
                        proposed.limits = limits.clone();
                        proposed.policy_epoch = increment(self.policy_epoch)?;
                    }
                }
                // Check the final candidate including this attempt's permanent
                // receipt and audit before publishing any configuration change.
                next = proposed;
                Ok(())
            };
            CustodyReceipt {
                command_id: request.command_id.clone(),
                request_digest: digest.clone(),
                principal: context.principal.clone(),
                revision,
                admitted_at_ms,
                previous_policy_epoch: self.policy_epoch,
                policy_epoch: next.policy_epoch,
                outcome,
            }
        };
        if prior.is_none() {
            next.commands
                .insert(request.command_id.clone(), receipt.clone());
        }
        next.audit.push(CustodyAudit {
            principal: context.principal.clone(),
            request_id: context.request_id.clone(),
            command_id: request.command_id.clone(),
            request_digest: digest,
            revision,
            admitted_at_ms,
            policy_epoch: next.policy_epoch,
            replay: prior.is_some(),
            accepted: receipt.outcome.is_ok(),
        });
        next.validate()?;
        Ok((next, receipt))
    }

    pub fn validate(&self) -> Result<()> {
        self.limits.validate()?;
        validate_custody_administrators(&self.administrators)?;
        self.origin.request.validate()?;
        self.origin.receipt.validate()?;
        if self.policy_epoch == 0 || self.revision < self.origin.revision {
            return Err(Error::new(
                ErrorCode::Corruption,
                "custody state position differs",
            ));
        }
        if self.commands.len() > self.limits.max_commands
            || self.audit.len() > self.limits.max_audit_records
        {
            return Err(Error::new(
                ErrorCode::QuotaExceeded,
                "custody metadata count budget exhausted",
            ));
        }
        for (identity, receipt) in &self.commands {
            receipt.validate()?;
            if identity != &receipt.command_id
                || receipt.revision > self.revision
                || receipt.policy_epoch > self.policy_epoch
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "custody retained command differs",
                ));
            }
        }
        let mut previous = self.origin.revision;
        for event in &self.audit {
            validate_name(&event.principal)?;
            validate_name(&event.request_id)?;
            let receipt = self
                .commands
                .get(&event.command_id)
                .ok_or_else(|| Error::new(ErrorCode::Corruption, "custody audit command absent"))?;
            if event.revision <= previous
                || event.revision > self.revision
                || event.request_digest != receipt.request_digest
                || event.policy_epoch > self.policy_epoch
                || event.accepted != receipt.outcome.is_ok()
            {
                return Err(Error::new(
                    ErrorCode::Corruption,
                    "custody audit linkage differs",
                ));
            }
            previous = event.revision;
        }
        struct Budget(usize);
        impl std::io::Write for Budget {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self
                    .0
                    .checked_sub(bytes.len())
                    .ok_or_else(|| std::io::Error::other("custody metadata budget exhausted"))?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        serde_json::to_writer(Budget(self.limits.max_state_bytes), self).map_err(|_| {
            Error::new(
                ErrorCode::QuotaExceeded,
                "custody metadata byte budget exhausted",
            )
        })?;
        Ok(())
    }
}
fn increment(value: u64) -> Result<u64> {
    value
        .checked_add(1)
        .ok_or_else(|| Error::new(ErrorCode::Conflict, "custody epoch exhausted"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::tests::seed;
    use kasumi_types::{RequestAuthorization, RetirementReceipt};

    fn state() -> CustodyState {
        let (_, seed) = seed().unwrap();
        let request = seed.request().clone();
        let receipt = RetirementReceipt {
            tenant: request.checkpoint.tenant.clone(),
            source_incarnation: request.expected_source_incarnation.clone(),
            target_incarnation: request.target_incarnation.clone(),
            retirement_id: request.retirement_id.clone(),
            principal: "owner".into(),
            admitted_at_ms: 123,
            request_digest: request.reference().unwrap().request_digest,
            checkpoint: request.checkpoint.clone(),
            revision: 1,
            policy_epoch: 2,
            closure_digest: "4".repeat(64),
        };
        CustodyState::new(
            RetiredSnapshotState {
                revision_base: 0,
                revision: 1,
                policy_epoch: 2,
                administrators: BTreeSet::from(["owner".into()]),
                request,
                receipt,
            },
            CustodyLimits::default(),
        )
        .unwrap()
    }
    fn context(principal: &str) -> RequestContext {
        RequestContext {
            tenant: "tenant".into(),
            principal: principal.into(),
            request_id: "request".into(),
            scopes: BTreeSet::from([Action::Admin]),
            authorization: RequestAuthorization::service_identity(),
        }
    }
    fn request(state: &CustodyState, id: &str, action: CustodyAction) -> CustodyRequest {
        CustodyRequest {
            retirement: state.origin.request.reference().unwrap(),
            command_id: id.into(),
            expected_policy_epoch: state.policy_epoch,
            not_after_ms: 200,
            action,
        }
    }
    #[test]
    fn rotation_replay_requires_current_admin_and_preserves_exact_original_actor() {
        let state = state();
        let request = request(
            &state,
            "rotate",
            CustodyAction::ReplaceAdministrators(BTreeSet::from(["new-owner".into()])),
        );
        let (changed, receipt) = state.apply(&context("owner"), &request, 199, 2).unwrap();
        assert!(receipt.outcome.is_ok());
        assert!(changed.authorize(&context("owner")).is_err());
        assert!(changed.apply(&context("owner"), &request, 199, 3).is_err());
        let (replayed, replay) = changed
            .apply(&context("new-owner"), &request, 900, 3)
            .unwrap();
        assert_eq!(receipt, replay);
        assert_eq!(replayed.commands.len(), 1);
        assert_eq!(replayed.policy_epoch, changed.policy_epoch);
        assert_eq!(replayed.audit.len(), 2);
        assert_eq!(replayed.audit[1].principal, "new-owner");
        assert_eq!(replay.principal, "owner");
        let restored: CustodyState =
            serde_json::from_slice(&serde_json::to_vec(&replayed).unwrap()).unwrap();
        restored.validate().unwrap();
        assert!(restored.authorize(&context("owner")).is_err());
    }
    #[test]
    fn stale_policy_is_a_permanent_exact_failure_and_changed_identity_conflicts() {
        let state = state();
        let mut request = request(
            &state,
            "stale",
            CustodyAction::SetLimits(state.limits.clone()),
        );
        request.expected_policy_epoch += 1;
        let (changed, receipt) = state.apply(&context("owner"), &request, 100, 2).unwrap();
        assert_eq!(
            receipt.outcome.as_ref().unwrap_err().code,
            ErrorCode::Conflict
        );
        let (_, replay) = changed.apply(&context("owner"), &request, 100, 3).unwrap();
        assert_eq!(receipt, replay);
        request.expected_policy_epoch = 1;
        assert!(changed.apply(&context("owner"), &request, 100, 3).is_err());
        assert_eq!(changed.administrators, state.administrators);
    }
    #[test]
    fn exhausted_command_audit_and_byte_budgets_publish_no_partial_policy() {
        let state = state();
        let request = request(
            &state,
            "quota",
            CustodyAction::SetLimits(CustodyLimits {
                max_commands: 1,
                max_audit_records: 1,
                max_state_bytes: 4096,
            }),
        );
        let (changed, _) = state.apply(&context("owner"), &request, 100, 2).unwrap();
        let before = changed.clone();
        let rotate = self::request(
            &changed,
            "rotate",
            CustodyAction::ReplaceAdministrators(BTreeSet::from(["new-owner".into()])),
        );
        assert!(changed.apply(&context("owner"), &rotate, 100, 3).is_err());
        assert!(changed.apply(&context("owner"), &request, 100, 3).is_err());
        assert_eq!(before, changed);
        let oversized = self::request(
            &state,
            "huge",
            CustodyAction::ReplaceAdministrators(
                (0..100)
                    .map(|n| format!("administrator-{n:03}-{}", "x".repeat(64)))
                    .collect(),
            ),
        );
        let mut bounded = state.clone();
        bounded.limits.max_state_bytes = 4096;
        assert!(
            bounded
                .apply(&context("owner"), &oversized, 100, 2)
                .is_err()
        );
        assert_eq!(bounded.administrators, state.administrators);
    }
    #[test]
    fn closed_request_rejects_payload_fields_and_cross_source_observations() {
        let state = state();
        let mut request = request(
            &state,
            "observe",
            CustodyAction::SetLimits(state.limits.clone()),
        );
        let mut wire = serde_json::to_value(&request).unwrap();
        wire["payload"] = serde_json::json!({"collection":"journal", "body":"private"});
        assert!(serde_json::from_value::<CustodyRequest>(wire).is_err());
        request.retirement.source_incarnation = uuid::Uuid::new_v4().to_string();
        assert!(state.apply(&context("owner"), &request, 100, 2).is_err());
        let mut wrong = context("owner");
        wrong.tenant = "other".into();
        assert!(state.authorize(&wrong).is_err());
    }
    #[test]
    fn full_count_and_byte_budgets_expand_without_discarding_retained_history() {
        let original = state();
        let mut bounded = original.clone();
        bounded.limits = CustodyLimits {
            max_commands: 1,
            max_audit_records: 1,
            max_state_bytes: 4096,
        };
        let first = request(
            &bounded,
            "first",
            CustodyAction::SetLimits(bounded.limits.clone()),
        );
        let (mut full, first_receipt) = bounded.apply(&context("owner"), &first, 100, 2).unwrap();
        // Fill both count bounds; the expansion includes its own receipt/audit.
        full.limits.max_state_bytes = 4096;
        let expansion = request(
            &full,
            "expand",
            CustodyAction::SetLimits(CustodyLimits {
                max_commands: 3,
                max_audit_records: 3,
                max_state_bytes: 8192,
            }),
        );
        assert!(full.apply(&context("revoked"), &expansion, 100, 3).is_err());
        let (expanded, receipt) = full.apply(&context("owner"), &expansion, 100, 3).unwrap();
        receipt.outcome.unwrap();
        assert_eq!(expanded.commands["first"], first_receipt);
        assert_eq!(expanded.audit[..1], full.audit[..]);
        let mut byte_full = original.clone();
        let mut revision = 2;
        while serde_json::to_vec(&byte_full).unwrap().len() < 4096 {
            let fill = request(
                &byte_full,
                &format!("fill-{revision}"),
                CustodyAction::SetLimits(byte_full.limits.clone()),
            );
            byte_full = byte_full
                .apply(&context("owner"), &fill, 100, revision)
                .unwrap()
                .0;
            revision += 1;
        }
        byte_full.limits.max_state_bytes = serde_json::to_vec(&byte_full).unwrap().len() + 16;
        byte_full.validate().unwrap();
        let old_byte_cap = byte_full.limits.max_state_bytes;
        let large = request(
            &byte_full,
            "large",
            CustodyAction::ReplaceAdministrators(
                (0..100)
                    .map(|n| format!("administrator-{n:03}-{}", "x".repeat(64)))
                    .collect(),
            ),
        );
        assert!(
            byte_full
                .apply(&context("owner"), &large, 100, revision)
                .is_err()
        );
        let grow = request(
            &byte_full,
            "grow-bytes",
            CustodyAction::SetLimits(CustodyLimits {
                max_state_bytes: 32768,
                ..byte_full.limits.clone()
            }),
        );
        let (expanded, receipt) = byte_full
            .apply(&context("owner"), &grow, 100, revision)
            .unwrap();
        receipt.outcome.unwrap();
        assert!(
            serde_json::to_vec(&expanded).unwrap().len() > old_byte_cap,
            "the expansion's own records exceed the previous byte cap"
        );
        let large = request(&expanded, "large", large.action);
        let (rotated, receipt) = expanded
            .apply(&context("owner"), &large, 100, revision + 1)
            .unwrap();
        receipt.outcome.unwrap();
        assert_eq!(rotated.audit[..byte_full.audit.len()], byte_full.audit[..]);
    }
}
