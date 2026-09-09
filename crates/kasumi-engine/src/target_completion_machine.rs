//! Deterministic completion attempt transitions. Callers must first verify the
//! exact live Control/issuer authorization against the actual applying leader.
//! Point lookups come from the selected immutable prefix, never physical rows
//! whose ordinal is beyond the current generation's applied head.
use kasumi_types::*;

pub(crate) struct CompletionMachine<'a> {
    pub origin: &'a TargetOrigin,
    pub head: &'a mut TargetCompletionHead,
    pub completion: Option<&'a TargetCompletionFact>,
    pub terminal_bytes: u64,
    pub maximum_bytes: u64,
}
pub(crate) struct ResolutionApply {
    pub intent: LifecycleIntent,
    pub admitted_at_ms: u64,
    pub dispatch_not_after_ms: u64,
    pub revision: u64,
    pub position: TargetCommitPosition,
}
impl CompletionMachine<'_> {
    pub(crate) fn prepare(
        &mut self,
        attempt: TargetCompletionAttempt,
        predecessor: Option<&TargetCompletionResolutionFact>,
        terminal: Option<&TargetCompletionResolutionFact>,
    ) -> Result<TargetCompletionAttempt> {
        self.head.validate(self.origin)?;
        attempt.validate()?;
        if attempt.origin != *self.origin {
            return Err(conflict("completion preparation changed physical target"));
        }
        if let Some(terminal) = terminal {
            terminal.validate()?;
            let original = &terminal.input.attempt;
            if original.origin != attempt.origin
                || original.intent != attempt.intent
                || original.input != attempt.input
                || original.dispatch_not_after_ms != attempt.dispatch_not_after_ms
            {
                return Err(conflict("original prepared completion identity changed"));
            }
            // Exact historical preparation may be observed; it cannot become
            // active again or regain the reservation consumed by resolution.
            return Ok((**original).clone());
        }
        if let Some(active) = &self.head.active {
            if active.intent == attempt.intent
                && active.input == attempt.input
                && active.dispatch_not_after_ms == attempt.dispatch_not_after_ms
            {
                return Ok((**active).clone());
            }
            return Err(conflict("original active completion is unresolved"));
        }
        if self.completion.is_some() {
            return Err(conflict("completed target cannot admit another attempt"));
        }
        if attempt.input.predecessor != self.head.predecessor {
            return Err(conflict(
                "completion did not name the latest exact target seal",
            ));
        }
        match (&attempt.input.predecessor, predecessor) {
            (None, None) => {}
            (Some(expected), Some(actual))
                if actual.sealed_reference()? == *expected
                    && attempt.revision > actual.revision
                    && attempt.position.term >= actual.position.term => {}
            _ => {
                return Err(conflict(
                    "completion predecessor lacks its exact terminal row",
                ));
            }
        }
        if !self
            .terminal_bytes
            .checked_add(attempt.reserved_terminal_bytes)
            .is_some_and(|required| required <= self.maximum_bytes)
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "completion terminal capacity must be reserved before dispatch",
            ));
        }
        self.head.active = Some(Box::new(attempt.clone()));
        Ok(attempt)
    }

    /// A delayed Complete is checked after every earlier ordered seal. An old
    /// admitted timestamp never permits it to cross a changed exact head.
    pub(crate) fn require_active(
        &self,
        intent: &LifecycleIntent,
        input: &TargetCompletionInput,
        dispatch_not_after_ms: u64,
        terminal: Option<&TargetCompletionResolutionFact>,
    ) -> Result<&TargetCompletionAttempt> {
        self.head.validate(self.origin)?;
        input.validate(self.origin, intent)?;
        if let Some(terminal) = terminal {
            terminal.validate()?;
            if terminal.input.attempt.intent != *intent
                || terminal.input.attempt.input != *input
                || terminal.input.attempt.dispatch_not_after_ms != dispatch_not_after_ms
            {
                return Err(conflict("terminal completion identity changed"));
            }
            return Err(conflict(
                "original completion attempt is permanently terminal",
            ));
        }
        let active = self
            .head
            .active
            .as_deref()
            .ok_or_else(|| conflict("completion lacks its committed capacity reservation"))?;
        if active.intent != *intent
            || active.input != *input
            || active.dispatch_not_after_ms != dispatch_not_after_ms
            || active.input.predecessor != self.head.predecessor
        {
            return Err(conflict(
                "completion crossed its exact original attempt or seal",
            ));
        }
        Ok(active)
    }

    pub(crate) fn resolve(
        &mut self,
        input: TargetCompletionResolutionInput,
        applied: ResolutionApply,
        previous: Option<&TargetCompletionResolutionFact>,
    ) -> Result<TargetCompletionResolutionFact> {
        self.head.validate(self.origin)?;
        input.validate(self.origin, &applied.intent)?;
        applied.position.validate()?;
        if applied.admitted_at_ms < applied.intent.accepted_at_ms
            || applied.admitted_at_ms >= applied.dispatch_not_after_ms
            || applied.dispatch_not_after_ms > applied.intent.original_credential_expires_at_ms
            || !self
                .origin
                .input
                .voters
                .contains_key(&applied.position.leader_node_id)
            || self
                .origin
                .materialization
                .request
                .checkpoint
                .revision
                .checked_add(1)
                .and_then(|base| base.checked_add(applied.position.index))
                != Some(applied.revision)
        {
            return Err(conflict(
                "resolution changed current target admission or applied position",
            ));
        }
        if let Some(previous) = previous {
            previous.validate()?;
            if previous.input != input
                || applied.revision <= previous.revision
                || applied.position.term < previous.position.term
                || !((applied.intent == previous.resolution_intent
                    && applied.dispatch_not_after_ms == previous.dispatch_not_after_ms)
                    || (applied.intent.request.command_id
                        != previous.resolution_intent.request.command_id
                        && applied.intent.revision > previous.resolution_intent.revision))
            {
                return Err(conflict(
                    "permanent terminal resolution input or order changed",
                ));
            }
            // Fresh observation resolves the same immutable first result. It
            // does not replace its Control identity, target position or cap.
            return Ok(previous.clone());
        }
        if self.head.active.as_deref() != Some(input.attempt.as_ref()) {
            return Err(conflict(
                "resolution lacks the exact prepared active attempt",
            ));
        }
        let terminal = if let Some(completion) = self.completion {
            if completion.completion_intent != input.attempt.intent
                || completion.predecessor != input.attempt.input.predecessor
                || completion.materialized != input.attempt.input.quorum.materialized
            {
                return Err(conflict("another completion has already won"));
            }
            TargetCompletionTerminal::Committed(Box::new(completion.clone()))
        } else {
            TargetCompletionTerminal::Sealed
        };
        let fact = TargetCompletionResolutionFact {
            input,
            resolution_intent: applied.intent,
            admitted_at_ms: applied.admitted_at_ms,
            dispatch_not_after_ms: applied.dispatch_not_after_ms,
            revision: applied.revision,
            position: applied.position,
            terminal,
        };
        fact.validate()?;
        if matches!(fact.terminal, TargetCompletionTerminal::Sealed) {
            self.head.predecessor = Some(fact.sealed_reference()?);
        }
        self.head.active = None;
        self.head.validate(self.origin)?;
        Ok(fact)
    }
}
/// The next physical row's exact framed size is supplied by the typed prefix
/// writer. It includes both point and ordinal entries; the budget transition is
/// published only together with those selected writes and the matching head.
#[derive(Debug)]
pub(crate) struct BudgetTransition {
    pub fact: TargetResolutionBudgetFact,
    pub changed: bool,
}
impl CompletionMachine<'_> {
    pub(crate) fn maintain_budget(
        &self,
        proposed: TargetResolutionBudgetFact,
        framed_record_bytes: u64,
        previous: Option<&TargetResolutionBudgetFact>,
    ) -> Result<BudgetTransition> {
        self.head.validate(self.origin)?;
        proposed.validate()?;
        if proposed.origin != *self.origin {
            return Err(conflict("budget maintenance changed physical target"));
        }
        if let Some(previous) = previous {
            previous.validate()?;
            if previous.origin != proposed.origin
                || previous.input != proposed.input
                || !((previous.intent == proposed.intent
                    && previous.dispatch_not_after_ms == proposed.dispatch_not_after_ms)
                    || (previous.intent.request.command_id != proposed.intent.request.command_id
                        && proposed.intent.revision > previous.intent.revision))
            {
                return Err(conflict(
                    "permanent target budget identity or order changed",
                ));
            }
            return Ok(BudgetTransition {
                fact: previous.clone(),
                changed: false,
            });
        }
        if proposed.input.expected_bytes != self.maximum_bytes {
            return Err(conflict("target metadata budget compare-and-set changed"));
        }
        let encoded_record =
            serde_json::to_vec(&TargetResolutionRecord::Budget(Box::new(proposed.clone())))
                .map_err(|_| conflict("target budget record encoding failed"))?;
        let encoded_bytes = u64::try_from(encoded_record.len())
            .map_err(|_| conflict("target budget record length overflow"))?;
        if framed_record_bytes < encoded_bytes {
            return Err(conflict("target budget row framing was not accounted"));
        }
        let reserved = self
            .head
            .active
            .as_ref()
            .map_or(0, |active| active.reserved_terminal_bytes);
        if !self
            .terminal_bytes
            .checked_add(reserved)
            .and_then(|bytes| bytes.checked_add(framed_record_bytes))
            .is_some_and(|bytes| bytes <= proposed.input.maximum_bytes)
        {
            return Err(Error::new(
                ErrorCode::ResourceExhausted,
                "target budget must preserve retained rows and the active terminal reserve",
            ));
        }
        Ok(BudgetTransition {
            fact: proposed,
            changed: true,
        })
    }
}
fn conflict(message: &str) -> Error {
    Error::new(ErrorCode::Conflict, message)
}

#[cfg(test)]
#[path = "target_completion_machine_tests.rs"]
pub(crate) mod tests;
