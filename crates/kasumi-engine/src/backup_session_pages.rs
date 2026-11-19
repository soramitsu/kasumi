//! Bounded observation of the permanent Control backup-session ledger.
//!
//! A page names at most [`MAX_CONTROL_BACKUP_SESSION_PAGE`] distinct sessions in
//! original claim order and visits at most twice that many permanent rows, so
//! terminal rows between claims cannot make one page unbounded. The
//! continuation names the last visited row by ordinal and chain digest. The
//! ledger is append-only, so a later claim or decision never redirects an
//! earlier continuation. This session page bound is independent of the
//! 256-object destination cleanup page.
use super::*;
use serde::{Deserialize, Serialize};

/// Largest number of distinct sessions returned by one observation page.
pub const MAX_CONTROL_BACKUP_SESSION_PAGE: usize = 256;
const MAX_SCANNED_ROWS: u64 = 2 * MAX_CONTROL_BACKUP_SESSION_PAGE as u64;
/// One permanent row (at most 2 MiB) is decoded at a time; the page retains
/// only fixed-size digests and outcomes.
const PAGE_WORKSPACE_BYTES: u64 = 8 << 20;

/// Continuation after the last visited permanent row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBackupSessionCursor {
    pub after_ordinal: u64,
    pub after_row_sha256: String,
}

/// The exact committed claim. `record_sha256` covers the complete record,
/// including the retained intent ciphertext represented here by its digest
/// and length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBackupSessionBinding {
    pub ordinal: u64,
    pub row_sha256: String,
    pub record_sha256: String,
    pub tenant: String,
    pub source_incarnation: String,
    pub revision: u64,
    pub source_purpose_sha256: String,
    pub namespace_binding: BackupNamespaceBinding,
    pub binding_nonce: uuid::Uuid,
    pub principal: String,
    pub request_id: String,
    pub destination_alias: Option<String>,
    pub command_id: uuid::Uuid,
    pub intent_ciphertext_sha256: String,
    pub intent_ciphertext_bytes: u64,
    pub position: BackupBindingPosition,
}

/// The selected immutable terminal decision and its exact ciphertext digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBackupSessionDecision {
    pub ordinal: u64,
    pub row_sha256: String,
    pub decision_sha256: String,
    pub outcome: BackupSessionOutcome,
    pub ciphertext_sha256: String,
    pub ciphertext_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBackupSessionEntry {
    pub session_id: uuid::Uuid,
    pub binding: ControlBackupSessionBinding,
    pub decision: Option<ControlBackupSessionDecision>,
}

/// One page read from a single selected Control generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlBackupSessionPage {
    pub head: BackupBindingHead,
    pub entries: Vec<ControlBackupSessionEntry>,
    pub scanned_from: u64,
    pub scanned_through: u64,
    pub next: Option<ControlBackupSessionCursor>,
}

fn page_corruption(_: anyhow::Error) -> Error {
    Error::new(
        ErrorCode::Corruption,
        "Control backup session page read failed",
    )
}

fn entry(
    view: &crate::backup_binding::View,
    row: crate::backup_binding::Row,
    row_sha256: String,
) -> Result<ControlBackupSessionEntry> {
    let session_id = row.record.claim.session_id;
    let decision = match view.terminal(session_id).map_err(page_corruption)? {
        Some(terminal) => {
            let row_sha256 = terminal.sha256().map_err(page_corruption)?;
            let decision = terminal.terminal.ok_or_else(|| {
                Error::new(ErrorCode::Corruption, "terminal row lacks its decision")
            })?;
            Some(ControlBackupSessionDecision {
                ordinal: terminal.ordinal,
                row_sha256,
                decision_sha256: staged_digest(&decision)?.0,
                ciphertext_bytes: decision.ciphertext.len() as u64,
                ciphertext_sha256: decision.ciphertext_sha256,
                outcome: decision.outcome,
            })
        }
        None => None,
    };
    let record_sha256 = staged_digest(&row.record)?.0;
    let claim = row.record.claim;
    Ok(ControlBackupSessionEntry {
        session_id,
        binding: ControlBackupSessionBinding {
            ordinal: row.ordinal,
            row_sha256,
            record_sha256,
            intent_ciphertext_bytes: claim.intent_ciphertext.len() as u64,
            tenant: claim.tenant,
            source_incarnation: claim.source_incarnation,
            revision: claim.revision,
            source_purpose_sha256: claim.source_purpose_sha256,
            namespace_binding: claim.namespace_binding,
            binding_nonce: claim.binding_nonce,
            principal: claim.principal,
            request_id: claim.request_id,
            destination_alias: claim.destination_alias,
            command_id: claim.command_id,
            intent_ciphertext_sha256: claim.intent_ciphertext_sha256,
            position: row.record.position,
        },
        decision,
    })
}

/// Read one page from a selected ledger view. `check` runs before each row.
pub(crate) fn session_page(
    view: &crate::backup_binding::View,
    after: Option<&ControlBackupSessionCursor>,
    limit: usize,
    check: &dyn Fn() -> Result<()>,
) -> Result<ControlBackupSessionPage> {
    if !(1..=MAX_CONTROL_BACKUP_SESSION_PAGE).contains(&limit) {
        return Err(Error::new(
            ErrorCode::InvalidArgument,
            "backup session page limit outside bounds",
        ));
    }
    let head = view.head().clone();
    let first = match after {
        None => 1,
        Some(cursor) => {
            let anchored = (1..=head.count).contains(&cursor.after_ordinal)
                && view
                    .row(cursor.after_ordinal)
                    .and_then(|row| row.sha256())
                    .map_err(page_corruption)?
                    == cursor.after_row_sha256;
            if !anchored {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "backup session cursor does not name this Control ledger",
                ));
            }
            cursor.after_ordinal + 1
        }
    };
    let mut entries = Vec::new();
    let mut last = after.cloned();
    let mut ordinal = first;
    while ordinal <= head.count && entries.len() < limit && ordinal - first < MAX_SCANNED_ROWS {
        check()?;
        let row = view.row(ordinal).map_err(page_corruption)?;
        let row_sha256 = row.sha256().map_err(page_corruption)?;
        if row.terminal.is_none() {
            entries.push(entry(view, row, row_sha256.clone())?);
        }
        last = Some(ControlBackupSessionCursor {
            after_ordinal: ordinal,
            after_row_sha256: row_sha256,
        });
        ordinal += 1;
    }
    let scanned_through = last.as_ref().map_or(0, |cursor| cursor.after_ordinal);
    Ok(ControlBackupSessionPage {
        next: last.filter(|_| scanned_through < head.count),
        head,
        entries,
        scanned_from: first,
        scanned_through,
    })
}

impl Database {
    /// Read one bounded page of this Control owner's permanent backup sessions
    /// under a quorum barrier. Every entry and the returned head come from the
    /// same selected generation.
    pub async fn control_backup_session_page(
        &self,
        operator: &RequestContext,
        after: Option<ControlBackupSessionCursor>,
        limit: usize,
    ) -> Result<ControlBackupSessionPage> {
        let result = async {
            self.access()?;
            self.engine.authorize(operator, None, Action::Admin)?;
            if self.engine.generation()?.tenant() != crate::control::CONTROL_TENANT {
                return Err(Error::new(
                    ErrorCode::InvalidArgument,
                    "backup session ledger belongs to Control",
                ));
            }
            let fence = self.response_fence(operator)?;
            let token = QueryCancellation::default();
            let _cancel = CancelOnDrop(token.clone());
            let registration = self.work.begin(token.clone())?;
            let reservation = self
                .admission()
                .reserve(PAGE_WORKSPACE_BYTES, Some(token.clone()))?;
            self.barrier().await?;
            let generation = self.engine.generation()?;
            let page = reservation
                .retained_read(token, move |_workspace, token| {
                    let _registration = registration;
                    session_page(&generation.backup_bindings, after.as_ref(), limit, &|| {
                        token.check()
                    })
                })
                .await?;
            fence.check()?;
            Ok(page)
        }
        .await;
        self.audit_result(operator, result).await
    }
}
