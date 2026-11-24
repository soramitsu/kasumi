//! Retain an authenticated tenant's original encrypted history one bounded
//! read at a time. Both groups must still own their selected positions when
//! the Control releases a page.
use super::*;

fn binding_page(
    view: &crate::backup_binding::View,
    tenant: &str,
    after: u64,
    token: &QueryCancellation,
) -> Result<(Option<BackupInventoryRecord>, BackupInventoryCursor)> {
    let count = view.head().count;
    if after > count {
        return Err(wrong_owner());
    }
    let mut through = after;
    let mut found = None;
    while through < count && through - after < BACKUP_INVENTORY_SCAN_ROWS {
        through += 1;
        token.check()?;
        if let Some(selected) =
            read_tenant_binding(view, tenant, through).map_err(Error::from_physical_source)?
        {
            found = Some(BackupInventoryRecord::Binding {
                selected: Box::new(selected),
            });
            break;
        }
    }
    Ok((
        found,
        if through == count {
            BackupInventoryCursor::RECOVERIES
        } else {
            BackupInventoryCursor::Bindings { after: through }
        },
    ))
}

fn recovery_page(
    state: &TenantState,
    tenant: &str,
    cursor: BackupInventoryCursor,
    token: &QueryCancellation,
) -> Result<(Option<BackupInventoryRecord>, BackupInventoryCursor)> {
    use std::ops::Bound::{Excluded, Included, Unbounded};
    let (start, end) = cursor.recovery_bounds()?;
    // These adjacent half-open string ranges partition the complete physical
    // map, including malformed keys outside ordinary UUID spellings.
    let lower = if start.is_nil() {
        Unbounded
    } else {
        Included(start.to_string())
    };
    let upper = end.as_u128().checked_add(1).map_or(Unbounded, |n| {
        Excluded(uuid::Uuid::from_u128(n).to_string())
    });
    let mut found = None;
    for (index, (key, operation)) in state
        .recovery_control
        .operations
        .range::<_, String>((lower, upper))
        .enumerate()
    {
        token.check()?;
        if *key != operation.request.operation_id.to_string() {
            return Err(Error::new(
                ErrorCode::Corruption,
                "selected recovery identity differs",
            ));
        }
        if index as u64 + 1 == BACKUP_INVENTORY_SCAN_ROWS
            || (found.is_some() && operation.request.tenant == tenant)
        {
            return Ok((None, cursor.split_recoveries()?));
        }
        if operation.request.tenant == tenant {
            check_inventory_recovery(key, operation)?;
            found = Some(BackupInventoryRecord::Recovery {
                request: Box::new(operation.request.clone()),
                request_sha256: operation.request_sha256.clone(),
                updated_revision: operation.updated_revision,
            });
        }
    }
    Ok((found, cursor.next_recoveries()?))
}

impl Database {
    pub async fn read_remote_backup_inventory(
        self: &Arc<Self>,
        actor: RequestContext,
        peer: String,
        command: BackupInventoryCommand,
    ) -> Result<crate::AdmittedOutput<BackupInventoryPage>> {
        let result = self
            .read_remote_backup_inventory_inner(&actor, &peer, command)
            .await;
        self.audit_result(&actor, result).await
    }
    async fn read_remote_backup_inventory_inner(
        self: &Arc<Self>,
        actor: &RequestContext,
        peer: &str,
        command: BackupInventoryCommand,
    ) -> Result<crate::AdmittedOutput<BackupInventoryPage>> {
        self.access()?;
        actor
            .authorization
            .require_control(&self.engine.generation()?.state.incarnation)?;
        self.authorize_remote_backup(actor, None)?;
        validate_sha256(peer)?;
        command.validate()?;
        let verifier = self
            .remote_backup_verifier
            .get()
            .cloned()
            .ok_or_else(unavailable)?;
        let token = QueryCancellation::default();
        let _cancel = CancelOnDrop(token.clone());
        let registration = self.work.begin(token.clone())?;
        let mut reply_workspace = self
            .admission()
            .reserve_waiting(3 * MAX_REMOTE_BACKUP_BYTES as u64, Some(token.clone()))?;
        let quorum = SourceQuorum::observe(&self.group)
            .await?
            .ok_or_else(unavailable)?;
        let metrics = self.group.metrics();
        let [voters] = metrics
            .membership_config
            .membership()
            .get_joint_config()
            .as_slice()
        else {
            return Err(unavailable());
        };
        if voters.len() != 3 || !voters.contains(&self.group.node_id()) {
            return Err(unavailable());
        }
        let initial = self
            .confirm_backup_reference(verifier.as_ref(), actor, peer, &command.reference)
            .await?;
        let route = self.remote_backup_route(actor, peer, &initial)?;
        let generation = self.engine.generation()?;
        let selection = staged_digest(&(
            "kasumi.backup-retention.selection.v1",
            &command.reference.tenant,
            &generation.state.incarnation,
            generation.state.revision,
            &generation.state.backup_binding_head,
            route,
            quorum.term,
            quorum.leader,
            quorum.membership,
            quorum.observed,
            initial.policy_epoch,
            initial.term,
            initial.leader,
            initial.membership_term,
            initial.membership_index,
            &initial.purpose_sha256,
        ))?
        .0;
        if command
            .read
            .selection
            .as_ref()
            .is_some_and(|expected| expected != &selection)
        {
            return Err(wrong_owner());
        }
        let read = generation.clone();
        let tenant = command.reference.tenant.clone();
        let cursor = command.read.cursor;
        let workspace = self.admission().reserve(8 << 20, Some(token.clone()))?;
        let (record, next) = workspace
            .retained_read(token.clone(), move |_workspace, token| {
                let _owner = registration;
                token.check()?;
                let (record, next) = match cursor {
                    BackupInventoryCursor::Bindings { after } => {
                        binding_page(&read.backup_bindings, &tenant, after, token)?
                    }
                    BackupInventoryCursor::Recoveries { .. } => {
                        recovery_page(&read.state, &tenant, cursor, token)?
                    }
                    BackupInventoryCursor::Finish => return Ok((None, None)),
                };
                Ok((record, Some(next)))
            })
            .await?;
        let released = self
            .confirm_backup_reference(verifier.as_ref(), actor, peer, &command.reference)
            .await?;
        if !same_authority(&initial, &released)
            || self.remote_backup_route(actor, peer, &released)? != route
            || !Arc::ptr_eq(&generation, &self.engine.generation()?)
        {
            return Err(wrong_owner());
        }
        quorum.check()?;
        token.check()?;
        let result = BackupInventoryPage {
            binding_count: generation.state.backup_binding_head.count,
            nonce: command.reference.nonce,
            selection,
            record,
            next,
        };
        result.validate(&command)?;
        reply_workspace.retain_workspace();
        Ok(crate::AdmittedOutput::new(
            result,
            Arc::new(reply_workspace),
        ))
    }
}
