//! Required point-addressed records separate immutable node genesis from later
//! explicitly approved tenant creation. Absence describes only a dormant template.
use super::*;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Proposal {
    pub format: u32,
    pub tenant: String,
    pub route: kasumi_engine::control::TenantRoute,
    pub nodes: BTreeMap<u64, kasumi_engine::control::ControlNode>,
    pub initial_policy: kasumi_types::Policy,
    pub initial_limits: kasumi_types::Limits,
    pub application_keys: serde_json::Value,
    pub custody_keys: serde_json::Value,
    pub authority_id: Option<Uuid>,
}
impl Proposal {
    pub(crate) fn digest(&self) -> Result<String> {
        ensure!(self.format == 1, "unsupported tenant enrollment proposal");
        kasumi_types::validate_name(&self.tenant)?;
        ensure!(
            !Uuid::parse_str(&self.route.incarnation)?.is_nil(),
            "nil enrollment incarnation"
        );
        let mut topology = kasumi_engine::control::ControlTopology {
            nodes: self.nodes.clone(),
            tenants: BTreeMap::new(),
        };
        topology
            .tenants
            .insert(self.tenant.clone(), self.route.clone());
        topology.validate()?;
        kasumi_engine::TenantEngine::new(
            self.tenant.clone(),
            self.route.incarnation.clone(),
            self.initial_policy.clone(),
            self.initial_limits.clone(),
        )?;
        Ok(format!(
            "enrollment-v1-{}",
            hex::encode(Sha256::digest(serde_json::to_vec(self)?))
        ))
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "origin", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Origin {
    Genesis {
        input_sha256: String,
    },
    Control {
        proposal: Box<Proposal>,
        creation_id: Uuid,
        request_id: String,
    },
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Stage {
    CreationDispatched,
    Prepared,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TenantRecord {
    format: u32,
    pub tenant: String,
    pub incarnation: Uuid,
    pub origin: Origin,
    pub stage: Stage,
    pub bootstrap_sha256: Option<String>,
    pub original_grant: Option<kasumi_serving::SignedLease>,
}
fn tenant_key(tenant: &str) -> Result<String> {
    kasumi_types::validate_name(tenant)?;
    Ok(format!("tenant/{tenant}"))
}
impl TenantRecord {
    fn validate(&self, tenant: &str) -> Result<()> {
        ensure!(
            self.format == 1 && self.tenant == tenant && !self.incarnation.is_nil(),
            "unsupported or substituted tenant enrollment"
        );
        if let Origin::Control {
            proposal,
            creation_id,
            request_id,
        } = &self.origin
        {
            ensure!(
                !creation_id.is_nil() && !request_id.is_empty() && request_id.len() <= 1024,
                "invalid original enrollment dispatch"
            );
            proposal.digest()?;
            if let Some(grant) = &self.original_grant {
                grant.claims.request.validate()?;
                ensure!(
                    grant.claims.request.identity.tenant == tenant
                        && grant.claims.request.identity.incarnation == self.incarnation
                        && grant.claims.request.identity.authority_epoch == 1
                        && grant.claims.request.purpose == kasumi_serving::LeasePurpose::Serving
                        && Some(grant.claims.authority_id) == proposal.authority_id
                        && grant.claims.recovery_checkpoint.is_none(),
                    "original enrollment grant binding differs"
                );
            }
            ensure!(
                self.stage != Stage::Prepared
                    || proposal.authority_id.is_none()
                    || self.original_grant.is_some(),
                "completed independent enrollment lost its original grant"
            );
            ensure!(
                proposal.tenant == tenant
                    && Uuid::parse_str(&proposal.route.incarnation)? == self.incarnation,
                "enrollment proposal identity differs"
            );
        }
        ensure!(
            self.stage != Stage::Prepared || self.bootstrap_sha256.is_some(),
            "prepared tenant has no bootstrap binding"
        );
        if let Some(digest) = &self.bootstrap_sha256 {
            kasumi_types::validate_sha256(digest)?;
        }
        Ok(())
    }
    pub(crate) fn require_proposal(&self, proposal: &Proposal) -> Result<()> {
        self.validate(&proposal.tenant)?;
        let Origin::Control {
            proposal: original, ..
        } = &self.origin
        else {
            anyhow::bail!("genesis tenant cannot be recreated through live enrollment")
        };
        ensure!(
            original.digest()? == proposal.digest()?,
            "original tenant enrollment inputs conflict"
        );
        Ok(())
    }
}
pub(crate) fn tenant_record(store: &TenantStore, tenant: &str) -> Result<Option<TenantRecord>> {
    let Some(bytes) = store.get_bounded(NS, tenant_key(tenant)?.as_bytes(), MAX_INPUT)? else {
        return Ok(None);
    };
    let record: TenantRecord = serde_json::from_slice(&bytes)?;
    record.validate(tenant)?;
    Ok(Some(record))
}
impl Enrollment {
    pub(crate) fn record_genesis_tenant(
        &self,
        store: &TenantStore,
        tenant: &str,
        incarnation: Uuid,
        bootstrap_sha256: String,
    ) -> Result<()> {
        let record = TenantRecord {
            format: 1,
            tenant: tenant.into(),
            incarnation,
            origin: Origin::Genesis {
                input_sha256: self.head.input_sha256.clone(),
            },
            stage: Stage::Prepared,
            bootstrap_sha256: Some(bootstrap_sha256),
            original_grant: None,
        };
        record.validate(tenant)?;
        ensure!(
            tenant_record(store, tenant)?.is_none(),
            "genesis tenant enrollment already exists"
        );
        store.write_batch(&[WriteOp::put(
            NS,
            tenant_key(tenant)?.as_bytes(),
            serde_json::to_vec(&record)?,
        )])
    }
}
pub(crate) fn dispatch_tenant(
    store: &TenantStore,
    proposal: Proposal,
    request_id: String,
) -> Result<TenantRecord> {
    let record = TenantRecord {
        format: 1,
        tenant: proposal.tenant.clone(),
        incarnation: Uuid::parse_str(&proposal.route.incarnation)?,
        origin: Origin::Control {
            proposal: Box::new(proposal),
            creation_id: Uuid::new_v4(),
            request_id,
        },
        stage: Stage::CreationDispatched,
        bootstrap_sha256: None,
        original_grant: None,
    };
    record.validate(&record.tenant)?;
    ensure!(
        tenant_record(store, &record.tenant)?.is_none(),
        "tenant enrollment has already been dispatched"
    );
    store.write_batch(&[WriteOp::put(
        NS,
        tenant_key(&record.tenant)?.as_bytes(),
        serde_json::to_vec(&record)?,
    )])?;
    Ok(record)
}
pub(crate) fn update_tenant(
    store: &TenantStore,
    before: &TenantRecord,
    after: &TenantRecord,
) -> Result<()> {
    before.validate(&before.tenant)?;
    after.validate(&before.tenant)?;
    ensure!(
        serde_json::to_vec(
            &tenant_record(store, &before.tenant)?.context("tenant dispatch disappeared")?
        )? == serde_json::to_vec(before)?,
        "tenant enrollment changed during dispatch"
    );
    ensure!(
        serde_json::to_vec(&before.origin)? == serde_json::to_vec(&after.origin)?
            && before.incarnation == after.incarnation,
        "tenant enrollment cannot replace its original identity or inputs"
    );
    ensure!(
        before.stage == Stage::CreationDispatched
            && (after.stage == Stage::CreationDispatched || after.stage == Stage::Prepared),
        "tenant enrollment outcome is permanent"
    );
    ensure!(
        before.original_grant.is_none()
            || serde_json::to_vec(&before.original_grant)?
                == serde_json::to_vec(&after.original_grant)?,
        "tenant enrollment cannot replace its original grant"
    );
    store.write_batch(&[WriteOp::put(
        NS,
        tenant_key(&before.tenant)?.as_bytes(),
        serde_json::to_vec(after)?,
    )])
}
