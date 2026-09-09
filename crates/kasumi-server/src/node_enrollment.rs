//! Explicit node enrollment records. Normal startup only verifies completed input;
//! it never repairs a partial installation or reacquires a grant to finish one.
use anyhow::{Context, Result, ensure};
use kasumi_store::{NodeStore, TenantStore, WriteOp};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

const NS: &str = "node.enrollment";
const MAX_INPUT: usize = 2 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Kind {
    Data,
    Authority,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Input {
    Data {
        configuration: Box<crate::runtime::RuntimeConfig>,
    },
    Authority {
        configuration: Box<crate::authority_runtime::AuthorityRuntimeConfig>,
    },
}
impl Input {
    fn identity(&self) -> (Kind, Uuid) {
        match self {
            Self::Data { configuration } => (Kind::Data, configuration.database_id),
            Self::Authority { configuration } => (Kind::Authority, configuration.database_id),
        }
    }
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Head {
    format: u32,
    kind: Kind,
    database_id: Uuid,
    input_sha256: String,
    complete: bool,
}

pub(crate) struct Enrollment {
    head: Head,
}
impl Enrollment {
    pub(crate) fn begin(store: &Arc<TenantStore>, input: &Input) -> Result<Self> {
        let bytes = serde_json::to_vec(input)?;
        ensure!(
            bytes.len() <= MAX_INPUT,
            "node enrollment input exceeds limit"
        );
        let (kind, database_id) = input.identity();
        ensure!(!database_id.is_nil(), "nil node enrollment identity");
        store.read_view()?.visit(NS, MAX_INPUT, |_, _| {
            anyhow::bail!("node enrollment has already begun")
        })?;
        let head = Head {
            format: 1,
            kind,
            database_id,
            input_sha256: hex::encode(Sha256::digest(&bytes)),
            complete: false,
        };
        store.write_batch(&[
            WriteOp::put(NS, b"input", bytes),
            WriteOp::put(NS, b"head", serde_json::to_vec(&head)?),
        ])?;
        Ok(Self { head })
    }
    pub(crate) fn record_grant(
        &self,
        store: &TenantStore,
        grant: &kasumi_serving::VerifiedLease,
    ) -> Result<()> {
        grant.check()?;
        let tenant = &grant.identity().tenant;
        let key = format!("grant/{tenant}");
        ensure!(
            store.get_bounded(NS, key.as_bytes(), 64 << 10)?.is_none(),
            "enrollment cannot replace its original serving grant"
        );
        let bytes = serde_json::to_vec(grant.signed())?;
        ensure!(
            bytes.len() <= 64 << 10,
            "enrollment grant exceeds record limit"
        );
        store.write_batch(&[WriteOp::put(NS, key.into_bytes(), bytes)])?;
        grant.check()
    }
    pub(crate) fn complete(self, store: &TenantStore) -> Result<()> {
        let retained: Head = serde_json::from_slice(
            &store
                .get_bounded(NS, b"head", 4096)?
                .context("node enrollment head absent")?,
        )?;
        ensure!(
            retained == self.head,
            "node enrollment input or outcome changed"
        );
        let input = store
            .get_bounded(NS, b"input", MAX_INPUT)?
            .context("node enrollment input absent")?;
        ensure!(
            hex::encode(Sha256::digest(&input)) == self.head.input_sha256,
            "node enrollment input changed"
        );
        let mut head = self.head;
        head.complete = true;
        store.write_batch(&[WriteOp::put(NS, b"head", serde_json::to_vec(&head)?)])
    }
}

pub(crate) fn require_complete(
    store: &Arc<TenantStore>,
    database_id: Uuid,
    kind: Kind,
) -> Result<()> {
    let view = store.read_view()?;
    let head: Head =
        serde_json::from_slice(&view.get(NS, b"head", 4096)?.context(
            "node enrollment is absent or incomplete; explicit provisioning is required",
        )?)?;
    ensure!(
        head.format == 1
            && head.complete
            && head.database_id == database_id
            && !database_id.is_nil()
            && head.kind == kind,
        "node enrollment identity or outcome differs"
    );
    let bytes = view
        .get(NS, b"input", MAX_INPUT)?
        .context("node enrollment input absent")?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == head.input_sha256,
        "node enrollment input digest differs"
    );
    let input: Input = serde_json::from_slice(&bytes)?;
    ensure!(
        input.identity() == (kind, database_id),
        "node enrollment input identity differs"
    );
    Ok(())
}

/// Reopen only the node and audit just created by the explicit one-shot operation.
/// This helper is private; a normal daemon cannot use it to complete a partial node.
pub(crate) async fn audit_after_creation(
    path: &std::path::Path,
    database_id: Uuid,
    scratch: &kasumi_store::ScratchDiskConfig,
    security: &crate::runtime::SecurityAuditConfig,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
    credential: crate::serving_runtime::CredentialSource,
) -> Result<(Arc<NodeStore>, Arc<kasumi_engine::SecurityAudit>)> {
    let node = NodeStore::open_existing(
        path,
        database_id,
        kasumi_store::ScratchDisk::open(scratch.clone())?,
    )?;
    let store = TenantStore::open_existing(
        node.clone(),
        kasumi_engine::SECURITY_TENANT.into(),
        security.keys.provider(credential)?,
        kasumi_store::StorageAccess::security_audit(),
    )
    .await?;
    match security.open(store.clone(), admission) {
        Ok(audit) => Ok((node, audit)),
        Err(error) => {
            store.shutdown().await;
            Err(error)
        }
    }
}

#[cfg(test)]
#[path = "node_enrollment_tests.rs"]
mod tests;
