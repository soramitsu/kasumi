//! Canonical first installation and read-only authenticated restart inputs.
use crate::{AuthorityBootstrap, AuthorityInstallation};
use anyhow::{Context, Result, ensure};
use kasumi_serving::{SigningCertificateVerification, TrustVerifierIdentity};
use kasumi_store::{TenantStorageSet, WriteOp};
use serde::{Deserialize, Serialize};

const NS: &str = "authority.installation";
const MAX_DESCRIPTOR_BYTES: usize = 256 << 10;

#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum Descriptor {
    Replicated {
        installation: AuthorityInstallation,
        bootstrap: AuthorityBootstrap,
    },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum LocalBinding {
    AuthorityMember { verifier: TrustVerifierIdentity },
}

pub(crate) struct Installed {
    pub bootstrap: AuthorityBootstrap,
    pub binding: Vec<u8>,
    pub resource_floor: u64,
}

fn validate(installation: &AuthorityInstallation, bootstrap: &AuthorityBootstrap) -> Result<()> {
    installation.validate()?;
    bootstrap.validate()?;
    bootstrap.initial_signer_certificate.verify(
        &installation
            .manifest
            .signing_domain(installation.partition)?,
    )?;
    Ok(())
}

pub(crate) fn initialize(
    stores: &TenantStorageSet,
    installation: &AuthorityInstallation,
    bootstrap: &AuthorityBootstrap,
    verifier: &TrustVerifierIdentity,
) -> Result<()> {
    validate(installation, bootstrap)?;
    verifier.validate()?;
    if let Some(member) = bootstrap.membership.members.get(&verifier.node_id) {
        ensure!(
            &member.verifier == verifier,
            "initial authority member physical verifier differs"
        );
    }
    let genesis =
        crate::state::Backend::initial_state(stores.application(), installation, bootstrap)?;
    let binding = serde_json::to_vec(&Descriptor::Replicated {
        installation: installation.clone(),
        bootstrap: bootstrap.clone(),
    })?;
    ensure!(
        binding.len() <= MAX_DESCRIPTOR_BYTES,
        "authority installation descriptor exceeds budget"
    );
    let local = serde_json::to_vec(&LocalBinding::AuthorityMember {
        verifier: verifier.clone(),
    })?;
    let binding = WriteOp::put(NS, b"binding", binding);
    let local = WriteOp::put(NS, b"local-member", local);
    let floor = WriteOp::put(
        NS,
        b"resource-floor",
        serde_json::to_vec(&bootstrap.capacity.max_state_bytes)?,
    );
    let group = &installation.manifest.partitions[&installation.partition].group;
    let [node, group] = kasumi_raft::initial_storage_identity(verifier.node_id, group)?;
    stores.initialize_state(
        &[binding.clone(), local.clone(), floor, genesis],
        &[binding, local, node, group],
    )
}

pub(crate) fn decode_resource_floor(bytes: &[u8]) -> Result<u64> {
    let floor = serde_json::from_slice::<u64>(bytes)?;
    ensure!(
        serde_json::to_vec(&floor)? == bytes,
        "noncanonical authority resource floor"
    );
    Ok(floor)
}

pub(crate) fn load(
    stores: &TenantStorageSet,
    installation: &AuthorityInstallation,
    verifier: &TrustVerifierIdentity,
) -> Result<Installed> {
    installation.validate()?;
    verifier.validate()?;
    let read_pair = |key: &[u8], limit| -> Result<Vec<u8>> {
        let app = stores
            .application()
            .get_bounded(NS, key, limit)?
            .context("authority installation record absent")?;
        let custody = stores
            .custody()
            .store()
            .get_bounded(NS, key, limit)?
            .context("authority custody installation record absent")?;
        ensure!(
            app == custody,
            "authority application/custody installation records differ"
        );
        Ok(app)
    };
    let binding = read_pair(b"binding", MAX_DESCRIPTOR_BYTES)?;
    let descriptor: Descriptor = serde_json::from_slice(&binding)?;
    ensure!(
        serde_json::to_vec(&descriptor)? == binding,
        "noncanonical authority installation descriptor"
    );
    let Descriptor::Replicated {
        installation: saved,
        bootstrap,
    } = descriptor;
    ensure!(
        saved == *installation,
        "authority immutable installation differs"
    );
    validate(&saved, &bootstrap)?;
    let local = read_pair(b"local-member", 4096)?;
    let local_binding: LocalBinding = serde_json::from_slice(&local)?;
    ensure!(
        serde_json::to_vec(&local_binding)? == local,
        "noncanonical authority local member"
    );
    let LocalBinding::AuthorityMember { verifier: saved } = local_binding;
    ensure!(
        saved == *verifier,
        "authority storage cannot reopen under another member identity"
    );
    let floor_bytes = stores
        .application()
        .get_bounded(NS, b"resource-floor", 32)?
        .context("authority resource floor absent")?;
    let resource_floor = decode_resource_floor(&floor_bytes)?;
    ensure!(
        resource_floor >= bootstrap.capacity.max_state_bytes,
        "authority resource floor is below installed genesis"
    );
    let group = &installation.manifest.partitions[&installation.partition].group;
    kasumi_raft::ControlLog::open(stores.custody().clone(), verifier.node_id, group.clone())?;
    Ok(Installed {
        bootstrap,
        binding,
        resource_floor,
    })
}
