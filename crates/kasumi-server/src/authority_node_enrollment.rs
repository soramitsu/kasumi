//! Explicit local authority installation. This owns all resources to terminal
//! drain even if the initiating CLI drops its result; normal startup is strict.
use crate::{
    authority_runtime::AuthorityRuntimeConfig,
    node_enrollment::{Enrollment, Input},
};
use anyhow::{Result, ensure};
use kasumi_authority::IndependentAuthority;
use kasumi_store::{StorageAccess, TenantStorageSet};
use std::sync::Arc;

pub(crate) async fn initialize(config: AuthorityRuntimeConfig) -> Result<()> {
    config.validate()?;
    config.bootstrap.validate()?;
    ensure!(
        config.replication.voters()? == config.bootstrap.membership.voters,
        "authority first enrollment requires its exact original voters"
    );
    // The detached owner has only a unit result: resources are explicitly drained
    // before completion, so a lost successful CLI reply cannot lose live scopes.
    tokio::spawn(async move {
        let admission = kasumi_engine::admission::NodeAdmission::new(config.admission.clone())?;
        let (node, audit) = crate::node_provision::create(
            &config.database_path,
            config.database_id,
            &config.scratch_disk,
            &config.security_audit,
            admission.clone(),
        )
        .await?;
        let credential: crate::serving_runtime::CredentialSource =
            Arc::new(crate::runtime::file_secret);
        let mut pair = None;
        let mut verifier = None;
        let result = async {
            let enrollment = Enrollment::begin(
                audit.store(),
                &Input::Authority {
                    configuration: Box::new(config.clone()),
                },
            )?;
            let domain = config
                .installation
                .manifest
                .signing_domain(config.installation.partition)?;
            let installed = config
                .signer_verifier
                .open(
                    std::collections::BTreeMap::from([(domain.digest()?, domain.clone())]),
                    credential.clone(),
                    node.scratch_disk().clone(),
                    admission.clone(),
                )
                .await?;
            verifier = Some(installed.clone());
            // Validate the actual installed current signer/trust pair before any
            // authority domain effects; do not initialize the verifier here.
            let _signer = crate::signer_runtime::OperationalSignerConfig::load(
                &config.operational_signer_file,
                &domain,
            )?
            .open(&installed)?;
            let stores = TenantStorageSet::initialize_catalogs(
                node.clone(),
                config.installation.tenant(),
                config.keys.provider(credential.clone())?,
                config.custody_keys.provider(credential)?,
                StorageAccess::independent_authority(
                    &config.installation.manifest,
                    config.installation.partition,
                )?,
            )
            .await?;
            pair = Some(stores.clone());
            let installation = config.installation.clone();
            let bootstrap = config.bootstrap.clone();
            let physical = config.signer_verifier.identity.clone();
            tokio::task::spawn_blocking(move || {
                IndependentAuthority::initialize_storage(
                    &stores,
                    &installation,
                    &bootstrap,
                    &physical,
                )
            })
            .await??;
            enrollment.complete(audit.store())
        }
        .await;
        let mut report = kasumi_types::drain::DrainReport::default();
        if let Some(stores) = pair {
            if let Err(failure) = stores.shutdown().await {
                report.merge(&failure);
            }
        }
        if let Err(error) = node.drain_initializers().await {
            report.record("authority enrollment initializers", 0, error);
        }
        if let Some(verifier) = verifier {
            if let Err(failure) = verifier.shutdown().await {
                report.merge(&failure);
            }
        }
        if let Err(failure) = audit.shutdown().await {
            report.merge(&failure);
        }
        drop(audit);
        drop(node);
        match (result, report.complete()) {
            (Ok(()), close) => close.map_err(Into::into),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(failure)) => Err(error.context(failure)),
        }
    })
    .await?
}
