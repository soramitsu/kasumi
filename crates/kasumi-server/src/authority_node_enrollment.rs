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
    crate::startup_owner::open(
        crate::startup_owner::Kind::Authority,
        initialize_owned(config),
    )
    .await?;
    Ok(())
}

// Only an actually drained outcome may cross the acknowledged startup handoff.
struct Enrolled;
impl crate::startup_owner::Runtime for Enrolled {
    fn close(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = kasumi_types::drain::DrainResult> + Send + '_>,
    > {
        Box::pin(async { Ok(()) })
    }
}

async fn initialize_owned(config: AuthorityRuntimeConfig) -> Result<Enrolled> {
    let mut pending = crate::startup_resources::Resources::default();
    // Keep a dispatched blocking child outside the caught future too. An unwind
    // after dispatch cannot replace its exact join with a storage-close guess.
    let mut genesis = None;
    let result = crate::startup_preparation::capture("authority enrollment", async {
        let admission = kasumi_engine::admission::NodeAdmission::new(config.admission.clone())?;
        let (node, audit) = crate::node_provision::create(
            &config.database_path,
            config.database_id,
            &config.persistent_disk,
            &config.scratch_disk,
            &config.security_audit,
            admission.clone(),
        )
        .await?;
        pending.owned_nodes.push(node.clone());
        pending.audits.push(audit.clone());
        #[cfg(test)]
        crate::startup_preparation::checkpoint(config.database_id, "authority-enrollment-node");
        let credential: crate::serving_runtime::CredentialSource =
            Arc::new(crate::runtime::file_secret);
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
                node.persistent_disk().clone(),
                node.scratch_disk().clone(),
                admission.clone(),
            )
            .await?;
        pending.verifiers.push(installed.clone());
        #[cfg(test)]
        crate::startup_preparation::checkpoint(config.database_id, "authority-enrollment-verifier");
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
        pending.stores.push(stores.application().clone());
        pending.stores.push(stores.custody().store().clone());
        #[cfg(test)]
        crate::startup_preparation::checkpoint(config.database_id, "authority-enrollment-pair");
        let installation = config.installation.clone();
        let bootstrap = config.bootstrap.clone();
        let physical = config.signer_verifier.identity.clone();
        #[cfg(test)]
        let database_id = config.database_id;
        genesis = Some(tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            tests::blocking_checkpoint(database_id);
            IndependentAuthority::initialize_storage(&stores, &installation, &bootstrap, &physical)
        }));
        #[cfg(test)]
        crate::startup_preparation::checkpoint(
            config.database_id,
            "authority-enrollment-genesis-dispatched",
        );
        let created = genesis.as_mut().expect("genesis child was installed").await;
        genesis.take();
        created??;
        #[cfg(test)]
        crate::startup_preparation::checkpoint(config.database_id, "authority-enrollment-genesis");
        enrollment.complete(audit.store())?;
        #[cfg(test)]
        crate::startup_preparation::checkpoint(config.database_id, "authority-enrollment-complete");
        Ok(())
    })
    .await;
    #[cfg(test)]
    if result.is_err() {
        crate::startup_preparation::failure_checkpoint(config.database_id).await;
    }
    let mut report = kasumi_types::drain::DrainReport::default();
    if let Some(child) = genesis.as_mut() {
        #[cfg(test)]
        tests::joining_checkpoint(config.database_id);
        match child.await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                report.record("authority enrollment genesis", 0, error);
            }
            Err(error) => {
                report.record("authority enrollment genesis", 0, error.into());
            }
        }
        genesis.take();
    }
    if let Err(error) = crate::startup_owner::finish(&mut pending).await {
        report.merge(&error);
    }
    match (result, report.complete()) {
        (Ok(()), Ok(())) => Ok(Enrolled),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(drain)) => Err(drain.into()),
        (Err(error), Err(drain)) => Err(error.context(drain)),
    }
}

#[cfg(test)]
#[path = "authority_node_enrollment_tests.rs"]
mod tests;
