//! Explicit local authority installation. This owns all resources to terminal
//! drain even if the initiating CLI drops its result; normal startup is strict.
use crate::authority_enrollment_terminal::{
    Body, BodyOutcome, EnrollmentFailure, EnrollmentTerminal, EnrollmentTerminalFacade, Genesis,
};
use crate::{
    authority_runtime::AuthorityRuntimeConfig,
    node_enrollment::{Enrollment, Input},
};
use anyhow::{Result, ensure};
use kasumi_authority::IndependentAuthority;
use kasumi_store::{StorageAccess, TenantStorageSet};
use std::sync::Arc;

pub(crate) async fn initialize(
    config: AuthorityRuntimeConfig,
) -> std::result::Result<(), EnrollmentFailure> {
    config.validate()?;
    config.bootstrap.validate()?;
    (|| -> Result<()> {
        ensure!(
            config.replication.voters()? == config.bootstrap.membership.voters,
            "authority first enrollment requires its exact original voters"
        );
        Ok(())
    })()?;
    let storage = crate::runtime_memory::RuntimeStorage::installed(&config.admission)?;
    initialize_with_storage(config, storage).await
}

pub(crate) async fn initialize_with_storage(
    config: AuthorityRuntimeConfig,
    storage: crate::runtime_memory::RuntimeStorage,
) -> std::result::Result<(), EnrollmentFailure> {
    config.validate()?;
    config.bootstrap.validate()?;
    (|| -> Result<()> {
        ensure!(
            config.replication.voters()? == config.bootstrap.membership.voters,
            "authority first enrollment requires its exact original voters"
        );
        Ok(())
    })()?;
    storage.require_policy(&config.admission)?;
    let admission = storage.facade(&config.admission)?;
    let participant = crate::authority_runtime::AuthorityParticipantName::new(
        config.installation.manifest.authority_id,
        config.installation.partition,
    );
    let terminal = crate::administration::OriginalRecoveries::prepare_authority_enrollment(
        &admission,
        crate::administration::OriginalRecoveryParticipants::one(participant.as_str()),
        config.database_id,
    )?;
    let loan = match terminal.begin() {
        Ok(loan) => loan,
        Err(_) => {
            return Err(EnrollmentFailure::Retained(EnrollmentTerminalFacade {
                terminal,
            }));
        }
    };
    // The gate and both actual terminal controls precede the named owned
    // future. Its exact worker is installed synchronously before any await.
    let terminal = loan.spawn(run_enrollment, (config, storage, admission));
    EnrollmentTerminalFacade { terminal }.claim().await
}

#[allow(
    clippy::manual_async_fn,
    reason = "the named producer signature exposes the exact future type used by its prospective backing quote"
)]
fn initialize_body<'a>(
    config: &'a AuthorityRuntimeConfig,
    storage: &'a crate::runtime_memory::RuntimeStorage,
    admission: Arc<kasumi_engine::admission::NodeAdmission>,
    originals: &'a crate::administration::OriginalRecoveries,
    pending: &'a mut crate::startup_resources::Resources,
    genesis: &'a mut Genesis,
) -> impl std::future::Future<Output = Result<BodyOutcome>> + Send + 'a {
    async move {
        pending.owned_admissions.push(admission.clone());
        pending.signer_original_recoveries =
            Some(config.signer_verifier.node_start_inventory(&admission)?);
        let (node, audit) = crate::node_provision::create(
            &config.database_path,
            config.database_id,
            &config.persistent_disk,
            &config.scratch_disk,
            &config.security_audit,
            admission.clone(),
            storage,
            originals,
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
                pending
                    .signer_original_recoveries
                    .as_ref()
                    .expect("same installed authority enrollment verifier inventory"),
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
        genesis.handle = Some(tokio::task::spawn_blocking(move || {
            #[cfg(test)]
            tests::blocking_checkpoint(database_id);
            IndependentAuthority::initialize_storage(&stores, &installation, &bootstrap, &physical)
        }));
        #[cfg(test)]
        crate::startup_preparation::checkpoint(
            config.database_id,
            "authority-enrollment-genesis-dispatched",
        );
        if !genesis.join().await {
            return Ok(BodyOutcome::GenesisRejected);
        }
        #[cfg(test)]
        crate::startup_preparation::checkpoint(config.database_id, "authority-enrollment-genesis");
        enrollment.complete(audit.store())?;
        #[cfg(test)]
        crate::startup_preparation::checkpoint(config.database_id, "authority-enrollment-complete");
        Ok(BodyOutcome::Completed)
    }
}

pub(crate) fn body_backing() -> Result<kasumi_engine::admission::startup::StartupBacking> {
    fn quote<F: std::future::Future>(
        _: impl FnOnce(
            &'static AuthorityRuntimeConfig,
            &'static crate::runtime_memory::RuntimeStorage,
            Arc<kasumi_engine::admission::NodeAdmission>,
            &'static crate::administration::OriginalRecoveries,
            &'static mut crate::startup_resources::Resources,
            &'static mut Genesis,
        ) -> F,
    ) -> Result<kasumi_engine::admission::startup::StartupBacking> {
        kasumi_engine::admission::startup::StartupBacking::empty().boxed::<F>()
    }
    // Pure type quotation: the constructor function is never invoked here.
    quote(initialize_body)
}

async fn run_enrollment(
    mut terminal: kasumi_engine::admission::startup::StartupTerminalLoan<EnrollmentTerminal>,
    (config, storage, admission): (
        AuthorityRuntimeConfig,
        crate::runtime_memory::RuntimeStorage,
        Arc<kasumi_engine::admission::NodeAdmission>,
    ),
) {
    let parents = terminal
        .parents
        .as_ref()
        .expect("same initial enrollment parent")
        .clone();
    {
        let EnrollmentTerminal {
            pending,
            genesis,
            body,
            original,
            ..
        } = &mut *terminal;
        Body::new(
            initialize_body(
                &config,
                &storage,
                admission,
                &parents,
                pending.as_mut().expect("preinstalled whole resources"),
                genesis,
            ),
            body,
            original,
        )
        .await;
    }
    #[cfg(test)]
    if terminal.original.is_some() || terminal.body.panic.is_some() {
        crate::startup_preparation::failure_checkpoint(config.database_id).await;
    }
    if terminal.genesis.handle.is_some() {
        #[cfg(test)]
        tests::joining_checkpoint(config.database_id);
        terminal.genesis.join().await;
    }
    // One actual cleanup attempt. Retained ownership is a delivered typed
    // rejection; it never becomes permission to retry enrollment or refund.
    crate::authority_enrollment_terminal::cleanup(&mut terminal).await;
    terminal.ready = true;
}

#[cfg(test)]
#[path = "authority_node_enrollment_tests.rs"]
mod tests;
