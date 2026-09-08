//! Local operator commands. Bearer material is written only to private files.
use crate::standalone::{ClientProfile, initialize};
use anyhow::{Context, Result, ensure};
use kasumi_store::private_files;
use std::path::Path;
use uuid::Uuid;

pub async fn command(arguments: &[String]) -> Result<bool> {
    match arguments {
        [command, configuration, output] if command == "recover-administrator" => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &crate::standalone::recover_administrator(
                        Path::new(configuration),
                        Path::new(output)
                    )
                    .await?
                )?
            );
        }
        [command, configuration, output] if command == "backup-operator-keys" => {
            crate::standalone::backup_operator_keys(Path::new(configuration), Path::new(output))
                .await?;
            println!("Operator keys copied to private backup directory.");
        }
        [command, action, configuration] if command == "maintenance" => match action.as_str() {
            "rotate-wrapping-keys" => {
                crate::standalone::rotate_wrapping_keys(Path::new(configuration)).await?;
                println!(
                    "Wrapping keys rotated; previous generations retained and catalogs rewrapped."
                );
            }
            "rotate-signer" => {
                println!(
                    "{}",
                    serde_json::json!({"generation":crate::standalone::rotate_signing_key(Path::new(configuration)).await?})
                );
            }
            "rotate-certificates" => {
                println!(
                    "{}",
                    crate::standalone::rotate_certificates(Path::new(configuration)).await?
                );
            }
            _ => anyhow::bail!("unknown maintenance operation"),
        },
        [command, mode_flag, mode, directory]
            if command == "init" && mode_flag == "--mode" && mode == "standalone" =>
        {
            println!(
                "{}",
                serde_json::to_string_pretty(&initialize(Path::new(directory), "default").await?)?
            );
        }
        [command, mode_flag, mode, directory, tenant_flag, tenant]
            if command == "init"
                && mode_flag == "--mode"
                && mode == "standalone"
                && tenant_flag == "--tenant" =>
        {
            println!(
                "{}",
                serde_json::to_string_pretty(&initialize(Path::new(directory), tenant).await?)?
            );
        }
        [command, action, path]
            if command == "credential" && (action == "renew" || action == "watch") =>
        {
            let profile = ClientProfile::load(Path::new(path))?;
            let _lock = private_files::ExclusiveLock::acquire(
                &profile.bearer_file.with_extension("watch.lock"),
            )?;
            loop {
                match renew(&profile).await {
                    Ok(expiry) => {
                        if action == "renew" {
                            println!(
                                "{}",
                                serde_json::json!({"family_id":profile.family_id,"expires_at_ms":expiry})
                            );
                            break;
                        }
                        let now = kasumi_clock::EpochClock::system()?.now_ms()?;
                        let delay = expiry.saturating_sub(now).saturating_mul(2) / 3;
                        tokio::select! { _ = tokio::time::sleep(std::time::Duration::from_millis(delay.max(1000))) => {}, _ = tokio::signal::ctrl_c() => break }
                    }
                    Err(error) if action == "watch" && retryable(&error) => {
                        tracing::warn!(
                            "credential renewal unavailable; retaining original renewal identity"
                        );
                        tokio::select! { _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}, _ = tokio::signal::ctrl_c() => break }
                    }
                    Err(error) => return Err(error),
                }
            }
        }
        [command, action, profile_path, request_path, output_path]
            if command == "credential" && action == "create" =>
        {
            let profile = ClientProfile::load(Path::new(profile_path))?;
            let request: kasumi_types::CreateCredential = serde_json::from_slice(
                &crate::runtime::read_bounded(Path::new(request_path), 128 << 10)?,
            )?;
            request.validate()?;
            let output = Path::new(output_path);
            ensure!(
                output.is_absolute(),
                "output client profile path must be absolute"
            );
            private_files::check_directory(output.parent().context("profile has no parent")?)?;
            let _lock =
                private_files::ExclusiveLock::acquire(&output.with_extension("create.lock"))?;
            let journal = output.with_extension("create.json");
            if output.exists() {
                let existing = ClientProfile::load(output)?;
                ensure!(
                    existing.family_id == request.family_id
                        && existing.tenant == request.tenant
                        && existing.resource == request.resource
                        && existing.bearer_file == output.with_extension("token"),
                    "output profile belongs to another credential"
                );
            } else {
                ensure!(
                    !output.with_extension("token").exists() || journal.exists(),
                    "existing token has no matching creation journal"
                );
            }
            if journal.exists() {
                let original: kasumi_types::CreateCredential =
                    serde_json::from_slice(&private_files::read(&journal, 128 << 10)?)?;
                ensure!(
                    original == request,
                    "credential creation differs from original attempt"
                );
            } else {
                private_files::create(&journal, &serde_json::to_vec(&request)?)?;
            }
            let mut client =
                kasumi_client::KasumiAdminClient::connect(&profile.connection(true)?).await?;
            let issued = client
                .create_credential(&profile.bearer()?, &request)
                .await?;
            let bearer_file = output.with_extension("token");
            private_files::replace(&bearer_file, issued.token.as_bytes())?;
            let created = ClientProfile {
                family_id: issued.family_id,
                tenant: request.tenant,
                resource: request.resource,
                bearer_file,
                ..profile
            };
            private_files::replace(output, &serde_json::to_vec_pretty(&created)?)?;
            std::fs::remove_file(&journal)?;
            private_files::sync_parent(&journal)?;
            println!(
                "{}",
                serde_json::json!({"profile":output,"family_id":issued.family_id,"expires_at_ms":issued.expires_at_ms})
            );
        }
        [command, action, profile_path, family]
            if command == "credential" && (action == "status" || action == "revoke") =>
        {
            let profile = ClientProfile::load(Path::new(profile_path))?;
            let reference = kasumi_types::CredentialReference {
                family_id: Uuid::parse_str(family)?,
            };
            let mut client =
                kasumi_client::KasumiAdminClient::connect(&profile.connection(true)?).await?;
            let bearer = profile.bearer()?;
            let status = if action == "status" {
                client.credential_status(&bearer, &reference).await?
            } else {
                client.revoke_credential(&bearer, &reference).await?
            };
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn retryable(error: &anyhow::Error) -> bool {
    match error.downcast_ref::<kasumi_client::ClientError>() {
        Some(kasumi_client::ClientError::Connection(_)) => true,
        Some(kasumi_client::ClientError::Transport(status)) => matches!(
            status.code(),
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded | tonic::Code::Unknown
        ),
        _ => false,
    }
}

/// Persist the renewal identity before dispatch, and keep it through any
/// uncertain result. Crashing after token replacement can only replay the same
/// issuance; it cannot extend an already admitted request's deadline.
async fn renew(profile: &ClientProfile) -> Result<u64> {
    let journal = profile.bearer_file.with_extension("renewal.json");
    let request: kasumi_types::RenewCredential = if journal.exists() {
        serde_json::from_slice(&private_files::read(&journal, 4096)?)?
    } else {
        let request = kasumi_types::RenewCredential {
            family_id: profile.family_id,
            renewal_id: Uuid::new_v4(),
        };
        private_files::create(&journal, &serde_json::to_vec(&request)?)?;
        request
    };
    ensure!(
        request.family_id == profile.family_id,
        "renewal journal belongs to another credential"
    );
    let mut client = kasumi_client::KasumiAdminClient::connect(&profile.connection(true)?).await?;
    let issued = client
        .renew_credential(&profile.bearer()?, &request)
        .await?;
    ensure!(
        issued.family_id == profile.family_id,
        "renewed credential family differs"
    );
    private_files::replace(&profile.bearer_file, issued.token.as_bytes())?;
    std::fs::remove_file(&journal)?;
    private_files::sync_parent(&journal)?;
    Ok(issued.expires_at_ms)
}
