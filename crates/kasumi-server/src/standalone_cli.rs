//! Local operator commands. Bearer material is written only to private files.
use crate::standalone::{ClientProfile, StandaloneNetwork, initialize};
use anyhow::{Context, Result, ensure};
use kasumi_store::private_files;
use std::path::Path;
use uuid::Uuid;

pub async fn command(arguments: &[String]) -> Result<bool> {
    if crate::recovery_cli::command(arguments).await? {
        return Ok(true);
    }
    if crate::backup_cli::command(arguments).await? {
        return Ok(true);
    }
    if crate::audit_cli::command(arguments).await? {
        return Ok(true);
    }
    match arguments {
        [command, action, configuration, input] if command == "tenant" => {
            let result = match action.as_str() {
                "stage" => {
                    let request: crate::standalone::StageTenantRequest = serde_json::from_slice(
                        &crate::runtime::read_bounded(Path::new(input), 2 << 20)?,
                    )?;
                    crate::standalone::stage_tenant(Path::new(configuration), request).await?
                }
                "stage-status" => {
                    crate::standalone::tenant_stage_status(
                        Path::new(configuration),
                        Uuid::parse_str(input)?,
                    )
                    .await?
                }
                _ => anyhow::bail!("unknown tenant staging operation"),
            };
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        [command, configuration] if command == "initialize-target-journal" => {
            crate::target_journal_installation::initialize_from_file(Path::new(configuration))
                .await?;
            println!(
                "Target journal initialized; normal startup now requires this installed journal."
            );
        }
        [command, configuration] if command == "initialize-signer-verifier" => {
            crate::signer_runtime::initialize_from_file(Path::new(configuration)).await?;
            println!("Signer verifier initialized; installation roots remain operator-held.");
        }
        [command, action, configuration, input] if command == "local-recovery" => {
            let configuration = Path::new(configuration);
            let status = match action.as_str() {
                "start" => {
                    let request: crate::local_recovery::LocalRecoveryStart =
                        serde_json::from_slice(&crate::runtime::read_bounded(
                            Path::new(input),
                            2 << 20,
                        )?)?;
                    let operation = request.operation_id;
                    crate::local_recovery::start(configuration, request).await?;
                    crate::local_recovery::resume(configuration, operation).await?
                }
                "status" => {
                    crate::local_recovery::status(configuration, Uuid::parse_str(input)?).await?
                }
                "resume" => {
                    crate::local_recovery::resume(configuration, Uuid::parse_str(input)?).await?
                }
                "stop" => {
                    crate::local_recovery::stop(configuration, Uuid::parse_str(input)?).await?
                }
                _ => anyhow::bail!("unknown local recovery operation"),
            };
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
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
        [command, directory] if command == "verify-operator-keys" => {
            println!(
                "{}",
                serde_json::to_string_pretty(&crate::standalone_key_backup::verify(Path::new(
                    directory
                ))?)?
            );
        }
        [command, configuration, output] if command == "backup-operator-keys" => {
            crate::standalone::backup_operator_keys(Path::new(configuration), Path::new(output))
                .await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&crate::standalone_key_backup::verify(Path::new(
                    output
                ))?)?
            );
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
        [
            command,
            mode_flag,
            mode,
            directory,
            policy_flag,
            policy,
            network_flag,
            network,
        ] if command == "init"
            && mode_flag == "--mode"
            && mode == "standalone"
            && policy_flag == "--directory-policy"
            && network_flag == "--network" =>
        {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &initialize(
                        Path::new(directory),
                        "default",
                        directory_policy(Path::new(policy))?,
                        standalone_network(Path::new(network))?
                    )
                    .await?
                )?
            );
        }
        [
            command,
            mode_flag,
            mode,
            directory,
            policy_flag,
            policy,
            network_flag,
            network,
            tenant_flag,
            tenant,
        ] if command == "init"
            && mode_flag == "--mode"
            && mode == "standalone"
            && policy_flag == "--directory-policy"
            && network_flag == "--network"
            && tenant_flag == "--tenant" =>
        {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &initialize(
                        Path::new(directory),
                        tenant,
                        directory_policy(Path::new(policy))?,
                        standalone_network(Path::new(network))?
                    )
                    .await?
                )?
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
                principal: request.principal,
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

/// Load the caller's explicit namespace bounds before any installation work.
/// Numeric validity does not replace qualification of the selected filesystem.
pub fn directory_policy(path: &Path) -> Result<kasumi_store::DirectoryPolicy> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(4097)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 4096, "directory policy exceeds size limit");
    let policy: kasumi_store::DirectoryPolicy = serde_json::from_slice(&bytes)?;
    policy.validate()?;
    Ok(policy)
}

/// Read the complete selected loopback identity before creating installation files.
pub fn standalone_network(path: &Path) -> Result<StandaloneNetwork> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(4097)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 4096, "standalone network exceeds size limit");
    let network: StandaloneNetwork = serde_json::from_slice(&bytes)?;
    network.validate()?;
    Ok(network)
}

#[cfg(test)]
mod standalone_network_tests {
    use super::*;

    #[test]
    fn explicit_network_is_strict_and_prevalidated() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let path = directory.path().join("network.json");
        let valid = br#"{"mcp_listen":"127.0.0.1:19443","mcp_public_url":"https://localhost:19443/mcp","native_listen":"127.0.0.1:19444","admin_listen":"127.0.0.1:19445"}"#;
        std::fs::write(&path, valid).unwrap();
        let selected = standalone_network(&path).unwrap();
        assert_eq!(selected.mcp_listen.port(), 19443);
        let explicit_default_https_port = br#"{"mcp_listen":"127.0.0.1:443","mcp_public_url":"https://localhost:443/mcp","native_listen":"127.0.0.1:19444","admin_listen":"127.0.0.1:19445"}"#;
        std::fs::write(&path, explicit_default_https_port).unwrap();
        assert_eq!(standalone_network(&path).unwrap().mcp_listen.port(), 443);
        for bytes in [
            br#"{}"#.as_slice(),
            br#"{"mcp_listen":"127.0.0.1:19443","mcp_public_url":"https://localhost:19444/mcp","native_listen":"127.0.0.1:19444","admin_listen":"127.0.0.1:19445"}"#.as_slice(),
            br#"{"mcp_listen":"127.0.0.1:19443","mcp_public_url":"https://localhost:19443/mcp","native_listen":"127.0.0.1:19443","admin_listen":"127.0.0.1:19445"}"#.as_slice(),
            br#"{"mcp_listen":"127.0.0.1:19443","mcp_public_url":"https://localhost:19443/mcp","native_listen":"127.0.0.1:19444","admin_listen":"127.0.0.1:19445","legacy_port":9443}"#.as_slice(),
            br#"{"mcp_listen":"127.0.0.1:19443","mcp_public_url":"https://localhost:19443/mcp","native_listen":"127.0.0.1:19444","admin_listen":"127.0.0.1:19445","mcp_listen":"127.0.0.1:19446"}"#.as_slice(),
            br#"{"mcp_listen":"127.0.0.1:443","mcp_public_url":"https://localhost/mcp","native_listen":"127.0.0.1:19444","admin_listen":"127.0.0.1:19445"}"#.as_slice(),
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(standalone_network(&path).is_err());
        }
        std::fs::write(&path, vec![b' '; 4097]).unwrap();
        assert!(standalone_network(&path).is_err());
    }
}

#[cfg(test)]
mod directory_policy_tests {
    use super::*;
    #[test]
    fn explicit_policy_is_bounded_strict_and_preserves_caller_values() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let path = directory.path().join("policy.json");
        std::fs::write(&path, br#"{"extent_bytes":1048576,"max_entries":32768}"#).unwrap();
        let policy = directory_policy(&path).unwrap();
        assert_eq!(policy.extent_bytes, 1048576);
        assert_eq!(policy.max_entries, 32768);
        for bytes in [
            br#"{}"#.as_slice(),
            br#"{"extent_bytes":1048576}"#.as_slice(),
            br#"{"extent_bytes":0,"max_entries":1}"#.as_slice(),
            br#"{"extent_bytes":1,"max_entries":1,"legacy_default":true}"#.as_slice(),
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(directory_policy(&path).is_err());
        }
        std::fs::write(&path, vec![b' '; 4097]).unwrap();
        assert!(directory_policy(&path).is_err());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
