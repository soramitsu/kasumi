//! Local operator commands. Bearer material is written only to private files.
use crate::{
    audit_destination::TenantAuditPlacementConfig,
    standalone::{ClientProfile, StandaloneNetwork, initialize, validate_initial_audit_placements},
};
use anyhow::{Context, Result, ensure};
use kasumi_store::private_files;
use std::{collections::BTreeMap, path::Path};
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
        [command, configuration, request, output] if command == "enroll-backup-destination" => {
            crate::backup_destination_installation::command(
                Path::new(configuration),
                Path::new(request),
                Path::new(output),
            )
            .await?;
            println!(
                "Captured the enrolled backup destination binding; install the receipt's configuration explicitly before startup."
            );
        }
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
        [command, configuration, manifest] if command == "recover-existing-credentials" => {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &crate::standalone::recover_existing_credentials(
                        Path::new(configuration),
                        Path::new(manifest)
                    )
                    .await?
                )?
            );
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
        [command, action, configuration, source]
            if command == "maintenance" && action == "move-tenant-audit-cache" =>
        {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &crate::standalone::move_tenant_audit_cache(
                        Path::new(configuration),
                        Path::new(source)
                    )
                    .await?
                )?
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
            allocation_flag,
            allocation,
            network_flag,
            network,
            placements_flag,
            placements,
        ] if command == "init"
            && mode_flag == "--mode"
            && mode == "standalone"
            && policy_flag == "--directory-policy"
            && allocation_flag == "--file-allocation-policy"
            && network_flag == "--network"
            && placements_flag == "--tenant-audit-placements" =>
        {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &initialize(
                        Path::new(directory),
                        "default",
                        directory_policy(Path::new(policy))?,
                        file_allocation_policy(Path::new(allocation))?,
                        standalone_network(Path::new(network))?,
                        tenant_audit_placements(Path::new(placements), "default")?,
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
            allocation_flag,
            allocation,
            network_flag,
            network,
            placements_flag,
            placements,
            tenant_flag,
            tenant,
        ] if command == "init"
            && mode_flag == "--mode"
            && mode == "standalone"
            && policy_flag == "--directory-policy"
            && allocation_flag == "--file-allocation-policy"
            && network_flag == "--network"
            && placements_flag == "--tenant-audit-placements"
            && tenant_flag == "--tenant" =>
        {
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &initialize(
                        Path::new(directory),
                        tenant,
                        directory_policy(Path::new(policy))?,
                        file_allocation_policy(Path::new(allocation))?,
                        standalone_network(Path::new(network))?,
                        tenant_audit_placements(Path::new(placements), tenant)?,
                    )
                    .await?
                )?
            );
        }
        [command, action, path] if command == "credential" && action == "inspect" => {
            // Offline and unverified: reads this profile's own bearer file only
            // to report when it expires, e.g. before a planned restart.
            let profile = ClientProfile::load(Path::new(path))?;
            let expires_at_ms = bearer_expiry_ms(profile.bearer()?.as_str())?;
            let now = kasumi_clock::EpochClock::system()?.now_ms()?;
            println!(
                "{}",
                serde_json::json!({
                    "family_id": profile.family_id,
                    "tenant": profile.tenant,
                    "principal": profile.principal,
                    "expires_at_ms": expires_at_ms,
                    "remaining_seconds": expires_at_ms.saturating_sub(now) / 1000,
                    "expired": expires_at_ms <= now,
                    // The latest credential of an unrevoked family can still
                    // renew itself online until then.
                    "online_recovery_until_ms": expires_at_ms.saturating_add(
                        kasumi_types::EXPIRED_CREDENTIAL_RECOVERY_WINDOW_SECONDS * 1000
                    ),
                })
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
                        let delay = renewal_delay_ms(expiry.saturating_sub(now), random_unit());
                        tokio::select! { _ = tokio::time::sleep(std::time::Duration::from_millis(delay)) => {}, _ = tokio::signal::ctrl_c() => break }
                    }
                    Err(error) if action == "watch" && retryable(&error) => {
                        tracing::warn!(
                            "credential renewal unavailable; retaining original renewal identity"
                        );
                        let delay = retry_delay_ms(random_unit());
                        tokio::select! { _ = tokio::time::sleep(std::time::Duration::from_millis(delay)) => {}, _ = tokio::signal::ctrl_c() => break }
                    }
                    Err(error) => return Err(explain_renewal_failure(profile.family_id, error)),
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

/// The `exp` claim of a compact JWT, in milliseconds, without verifying the
/// token: the daemon verifies every use; this only reports the profile's state.
fn bearer_expiry_ms(token: &str) -> Result<u64> {
    use base64::Engine as _;
    let payload = token
        .split('.')
        .nth(1)
        .context("bearer file does not hold a compact JWT")?;
    let claims: serde_json::Value =
        serde_json::from_slice(&base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload)?)?;
    claims["exp"]
        .as_u64()
        .and_then(|seconds| seconds.checked_mul(1000))
        .context("bearer token has no exp claim")
}

/// Renew somewhere between 50% and 70% of the remaining lifetime. Credentials
/// issued together (installation, recovery) would otherwise all renew in the
/// same second, every hour, and contend for the same admission budget.
fn renewal_delay_ms(remaining_ms: u64, unit: f64) -> u64 {
    let fraction = 0.5 + 0.2 * unit.clamp(0.0, 1.0);
    ((remaining_ms as f64 * fraction) as u64).max(1000)
}

/// While the daemon is unavailable, retry every 3 to 8 seconds rather than in
/// lockstep with every other watcher.
fn retry_delay_ms(unit: f64) -> u64 {
    3000 + (5000.0 * unit.clamp(0.0, 1.0)) as u64
}

/// A uniform value in [0, 1) from the operating system's random source.
fn random_unit() -> f64 {
    (Uuid::new_v4().as_u128() >> 75) as f64 / (1u64 << 53) as f64
}

/// A renewal the daemon refused is final for this watcher. If online recovery
/// refused the expired credential too, only stopped-installation recovery can
/// renew it; say why and how. An uncertain recovery is retried as it is.
fn explain_renewal_failure(family_id: Uuid, error: anyhow::Error) -> anyhow::Error {
    if error.downcast_ref::<RecoveryRefused>().is_none() || retryable(&error) {
        return error;
    }
    let unsupported = matches!(
        error.downcast_ref::<kasumi_client::ClientError>(),
        Some(kasumi_client::ClientError::Transport(status))
            if status.code() == tonic::Code::Unimplemented
    );
    error.context(format!(
        "credential family {} was refused renewal, most likely because it expired while the daemon was unavailable, and {}. \
         Online recovery renews only the family's latest credential, less than {} hours after it expired, while the family is unrevoked. \
         Otherwise stop kasumid, run `kasumid recover-existing-credentials <configuration.json> <private-manifest.json>` \
         for the expired profiles, start kasumid, then restart this watcher",
        family_id,
        if unsupported {
            "this kasumid does not offer online recovery"
        } else {
            "online recovery refused it"
        },
        kasumi_types::EXPIRED_CREDENTIAL_RECOVERY_WINDOW_SECONDS / 3600
    ))
}

fn retryable(error: &anyhow::Error) -> bool {
    match error.downcast_ref::<kasumi_client::ClientError>() {
        Some(kasumi_client::ClientError::Connection(_)) => true,
        Some(kasumi_client::ClientError::Transport(status)) => matches!(
            status.code(),
            tonic::Code::Cancelled
                | tonic::Code::Unavailable
                | tonic::Code::DeadlineExceeded
                | tonic::Code::Unknown
        ),
        _ => false,
    }
}

#[cfg(test)]
mod credential_renewal_tests {
    use super::*;
    use kasumi_client::ClientError;

    #[test]
    fn inspect_reads_the_bearer_expiry_without_a_daemon() {
        use base64::Engine as _;
        let encode = |value: &serde_json::Value| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.to_string())
        };
        let token = format!(
            "{}.{}.signature",
            encode(&serde_json::json!({"alg": "EdDSA", "typ": "at+jwt"})),
            encode(&serde_json::json!({"exp": 1_793_900_000u64, "sub": "fixture"}))
        );
        assert_eq!(bearer_expiry_ms(&token).unwrap(), 1_793_900_000_000);
        assert!(bearer_expiry_ms("opaque").is_err());
        let no_exp = format!(
            "{}.{}.s",
            encode(&serde_json::json!({})),
            encode(&serde_json::json!({"sub": "x"}))
        );
        assert!(bearer_expiry_ms(&no_exp).is_err());
    }

    #[test]
    fn renewals_spread_over_a_fifth_of_the_lifetime_and_retries_are_jittered() {
        let hour = 3_600_000;
        assert_eq!(renewal_delay_ms(hour, 0.0), hour / 2);
        assert_eq!(renewal_delay_ms(hour, 1.0), hour * 7 / 10);
        assert!((hour / 2..=hour * 7 / 10).contains(&renewal_delay_ms(hour, 0.37)));
        assert_eq!(renewal_delay_ms(0, 0.5), 1000);
        assert_eq!(retry_delay_ms(0.0), 3000);
        assert_eq!(retry_delay_ms(1.0), 8000);
        let samples = (0..256).map(|_| random_unit()).collect::<Vec<_>>();
        assert!(samples.iter().all(|unit| (0.0..1.0).contains(unit)));
        assert!(samples.iter().any(|unit| *unit < 0.5) && samples.iter().any(|unit| *unit >= 0.5));
    }

    #[test]
    fn only_a_refused_recovery_points_to_stopped_installation_recovery() {
        let family = Uuid::new_v4();
        let refused = |code| {
            anyhow::Error::new(ClientError::Transport(tonic::Status::new(
                code,
                "fixture reason",
            )))
            .context(RecoveryRefused)
        };
        let message = format!(
            "{:#}",
            explain_renewal_failure(family, refused(tonic::Code::Unauthenticated))
        );
        for expected in [
            family.to_string().as_str(),
            "online recovery refused it",
            "less than 24 hours after it expired",
            "recover-existing-credentials",
            "fixture reason",
        ] {
            assert!(
                message.contains(expected),
                "{expected:?} missing: {message}"
            );
        }
        let message = format!(
            "{:#}",
            explain_renewal_failure(family, refused(tonic::Code::Unimplemented))
        );
        assert!(
            message.contains("does not offer online recovery"),
            "{message}"
        );
        // An uncertain recovery keeps its identity and is retried.
        assert!(retryable(&refused(tonic::Code::Unavailable)));
        assert!(!retryable(&refused(tonic::Code::Unauthenticated)));
        let uncertain = format!(
            "{:#}",
            explain_renewal_failure(family, refused(tonic::Code::Unavailable))
        );
        assert!(
            !uncertain.contains("recover-existing-credentials"),
            "{uncertain}"
        );
        let other = explain_renewal_failure(family, anyhow::anyhow!("fixture corrupt journal"));
        assert_eq!(format!("{other:#}"), "fixture corrupt journal");
    }

    #[test]
    fn credential_watch_retries_only_uncertain_transport_failures() {
        for code in [
            tonic::Code::Cancelled,
            tonic::Code::Unavailable,
            tonic::Code::DeadlineExceeded,
            tonic::Code::Unknown,
        ] {
            assert!(
                retryable(&ClientError::Transport(tonic::Status::new(code, "fixture")).into()),
                "uncertain transport {code:?} must retain the renewal identity"
            );
        }
        for code in [
            tonic::Code::Ok,
            tonic::Code::InvalidArgument,
            tonic::Code::NotFound,
            tonic::Code::AlreadyExists,
            tonic::Code::PermissionDenied,
            tonic::Code::ResourceExhausted,
            tonic::Code::FailedPrecondition,
            tonic::Code::Aborted,
            tonic::Code::OutOfRange,
            tonic::Code::Unimplemented,
            tonic::Code::Internal,
            tonic::Code::DataLoss,
            tonic::Code::Unauthenticated,
        ] {
            assert!(!retryable(
                &ClientError::Transport(tonic::Status::new(code, "fixture")).into()
            ));
        }
        for error in [
            ClientError::DecodeRejected {
                code: tonic::Code::Cancelled,
                reason: "fixture invalid proof",
                database: None,
            },
            ClientError::Authorization,
            ClientError::InvalidResponse("fixture invalid family"),
            ClientError::RequestTooLarge,
        ] {
            assert!(!retryable(&error.into()));
        }
        for message in [
            "renewal journal belongs to another credential",
            "renewal journal issuance has expired",
            "fixture corrupt journal",
        ] {
            assert!(!retryable(&anyhow::anyhow!(message)));
        }
    }
}

/// Marks a failure of online recovery after the daemon refused the bearer.
#[derive(Debug)]
struct RecoveryRefused;
impl std::fmt::Display for RecoveryRefused {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("online recovery of the expired credential failed")
    }
}
impl std::error::Error for RecoveryRefused {}

/// Persist the renewal identity before dispatch, and keep it through any
/// uncertain result. Crashing after token replacement can only replay the same
/// issuance; it cannot extend an already admitted request's deadline. A bearer
/// the daemon refuses is presented for online recovery with the same identity:
/// only the family's latest credential recovers, and only within the fixed
/// window after it expired (docs/credential-lifetime.md).
async fn renew(profile: &ClientProfile) -> Result<u64> {
    let journal = profile.bearer_file.with_extension("renewal.json");
    // A replayed issuance whose reply was lost until after it expired becomes
    // the bearer, since only the family's latest credential can recover it;
    // the second pass then recovers from it under a new identity.
    for _ in 0..2 {
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
        let mut client =
            kasumi_client::KasumiAdminClient::connect(&profile.connection(true)?).await?;
        let bearer = profile.bearer()?;
        let issued = match client.renew_credential(&bearer, &request).await {
            Err(kasumi_client::ClientError::Transport(status))
                if status.code() == tonic::Code::Unauthenticated =>
            {
                tracing::warn!(
                    family_id = %profile.family_id,
                    "the daemon refused this credential for renewal; presenting it for online recovery"
                );
                client
                    .recover_credential(&bearer, &request)
                    .await
                    .map_err(|error| anyhow::Error::new(error).context(RecoveryRefused))?
            }
            result => result?,
        };
        ensure!(
            issued.family_id == profile.family_id,
            "renewed credential family differs"
        );
        let expired = issued.expires_at_ms <= kasumi_clock::EpochClock::system()?.now_ms()?;
        ensure!(
            !expired
                || bearer_expiry_ms(&bearer).is_ok_and(|current| current <= issued.expires_at_ms),
            "renewal journal issuance has expired; stopped-installation credential recovery is required"
        );
        private_files::replace(&profile.bearer_file, issued.token.as_bytes())?;
        std::fs::remove_file(&journal)?;
        private_files::sync_parent(&journal)?;
        if !expired {
            return Ok(issued.expires_at_ms);
        }
        tracing::warn!(
            family_id = %profile.family_id,
            "a replayed renewal had already expired; recovering from it"
        );
    }
    anyhow::bail!(
        "renewal journal issuance has expired; stopped-installation credential recovery is required"
    )
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

/// Read the caller's explicit per-file physical allowance before installation.
/// This finite bound must be qualified for the selected filesystem.
pub fn file_allocation_policy(path: &Path) -> Result<kasumi_store::FileAllocationPolicy> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(4097)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() <= 4096,
        "file allocation policy exceeds size limit"
    );
    let policy: kasumi_store::FileAllocationPolicy = serde_json::from_slice(&bytes)?;
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

/// Load an owner-only, bounded map with one explicit choice for each initial group.
pub fn tenant_audit_placements(
    path: &Path,
    tenant: &str,
) -> Result<BTreeMap<String, TenantAuditPlacementConfig>> {
    #[derive(serde::Deserialize)]
    struct PlacementMap(
        #[serde(
            deserialize_with = "crate::audit_destination::deserialize_tenant_audit_placements"
        )]
        BTreeMap<String, TenantAuditPlacementConfig>,
    );
    let bytes = private_files::read(path, 64 << 10)?;
    let PlacementMap(placements) = serde_json::from_slice(&bytes)?;
    validate_initial_audit_placements(tenant, &placements)?;
    Ok(placements)
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

#[cfg(test)]
mod file_allocation_policy_tests {
    use super::*;

    #[test]
    fn explicit_allowance_is_bounded_strict_and_preserves_zero_or_selected_bytes() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let path = directory.path().join("allocation.json");
        for allowance in [0, 1048576] {
            std::fs::write(
                &path,
                format!("{{\"maximum_extra_extent_bytes\":{allowance}}}"),
            )
            .unwrap();
            assert_eq!(
                file_allocation_policy(&path)
                    .unwrap()
                    .maximum_extra_extent_bytes,
                allowance
            );
        }
        for bytes in [
            br#"{}"#.as_slice(),
            br#"{"maximum_extra_extent_bytes":true}"#.as_slice(),
            br#"{"maximum_extra_extent_bytes":-1}"#.as_slice(),
            br#"{"maximum_extra_extent_bytes":9223372036854775808}"#.as_slice(),
            br#"{"maximum_extra_extent_bytes":1,"legacy_default":true}"#.as_slice(),
            br#"{"maximum_extra_extent_bytes":1,"maximum_extra_extent_bytes":2}"#.as_slice(),
        ] {
            std::fs::write(&path, bytes).unwrap();
            assert!(file_allocation_policy(&path).is_err());
        }
        std::fs::write(&path, vec![b' '; 4097]).unwrap();
        assert!(file_allocation_policy(&path).is_err());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }

    #[test]
    fn init_without_explicit_file_allowance_cannot_create_an_installation() {
        std::thread::Builder::new()
            .name("CLI missing file allocation policy fixture".into())
            .stack_size(16 << 20)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(Box::pin(init_without_file_allowance_impl()))
            })
            .unwrap()
            .join()
            .unwrap();
    }

    async fn init_without_file_allowance_impl() {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let target = directory.path().join("new-installation");
        let arguments = [
            "init".into(),
            "--mode".into(),
            "standalone".into(),
            target.to_string_lossy().into_owned(),
            "--directory-policy".into(),
            "unused-directory-policy.json".into(),
            "--network".into(),
            "unused-network.json".into(),
        ];
        assert!(!command(&arguments).await.unwrap());
        assert!(!target.exists());
    }
}

#[cfg(test)]
mod tenant_audit_placement_tests {
    use super::*;

    #[test]
    fn explicit_placements_are_private_bounded_complete_and_strict() -> Result<()> {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let path = directory.path().join("placements.json");
        let selected = serde_json::json!({
            "__kasumi_control": {"kind": "local_replica_only"},
            "default": {"kind": "external", "destination": {
                "kind": "filesystem", "directory": directory.path().join("archives")
            }}
        });
        private_files::create(&path, &serde_json::to_vec_pretty(&selected)?)?;
        assert_eq!(
            serde_json::to_value(tenant_audit_placements(&path, "default")?)?,
            selected
        );
        assert!(!directory.path().join("archives").exists());
        for invalid in [
            serde_json::json!(null),
            serde_json::json!({}),
            serde_json::json!({"default": {"kind":"local_replica_only"}}),
            serde_json::json!({"__kasumi_control": {"kind":"local_replica_only"}}),
            serde_json::json!({"__kasumi_control": {"kind":"local_replica_only"}, "default":null}),
            serde_json::json!({"__kasumi_control": {"kind":"local_replica_only"}, "default":{"kind":"filesystem","directory":"/archive"}}),
            serde_json::json!({"__kasumi_control": {"kind":"local_replica_only"}, "default":{"kind":"local_replica_only","legacy":true}}),
            serde_json::json!({"__kasumi_control": {"kind":"local_replica_only"}, "default":{"kind":"external","destination":{"kind":"filesystem","directory":"relative"}}}),
            serde_json::json!({"__kasumi_control": {"kind":"local_replica_only"}, "default":{"kind":"unknown"}}),
            serde_json::json!({"__kasumi_control": {"kind":"local_replica_only"}, "default":{"kind":"local_replica_only"}, "other":{"kind":"local_replica_only"}}),
        ] {
            private_files::replace(&path, &serde_json::to_vec(&invalid)?)?;
            assert!(tenant_audit_placements(&path, "default").is_err());
        }
        private_files::replace(&path, br#"{"__kasumi_control":{"kind":"local_replica_only"},"default":{"kind":"local_replica_only"},"default":{"kind":"local_replica_only"}}"#)?;
        assert!(tenant_audit_placements(&path, "default").is_err());
        private_files::replace(&path, &vec![b' '; (64 << 10) + 1])?;
        assert!(tenant_audit_placements(&path, "default").is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            private_files::replace(&path, &serde_json::to_vec(&selected)?)?;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
            assert!(tenant_audit_placements(&path, "default").is_err());
            let alias = directory.path().join("alias.json");
            std::os::unix::fs::symlink(&path, &alias)?;
            assert!(tenant_audit_placements(&alias, "default").is_err());
        }
        Ok(())
    }

    #[test]
    fn init_without_explicit_audit_placements_cannot_create_an_installation() -> Result<()> {
        std::thread::Builder::new()
            .name("CLI missing tenant audit placements fixture".into())
            .stack_size(16 << 20)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(Box::pin(missing_audit_placements_impl()))
            })?
            .join()
            .unwrap()
    }
    async fn missing_audit_placements_impl() -> Result<()> {
        let root = kasumi_store::test_utils::private_tempdir()?;
        let directory = root.path().join("new-installation");
        let arguments = vec![
            "init".into(),
            "--mode".into(),
            "standalone".into(),
            directory.display().to_string(),
            "--directory-policy".into(),
            "missing-policy.json".into(),
            "--file-allocation-policy".into(),
            "missing-allocation.json".into(),
            "--network".into(),
            "missing-network.json".into(),
        ];
        assert!(!command(&arguments).await?);
        let mut named = arguments;
        named.extend(["--tenant".into(), "default".into()]);
        assert!(!command(&named).await?);
        assert!(!directory.exists());
        Ok(())
    }
}
