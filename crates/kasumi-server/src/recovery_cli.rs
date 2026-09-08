//! Native distributed recovery commands. Start and stop attempts durably freeze
//! their endpoint, trust, credential resource and exact identities before I/O.
use crate::standalone::ClientProfile;
use anyhow::{Context, Result, ensure};
use kasumi_store::private_files;
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    endpoint: String,
    resource: CredentialResource,
    family_id: Uuid,
    server_pin: String,
    client_pin: String,
    ca_sha256: String,
}
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "request",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Operation {
    Start(Box<RecoveryStart>),
    Stop(RecoveryStop),
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    format: u32,
    binding: Binding,
    operation: Operation,
}
fn binding(profile: &ClientProfile) -> Result<Binding> {
    ensure!(
        profile.tenant == crate::runtime::CONTROL_TENANT,
        "distributed recovery requires a Control administrator profile"
    );
    let connection = profile.connection(true)?;
    Ok(Binding {
        endpoint: connection.endpoint,
        resource: profile.resource.clone(),
        family_id: profile.family_id,
        server_pin: profile.admin_certificate_pin.clone(),
        client_pin: hex::encode(connection.identity.certificate_pin()),
        ca_sha256: hex::encode(Sha256::digest(&connection.trusted_ca_pem)),
    })
}
pub(crate) async fn command(arguments: &[String]) -> Result<bool> {
    match arguments {
        [command, action, configuration, name]
            if command == "control-recovery" && action == "configuration-digest" =>
        {
            let runtime = crate::runtime::RuntimeConfig::load(configuration)?;
            let route = runtime
                .control
                .lifecycle
                .as_ref()
                .and_then(|c| c.recovery.as_ref())
                .and_then(|c| c.routes.get(name))
                .context("recovery route is not installed")?;
            println!(
                "{}",
                route.digest(
                    runtime
                        .serving_authorities
                        .get(&route.authority)
                        .context("recovery issuer is not installed")?
                )?
            );
        }
        [command, action, profile, input, attempt]
            if command == "control-recovery" && (action == "start" || action == "stop") =>
        {
            let profile = ClientProfile::load(Path::new(profile))?;
            let binding = binding(&profile)?;
            let attempt = Path::new(attempt);
            ensure!(
                attempt.is_absolute(),
                "recovery attempt path must be absolute"
            );
            private_files::check_directory(attempt.parent().context("attempt parent absent")?)?;
            let lock = attempt.with_extension("recovery.lock");
            ensure!(lock != attempt, "attempt collides with its lock");
            let _lock = private_files::ExclusiveLock::acquire(&lock)?;
            let requested = if action == "start" {
                let request: RecoveryStart = serde_json::from_slice(
                    &crate::runtime::read_bounded(Path::new(input), MAX_RECOVERY_START_BYTES)?,
                )?;
                request.validate()?;
                Operation::Start(Box::new(request))
            } else {
                Operation::Stop(RecoveryStop {
                    operation_id: Uuid::parse_str(input)?,
                    command_id: Uuid::new_v4(),
                })
            };
            let attempt_record = if attempt.exists() {
                let record: Attempt = serde_json::from_slice(&private_files::read(
                    attempt,
                    MAX_RECOVERY_RECORD_BYTES,
                )?)?;
                ensure!(
                    record.format == 1 && record.binding == binding,
                    "recovery retry endpoint, trust or credential resource differs"
                );
                let matches = match (&record.operation, &requested) {
                    (Operation::Start(old), Operation::Start(new)) => old == new,
                    (Operation::Stop(old), Operation::Stop(new)) => {
                        old.operation_id == new.operation_id
                    }
                    _ => false,
                };
                ensure!(
                    matches,
                    "recovery retry differs from its original operation"
                );
                record
            } else {
                let record = Attempt {
                    format: 1,
                    binding,
                    operation: requested,
                };
                private_files::publish(attempt, &serde_json::to_vec(&record)?)?;
                record
            };
            let mut client =
                kasumi_client::KasumiRecoveryClient::connect(&profile.connection(true)?).await?;
            let record = match attempt_record.operation {
                Operation::Start(request) => client.start(&profile.bearer()?, &request).await?,
                Operation::Stop(request) => client.stop(&profile.bearer()?, &request).await?,
            };
            println!("{}", serde_json::to_string_pretty(&record)?);
        }
        [command, action, profile, operation]
            if command == "control-recovery" && action == "status" =>
        {
            let profile = ClientProfile::load(Path::new(profile))?;
            binding(&profile)?;
            let mut client =
                kasumi_client::KasumiRecoveryClient::connect(&profile.connection(true)?).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &client
                        .status(
                            &profile.bearer()?,
                            &RecoveryStatusRequest {
                                operation_id: Uuid::parse_str(operation)?
                            }
                        )
                        .await?
                )?
            );
        }
        [command, action, profile, operation, steps]
            if command == "control-recovery" && action == "resume" =>
        {
            let profile = ClientProfile::load(Path::new(profile))?;
            binding(&profile)?;
            let mut client =
                kasumi_client::KasumiRecoveryClient::connect(&profile.connection(true)?).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &client
                        .resume(
                            &profile.bearer()?,
                            &RecoveryResume {
                                operation_id: Uuid::parse_str(operation)?,
                                max_steps: steps.parse()?
                            }
                        )
                        .await?
                )?
            );
        }
        [command, action, profile, operation, phase]
            if command == "control-recovery" && action == "phase" =>
        {
            let profile = ClientProfile::load(Path::new(profile))?;
            binding(&profile)?;
            let mut client =
                kasumi_client::KasumiRecoveryClient::connect(&profile.connection(true)?).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &client
                        .read_phase(
                            &profile.bearer()?,
                            &RecoveryPhaseRequest {
                                operation_id: Uuid::parse_str(operation)?,
                                phase_id: Uuid::parse_str(phase)?
                            }
                        )
                        .await?
                )?
            );
        }
        [command, ..] if command == "control-recovery" => anyhow::bail!(
            "usage: kasumid control-recovery configuration-digest CONFIGURATION ROUTE | start CONTROL_PROFILE REQUEST_JSON PRIVATE_ATTEMPT_JSON | stop CONTROL_PROFILE OPERATION_UUID PRIVATE_ATTEMPT_JSON | status CONTROL_PROFILE OPERATION_UUID | resume CONTROL_PROFILE OPERATION_UUID MAX_STEPS | phase CONTROL_PROFILE OPERATION_UUID PHASE_UUID"
        ),
        _ => return Ok(false),
    }
    Ok(true)
}
