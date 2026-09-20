//! Native distributed recovery commands. Start and stop attempts durably freeze
//! their endpoint, trust, credential resource and exact identities before I/O.
use crate::standalone::ClientProfile;
use anyhow::{Context, Result, ensure};
use kasumi_store::private_files;
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    sync::Arc,
    time::Duration,
};
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    members: BTreeMap<u64, (String, BTreeSet<String>)>,
    resource: CredentialResource,
    family_id: Uuid,
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
    let connections = profile.administrative_connections()?;
    let connection = connections
        .values()
        .next()
        .context("no administrative members")?;
    Ok(Binding {
        members: profile
            .administrative_members
            .iter()
            .map(|(id, member)| {
                (
                    *id,
                    (member.endpoint.clone(), member.certificate_pins.clone()),
                )
            })
            .collect(),
        resource: profile.resource.clone(),
        family_id: profile.family_id,
        client_pin: hex::encode(connection.identity.certificate_pin()),
        ca_sha256: hex::encode(Sha256::digest(&connection.trusted_ca_pem)),
    })
}
fn request_timeout(value: &str) -> Result<Duration> {
    let millis: u64 = value.parse()?;
    ensure!(
        (1..=600_000).contains(&millis),
        "recovery timeout must be 1 to 600000 milliseconds"
    );
    Ok(Duration::from_millis(millis))
}
fn client(profile: &ClientProfile) -> Result<kasumi_client::KasumiRecoveryPool> {
    let connections = profile.administrative_connections()?;
    let profile = profile.clone();
    kasumi_client::KasumiRecoveryPool::new(connections, Arc::new(move || profile.bearer()))
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
        [command, action, profile, input, attempt, timeout]
            if command == "control-recovery" && (action == "start" || action == "stop") =>
        {
            let duration = request_timeout(timeout)?;
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
            let mut client = client(&profile)?;
            let record = match attempt_record.operation {
                Operation::Start(request) => client.start(&request, duration).await?,
                Operation::Stop(request) => client.stop(&request, duration).await?,
            };
            println!("{}", serde_json::to_string_pretty(&record)?);
        }
        [command, action, profile, operation, timeout]
            if command == "control-recovery" && action == "status" =>
        {
            let duration = request_timeout(timeout)?;
            let profile = ClientProfile::load(Path::new(profile))?;
            binding(&profile)?;
            let mut client = client(&profile)?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &client
                        .status(
                            &RecoveryStatusRequest {
                                operation_id: Uuid::parse_str(operation)?
                            },
                            duration
                        )
                        .await?
                )?
            );
        }
        [command, action, profile, operation, steps, timeout]
            if command == "control-recovery" && action == "resume" =>
        {
            let duration = request_timeout(timeout)?;
            let profile = ClientProfile::load(Path::new(profile))?;
            binding(&profile)?;
            let mut client = client(&profile)?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &client
                        .resume(
                            &RecoveryResume {
                                operation_id: Uuid::parse_str(operation)?,
                                max_steps: steps.parse()?
                            },
                            duration
                        )
                        .await?
                )?
            );
        }
        [command, action, profile, operation, phase, timeout]
            if command == "control-recovery" && action == "phase" =>
        {
            let duration = request_timeout(timeout)?;
            let profile = ClientProfile::load(Path::new(profile))?;
            binding(&profile)?;
            let mut client = client(&profile)?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &client
                        .read_phase(
                            &RecoveryPhaseRequest {
                                operation_id: Uuid::parse_str(operation)?,
                                phase_id: Uuid::parse_str(phase)?
                            },
                            duration
                        )
                        .await?
                )?
            );
        }
        [command, ..] if command == "control-recovery" => anyhow::bail!(
            "usage: kasumid control-recovery configuration-digest CONFIGURATION ROUTE | start CONTROL_PROFILE REQUEST_JSON PRIVATE_ATTEMPT_JSON TIMEOUT_MS | stop CONTROL_PROFILE OPERATION_UUID PRIVATE_ATTEMPT_JSON TIMEOUT_MS | status CONTROL_PROFILE OPERATION_UUID TIMEOUT_MS | resume CONTROL_PROFILE OPERATION_UUID MAX_STEPS TIMEOUT_MS | phase CONTROL_PROFILE OPERATION_UUID PHASE_UUID TIMEOUT_MS"
        ),
        _ => return Ok(false),
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recovery_attempt_binding_includes_every_installed_member_and_rejects_the_old_profile_shape()
    {
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let certificate = directory.path().join("client.pem");
        let key = directory.path().join("client-key.pem");
        // Public unit fixture only; no listener is opened with this key.
        private_files::create(
            &certificate,
            include_bytes!("../../kasumi-client/src/installed-pool-test-cert.pem"),
        )
        .unwrap();
        private_files::create(
            &key,
            include_bytes!("../../kasumi-client/src/installed-pool-test-key.pem"),
        )
        .unwrap();
        let mut profile = ClientProfile {
            format: 1,
            family_id: Uuid::new_v4(),
            tenant: crate::runtime::CONTROL_TENANT.into(),
            resource: CredentialResource::Control {
                incarnation: Uuid::new_v4(),
            },
            native_endpoint: "https://localhost:9444".into(),
            mcp_endpoint: "https://localhost:9443/mcp".into(),
            administrative_members: (1..=3)
                .map(|id| {
                    (
                        id,
                        crate::serving_runtime::AuthorityEndpoint {
                            endpoint: format!("https://localhost:{}", 9500 + id),
                            certificate_pins: BTreeSet::from(["ab".repeat(32)]),
                        },
                    )
                })
                .collect(),
            identity: crate::runtime::TlsFiles {
                certificate: certificate.clone(),
                private_key: key,
            },
            server_ca: certificate,
            native_certificate_pin: "ab".repeat(32),
            bearer_file: directory.path().join("unused.token"),
        };
        let original = binding(&profile).unwrap();
        assert_eq!(original.members.len(), 3);
        assert!(
            profile.connection(true).is_err(),
            "member-specific commands cannot silently select a peer"
        );
        profile
            .administrative_members
            .get_mut(&3)
            .unwrap()
            .certificate_pins = BTreeSet::from(["cd".repeat(32)]);
        assert_ne!(binding(&profile).unwrap(), original);
        profile
            .administrative_members
            .get_mut(&3)
            .unwrap()
            .certificate_pins = BTreeSet::from(["ab".repeat(32)]);
        profile.administrative_members.get_mut(&2).unwrap().endpoint =
            "https://replacement.example:9502".into();
        assert_ne!(binding(&profile).unwrap(), original);
        let mut old = serde_json::to_value(&profile).unwrap();
        old.as_object_mut()
            .unwrap()
            .remove("administrative_members");
        old["admin_endpoint"] = serde_json::json!("https://localhost:9501");
        old["admin_certificate_pin"] = serde_json::json!("ab".repeat(32));
        assert!(serde_json::from_value::<ClientProfile>(old).is_err());
    }
    #[test]
    fn every_recovery_invocation_requires_a_finite_bounded_timeout() {
        for invalid in ["", "0", "-1", "600001", "18446744073709551616"] {
            assert!(request_timeout(invalid).is_err());
        }
        assert_eq!(request_timeout("1").unwrap(), Duration::from_millis(1));
        assert_eq!(request_timeout("600000").unwrap(), Duration::from_secs(600));
    }
}
