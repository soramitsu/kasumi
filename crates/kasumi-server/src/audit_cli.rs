//! Historical page attempts persist their endpoint, trust and exact cursor
//! before dispatch. Retrying never chooses a later stream or end position.
use crate::standalone::ClientProfile;
use anyhow::{Context, Result, ensure};
use kasumi_store::private_files;
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Binding {
    endpoint: String,
    resource: CredentialResource,
    family_id: Uuid,
    server_pins: std::collections::BTreeSet<String>,
    client_pin: String,
    ca_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    format: u32,
    operation: String,
    binding: Binding,
    original: serde_json::Value,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    resolved: Option<serde_json::Value>,
}
fn binding(profile: &ClientProfile) -> Result<Binding> {
    ensure!(
        profile.tenant == crate::runtime::CONTROL_TENANT,
        "service audit requires a Control administrator profile"
    );
    let connection = profile.connection(true)?;
    Ok(Binding {
        endpoint: connection.endpoint,
        resource: profile.resource.clone(),
        family_id: profile.family_id,
        server_pins: profile.administrative_member()?.certificate_pins.clone(),
        client_pin: hex::encode(connection.identity.certificate_pin()),
        ca_sha256: hex::encode(Sha256::digest(&connection.trusted_ca_pem)),
    })
}
pub(crate) async fn command(arguments: &[String]) -> Result<bool> {
    match arguments {
        [command, action, profile] if command == "audit" && action == "status" => {
            let profile = ClientProfile::load(Path::new(profile))?;
            binding(&profile)?;
            let mut client =
                kasumi_client::KasumiAdminClient::connect(&profile.connection(true)?).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(
                    &client.security_audit_status(&profile.bearer()?).await?
                )?
            );
        }
        [command, action, profile, stream, index] if command == "audit" && action == "verify" => {
            let profile = ClientProfile::load(Path::new(profile))?;
            binding(&profile)?;
            let mut client =
                kasumi_client::KasumiAdminClient::connect(&profile.connection(true)?).await?;
            let proof = client
                .verify_security_audit_archive(
                    &profile.bearer()?,
                    &SecurityAuditVerifyRequest {
                        stream_id: Uuid::parse_str(stream)?,
                        index: index.parse()?,
                    },
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(proof.observation())?);
        }
        [command, action, profile, input, output]
            if command == "audit" && (action == "export" || action == "archives") =>
        {
            page(
                action,
                Path::new(profile),
                Path::new(input),
                Path::new(output),
            )
            .await?;
            println!("{}", serde_json::json!({"page":output}));
        }
        [command, ..] if command == "audit" => anyhow::bail!(
            "usage: kasumid audit status PROFILE | audit export|archives PROFILE REQUEST_JSON OUTPUT_JSON | audit verify PROFILE STREAM_UUID INDEX"
        ),
        _ => return Ok(false),
    }
    Ok(true)
}

async fn page(operation: &str, profile_path: &Path, input: &Path, output: &Path) -> Result<()> {
    ensure!(output.is_absolute(), "audit page output must be absolute");
    private_files::check_directory(output.parent().context("audit page has no parent")?)?;
    let profile = ClientProfile::load(profile_path)?;
    let binding = binding(&profile)?;
    let original: serde_json::Value = serde_json::from_slice(&crate::runtime::read_bounded(
        input,
        MAX_SECURITY_AUDIT_PAGE_BYTES,
    )?)?;
    match operation {
        "export" => {
            serde_json::from_value::<SecurityAuditExportRequest>(original.clone())?.validate()?
        }
        "archives" => serde_json::from_value::<SecurityAuditArchivePageRequest>(original.clone())?
            .validate()?,
        _ => anyhow::bail!("unknown audit page operation"),
    }
    let lock = output.with_extension("audit.lock");
    let journal = output.with_extension("audit-attempt.json");
    ensure!(
        journal != output && lock != output,
        "audit output collides with its attempt journal or lock"
    );
    let _lock = private_files::ExclusiveLock::acquire(&lock)?;
    let mut attempt = if journal.exists() {
        let attempt: Attempt = serde_json::from_slice(&private_files::read(
            &journal,
            MAX_SECURITY_AUDIT_PAGE_BYTES,
        )?)?;
        ensure!(
            attempt.format == 1
                && attempt.operation == operation
                && attempt.binding == binding
                && attempt.original == original,
            "audit retry differs from its original endpoint, credential, trust or input"
        );
        attempt
    } else {
        ensure!(
            !output.exists(),
            "existing audit output has no matching attempt"
        );
        let attempt = Attempt {
            format: 1,
            operation: operation.into(),
            binding,
            original,
            resolved: None,
        };
        private_files::publish(&journal, &serde_json::to_vec(&attempt)?)?;
        attempt
    };
    ensure!(
        !output.exists(),
        "audit page already published; use its cursor with a new output path"
    );
    let mut client = kasumi_client::KasumiAdminClient::connect(&profile.connection(true)?).await?;
    if attempt.resolved.is_none() {
        let resolved = match operation {
            "export" => {
                let mut request: SecurityAuditExportRequest =
                    serde_json::from_value(attempt.original.clone())?;
                if request.cursor.is_none() {
                    let status = client.security_audit_status(&profile.bearer()?).await?;
                    request.cursor = Some(SecurityAuditCursor {
                        stream_id: status.position.stream_id,
                        next_sequence: 0,
                        through_sequence: status.position.next_sequence,
                    });
                }
                serde_json::to_value(request)?
            }
            "archives" => {
                let mut request: SecurityAuditArchivePageRequest =
                    serde_json::from_value(attempt.original.clone())?;
                if request.cursor.is_none() {
                    let status = client.security_audit_status(&profile.bearer()?).await?;
                    request.cursor = Some(SecurityAuditArchiveCursor {
                        stream_id: status.position.stream_id,
                        next_index: 0,
                        through_index: status.archive_segments,
                    });
                }
                serde_json::to_value(request)?
            }
            _ => unreachable!(),
        };
        attempt.resolved = Some(resolved);
        private_files::replace(&journal, &serde_json::to_vec(&attempt)?)?;
    }
    let resolved = attempt
        .resolved
        .context("audit attempt lacks a fixed range")?;
    let bytes = match operation {
        "export" => {
            let options = kasumi_client::JsonReadOptions {
                resources: kasumi_client::ClientResources::new(256 << 20, 2)?,
                limits: kasumi_client::ClientDecodeLimits {
                    max_request_bytes: 64 << 10,
                    max_wire_bytes: 2 << 20,
                    max_json_bytes: 1 << 20,
                    max_decoded_bytes: 64 << 20,
                    max_rows: 1024,
                    ..Default::default()
                },
                deadline: tokio::time::Instant::now() + std::time::Duration::from_secs(30),
            };
            let page = client
                .export_security_audit(
                    &profile.bearer()?,
                    &serde_json::from_value(resolved)?,
                    &options,
                )
                .await?;
            serde_json::to_vec(&*page)?
        }
        "archives" => serde_json::to_vec(
            &client
                .security_audit_archives(&profile.bearer()?, &serde_json::from_value(resolved)?)
                .await?,
        )?,
        _ => unreachable!(),
    };
    ensure!(
        bytes.len() <= MAX_SECURITY_AUDIT_PAGE_BYTES,
        "audit page exceeds its byte limit"
    );
    private_files::publish(output, &bytes)?;
    Ok(())
}
