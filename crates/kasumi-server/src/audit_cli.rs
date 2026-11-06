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
        [command, action, profile, exported, through, output]
            if command == "audit" && action == "prune" =>
        {
            prune(
                Path::new(profile),
                Path::new(exported),
                through.parse().context("invalid archive index")?,
                Path::new(output),
            )
            .await?;
            println!("{}", serde_json::json!({"prune":output}));
        }
        [command, ..] if command == "audit" => anyhow::bail!(
            "usage: kasumid audit status PROFILE | audit export|archives PROFILE REQUEST_JSON OUTPUT_JSON | audit verify PROFILE STREAM_UUID INDEX | audit prune PROFILE EXPORT_PAGE_JSON THROUGH_INDEX OUTPUT_JSON"
        ),
        _ => return Ok(false),
    }
    Ok(true)
}

/// The attempt journal beside `output`, persisted before any dispatch, and
/// its lock. A retry must repeat the original endpoint, credential family,
/// trust and input; a published output is never overwritten.
struct Journal {
    _lock: private_files::ExclusiveLock,
    path: std::path::PathBuf,
    attempt: Attempt,
}
fn journal(
    operation: &str,
    binding: Binding,
    original: serde_json::Value,
    output: &Path,
) -> Result<Journal> {
    let lock = output.with_extension("audit.lock");
    let path = output.with_extension("audit-attempt.json");
    ensure!(
        path != output && lock != output,
        "audit output collides with its attempt journal or lock"
    );
    let lock = private_files::ExclusiveLock::acquire(&lock)?;
    let attempt = if path.exists() {
        let attempt: Attempt =
            serde_json::from_slice(&private_files::read(&path, MAX_SECURITY_AUDIT_PAGE_BYTES)?)?;
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
        private_files::publish(&path, &serde_json::to_vec(&attempt)?)?;
        attempt
    };
    ensure!(
        !output.exists(),
        "audit output already published; choose a new output path"
    );
    Ok(Journal {
        _lock: lock,
        path,
        attempt,
    })
}

/// Prune the archive segments below `through_index`, covered by the export
/// whose last page is `exported`. The request is fixed from that page and
/// journaled before dispatch; repeating the command after an uncertain outcome
/// resends it, and the server prunes nothing more.
async fn prune(
    profile_path: &Path,
    exported: &Path,
    through_index: u64,
    output: &Path,
) -> Result<()> {
    ensure!(output.is_absolute(), "audit prune output must be absolute");
    private_files::check_directory(
        output
            .parent()
            .context("audit prune output has no parent")?,
    )?;
    let profile = ClientProfile::load(profile_path)?;
    let binding = binding(&profile)?;
    let page: SecurityAuditPage = serde_json::from_slice(&crate::runtime::read_bounded(
        exported,
        MAX_SECURITY_AUDIT_PAGE_BYTES,
    )?)?;
    let request = SecurityAuditPruneRequest {
        stream_id: page.stream_id,
        through_index,
        exported: page.resumed(),
    };
    request.validate()?;
    let original = serde_json::to_value(&request)?;
    let journal = journal("prune", binding, original, output)?;
    let request: SecurityAuditPruneRequest =
        serde_json::from_value(journal.attempt.original.clone())?;
    let mut client = kasumi_client::KasumiAdminClient::connect(&profile.connection(true)?).await?;
    let result = client
        .prune_security_audit(&profile.bearer()?, &request)
        .await?;
    private_files::publish(output, &serde_json::to_vec(&result)?)?;
    Ok(())
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
    let Journal {
        _lock,
        path: journal,
        mut attempt,
    } = journal(operation, binding, original, output)?;
    let mut client = kasumi_client::KasumiAdminClient::connect(&profile.connection(true)?).await?;
    if attempt.resolved.is_none() {
        let resolved = match operation {
            "export" => {
                let mut request: SecurityAuditExportRequest =
                    serde_json::from_value(attempt.original.clone())?;
                if request.cursor.is_none() {
                    let status = client.security_audit_status(&profile.bearer()?).await?;
                    request.cursor = Some(status.snapshot_cursor());
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
                        snapshot_head: status
                            .position
                            .archive_head
                            .as_ref()
                            .map(|archive| archive.object.clone()),
                        previous: None,
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
