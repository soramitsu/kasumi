//! Backup identities survive process loss; cleanup always targets an explicit
//! permanently aborted session through the authenticated administrative API.
use crate::standalone::ClientProfile;
use anyhow::{Context, Result, ensure};
use kasumi_client::KasumiAdminClient;
use kasumi_store::private_files;
use kasumi_types::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use uuid::Uuid;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
    tenant: String,
    resource: CredentialResource,
    endpoint: String,
    server_pin: String,
    client_pin: String,
    ca_sha256: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Creation {
    format: u32,
    binding: Binding,
    destination: String,
    session_id: Uuid,
}
fn binding(
    profile: &ClientProfile,
    connection: &kasumi_client::KasumiClientConfig,
) -> Result<Binding> {
    ensure!(
        matches!(profile.resource, CredentialResource::Database { .. }),
        "backup requires an application database profile"
    );
    Ok(Binding {
        tenant: profile.tenant.clone(),
        resource: profile.resource.clone(),
        endpoint: connection.endpoint.clone(),
        server_pin: profile.admin_certificate_pin.clone(),
        client_pin: hex::encode(connection.identity.certificate_pin()),
        ca_sha256: hex::encode(Sha256::digest(&connection.trusted_ca_pem)),
    })
}
async fn client(path: &Path) -> Result<(ClientProfile, KasumiAdminClient)> {
    let profile = ClientProfile::load(path)?;
    let connection = profile.connection(true)?;
    binding(&profile, &connection)?;
    let client = KasumiAdminClient::connect(&connection).await?;
    Ok((profile, client))
}
pub(crate) async fn command(arguments: &[String]) -> Result<bool> {
    match arguments {
        [command, action, profile, destination, output]
            if command == "backup" && action == "create" =>
        {
            let checkpoint = create(Path::new(profile), destination, Path::new(output)).await?;
            println!(
                "{}",
                serde_json::json!({"checkpoint":output,"session_id":checkpoint.backup_id})
            );
        }
        [command, action, profile, destination, session]
            if command == "backup" && action == "status" =>
        {
            let (profile, mut client) = client(Path::new(profile)).await?;
            let status = client
                .backup_session_status(
                    &profile.bearer()?,
                    &BackupSessionRequest {
                        destination: destination.clone(),
                        session_id: Uuid::parse_str(session)?,
                    },
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        [command, action, profile, destination, session]
            if command == "backup" && action == "verify" =>
        {
            let (profile, mut client) = client(Path::new(profile)).await?;
            let proof = client
                .verify_backup_checkpoint(
                    &profile.bearer()?,
                    &VerifyBackupCheckpoint {
                        destination: destination.clone(),
                        backup_id: Uuid::parse_str(session)?,
                    },
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(proof.checkpoint())?);
        }
        [command, action, profile, destination, session, reason]
            if command == "backup" && action == "abort" =>
        {
            let (profile, mut client) = client(Path::new(profile)).await?;
            let status = client
                .abort_backup_session(
                    &profile.bearer()?,
                    &AbortBackupSession {
                        destination: destination.clone(),
                        session_id: Uuid::parse_str(session)?,
                        reason: reason.clone(),
                    },
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&status)?);
        }
        [command, action, profile, destination, session, maximum]
            if command == "backup" && action == "cleanup" =>
        {
            let maximum: usize = maximum.parse()?;
            ensure!((1..=256).contains(&maximum), "cleanup limit must be 1..256");
            let (profile, mut client) = client(Path::new(profile)).await?;
            let result = client
                .cleanup_backup_session(
                    &profile.bearer()?,
                    &CleanupBackupSession {
                        destination: destination.clone(),
                        session_id: Uuid::parse_str(session)?,
                        max_objects: maximum,
                    },
                )
                .await?;
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        [command, ..] if command == "backup" => anyhow::bail!(
            "usage: kasumid backup create PROFILE DESTINATION CHECKPOINT_JSON | backup status|verify PROFILE DESTINATION SESSION_UUID | backup abort PROFILE DESTINATION SESSION_UUID REASON | backup cleanup PROFILE DESTINATION SESSION_UUID MAX_OBJECTS"
        ),
        _ => return Ok(false),
    }
    Ok(true)
}
async fn create(
    profile_path: &Path,
    destination: &str,
    output: &Path,
) -> Result<FullBackupCheckpoint> {
    ensure!(
        output.is_absolute(),
        "backup checkpoint output must be absolute"
    );
    private_files::check_directory(output.parent().context("checkpoint has no parent")?)?;
    validate_name(destination)?;
    let profile = ClientProfile::load(profile_path)?;
    let connection = profile.connection(true)?;
    let binding = binding(&profile, &connection)?;
    let lock = output.with_extension("backup.lock");
    let journal = output.with_extension("backup-attempt.json");
    ensure!(
        lock != output && journal != output,
        "backup output collides with its journal or lock"
    );
    let _lock = private_files::ExclusiveLock::acquire(&lock)?;
    let creation = if journal.exists() {
        let creation: Creation =
            serde_json::from_slice(&private_files::read(&journal, 128 << 10)?)?;
        ensure!(
            creation.format == 1
                && !creation.session_id.is_nil()
                && creation.binding == binding
                && creation.destination == destination,
            "backup retry differs from its original destination, resource, endpoint or trust"
        );
        creation
    } else {
        ensure!(
            !output.exists(),
            "existing checkpoint has no creation journal"
        );
        let creation = Creation {
            format: 1,
            binding,
            destination: destination.into(),
            session_id: Uuid::new_v4(),
        };
        private_files::publish(&journal, &serde_json::to_vec(&creation)?)?;
        creation
    };
    // A new invocation obtains fresh authentication while retaining the exact
    // session. The server resolves a published root before any completion/abort.
    let mut client = KasumiAdminClient::connect(&connection).await?;
    let proof = client
        .create_backup_checkpoint(
            &profile.bearer()?,
            &CreateBackupCheckpoint {
                destination: destination.into(),
                session_id: creation.session_id,
            },
        )
        .await?;
    let checkpoint = proof.checkpoint();
    ensure!(
        checkpoint.tenant == profile.tenant,
        "backup checkpoint tenant differs"
    );
    if let CredentialResource::Database { incarnation } = profile.resource {
        ensure!(
            checkpoint.source_incarnation == incarnation.to_string(),
            "backup source incarnation differs"
        );
    }
    if output.exists() {
        let previous: FullBackupCheckpoint =
            serde_json::from_slice(&private_files::read(output, 128 << 10)?)?;
        ensure!(
            &previous == checkpoint,
            "published backup checkpoint differs from original session"
        );
    } else {
        private_files::publish(output, &serde_json::to_vec_pretty(checkpoint)?)?;
    }
    Ok(checkpoint.clone())
}
