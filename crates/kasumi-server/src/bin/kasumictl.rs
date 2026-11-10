//! Administrative operations use the separate, pinned TLS 1.3/mTLS gRPC endpoint.
//! Tokens are loaded from a private installed file for every request.
use anyhow::{Context, Result, bail, ensure};
use kasumi_server::{
    api::MAX_REQUEST_BYTES,
    rpc::proto::{
        CollectionDefinitionRequest, ManagementRequest, ReadPolicyLimitsRequest, ReadSchemaRequest,
        SchemaActivationStatusRequest, SchemaChangeSetRequest, SetLimitsRequest, SetPolicyRequest,
        SetSuspendedRequest,
    },
    runtime::AdminClientConfig,
};
use std::io::Read;

fn read_json(path: &str) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path).context("opening operation JSON")?;
    ensure!(
        file.metadata()?.len() <= MAX_REQUEST_BYTES as u64,
        "operation file exceeds request limit"
    );
    let mut bytes = Vec::new();
    file.take(MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_REQUEST_BYTES,
        "operation file exceeds request limit"
    );
    let _: serde_json::Value = serde_json::from_slice(&bytes).context("invalid operation JSON")?;
    Ok(bytes)
}
/// Deadline for observations and single catalog/policy writes.
const ADMIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
/// Management commands (backup, key rotation and rewrap, membership) and
/// schema activation run inside the RPC; an expired client deadline resets
/// the stream and cancels that work on the server.
const LONG_ADMIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

fn request<T>(
    message: T,
    authorization: &tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
) -> tonic::Request<T> {
    request_within(message, authorization, ADMIN_TIMEOUT)
}

fn request_within<T>(
    message: T,
    authorization: &tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
    timeout: std::time::Duration,
) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", authorization.clone());
    request.set_timeout(timeout);
    request
}

fn leader_hint(status: &tonic::Status) {
    if let Some(leader) = status
        .metadata()
        .get("kasumi-leader-node-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    {
        eprintln!(
            "Select the configured endpoint for leader node {leader}; preserve the idempotency key when retrying."
        );
    }
}

/// Why an administrative read failed. The server's own error says what to
/// correct (a stale incarnation, a missing grant); the gRPC code alone does not.
fn observation_failure(status: &tonic::Status) -> anyhow::Error {
    match serde_json::from_slice::<kasumi_types::Error>(status.details()) {
        Ok(error) => anyhow::anyhow!("administrative observation failed: {error}"),
        Err(_) => anyhow::anyhow!("administrative observation failed ({})", status.code()),
    }
}

/// Commands that use the administrative endpoint. After `--profile`, one of
/// these selects administration through that installed profile; any other
/// command after `--profile` is a data command.
const ADMINISTRATIVE_OPERATIONS: [&str; 15] = [
    "health",
    "ready",
    "metrics",
    "compact",
    "activate-schema",
    "read-schema",
    "read-policy-limits",
    "schema-status",
    "create-collection",
    "replace-collection",
    "set-policy",
    "set-limits",
    "suspend",
    "resume",
    "manage",
];

/// `--profile <profile.json> <administrative operation> ...`.
fn selects_profile_administration(arguments: &[std::ffi::OsString]) -> bool {
    matches!(
        arguments,
        [flag, _, operation, ..]
            if flag == "--profile"
                && operation
                    .to_str()
                    .is_some_and(|operation| ADMINISTRATIVE_OPERATIONS.contains(&operation))
    )
}

/// The administrative client of `--config <client.json>` or of an installed
/// `--profile <profile.json>`.
fn admin_client(flag: &str, path: &str) -> Result<AdminClientConfig> {
    match flag {
        "--config" => AdminClientConfig::load(path),
        "--profile" => AdminClientConfig::from_profile(
            &kasumi_client::ClientProfile::load(std::path::Path::new(path))
                .with_context(|| format!("loading installed profile {path}"))?,
        ),
        _ => bail!("first argument must be --config or --profile\n{USAGE}"),
    }
}

fn main() -> std::process::ExitCode {
    kasumi_server::process_runtime::block_on(async_main)
}

async fn async_main() -> std::process::ExitCode {
    let arguments = std::env::args_os().skip(1).collect::<Vec<_>>();
    if !selects_profile_administration(&arguments)
        && arguments
            .first()
            .is_some_and(|first| kasumi_server::data_cli::selects_data(first))
    {
        // Data commands print one JSON document and exit with its class
        // status, including for arguments that are not UTF-8.
        let status = kasumi_server::data_cli::run(arguments, &mut std::io::stdout().lock()).await;
        return std::process::ExitCode::from(status);
    }
    let Some(arguments) = arguments
        .into_iter()
        .map(|argument| argument.into_string().ok())
        .collect::<Option<Vec<_>>>()
    else {
        eprintln!("Error: arguments must be UTF-8");
        return std::process::ExitCode::FAILURE;
    };
    match run(&arguments).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:?}");
            std::process::ExitCode::FAILURE
        }
    }
}

const USAGE: &str = "\
usage: kasumictl <command>

Offline:
  schema-reference <operation.json>          canonical digest of a schema change
  example-config                             an admin client profile template

Every command below takes either an admin client file (--config <client.json>)
or an installed client profile (--profile <profile.json>, such as a standalone
installation's profiles/operator.json), except authority-maintenance, which
takes --config only.

Node status (prints the protected endpoint's body and exits 1 unless it
answered 200):
  --config <client.json> health              startup completed and serving
  --config <client.json> ready               every local group covered and admitted
  --config <client.json> metrics             Prometheus text

Storage:
  --config <client.json> compact             start a compaction cycle on every node database
                                             at its next step, clearing any deferral backoff

Administration:
  --config <client.json> activate-schema|read-schema|read-policy-limits|schema-status <operation.json>
  --config <client.json> create-collection|replace-collection|set-policy|set-limits <operation.json>
  --config <client.json> suspend|resume
  --config <client.json> manage <command.json>
  --config <client.json> authority-maintenance <request.json>

  help, --help, -h                           print this help";

async fn run(arguments: &[String]) -> Result<()> {
    if matches!(
        arguments.first().map(String::as_str),
        Some("help" | "--help" | "-h")
    ) {
        println!(
            "{USAGE}\n\nData commands:\n{}",
            kasumi_server::data_cli::USAGE
        );
        return Ok(());
    }
    if let [flag, path, operation] = arguments
        && matches!(flag.as_str(), "--config" | "--profile")
        && operation == "compact"
    {
        let (status, body) = admin_client(flag, path)?.request_compaction().await?;
        println!("{body}");
        ensure!(status == 200, "compaction request answered HTTP {status}");
        return Ok(());
    }
    if let [flag, path, operation] = arguments
        && matches!(flag.as_str(), "--config" | "--profile")
        && matches!(operation.as_str(), "health" | "ready" | "metrics")
    {
        let (status, body) = admin_client(flag, path)?
            .observe(&format!("/{operation}"))
            .await?;
        print!("{body}");
        ensure!(status == 200, "{operation} answered HTTP {status}");
        return Ok(());
    }
    if let [operation, path] = arguments
        && operation == "schema-reference"
    {
        // Offline preparation uses the same typed canonical digest as activation
        // and permanent status; no configuration or credentials are loaded.
        let change: kasumi_types::SchemaChangeSet = serde_json::from_slice(&read_json(path)?)?;
        println!("{}", serde_json::to_string(&change.reference()?)?);
        return Ok(());
    }
    if arguments == ["example-config"] {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "endpoint":"https://admin.kasumi.example:9445",
                "identity":{"certificate":"/etc/kasumi/admin-client.pem","private_key":"/etc/kasumi/admin-client-key.pem"},
                "server_ca":"/etc/kasumi/server-ca.pem","server_certificate_pins":["REPLACE_WITH_64_DIGIT_SERVER_CERTIFICATE_SHA256"],
                "token_file":"/etc/kasumi/credentials/admin-token"
            }))?
        );
        return Ok(());
    }
    let [flag, path, operation, rest @ ..] = arguments else {
        bail!("{USAGE}");
    };
    ensure!(
        matches!(flag.as_str(), "--config" | "--profile"),
        "first argument must be --config or --profile"
    );
    if operation == "authority-maintenance" {
        ensure!(
            flag == "--config",
            "authority-maintenance requires an authority client file (--config)"
        );
        let [file] = rest else {
            bail!("authority-maintenance requires one typed request JSON file");
        };
        let request: kasumi_serving::AuthorityMaintenanceRequest =
            serde_json::from_slice(&read_json(file)?)?;
        request.validate()?;
        let mut client =
            kasumi_server::authority_client::AuthorityClientConfig::load(path)?.pool()?;
        let response = client
            .maintenance(&request, std::time::Duration::from_secs(40))
            .await?;
        println!("{}", serde_json::to_string_pretty(&response)?);
        return Ok(());
    }
    let payload = match (operation.as_str(), rest) {
        (
            "activate-schema" | "read-schema" | "read-policy-limits" | "schema-status"
            | "create-collection" | "replace-collection" | "set-policy" | "set-limits" | "manage",
            [file],
        ) => Some(read_json(file)?),
        ("suspend" | "resume", []) => None,
        _ => bail!("unsupported administrative command or argument count"),
    };
    // Parse typed payloads before connecting; exact JSON bytes still go on the wire.
    if let Some(bytes) = &payload {
        match operation.as_str() {
            "activate-schema" => {
                serde_json::from_slice::<kasumi_types::SchemaChangeSet>(bytes)?;
            }
            "read-schema" => {
                serde_json::from_slice::<kasumi_types::ReadSchema>(bytes)?;
            }
            "read-policy-limits" => {
                serde_json::from_slice::<kasumi_types::ReadPolicyLimits>(bytes)?;
            }
            "schema-status" => {
                serde_json::from_slice::<kasumi_types::ReadSchemaActivation>(bytes)?;
            }
            "create-collection" | "replace-collection" => {
                serde_json::from_slice::<kasumi_types::CollectionDefinition>(bytes)?;
            }
            "set-policy" => {
                serde_json::from_slice::<kasumi_types::Policy>(bytes)?;
            }
            "manage" => {
                serde_json::from_slice::<kasumi_server::administration::ManagementCommand>(bytes)?;
            }
            "set-limits" => {
                serde_json::from_slice::<kasumi_types::Limits>(bytes)?;
            }
            _ => unreachable!(),
        }
    }
    let expected_policy_limits = if operation == "read-policy-limits" {
        Some(serde_json::from_slice::<kasumi_types::ReadPolicyLimits>(
            payload.as_deref().unwrap(),
        )?)
    } else {
        None
    };
    let (mut client, authorization) = admin_client(flag, path)?.connect().await?;
    if matches!(
        operation.as_str(),
        "read-schema" | "read-policy-limits" | "schema-status"
    ) {
        let result = if operation == "read-schema" {
            client
                .read_schema(request(
                    ReadSchemaRequest {
                        request_json: payload.unwrap(),
                    },
                    &authorization,
                ))
                .await
                .map(|response| response.into_inner().response_json)
        } else if operation == "read-policy-limits" {
            client
                .read_policy_limits(request(
                    ReadPolicyLimitsRequest {
                        request_json: payload.unwrap(),
                    },
                    &authorization,
                ))
                .await
                .map(|response| response.into_inner().response_json)
        } else {
            client
                .schema_activation_status(request(
                    SchemaActivationStatusRequest {
                        request_json: payload.unwrap(),
                    },
                    &authorization,
                ))
                .await
                .map(|response| response.into_inner().response_json)
        }
        .map_err(|status| {
            leader_hint(&status);
            observation_failure(&status)
        })?;
        if let Some(expected) = expected_policy_limits {
            let snapshot: kasumi_types::PolicyLimitsSnapshot = serde_json::from_slice(&result)?;
            ensure!(
                snapshot.tenant == expected.tenant
                    && snapshot.incarnation == expected.expected_incarnation,
                "policy/limits readback identity differs from the requested database"
            );
            println!("{}", serde_json::to_string(&snapshot)?);
        } else {
            let result: serde_json::Value = serde_json::from_slice(&result)?;
            println!("{}", serde_json::to_string(&result)?);
        }
        return Ok(());
    }
    if operation == "manage" {
        let response = client
            .manage(request_within(
                ManagementRequest {
                    command_json: payload.unwrap(),
                },
                &authorization,
                LONG_ADMIN_TIMEOUT,
            ))
            .await
            .map_err(|status| {
                leader_hint(&status);
                serde_json::from_slice::<kasumi_types::Error>(status.details())
                    .map(anyhow::Error::new)
                    .unwrap_or_else(|_| {
                        anyhow::anyhow!("administrative request failed; outcome may be unknown")
                    })
            })?
            .into_inner();
        let result: serde_json::Value = serde_json::from_slice(&response.result_json)?;
        println!("{}", serde_json::to_string(&result)?);
        return Ok(());
    }
    let result = match operation.as_str() {
        "activate-schema" => {
            client
                .activate_schema(request_within(
                    SchemaChangeSetRequest {
                        request_json: payload.unwrap(),
                    },
                    &authorization,
                    LONG_ADMIN_TIMEOUT,
                ))
                .await
        }
        "create-collection" => {
            client
                .create_collection(request(
                    CollectionDefinitionRequest {
                        definition_json: payload.unwrap(),
                    },
                    &authorization,
                ))
                .await
        }
        "replace-collection" => {
            client
                .replace_collection(request(
                    CollectionDefinitionRequest {
                        definition_json: payload.unwrap(),
                    },
                    &authorization,
                ))
                .await
        }
        "set-policy" => {
            client
                .set_policy(request(
                    SetPolicyRequest {
                        policy_json: payload.unwrap(),
                    },
                    &authorization,
                ))
                .await
        }
        "set-limits" => {
            client
                .set_limits(request(
                    SetLimitsRequest {
                        limits_json: payload.unwrap(),
                    },
                    &authorization,
                ))
                .await
        }
        "suspend" | "resume" => {
            client
                .set_suspended(request(
                    SetSuspendedRequest {
                        suspended: operation == "suspend",
                    },
                    &authorization,
                ))
                .await
        }
        _ => unreachable!(),
    };
    match result {
        Ok(response) => {
            let receipt = kasumi_client::decode_native_write_receipt(response.into_inner())?;
            println!("{}", serde_json::to_string(&receipt)?);
            Ok(())
        }
        Err(status) => {
            leader_hint(&status);
            if let Ok(error) = serde_json::from_slice::<kasumi_types::Error>(status.details()) {
                bail!("{}", error);
            }
            bail!(
                "administrative request failed ({}); result may be unknown; inspect current state before retrying",
                status.code()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kasumi_types::{ReadAssertion, ReadSchemaActivation, SchemaActivationRef};
    use serde_json::json;

    #[tokio::test]
    async fn schema_reference_is_offline_and_rejects_malformed_effects() {
        let directory = tempfile::tempdir().unwrap();
        let operation = directory.path().join("activation.json");
        let payload = json!({
            "activation_id": "local-core-schema-1",
            "expected_incarnation": "54b2e0dd-135a-439e-b053-38ba6cba2310",
            "expected_schema_epoch": 1,
            "read_set": [],
            "changes": [{"kind":"create", "definition": {
                "name":"records", "write_mode":"mutable", "retention_class":"operational",
                "strict_read_audit":true, "schema":{"type":"object"}, "indexes":[]
            }}]
        });
        std::fs::write(&operation, serde_json::to_vec(&payload).unwrap()).unwrap();
        run(&["schema-reference".into(), operation.display().to_string()])
            .await
            .unwrap();
        let original: kasumi_types::SchemaChangeSet =
            serde_json::from_value(payload.clone()).unwrap();
        let first = original.reference().unwrap();
        assert_eq!(first.activation_id, "local-core-schema-1");
        assert_eq!(first.request_digest.len(), 64);
        let mut changed = payload.clone();
        changed["changes"][0]["definition"]["strict_read_audit"] = json!(false);
        let changed: kasumi_types::SchemaChangeSet = serde_json::from_value(changed).unwrap();
        assert_ne!(
            first.request_digest,
            changed.reference().unwrap().request_digest
        );
        for invalid in [
            json!({"activation_id":"local-core-schema-1"}),
            json!({"reference":first}),
            {
                let mut extra = payload.clone();
                extra["extra"] = json!(true);
                extra
            },
        ] {
            std::fs::write(&operation, serde_json::to_vec(&invalid).unwrap()).unwrap();
            let error = run(&["schema-reference".into(), operation.display().to_string()])
                .await
                .unwrap_err();
            assert!(error.downcast_ref::<serde_json::Error>().is_some());
        }
        assert!(run(&["schema-reference".into()]).await.is_err());
        assert!(
            run(&[
                "schema-reference".into(),
                operation.display().to_string(),
                "extra".into()
            ])
            .await
            .is_err()
        );
    }

    #[test]
    fn a_failed_administrative_read_reports_the_servers_reason() {
        let refused = tonic::Status::with_details(
            tonic::Code::PermissionDenied,
            "peer text",
            serde_json::to_vec(&kasumi_types::Error::new(
                kasumi_types::ErrorCode::Forbidden,
                "principal lacks the schema read grant",
            ))
            .unwrap()
            .into(),
        );
        assert_eq!(
            observation_failure(&refused).to_string(),
            "administrative observation failed: Forbidden: principal lacks the schema read grant"
        );
        // A status without a Kasumi error keeps the gRPC code as its only reason.
        let unreachable = tonic::Status::unavailable("peer text");
        let message = observation_failure(&unreachable).to_string();
        assert!(
            message.starts_with("administrative observation failed (") && !message.contains("peer"),
            "{message}"
        );
    }

    #[test]
    fn an_installed_profile_selects_administration_only_for_administrative_commands() {
        let arguments = |line: &str| {
            line.split(' ')
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        };
        for administrative in [
            "--profile /p/operator.json create-collection c.json",
            "--profile /p/operator.json manage m.json",
            "--profile /p/control.json metrics",
            "--profile /p/operator.json suspend",
        ] {
            assert!(selects_profile_administration(&arguments(administrative)));
        }
        for data in [
            "--profile /p/default.json collections",
            "--profile /p/default.json get docs a",
            "--profile /p/default.json --expect-tenant t get docs a",
            "--expect-tenant t --profile /p/default.json create-collection c.json",
            "--config /c.json create-collection c.json",
            "--profile",
        ] {
            assert!(!selects_profile_administration(&arguments(data)), "{data}");
        }
    }

    #[tokio::test]
    async fn profile_administration_loads_the_profile_and_refuses_authority_maintenance() {
        let error = run(&[
            "--profile".into(),
            "/nonexistent/operator.json".into(),
            "suspend".into(),
        ])
        .await
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("/nonexistent/operator.json"),
            "{error:#}"
        );
        let error = run(&[
            "--profile".into(),
            "/nonexistent/operator.json".into(),
            "authority-maintenance".into(),
            "/nonexistent/request.json".into(),
        ])
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("requires an authority client file"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn data_commands_are_parsed_before_the_profile_is_read() {
        async fn data(command: &[&str]) -> (u8, serde_json::Value) {
            let command = ["--profile", "/nonexistent/profile.json"]
                .iter()
                .chain(command)
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>();
            let mut out = Vec::new();
            let status = kasumi_server::data_cli::run(command, &mut out).await;
            (status, serde_json::from_slice(&out).unwrap())
        }
        let (status, document) = data(&["fetch", "docs"]).await;
        assert_eq!(status, 2);
        assert_eq!(document["ok"], json!(false));
        assert_eq!(document["error"]["class"], json!("invalid_request"));
        let message = document["error"]["message"].as_str().unwrap();
        assert!(message.contains("unknown data command"), "{message}");
        let (status, document) = data(&["get", "docs", "a"]).await;
        assert_eq!(
            status, 3,
            "a valid command reaches profile loading: {document}"
        );
        assert_eq!(document["error"]["class"], json!("profile_rejected"));
        let message = document["error"]["message"].as_str().unwrap();
        assert!(message.contains("/nonexistent/profile.json"), "{message}");
    }

    fn lookup() -> ReadSchemaActivation {
        ReadSchemaActivation {
            reference: SchemaActivationRef {
                activation_id: "installation-schema-1".into(),
                request_digest: "a".repeat(64),
            },
            read_set: vec![
                ReadAssertion::Snapshot {
                    incarnation: "54b2e0dd-135a-439e-b053-38ba6cba2310".into(),
                    policy_epoch: 3,
                    schema_epoch: 2,
                },
                ReadAssertion::Before {
                    not_after_ms: 1_800_000_000_000,
                },
            ],
        }
    }

    async fn status_with_missing_config(bytes: &[u8]) -> (anyhow::Error, String) {
        let directory = tempfile::tempdir().unwrap();
        let operation = directory.path().join("lookup.json");
        let configuration = directory.path().join("missing-client.json");
        std::fs::write(&operation, bytes).unwrap();
        let error = run(&[
            "--config".into(),
            configuration.to_str().unwrap().into(),
            "schema-status".into(),
            operation.to_str().unwrap().into(),
        ])
        .await
        .unwrap_err();
        (error, configuration.display().to_string())
    }

    #[tokio::test]
    async fn schema_status_accepts_current_fenced_lookup_before_loading_configuration() {
        // Exercise the actual command path with the current SDK/server request.
        // A nonexistent configuration prevents any connection or credential read.
        let bytes = serde_json::to_vec_pretty(&lookup()).unwrap();
        let (error, configuration) = status_with_missing_config(&bytes).await;
        assert_eq!(error.to_string(), format!("opening {configuration}"));
        assert_eq!(
            error.downcast_ref::<std::io::Error>().unwrap().kind(),
            std::io::ErrorKind::NotFound
        );
    }

    #[tokio::test]
    async fn schema_status_rejects_unfenced_or_malformed_lookup_before_configuration() {
        let current = serde_json::to_value(lookup()).unwrap();
        let reference = current["reference"].clone();
        for invalid in [
            reference.clone(),
            json!({"reference": reference}),
            json!({"reference": current["reference"], "read_set": null}),
            json!({"reference": current["reference"], "read_set": [], "extra": true}),
            json!({"reference": current["reference"], "read_set": [{"kind": "before"}]}),
        ] {
            let (error, _) =
                status_with_missing_config(&serde_json::to_vec(&invalid).unwrap()).await;
            assert!(
                error.downcast_ref::<serde_json::Error>().is_some(),
                "invalid lookup reached configuration loading: {error:#}"
            );
        }
    }
}
