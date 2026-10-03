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
fn request<T>(
    message: T,
    authorization: &tonic::metadata::MetadataValue<tonic::metadata::Ascii>,
) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request
        .metadata_mut()
        .insert("authorization", authorization.clone());
    request.set_timeout(std::time::Duration::from_secs(15));
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

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    run(&arguments).await
}

async fn run(arguments: &[String]) -> Result<()> {
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
        bail!(
            "usage: kasumictl schema-reference <operation.json> | kasumictl --config <client.json> activate-schema|read-schema|read-policy-limits|schema-status|create-collection|replace-collection|set-policy|set-limits <operation.json>, or suspend|resume, or manage <command.json>, or authority-maintenance <request.json>"
        );
    };
    ensure!(flag == "--config", "first argument must be --config");
    if operation == "authority-maintenance" {
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
    let (mut client, authorization) = AdminClientConfig::load(path)?.connect().await?;
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
            anyhow::anyhow!("administrative observation failed ({})", status.code())
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
            .manage(request(
                ManagementRequest {
                    command_json: payload.unwrap(),
                },
                &authorization,
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
                .activate_schema(request(
                    SchemaChangeSetRequest {
                        request_json: payload.unwrap(),
                    },
                    &authorization,
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
