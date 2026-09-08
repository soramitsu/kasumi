//! Administrative operations use the separate, pinned TLS 1.3/mTLS gRPC endpoint.
//! Tokens are loaded from a private installed file for every request.
use anyhow::{Context, Result, bail, ensure};
use kasumi_server::{
    api::MAX_REQUEST_BYTES,
    rpc::proto::{
        CollectionDefinitionRequest, ManagementRequest, ReadSchemaRequest,
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
    if arguments.as_slice() == ["example-config"] {
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
    let [flag, path, operation, rest @ ..] = arguments.as_slice() else {
        bail!(
            "usage: kasumictl --config <client.json> activate-schema|read-schema|schema-status|create-collection|replace-collection|set-policy|set-limits <operation.json>, or suspend|resume, or manage <command.json>, or authority-maintenance <request.json>"
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
            "activate-schema" | "read-schema" | "schema-status" | "create-collection"
            | "replace-collection" | "set-policy" | "set-limits" | "manage",
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
            "schema-status" => {
                serde_json::from_slice::<kasumi_types::SchemaActivationRef>(bytes)?;
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
    let (mut client, authorization) = AdminClientConfig::load(path)?.connect().await?;
    if matches!(operation.as_str(), "read-schema" | "schema-status") {
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
            anyhow::anyhow!("schema observation failed ({})", status.code())
        })?;
        let result: serde_json::Value = serde_json::from_slice(&result)?;
        println!("{}", serde_json::to_string(&result)?);
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
            let receipt = response.into_inner();
            println!(
                "{}",
                serde_json::to_string(
                    &serde_json::json!({"revision":receipt.revision,"versions":receipt.versions})
                )?
            );
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
