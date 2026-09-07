//! Opt-in compatibility test against an actual, locally installed OpenBao binary.
//! Starts only loopback listeners, writes no token helper, and kills its child.
use anyhow::{Context, Result, ensure};
use kasumi_store::{
    EncryptedBackup, KeyProvider, NodeStore, TenantStore, TransitConfig, TransitKeyProvider,
    WriteOp,
};
use serde_json::{Value, json};
use std::{path::Path, process::Stdio, sync::Arc, time::Duration};

async fn post(client: &reqwest::Client, endpoint: &str, path: &str, body: Value) -> Result<Value> {
    let response = client
        .post(format!("{endpoint}/v1/{path}"))
        .json(&body)
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "OpenBao setup request failed at {path}: {}",
        response.status()
    );
    let bytes = response.bytes().await?;
    if bytes.is_empty() {
        Ok(Value::Null)
    } else {
        Ok(serde_json::from_slice(&bytes)?)
    }
}

async fn ca_file(path: &Path) -> Result<Vec<u8>> {
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().to_string();
        if name.contains("ca") && name.ends_with(".pem") {
            return Ok(std::fs::read(entry.path())?);
        }
    }
    anyhow::bail!("OpenBao has not generated its development CA yet")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires KASUMI_OPENBAO_BIN pointing to a verified local OpenBao release"]
async fn actual_openbao_transit_roundtrip_rotation_backups_and_warm_revocation() -> Result<()> {
    let binary = std::env::var_os("KASUMI_OPENBAO_BIN").context("set KASUMI_OPENBAO_BIN")?;
    let root = tempfile::tempdir()?;
    let certificate_dir = root.path().join("certificates");
    std::fs::create_dir(&certificate_dir)?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let endpoint = format!("https://127.0.0.1:{port}");
    let root_token = uuid::Uuid::new_v4().to_string();
    let mut child = tokio::process::Command::new(binary)
        .args([
            "server",
            "-dev",
            "-dev-tls",
            "-dev-no-store-token",
            "-log-level=error",
        ])
        .arg(format!("-dev-listen-address=127.0.0.1:{port}"))
        .arg(format!("-dev-tls-cert-dir={}", certificate_dir.display()))
        .env("BAO_DEV_ROOT_TOKEN_ID", &root_token)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let ca = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            ensure!(
                child.try_wait()?.is_none(),
                "OpenBao exited during test startup"
            );
            if let Ok(ca) = ca_file(&certificate_dir).await {
                return Ok(ca);
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await??;
    let mut headers = reqwest::header::HeaderMap::new();
    let mut token_header = reqwest::header::HeaderValue::from_str(&root_token)?;
    token_header.set_sensitive(true);
    headers.insert("X-Vault-Token", token_header);
    let client = reqwest::Client::builder()
        .https_only(true)
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
        .default_headers(headers)
        .timeout(Duration::from_secs(5))
        .no_proxy()
        .build()?;
    tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if client
                .get(format!("{endpoint}/v1/sys/health"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?;
    post(
        &client,
        &endpoint,
        "sys/mounts/transit",
        json!({"type":"transit"}),
    )
    .await?;
    for derived in [false, true] {
        let key_name = if derived {
            "customer-derived"
        } else {
            "customer-ordinary"
        };
        post(
            &client,
            &endpoint,
            &format!("transit/keys/{key_name}"),
            json!({"type":"aes256-gcm96", "derived":derived}),
        )
        .await?;
        let policy = format!(
            "path \"transit/datakey/plaintext/{key_name}\" {{ capabilities = [\"update\"] }}\npath \"transit/decrypt/{key_name}\" {{ capabilities = [\"update\"] }}\npath \"transit/rewrap/{key_name}\" {{ capabilities = [\"update\"] }}"
        );
        post(
            &client,
            &endpoint,
            &format!("sys/policies/acl/{key_name}"),
            json!({"policy":policy}),
        )
        .await?;
        let token_response = post(
            &client,
            &endpoint,
            "auth/token/create",
            json!({"policies":[key_name],"no_default_policy":true,"ttl":"5m"}),
        )
        .await?;
        let service_token = token_response
            .pointer("/auth/client_token")
            .and_then(Value::as_str)
            .context("service token missing")?
            .to_owned();
        let provider = Arc::new(TransitKeyProvider::new(TransitConfig {
            endpoint: endpoint.clone(),
            mount: "transit".into(),
            key_name: key_name.into(),
            token: service_token.clone(),
            namespace: None,
            ca_pem: Some(ca.clone()),
            derived,
        })?);
        let original = provider.generate_key("tenant-a").await?;
        assert_eq!(original.wrapped.version, 1);
        let plaintext = provider.unwrap_key("tenant-a", &original.wrapped).await?;
        assert_eq!(plaintext.as_bytes(), original.plaintext.as_bytes());
        if derived {
            assert!(
                provider
                    .unwrap_key("tenant-b", &original.wrapped)
                    .await
                    .is_err()
            );
        }
        let store = TenantStore::open_fixture(
            NodeStore::open(root.path().join(format!("{key_name}.redb")))?,
            "tenant-a".into(),
            provider.clone(),
        )
        .await?;
        store.write_batch(&[WriteOp::put("documents", b"private-id", b"private-body")])?;
        let before_rotation = store.encrypt_backup(1, b"logical snapshot")?.to_bytes()?;
        post(
            &client,
            &endpoint,
            &format!("transit/keys/{key_name}/rotate"),
            json!({}),
        )
        .await?;
        let rewrapped = provider.rewrap_key("tenant-a", &original.wrapped).await?;
        assert_eq!(rewrapped.version, 2);
        assert_eq!(
            provider
                .unwrap_key("tenant-a", &rewrapped)
                .await?
                .as_bytes(),
            original.plaintext.as_bytes()
        );
        store.rewrap_keys().await?;
        store.refresh_lease().await?;
        let after_rotation = store
            .encrypt_backup(2, b"rotated logical snapshot")?
            .to_bytes()?;
        post(
            &client,
            &endpoint,
            &format!("transit/keys/{key_name}/config"),
            json!({"min_decryption_version":2}),
        )
        .await?;
        assert!(
            provider
                .unwrap_key("tenant-a", &original.wrapped)
                .await
                .is_err()
        );
        assert!(
            EncryptedBackup::from_bytes(&before_rotation, 1 << 20)?
                .decrypt_fixture("tenant-a", provider.clone())
                .await
                .is_err()
        );
        assert_eq!(
            &*EncryptedBackup::from_bytes(&after_rotation, 1 << 20)?
                .decrypt_fixture("tenant-a", provider.clone())
                .await?
                .snapshot,
            b"rotated logical snapshot"
        );
        store.refresh_lease().await?;
        assert_eq!(
            store.get("documents", b"private-id")?.unwrap(),
            b"private-body"
        );
        post(
            &client,
            &endpoint,
            "auth/token/revoke",
            json!({"token":service_token}),
        )
        .await?;
        assert!(store.refresh_lease().await.is_err());
        assert!(store.get("documents", b"private-id").is_err());
    }
    child.kill().await?;
    child.wait().await?;
    Ok(())
}
