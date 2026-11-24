//! Opt-in compatibility test against an actual, locally installed OpenBao binary.
//! Starts only loopback listeners, writes no token helper, and kills its child.
#[path = "support/provider_control.rs"]
mod provider_control;
use anyhow::{Context, Result, ensure};
use kasumi_store::{
    EncryptedBackup, KeyProvider, NodeStore, TenantStore, TransitConfig, TransitKeyProvider,
    WriteOp,
};
use serde_json::{Value, json};
use std::io::Write;
use std::{
    os::unix::fs::OpenOptionsExt,
    path::Path,
    process::Stdio,
    sync::{Arc, RwLock},
    time::Duration,
};
use zeroize::Zeroizing;

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

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?
        .write_all(bytes)?;
    Ok(())
}

type Server = Option<tokio::process::Child>;

fn start_server(binary: &Path, config: &Path, generation: u8) -> Result<Server> {
    if provider_control::supervised() {
        provider_control::request(&format!("start-{generation}"), json!({"config":config}))?;
        return Ok(None);
    }
    Ok(Some(
        tokio::process::Command::new(binary)
            .arg("server")
            .arg("-config")
            .arg(config)
            .arg("-log-level=error")
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()?,
    ))
}

async fn stop_server(child: &mut Server, generation: u8) -> Result<()> {
    if let Some(process) = child {
        process.kill().await?;
        process.wait().await?;
    } else {
        provider_control::request(&format!("stop-{generation}"), Value::Null)?;
    }
    Ok(())
}

async fn ready_sealed(client: &reqwest::Client, endpoint: &str, child: &mut Server) -> Result<()> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Some(process) = child {
                ensure!(
                    process.try_wait()?.is_none(),
                    "OpenBao exited during startup"
                );
            }
            if let Ok(response) = client
                .get(format!("{endpoint}/v1/sys/seal-status"))
                .send()
                .await
                && response.status().is_success()
                && response.json::<Value>().await?["sealed"] == true
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await?
}

async fn scoped_token(
    client: &reqwest::Client,
    endpoint: &str,
    policy: &str,
) -> Result<Zeroizing<String>> {
    let response = post(
        client,
        endpoint,
        "auth/token/create",
        json!({"policies":[policy],"no_default_policy":true,"ttl":"15m"}),
    )
    .await?;
    Ok(Zeroizing::new(
        response
            .pointer("/auth/client_token")
            .and_then(Value::as_str)
            .context("scoped token missing")?
            .to_owned(),
    ))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires KASUMI_OPENBAO_BIN pointing to a verified local OpenBao release"]
async fn actual_openbao_transit_roundtrip_rotation_backups_and_warm_revocation() -> Result<()> {
    let fixture_memory = kasumi_store::test_utils::TestDiskMemory::new(256 << 20, 4096);
    let scratch_directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let fixture_scratch =
        kasumi_store::ScratchDisk::fixture(scratch_directory.path(), fixture_memory.clone());
    let binary = std::env::var_os("KASUMI_OPENBAO_BIN").context("set KASUMI_OPENBAO_BIN")?;
    let root = kasumi_store::test_utils::private_tempdir()?;
    let port = std::net::TcpListener::bind("127.0.0.1:0")?
        .local_addr()?
        .port();
    let endpoint = format!("https://127.0.0.1:{port}");
    let certificate =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;
    let ca = certificate.cert.pem().into_bytes();
    let cert_file = root.path().join("bao.pem");
    let key_file = root.path().join("bao.key");
    write_private(&cert_file, &ca)?;
    write_private(
        &key_file,
        certificate.signing_key.serialize_pem().as_bytes(),
    )?;
    let config = root.path().join("bao.json");
    write_private(
        &config,
        &serde_json::to_vec(&json!({
            "api_addr": endpoint, "disable_mlock": true,
            "storage":{"file":{"path":root.path().join("bao-storage")}},
            "listener":[{"tcp":{"address":format!("127.0.0.1:{port}"),
                "tls_cert_file":cert_file, "tls_key_file":key_file, "tls_min_version":"tls13",
                "tls_disable_client_certs":true, "cluster_address":"127.0.0.1:0"}}]
        }))?,
    )?;
    let builder = || -> Result<reqwest::ClientBuilder> {
        Ok(reqwest::Client::builder()
            .https_only(true)
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .add_root_certificate(reqwest::Certificate::from_pem(&ca)?)
            .timeout(Duration::from_secs(5))
            .no_proxy())
    };
    let public = builder()?.build()?;
    let mut child = start_server(binary.as_ref(), &config, 1)?;
    ready_sealed(&public, &endpoint, &mut child).await?;
    let initialized = post(
        &public,
        &endpoint,
        "sys/init",
        json!({"secret_shares":1,"secret_threshold":1}),
    )
    .await?;
    let unseal = Zeroizing::new(
        initialized
            .pointer("/keys_base64/0")
            .and_then(Value::as_str)
            .context("unseal share missing")?
            .to_owned(),
    );
    let mut token_header = reqwest::header::HeaderValue::from_str(
        initialized["root_token"]
            .as_str()
            .context("root token missing")?,
    )?;
    token_header.set_sensitive(true);
    drop(initialized);
    let opened = post(
        &public,
        &endpoint,
        "sys/unseal",
        json!({"key":unseal.as_str()}),
    )
    .await?;
    ensure!(opened["sealed"] == false, "OpenBao remained sealed");
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert("X-Vault-Token", token_header);
    let client = builder()?.default_headers(headers).build()?;
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
        let first_token = scoped_token(&client, &endpoint, key_name).await?;
        let credentials = Arc::new(RwLock::new(first_token.clone()));
        let provider = Arc::new(TransitKeyProvider::new(TransitConfig {
            endpoint: endpoint.clone(),
            mount: "transit".into(),
            key_name: key_name.into(),
            credential: {
                let credentials = credentials.clone();
                Arc::new(move || Ok(credentials.read().expect("test credential lock").clone()))
            },
            namespace: None,
            ca_pem: ca.clone(),
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
        let store = TenantStore::initialize_catalog_fixture(
            NodeStore::create_new_fixture(
                root.path().join(format!("{key_name}.kv")),
                kasumi_store::test_utils::NODE_STORE_ID,
                fixture_memory.clone(),
                fixture_scratch.clone(),
            )
            .expect("bounded node fixture setup succeeds"),
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
            EncryptedBackup::from_bytes(&before_rotation, 1 << 20, &store)?
                .decrypt_fixture("tenant-a", provider.clone(), &store)
                .await
                .is_err()
        );
        assert_eq!(
            &*EncryptedBackup::from_bytes(&after_rotation, 1 << 20, &store)?
                .decrypt_fixture("tenant-a", provider.clone(), &store)
                .await?
                .snapshot,
            b"rotated logical snapshot"
        );
        store.refresh_lease().await?;
        assert_eq!(
            store.get("documents", b"private-id")?.unwrap(),
            b"private-body"
        );
        let replacement = scoped_token(&client, &endpoint, key_name).await?;
        ensure!(
            replacement.as_str() != first_token.as_str(),
            "replacement token was reused"
        );
        post(
            &client,
            &endpoint,
            "auth/token/revoke",
            json!({"token":first_token.as_str()}),
        )
        .await?;
        ensure!(
            provider.unwrap_key("tenant-a", &rewrapped).await.is_err(),
            "revoked initial token was accepted"
        );
        *credentials.write().expect("test credential lock") = replacement.clone();
        store.refresh_lease().await?;
        assert_eq!(
            provider
                .unwrap_key("tenant-a", &rewrapped)
                .await?
                .as_bytes(),
            original.plaintext.as_bytes()
        );
        if derived {
            stop_server(&mut child, 1).await?;
            ensure!(
                provider.unwrap_key("tenant-a", &rewrapped).await.is_err(),
                "stopped provider returned a key"
            );
            child = start_server(binary.as_ref(), &config, 2)?;
            ready_sealed(&public, &endpoint, &mut child).await?;
            let opened = post(
                &public,
                &endpoint,
                "sys/unseal",
                json!({"key":unseal.as_str()}),
            )
            .await?;
            ensure!(
                opened["sealed"] == false,
                "restarted provider remained sealed"
            );
            assert_eq!(
                provider
                    .unwrap_key("tenant-a", &rewrapped)
                    .await?
                    .as_bytes(),
                original.plaintext.as_bytes()
            );
            store.refresh_lease().await?;
            assert_eq!(
                store.get("documents", b"private-id")?.unwrap(),
                b"private-body"
            );
        }
        post(
            &client,
            &endpoint,
            "auth/token/revoke",
            json!({"token":replacement.as_str()}),
        )
        .await?;
        assert!(store.refresh_lease().await.is_err());
        assert!(store.get("documents", b"private-id").is_err());
    }
    stop_server(&mut child, 2).await?;
    if provider_control::supervised() {
        provider_control::request("complete", Value::Null)?;
    }
    Ok(())
}
