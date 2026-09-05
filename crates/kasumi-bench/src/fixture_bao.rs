//! Actual loopback OpenBao process for authenticated network measurements.
//! No global environment mutation, token helper, system trust changes, or secret output.
use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

pub struct BaoFixture {
    child: tokio::process::Child,
    root: tempfile::TempDir,
    client: reqwest::Client,
    pub endpoint: String,
    pub ca_path: PathBuf,
    pub ca_pem: Vec<u8>,
}

impl BaoFixture {
    pub async fn start(binary: &Path) -> Result<Self> {
        ensure!(binary.is_file(), "verified OpenBao binary does not exist");
        let root = tempfile::tempdir()?;
        let cert_dir = root.path().join("bao-certificates");
        std::fs::create_dir(&cert_dir)?;
        let port = std::net::TcpListener::bind("127.0.0.1:0")?
            .local_addr()?
            .port();
        let endpoint = format!("https://127.0.0.1:{port}");
        let root_token = zeroize::Zeroizing::new(uuid::Uuid::new_v4().to_string());
        let mut child = tokio::process::Command::new(binary)
            .args([
                "server",
                "-dev",
                "-dev-tls",
                "-dev-no-store-token",
                "-log-level=error",
            ])
            .arg(format!("-dev-listen-address=127.0.0.1:{port}"))
            .arg(format!("-dev-tls-cert-dir={}", cert_dir.display()))
            .env("BAO_DEV_ROOT_TOKEN_ID", root_token.as_str())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()?;
        let ca_path = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                ensure!(
                    child.try_wait()?.is_none(),
                    "OpenBao exited during fixture startup"
                );
                for entry in std::fs::read_dir(&cert_dir)? {
                    let entry = entry?;
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.contains("ca") && name.ends_with(".pem") && entry.metadata()?.len() > 0
                    {
                        return Ok(entry.path());
                    }
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await??;
        let ca_pem = std::fs::read(&ca_path)?;
        let mut headers = reqwest::header::HeaderMap::new();
        let mut token_header = reqwest::header::HeaderValue::from_str(&root_token)?;
        token_header.set_sensitive(true);
        headers.insert("X-Vault-Token", token_header);
        let client = reqwest::Client::builder()
            .https_only(true)
            .no_proxy()
            .min_tls_version(reqwest::tls::Version::TLS_1_3)
            .add_root_certificate(reqwest::Certificate::from_pem(&ca_pem)?)
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .build()?;
        tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if client
                    .get(format!("{endpoint}/v1/sys/health"))
                    .send()
                    .await
                    .is_ok_and(|response| response.status().is_success())
                {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .context("OpenBao readiness deadline")?;
        let fixture = Self {
            child,
            root,
            client,
            endpoint,
            ca_path,
            ca_pem,
        };
        fixture
            .post("sys/mounts/transit", json!({"type":"transit"}))
            .await?;
        Ok(fixture)
    }

    pub fn directory(&self) -> &Path {
        self.root.path()
    }

    /// Create a distinct KEK and a short-lived child token limited to Kasumi's
    /// datakey/decrypt/rewrap operations on that key. Pass the token through a
    /// child process's Command::env, never global multithreaded environment mutation.
    pub async fn provision_key(&self, name: &str, derived: bool) -> Result<String> {
        ensure!(
            !name.is_empty()
                && name.len() <= 128
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "invalid fixture key name"
        );
        self.post(
            &format!("transit/keys/{name}"),
            json!({"type":"aes256-gcm96","derived":derived}),
        )
        .await?;
        let policy = format!(
            "path \"transit/datakey/plaintext/{name}\" {{ capabilities = [\"update\"] }}\npath \"transit/decrypt/{name}\" {{ capabilities = [\"update\"] }}\npath \"transit/rewrap/{name}\" {{ capabilities = [\"update\"] }}"
        );
        self.post(
            &format!("sys/policies/acl/{name}"),
            json!({"policy":policy}),
        )
        .await?;
        let response = self
            .post(
                "auth/token/create",
                json!({"policies":[name],"no_default_policy":true,"ttl":"24h"}),
            )
            .await?;
        Ok(response
            .pointer("/auth/client_token")
            .and_then(Value::as_str)
            .context("OpenBao child token missing")?
            .into())
    }

    async fn post(&self, path: &str, body: Value) -> Result<Value> {
        let response = self
            .client
            .post(format!("{}/v1/{path}", self.endpoint))
            .json(&body)
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "OpenBao fixture setup failed at {path}: {}",
            response.status()
        );
        let bytes = response.bytes().await?;
        ensure!(
            bytes.len() <= 65536,
            "OpenBao fixture response exceeded bound"
        );
        if bytes.is_empty() {
            Ok(Value::Null)
        } else {
            Ok(serde_json::from_slice(&bytes)?)
        }
    }

    pub async fn shutdown(mut self) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            self.child.kill().await?;
        }
        self.child.wait().await?;
        Ok(())
    }
}
