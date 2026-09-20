//! Opt-in real S3 interoperability against the official immutable MinIO image.
//! Uses only an explicitly supplied local Docker socket, bounded resources, TLS,
//! ephemeral credentials and one uniquely named test container.
use super::*;
use std::process::{Command, Output, Stdio};

const IMAGE: &str =
    "minio/minio@sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e";
struct Container {
    host: String,
    config: String,
    name: String,
}
impl Container {
    fn docker(&self) -> Command {
        let mut command = Command::new("docker");
        command.args(["--host", &self.host, "--config", &self.config]);
        command
    }
    fn run(&self, args: &[&str]) -> Result<Output> {
        let output = self.docker().args(args).output()?;
        ensure!(output.status.success(), "Docker fixture operation failed");
        Ok(output)
    }
}
impl Drop for Container {
    fn drop(&mut self) {
        let _ = self
            .docker()
            .args(["rm", "--force", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires explicit KASUMI_MINIO_DOCKER_HOST, KASUMI_MINIO_DOCKER_CONFIG and KASUMI_MINIO_WORKDIR; official pinned image must be pre-pulled"]
async fn actual_minio_tls_sigv4_encrypted_roundtrip_create_only_and_access_denial() -> Result<()> {
    let host =
        std::env::var("KASUMI_MINIO_DOCKER_HOST").context("set explicit local Docker socket")?;
    ensure!(
        host.starts_with("unix:///") && host.ends_with("/docker.sock"),
        "live fixture requires an explicit local Unix Docker socket"
    );
    let config =
        std::env::var("KASUMI_MINIO_DOCKER_CONFIG").context("set isolated Docker config")?;
    let workdir = std::env::var("KASUMI_MINIO_WORKDIR").context("set shared fixture directory")?;
    ensure!(
        Path::new(&config).is_absolute()
            && Path::new(&workdir).is_absolute()
            && !workdir.contains(','),
        "fixture paths must be explicit absolute paths"
    );
    let root = tempfile::tempdir_in(&workdir)?;
    let certs = root.path().join("certs");
    std::fs::create_dir(&certs)?;
    let certificate =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])?;
    let ca = certificate.cert.pem().into_bytes();
    std::fs::write(certs.join("public.crt"), &ca)?;
    std::fs::write(
        certs.join("private.key"),
        certificate.signing_key.serialize_pem(),
    )?;
    let container = Container {
        host,
        config,
        name: format!("kasumi-minio-test-{}", Uuid::new_v4()),
    };
    let image = container.run(&[
        "image",
        "inspect",
        "--format",
        "{{json .RepoDigests}}",
        IMAGE,
    ])?;
    let digests: Vec<String> = serde_json::from_slice(&image.stdout)?;
    ensure!(
        digests.iter().any(|digest| digest == IMAGE),
        "official immutable MinIO digest is not present"
    );
    let user = format!("test{}", Uuid::new_v4().simple());
    let password = Zeroizing::new(Uuid::new_v4().simple().to_string());
    let mount = format!(
        "type=bind,source={},target=/certs,readonly",
        certs.display()
    );
    let output = container
        .docker()
        .args([
            "run",
            "--detach",
            "--name",
            &container.name,
            "--pull",
            "never",
            "--memory",
            "512m",
            "--cpus",
            "1",
            "--pids-limit",
            "128",
            "--security-opt",
            "no-new-privileges",
            "--cap-drop",
            "ALL",
            "--read-only",
            "--tmpfs",
            "/data:rw,size=268435456,mode=0700",
            "--tmpfs",
            "/tmp:rw,size=16777216",
            "--publish",
            "127.0.0.1::9000",
            "--mount",
            &mount,
            "--env",
            "MINIO_ROOT_USER",
            "--env",
            "MINIO_ROOT_PASSWORD",
            "--env",
            "MINIO_BROWSER=off",
            IMAGE,
            "server",
            "/data",
            "--address",
            ":9000",
            "--console-address",
            "127.0.0.1:9001",
            "--certs-dir",
            "/certs",
            "--quiet",
        ])
        .env("MINIO_ROOT_USER", &user)
        .env("MINIO_ROOT_PASSWORD", password.as_str())
        .output()?;
    ensure!(
        output.status.success(),
        "starting bounded MinIO fixture failed"
    );
    let port = container.run(&["port", &container.name, "9000/tcp"])?;
    let address: std::net::SocketAddr = std::str::from_utf8(&port.stdout)?.trim().parse()?;
    ensure!(
        address.ip().is_loopback(),
        "S3 fixture must bind loopback only"
    );
    let endpoint = format!("https://127.0.0.1:{}", address.port());
    let bucket = format!("kasumi-{}", Uuid::new_v4().simple());
    let make = || S3BackupConfig {
        endpoint: endpoint.clone(),
        region: "us-east-1".into(),
        bucket: bucket.clone(),
        prefix: "encrypted/backups".into(),
        credential: {
            let user = user.clone();
            let password = password.clone();
            Arc::new(move || {
                Ok(Zeroizing::new(serde_json::json!({
                "access_key_id": user, "secret_access_key": password.as_str(), "session_token": null
            }).to_string()))
            })
        },
        ca_pem: Some(ca.clone()),
        max_bytes: 4 << 20,
    };
    let destination = S3BackupDestination::new(make())?;
    tokio::time::timeout(std::time::Duration::from_secs(45), async {
        loop {
            if destination
                .client
                .get(format!("{endpoint}/minio/health/live"))
                .send()
                .await
                .is_ok_and(|r| r.status().is_success())
            {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .context("MinIO TLS readiness failed")?;
    let bucket_url = destination.endpoint.join(&bucket)?;
    let headers =
        destination.signed_headers("PUT", &bucket_url, &[], time::OffsetDateTime::now_utc())?;
    let response = destination
        .client
        .put(bucket_url)
        .headers(headers)
        .body(Vec::new())
        .send()
        .await?;
    ensure!(
        response.status().is_success(),
        "signed S3 bucket creation failed: {}",
        response.status()
    );
    let provider = Arc::new(crate::test_utils::LocalKeyProvider::new([73; 32]));
    let store = TenantStore::initialize_catalog_fixture(
        crate::NodeStore::create_new_fixture(
            root.path().join("source.redb"),
            crate::test_utils::NODE_STORE_ID,
            crate::ScratchDisk::fixture(),
        )?,
        "customer".into(),
        provider.clone(),
    )
    .await?;
    let snapshot=r#"{"documents":{"first":{"exact":9007199254740993,"text":"日本語 English"}},"revision":17}"#.as_bytes();
    let encrypted = store.encrypt_backup(17, snapshot)?;
    let id = encrypted.id();
    let bytes = encrypted.to_bytes()?;
    destination.put(id, bytes.clone()).await?;
    assert_eq!(destination.get(id, 16 << 20).await?, bytes);
    assert!(
        destination
            .put(id, b"overwrite attempt".to_vec())
            .await
            .is_err()
    );
    let recovered = EncryptedBackup::from_bytes(&destination.get(id, 16 << 20).await?, 1 << 20)?
        .decrypt_fixture("customer", provider)
        .await?;
    assert_eq!(recovered.snapshot.as_slice(), snapshot);
    assert_eq!(recovered.revision, 17);
    assert!(
        destination
            .get(Uuid::new_v4(), MAX_BACKUP_BUNDLE_BYTES)
            .await
            .is_err()
    );
    let mut bad = make();
    let original = bad.credential.clone();
    bad.credential = Arc::new(move || {
        let mut bundle: serde_json::Value = serde_json::from_str(&original.load()?)?;
        bundle["secret_access_key"] = serde_json::json!("incorrect-credential");
        Ok(Zeroizing::new(bundle.to_string()))
    });
    assert!(
        S3BackupDestination::new(bad)?
            .get(id, 16 << 20)
            .await
            .is_err()
    );
    let mut untrusted = make();
    untrusted.ca_pem = None;
    assert!(
        S3BackupDestination::new(untrusted)?
            .get(id, 16 << 20)
            .await
            .is_err()
    );
    let mut tiny = make();
    tiny.max_bytes = 1;
    assert!(
        S3BackupDestination::new(tiny)?
            .get(id, 16 << 20)
            .await
            .is_err()
    );
    store.seal();
    Ok(())
}
