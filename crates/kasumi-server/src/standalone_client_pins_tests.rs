//! Client certificate admission on a served standalone installation.
use super::*;
use crate::runtime::NodeRuntime;

fn cli(arguments: &[&str]) -> Vec<String> {
    arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect()
}

/// A client certificate the installation CA issues outside the installer.
fn issue(root: &Path, name: &str) -> Result<TlsFiles> {
    let ca_key_pem = private_files::read(&root.join("operator/ca-key.pem"), 1 << 20)?;
    let ca_pem = private_files::read(&root.join("tls/ca.pem"), 1 << 20)?;
    let ca_key = rcgen::KeyPair::from_pem(std::str::from_utf8(&ca_key_pem)?)?;
    let issuer = rcgen::Issuer::from_ca_cert_pem(std::str::from_utf8(&ca_pem)?, &ca_key)?;
    let (certificate, key) = leaf(name, &issuer, true)?;
    let files = identity_files(&root.join("profiles"), name);
    private_files::create(&files.certificate, certificate.as_bytes())?;
    private_files::create(&files.private_key, key.as_bytes())?;
    Ok(files)
}

/// Whether the administrative listener admits `profile`'s certificate: it
/// answers a Control request with the Control bearer at all. A refusal of the
/// bearer itself (a token bound to another certificate) still means the
/// handshake admitted the certificate; a refused handshake answers nothing.
async fn admitted(profile: &ClientProfile, control: &ClientProfile) -> bool {
    match kasumi_client::KasumiAdminClient::connect(&profile.connection(true).unwrap()).await {
        Ok(mut client) => match client
            .security_audit_status(&control.bearer().unwrap())
            .await
        {
            Ok(_) => true,
            Err(kasumi_client::ClientError::Transport(status)) => matches!(
                status.code(),
                tonic::Code::Unauthenticated | tonic::Code::PermissionDenied
            ),
            Err(_) => false,
        },
        Err(_) => false,
    }
}

#[test]
fn a_served_installation_admits_only_enrolled_client_certificates() -> Result<()> {
    ownership_tests::run_large_fixture("client certificate admission", || async {
        let root = kasumi_store::test_utils::private_tempdir()?;
        let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &root.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let directory = installation
            .configuration
            .parent()
            .context("root")?
            .to_owned();
        let config =
            crate::runtime_storage_fixtures::retarget_standalone(&installation, &storage).await?;
        let configuration = installation.configuration.display().to_string();
        let control = ClientProfile::load(&installation.control_profile)?;
        let stranger_files = issue(&directory, "stranger")?;
        let stranger = ClientProfile {
            identity: stranger_files.clone().into(),
            ..control.clone()
        };
        let runtime =
            NodeRuntime::open_using_storage(config, crate::runtime::file_secret, storage.clone())
                .await?;
        let reload = runtime.tls_reload_handle()?;
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let serving = tokio::spawn(runtime.serve(shutdown));
        let checked = async {
            let mut ready = false;
            for _ in 0..300 {
                if admitted(&control, &control).await {
                    ready = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            ensure!(
                ready,
                "the administrative listener did not admit the Control profile"
            );
            // The CA issued it, but nothing enrolled it.
            assert!(!admitted(&stranger, &control).await);
            let certificate = stranger_files.certificate.display().to_string();
            assert!(
                crate::standalone_cli::command(&cli(&[
                    "client-certificate",
                    "enroll",
                    &configuration,
                    &certificate,
                    "stranger",
                ]))
                .await?
            );
            assert!(
                !admitted(&stranger, &control).await,
                "enrollment applies at the next reload"
            );
            reload.reload().await?;
            assert!(admitted(&stranger, &control).await);
            assert!(
                crate::standalone_cli::command(&cli(&[
                    "client-certificate",
                    "remove",
                    &configuration,
                    &certificate,
                ]))
                .await?
            );
            reload.reload().await?;
            assert!(!admitted(&stranger, &control).await);
            assert!(admitted(&control, &control).await);
            // A certificate another authority issued cannot be enrolled.
            let foreign = rcgen::generate_simple_self_signed(vec!["localhost".into()])?;
            let foreign_path = directory.join("profiles/foreign.pem");
            private_files::create(&foreign_path, foreign.cert.pem().as_bytes())?;
            assert!(
                crate::standalone_cli::command(&cli(&[
                    "client-certificate",
                    "enroll",
                    &configuration,
                    &foreign_path.display().to_string(),
                    "foreign",
                ]))
                .await
                .is_err()
            );
            // A malformed allowlist is refused and the listeners keep serving
            // the generation before it.
            let pins_path = directory.join("tls/client-pins.json");
            let pins = private_files::read(&pins_path, 1 << 20)?;
            private_files::replace(&pins_path, b"{\"format\":1}")?;
            assert!(reload.reload().await.is_err());
            assert!(admitted(&control, &control).await);
            assert!(!admitted(&stranger, &control).await);
            private_files::replace(&pins_path, &pins)?;
            Ok::<_, anyhow::Error>(())
        }
        .await;
        stop.send(true)?;
        serving.await??;
        checked
    })
}

#[test]
fn enabling_admission_lists_every_profile_certificate_and_is_resumable() -> Result<()> {
    ownership_tests::run_large_fixture("client certificate admission upgrade", || async {
        let root = kasumi_store::test_utils::private_tempdir()?;
        let (installation, _storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &root.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let directory = installation
            .configuration
            .parent()
            .context("root")?
            .to_owned();
        let pins_path = directory.join("tls/client-pins.json");
        // An installation from before admission names no allowlist.
        let mut config = RuntimeConfig::load(&installation.configuration)?;
        config.native.client_certificate_pins = None;
        config.admin.client_certificate_pins = None;
        private_files::replace(
            &installation.configuration,
            &serde_json::to_vec_pretty(&config)?,
        )?;
        std::fs::remove_file(&pins_path)?;
        let configuration = installation.configuration.display().to_string();
        assert!(
            crate::standalone_cli::command(&cli(&["client-certificate", "list", &configuration]))
                .await
                .is_err()
        );
        // An interrupted run wrote the allowlist but not the configuration.
        crate::client_pins::ClientPins::default().store(&pins_path)?;
        assert!(
            crate::standalone_cli::command(&cli(&["client-certificate", "enable", &configuration]))
                .await?
        );
        let config = RuntimeConfig::load(&installation.configuration)?;
        assert_eq!(
            config.native.client_certificate_pins.as_ref(),
            Some(&pins_path)
        );
        assert_eq!(
            config.admin.client_certificate_pins.as_ref(),
            Some(&pins_path)
        );
        let expected = [
            &installation.control_profile,
            &installation.tenant_profile,
            &installation.operator_profile,
        ]
        .map(|path| {
            TlsFiles::from(ClientProfile::load(path).unwrap().identity)
                .load()
                .unwrap()
                .certificate_pin()
        });
        let listed = crate::client_pins::ClientPins::load(&pins_path)?;
        assert_eq!(listed.admitted()?, BTreeSet::from(expected));
        // Rerunning changes nothing.
        let bytes = (
            std::fs::read(&installation.configuration)?,
            std::fs::read(&pins_path)?,
        );
        crate::standalone_cli::command(&cli(&["client-certificate", "enable", &configuration]))
            .await?;
        assert_eq!(
            (
                std::fs::read(&installation.configuration)?,
                std::fs::read(&pins_path)?
            ),
            bytes
        );
        Ok(())
    })
}
