use super::*;
use crate::tls_reload::ListenerSource;

/// What a SIGHUP reload and startup read: every listener the configuration
/// names, and every profile's client identity, must be a complete pair, and
/// every profile's certificate must be admitted.
fn assert_complete(configuration: &Path) -> Result<()> {
    let config = RuntimeConfig::load(configuration)?;
    ListenerSource::OAuth(config.mcp.tls.clone()).load()?;
    ListenerSource::Mutual(config.native.clone()).load()?;
    ListenerSource::Mutual(config.admin.clone()).load()?;
    let admitted = crate::client_pins::ClientPins::load(
        config
            .native
            .client_certificate_pins
            .as_ref()
            .context("client pins")?,
    )?
    .admitted()?;
    let root = installation_root(&config)?;
    let profiles = installed_profiles(&root.join("profiles"))?;
    ensure!(profiles.len() >= 4, "every generated profile is loadable");
    for (path, profile) in profiles {
        let identity = TlsFiles::from(profile.identity)
            .load()
            .with_context(|| format!("{} identity", path.display()))?;
        kasumi_transport::server_config(&identity, kasumi_transport::ClientAuthentication::OAuth)?;
        ensure!(
            admitted.contains(&identity.certificate_pin()),
            "{} presents an unadmitted certificate",
            path.display()
        );
    }
    Ok(())
}

/// Every file the configuration and the profiles name, before a rotation.
fn named_files(configuration: &Path) -> Result<Vec<PathBuf>> {
    let config = RuntimeConfig::load(configuration)?;
    let root = installation_root(&config)?;
    let mut files = Vec::new();
    for listener in [&config.mcp.tls, &config.native.tls, &config.admin.tls] {
        files.push(listener.certificate.clone());
        files.push(listener.private_key.clone());
    }
    for (_, profile) in installed_profiles(&root.join("profiles"))? {
        files.push(profile.identity.certificate);
        files.push(profile.identity.private_key);
    }
    files.sort();
    files.dedup();
    Ok(files)
}

/// The published listener generation directories, partial ones excluded.
fn listener_generations(root: &Path) -> Result<BTreeSet<PathBuf>> {
    let tls = root.join("tls");
    let mut found = BTreeSet::new();
    for entry in std::fs::read_dir(&tls)? {
        let path = entry?.path();
        if is_generation_directory(&path, &tls) {
            found.insert(path);
        }
    }
    Ok(found)
}

fn partial_directories(root: &Path) -> Result<Vec<PathBuf>> {
    let mut found = Vec::new();
    for parent in [root.join("tls"), root.join("profiles")] {
        for entry in std::fs::read_dir(parent)? {
            let path = entry?.path();
            if path
                .extension()
                .is_some_and(|extension| extension == "partial")
            {
                found.push(path);
            }
        }
    }
    Ok(found)
}

async fn rotation_fenced(
    configuration: &Path,
    storage: &crate::runtime_memory::RuntimeStorage,
) -> Result<bool> {
    let mut owner =
        OperatorState::open(&RuntimeConfig::load(configuration)?, storage.clone()).await?;
    let fenced = crate::local_recovery::require_runtime_ready(owner.audit.store()).is_err()
        && pending(owner.audit.store())?;
    owner.finish(Ok(fenced)).await
}

/// Interrupt one rotation after each of its write, sync and publication
/// boundaries in turn. At every interruption the configuration and every
/// profile name only complete pairs and serving is fenced; a rerun resumes
/// the journaled generation without replacing a published one, finishes
/// configuration, topology and profiles, and then retires the replaced files.
#[test]
fn an_interrupted_rotation_resumes_from_every_boundary_and_never_names_a_mixed_pair() -> Result<()>
{
    super::super::ownership_tests::run_large_fixture("certificate rotation boundaries", || async {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &directory.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let configuration = installation.configuration.clone();
        let root = installation_root(&RuntimeConfig::load(&configuration)?)?.to_owned();
        assert_complete(&configuration)?;
        let mut boundaries = Vec::new();
        for stop_at in 1.. {
            let before = named_files(&configuration)?;
            let before_generations = listener_generations(&root)?;
            interruption::plan(&root, Some(stop_at));
            let interrupted =
                rotate_certificates_with_storage(&configuration, storage.clone()).await;
            let reached = interruption::finish(&root);
            if interrupted.is_ok() {
                // This rotation passed every boundary without reaching stop_at.
                assert_eq!(reached.len(), stop_at - 1);
                break;
            }
            let error = format!("{:#}", interrupted.unwrap_err());
            assert!(
                error.contains(&format!(
                    "injected interruption after rotation boundary {stop_at}"
                )),
                "{error}"
            );
            let boundary = *reached.last().unwrap();
            boundaries.push(boundary);
            assert_complete(&configuration)
                .with_context(|| format!("interrupted after {stop_at} ({boundary})"))?;
            if stop_at == 1 || boundary == "configuration" {
                assert!(rotation_fenced(&configuration, &storage).await?);
            }
            // A generation published before the interruption is the one the
            // resumed rotation installs.
            let published = listener_generations(&root)?
                .difference(&before_generations)
                .next()
                .map(|generation| {
                    identity_files(generation, "native")
                        .load()
                        .map(|identity| identity.certificate_pin())
                })
                .transpose()?;
            interruption::plan(&root, None);
            let resumed = rotate_certificates_with_storage(&configuration, storage.clone()).await;
            interruption::finish(&root);
            let report = resumed.with_context(|| format!("resume after {stop_at} ({boundary})"))?;
            assert_complete(&configuration)?;
            let config = RuntimeConfig::load(&configuration)?;
            let native = config.native.tls.load()?.certificate_pin();
            if let Some(published) = published {
                assert_eq!(native, published, "resume replaced a published generation");
            }
            assert_eq!(report["native_certificate_pin"], hex::encode(native));
            // The replaced files and their directories are retired, nothing
            // partial remains, and nothing is pending.
            let after = named_files(&configuration)?;
            for file in &before {
                assert!(!after.contains(file), "{} is still named", file.display());
                assert!(!file.exists(), "{} was not retired", file.display());
            }
            for generation in &before_generations {
                assert!(
                    !generation.exists(),
                    "{} was not retired",
                    generation.display()
                );
            }
            assert!(partial_directories(&root)?.is_empty());
            assert_eq!(listener_generations(&root)?.len(), 1);
            let admitted = crate::client_pins::ClientPins::load(
                config.native.client_certificate_pins.as_ref().unwrap(),
            )?
            .admitted()?;
            let profiles = installed_profiles(&root.join("profiles"))?;
            let presented = profiles
                .iter()
                .map(|(_, profile)| {
                    TlsFiles::from(profile.identity.clone())
                        .load()
                        .map(|identity| identity.certificate_pin())
                })
                .collect::<Result<BTreeSet<_>>>()?;
            assert_eq!(admitted, presented, "only the current client certificates");
            let admin = hex::encode(config.admin.tls.load()?.certificate_pin());
            for (_, profile) in &profiles {
                assert_eq!(profile.native_certificate_pin, hex::encode(native));
                for member in profile.administrative_members.values() {
                    assert_eq!(member.certificate_pins, BTreeSet::from([admin.clone()]));
                }
            }
        }
        assert!(!rotation_fenced(&configuration, &storage).await?);
        // Every kind of boundary was interrupted at least once.
        for kind in [
            "journal",
            "generation-directory",
            "generation-key",
            "generation-certificate",
            "generation-sync",
            "generation-published",
            "admitted",
            "configuration",
            "topology",
            "credential-ledger",
            "credential",
            "profile",
            "retired-pin",
            "retired-file",
            "retired-sync",
            "retired-directory",
        ] {
            assert!(boundaries.contains(&kind), "{kind} was never interrupted");
        }
        // The installed Control topology pins the final MCP certificate.
        let config = RuntimeConfig::load(&configuration)?;
        let mut owner = OperatorState::open(&config, storage.clone()).await?;
        let pinned = async {
            let control = owner.control().await?;
            let topology = async {
                let context = offline_context(&control)?;
                let plane = kasumi_engine::control::ControlPlane::new(control.clone())?;
                Ok::<_, anyhow::Error>(
                    plane
                        .topology(&context)
                        .await?
                        .context("topology")?
                        .topology
                        .nodes[&1]
                        .certificate_pins
                        .clone(),
                )
            }
            .await;
            control.shutdown().await?;
            topology
        }
        .await;
        let pinned = owner.finish(pinned).await?;
        assert_eq!(
            pinned,
            BTreeSet::from([hex::encode(config.mcp.tls.load()?.certificate_pin())])
        );
        Ok(())
    })
}

/// A damaged published generation is never silently replaced: the
/// configuration may already name it.
#[test]
fn a_damaged_published_generation_stops_the_rerun() -> Result<()> {
    super::super::ownership_tests::run_large_fixture("damaged certificate generation", || async {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &directory.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let configuration = installation.configuration.clone();
        let root = installation_root(&RuntimeConfig::load(&configuration)?)?.to_owned();
        let stop_at = {
            interruption::plan(&root, None);
            rotate_certificates_with_storage(&configuration, storage.clone()).await?;
            let reached = interruption::finish(&root);
            // Stop the next rotation right after its listener generation publishes.
            reached
                .iter()
                .position(|boundary| *boundary == "generation-published")
                .unwrap()
                + 1
        };
        let before = RuntimeConfig::load(&configuration)?;
        interruption::plan(&root, Some(stop_at));
        assert!(
            rotate_certificates_with_storage(&configuration, storage.clone())
                .await
                .is_err()
        );
        interruption::finish(&root);
        let published = listener_generations(&root)?
            .into_iter()
            .find(|generation| Some(generation.as_path()) != before.native.tls.certificate.parent())
            .unwrap();
        // Replace one key with another valid key: the pair no longer matches.
        let damaged = identity_files(&published, "admin").private_key;
        let other = private_files::read(&identity_files(&published, "mcp").private_key, 1 << 20)?;
        private_files::replace(&damaged, &other)?;
        let error = rotate_certificates_with_storage(&configuration, storage.clone())
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("published admin certificate generation"),
            "{error:#}"
        );
        // Nothing moved past the damaged generation.
        let after = RuntimeConfig::load(&configuration)?;
        assert_eq!(after.admin.tls, before.admin.tls);
        assert!(rotation_fenced(&configuration, &storage).await?);
        Ok(())
    })
}

#[test]
fn rotation_rebinds_the_exact_original_issuance_and_leaves_revoked_families_revoked() -> Result<()>
{
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    fn claims(profile: &ClientProfile) -> Result<serde_json::Value> {
        let token = profile.bearer()?;
        let payload = token.split('.').nth(1).context("missing test JWT")?;
        Ok(serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload)?)?)
    }
    super::super::ownership_tests::run_large_fixture("certificate-bound families", || async {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &directory.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let configuration = installation.configuration;
        let config = RuntimeConfig::load(&configuration)?;
        let profiles = installation_root(&config)?.join("profiles");
        let operator = ClientProfile::load(&profiles.join("operator.json"))?;
        let revoked = operator.bearer()?;
        let mut owner = OperatorState::open(&config, storage.clone()).await?;
        owner.credentials.revoke(operator.family_id, "test")?;
        owner.finish(Ok(())).await?;
        let original = ClientProfile::load(&profiles.join("control.json"))?;
        let old_claims = claims(&original)?;
        let mcp = ClientProfile::load(&profiles.join("mcp.json"))?.bearer()?;
        rotate_certificates_with_storage(&configuration, storage.clone()).await?;
        let control = ClientProfile::load(&profiles.join("control.json"))?;
        let mut expected = old_claims.clone();
        let pin = TlsFiles::from(control.identity.clone())
            .load()?
            .certificate_pin();
        expected["cnf"] = serde_json::json!({"x5t#S256":URL_SAFE_NO_PAD.encode(pin)});
        assert_ne!(old_claims["cnf"], expected["cnf"]);
        assert_eq!(claims(&control)?, expected);
        let config = RuntimeConfig::load(&configuration)?;
        let mut owner = OperatorState::open(&config, storage).await?;
        assert_eq!(
            owner
                .credentials
                .status(control.family_id)?
                .specification
                .certificate_binding(),
            Some(pin)
        );
        assert!(
            owner
                .credentials
                .status(operator.family_id)?
                .revoked_at_ms
                .is_some()
        );
        assert!(*operator.bearer()? == *revoked);
        assert_eq!(
            *ClientProfile::load(&profiles.join("mcp.json"))?.bearer()?,
            *mcp
        );
        owner.finish(Ok(())).await
    })
}

#[test]
fn substituted_bearer_path_and_family_cannot_receive_rotated_credentials() -> Result<()> {
    super::super::ownership_tests::run_large_fixture("substituted certificate profile", || async {
        let directory = kasumi_store::test_utils::private_tempdir()?;
        let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &directory.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let config = RuntimeConfig::load(&installation.configuration)?;
        let profiles = installation_root(&config)?.join("profiles");
        let path = profiles.join("control.json");
        let control = ClientProfile::load(&path)?;
        let original = control.bearer()?;
        let other = ClientProfile::load(&profiles.join("operator.json"))?;
        let copied = profiles.join("copied.token");
        private_files::create(&copied, original.as_bytes())?;
        let mut owner = OperatorState::open(&config, storage).await?;
        for substitute in [
            ClientProfile {
                bearer_file: copied.clone(),
                ..control.clone()
            },
            ClientProfile {
                family_id: other.family_id,
                ..control.clone()
            },
        ] {
            let changed = owner.credentials.rotate_installed_certificate(
                &path,
                &substitute,
                || {
                    Ok(TlsFiles::from(control.identity.clone())
                        .load()?
                        .certificate_pin())
                },
                [99; 32],
                || Ok(()),
            );
            assert!(changed.is_err());
        }
        assert!(*control.bearer()? == *original);
        assert_eq!(
            private_files::read(&copied, 32 << 10)?.as_slice(),
            original.as_bytes()
        );
        owner.finish(Ok(())).await
    })
}
