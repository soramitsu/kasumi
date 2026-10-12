use super::*;

struct PastClock(u64);
impl kasumi_clock::WallClock for PastClock {
    fn now_ms(&self) -> Result<u64> {
        Ok(self.0)
    }
}

fn write_manifest(path: &Path, profiles: &[PathBuf]) -> Result<Manifest> {
    let intent = Manifest {
        format: 1,
        operation_id: Uuid::new_v4(),
        profiles: profiles
            .iter()
            .map(|path| {
                let (_, hash) = ClientProfile::load_with_sha256(path)?;
                Ok(Entry {
                    profile: path.clone(),
                    profile_sha256: hash,
                    renewal_id: Uuid::new_v4(),
                })
            })
            .collect::<Result<_>>()?,
    };
    private_files::replace(path, &serde_json::to_vec(&intent)?)?;
    Ok(intent)
}

#[test]
fn all_expired_families_recover_without_identity_changes_and_retry_exactly() -> Result<()> {
    super::super::ownership_tests::run_large_fixture("expired-credential-recovery", || async {
        let root = kasumi_store::test_utils::private_tempdir()?;
        let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &root.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let config = RuntimeConfig::load(&installation.configuration)?;
        let paths = [
            installation.control_profile.clone(),
            installation.tenant_profile.clone(),
        ];
        let mut owner = OperatorState::open(&config, storage.clone()).await?;
        let AuthKeySource::Local { signer_file } = &config.auth.source else {
            unreachable!()
        };
        let clock = Arc::new(kasumi_clock::EpochClock::new(
            Arc::new(kasumi_clock::SystemLeaseClock),
            Arc::new(PastClock(
                kasumi_clock::EpochClock::system()?.now_ms()? - 7_200_000,
            )),
        )?);
        let manager = LocalCredentials::with_test_clock(
            owner.audit.store().clone(),
            signer_file.clone(),
            config.auth.issuer.clone(),
            config.auth.audience.clone(),
            clock,
        )?;
        let mut journals = Vec::new();
        for path in &paths {
            let mut profile = ClientProfile::load(path)?;
            let mut specification = owner.credentials.status(profile.family_id)?.specification;
            specification.family_id = Uuid::new_v4();
            let expired = manager.create(specification, "expired-test-fixture")?;
            assert!(expired.expires_at_ms < kasumi_clock::EpochClock::system()?.now_ms()?);
            profile.family_id = expired.family_id;
            private_files::replace(path, &serde_json::to_vec(&profile)?)?;
            private_files::replace(&profile.bearer_file, expired.token.as_bytes())?;
            let old_request = RenewCredential {
                family_id: expired.family_id,
                renewal_id: Uuid::new_v4(),
            };
            let old_renewal = manager.renew(&old_request, "expired-test-fixture")?;
            assert!(old_renewal.expires_at_ms < kasumi_clock::EpochClock::system()?.now_ms()?);
            let journal = serde_json::to_vec(&old_request)?;
            private_files::create(
                &profile.bearer_file.with_extension("renewal.json"),
                &journal,
            )?;
            journals.push(journal);
        }
        drop(manager);
        owner.finish(Ok(())).await?;
        drop(owner);
        let manifest_path = root.path().join("recovery.json");
        let intent = write_manifest(&manifest_path, &paths)?;
        let originals = paths
            .iter()
            .map(|path| {
                let profile = ClientProfile::load(path)?;
                Ok((
                    std::fs::read(path)?,
                    std::fs::read(&profile.identity.certificate)?,
                    std::fs::read(&profile.identity.private_key)?,
                    std::fs::read(&profile.bearer_file)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let report =
            recover_with_storage(&installation.configuration, &manifest_path, storage.clone())
                .await?;
        assert_eq!(report.operation_id, intent.operation_id);
        assert_eq!(report.profiles.len(), 2);
        let mut renewed = Vec::new();
        for (index, entry) in intent.profiles.iter().enumerate() {
            let profile = ClientProfile::load(&entry.profile)?;
            assert_eq!(std::fs::read(&entry.profile)?, originals[index].0);
            assert_eq!(
                std::fs::read(&profile.identity.certificate)?,
                originals[index].1
            );
            assert_eq!(
                std::fs::read(&profile.identity.private_key)?,
                originals[index].2
            );
            let token = std::fs::read(&profile.bearer_file)?;
            assert_ne!(token, originals[index].3);
            renewed.push(token);
            assert_eq!(report.profiles[index].family_id, profile.family_id);
            assert!(
                report.profiles[index].expires_at_ms
                    > kasumi_clock::EpochClock::system()?.now_ms()?
            );
            assert!(!profile.bearer_file.with_extension("renewal.json").exists());
            let archive = profile
                .bearer_file
                .with_extension(format!("renewal.before-recovery-{}.json", entry.renewal_id));
            assert_eq!(std::fs::read(&archive)?, journals[index]);
            // Cover both interrupted states: before journal supersession, and
            // after supersession with the recovery request already durable.
            let pending = if index == 0 {
                serde_json::to_vec(&RenewCredential {
                    family_id: profile.family_id,
                    renewal_id: entry.renewal_id,
                })?
            } else {
                journals[index].clone()
            };
            private_files::create(
                &profile.bearer_file.with_extension("renewal.json"),
                &pending,
            )?;
        }
        let retry =
            recover_with_storage(&installation.configuration, &manifest_path, storage).await?;
        for (index, path) in paths.iter().enumerate() {
            let profile = ClientProfile::load(path)?;
            assert_eq!(std::fs::read(&profile.bearer_file)?, renewed[index]);
            assert_eq!(
                retry.profiles[index].expires_at_ms,
                report.profiles[index].expires_at_ms
            );
            assert!(!profile.bearer_file.with_extension("renewal.json").exists());
        }
        Ok(())
    })
}

#[test]
fn refuses_active_owner_mismatched_specification_and_revoked_family_before_publication()
-> Result<()> {
    super::super::ownership_tests::run_large_fixture("refused-credential-recovery", || async {
        let root = kasumi_store::test_utils::private_tempdir()?;
        let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
            &root.path().join("kasumi"),
            "tenant",
        )
        .await?;
        let config = RuntimeConfig::load(&installation.configuration)?;
        let paths = [
            installation.control_profile.clone(),
            installation.tenant_profile.clone(),
        ];
        let manifest_path = root.path().join("recovery.json");
        write_manifest(&manifest_path, &paths)?;
        let profile_original = std::fs::read(&paths[1])?;
        let control = ClientProfile::load(&paths[0])?;
        let tenant = ClientProfile::load(&paths[1])?;
        let token_original = std::fs::read(&control.bearer_file)?;
        let mut owner = OperatorState::open(&config, storage.clone()).await?;
        assert!(
            recover_with_storage(&installation.configuration, &manifest_path, storage.clone())
                .await
                .is_err()
        );
        owner.finish(Ok(())).await?;
        drop(owner);
        let mut mismatched = tenant.clone();
        mismatched.principal = "different-principal".into();
        private_files::replace(&paths[1], &serde_json::to_vec(&mismatched)?)?;
        write_manifest(&manifest_path, &paths)?;
        let error =
            recover_with_storage(&installation.configuration, &manifest_path, storage.clone())
                .await
                .unwrap_err();
        assert!(format!("{error:#}").contains("registered family specification"));
        assert_eq!(std::fs::read(&control.bearer_file)?, token_original);
        private_files::replace(&paths[1], &profile_original)?;
        write_manifest(&manifest_path, &paths)?;
        let mut owner = OperatorState::open(&config, storage.clone()).await?;
        owner
            .credentials
            .revoke(tenant.family_id, "recovery-test")?;
        owner.finish(Ok(())).await?;
        drop(owner);
        let error = recover_with_storage(&installation.configuration, &manifest_path, storage)
            .await
            .unwrap_err();
        assert!(format!("{error:#}").contains("revoked family"));
        assert_eq!(std::fs::read(&control.bearer_file)?, token_original);
        Ok(())
    })
}

#[test]
fn manifest_shape_and_current_policy_are_strict() -> Result<()> {
    let id = Uuid::new_v4();
    assert!(
        serde_json::from_str::<Manifest>(&format!(
            r#"{{"format":1,"format":1,"operation_id":"{id}","profiles":[]}}"#
        ))
        .is_err()
    );
    assert!(
        serde_json::from_str::<Entry>(r#"{"profile":"/tmp/p","profile_sha256":"abc"}"#).is_err()
    );
    let specification = CreateCredential {
        family_id: id,
        principal: "test".into(),
        tenant: "tenant".into(),
        resource: CredentialResource::Database {
            incarnation: Uuid::new_v4(),
        },
        scopes: BTreeSet::from([Action::Read, Action::Write]),
        lifetime_seconds: 3600,
    };
    let mut policy = Policy {
        grants: vec![Grant {
            principal: "test".into(),
            collection: Some("limited".into()),
            actions: BTreeSet::from([Action::Read]),
        }],
        strict_read_audit: false,
    };
    assert!(validate_policy(&specification, &policy).is_err());
    policy.grants[0].actions.insert(Action::Write);
    validate_policy(&specification, &policy)?;
    policy.grants[0].principal = "someone-else".into();
    assert!(validate_policy(&specification, &policy).is_err());
    Ok(())
}
