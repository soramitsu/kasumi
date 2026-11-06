//! Online recovery of credentials that expired while kasumid was down
//! (docs/credential-lifetime.md), through `credential renew` and `credential
//! watch` against a serving standalone installation.
use super::*;
use crate::runtime::NodeRuntime;
use kasumi_types::{
    RequestAuthorization, RequestContext, SecurityAuditRecord, SecurityEventKind, SecurityOutcome,
};

struct PastClock(u64);
impl kasumi_clock::WallClock for PastClock {
    fn now_ms(&self) -> Result<u64> {
        Ok(self.0)
    }
}

fn context(tenant: &str) -> RequestContext {
    RequestContext {
        authorization: RequestAuthorization::service_identity(),
        principal: "administrator".into(),
        tenant: tenant.into(),
        scopes: BTreeSet::from([Action::Read, Action::Write, Action::Admin, Action::Audit]),
        request_id: Uuid::new_v4().to_string(),
    }
}

fn renewal(action: &str, profile: &Path) -> Vec<String> {
    vec![
        "credential".into(),
        action.into(),
        profile.to_string_lossy().into_owned(),
    ]
}

async fn exported(audit: &kasumi_engine::SecurityAudit) -> Result<Vec<SecurityAuditRecord>> {
    let mut records = Vec::new();
    let mut cursor = None;
    loop {
        let page = audit.export_page(cursor, 1024).await?;
        cursor = page.cursor();
        records.extend(page.records);
        if cursor.is_none() {
            return Ok(records);
        }
    }
}

#[test]
fn expired_credentials_recover_online_and_refusals_name_offline_recovery() -> Result<()> {
    super::ownership_tests::run_large_fixture(
        "online credential recovery fixture",
        online_recovery_impl,
    )
}

async fn online_recovery_impl() -> Result<()> {
    let root = kasumi_store::test_utils::private_tempdir()?;
    let (installation, storage) = crate::runtime_storage_fixtures::initialize_standalone(
        &root.path().join("kasumi"),
        "tenant-a",
    )
    .await?;
    let mut config = RuntimeConfig::load(&installation.configuration)?;
    let mut tenant = ClientProfile::load(&installation.tenant_profile)?;
    let listeners = (0..3)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<Vec<_>>>()?;
    let addresses = listeners
        .iter()
        .map(std::net::TcpListener::local_addr)
        .collect::<std::io::Result<Vec<_>>>()?;
    config.mcp.listen = addresses[0];
    config.native.listen = addresses[1];
    config.admin.listen = addresses[2];
    config.mcp.protocol =
        crate::mcp::McpConfig::new(format!("https://localhost:{}/mcp", addresses[0].port()))?;
    tenant.mcp_endpoint = config.mcp.protocol.public_url.clone();
    tenant.native_endpoint = format!("https://localhost:{}", addresses[1].port());
    tenant
        .administrative_members
        .get_mut(&1)
        .context("standalone profile has no administrative member")?
        .endpoint = format!("https://localhost:{}", addresses[2].port());

    // While the installation is stopped, issue families of the tenant
    // profile's specification from clocks in the past, each with a profile.
    let directory = installation
        .tenant_profile
        .parent()
        .context("tenant profile has no directory")?
        .to_owned();
    let mut owner = OperatorState::open(&config, storage.clone()).await?;
    let issued = async {
        let AuthKeySource::Local { signer_file } = &config.auth.source else {
            anyhow::bail!("standalone installs the local issuer");
        };
        let specification = owner.credentials.status(tenant.family_id)?.specification;
        let now = kasumi_clock::EpochClock::system()?.now_ms()?;
        let mut issued = Vec::new();
        for (name, created_ms_ago) in [
            ("expired", 7_200_000),
            ("watched", 7_200_000),
            ("stale", 26 * 3_600_000),
            ("revoked", 7_200_000),
        ] {
            let manager = LocalCredentials::with_test_clock(
                owner.audit.store().clone(),
                signer_file.clone(),
                config.auth.issuer.clone(),
                config.auth.audience.clone(),
                Arc::new(kasumi_clock::EpochClock::new(
                    Arc::new(kasumi_clock::SystemLeaseClock),
                    Arc::new(PastClock(now - created_ms_ago)),
                )?),
            )?;
            let credential = manager.create(
                CreateCredential {
                    family_id: Uuid::new_v4(),
                    ..specification.clone()
                },
                "expired-test-fixture",
            )?;
            ensure!(credential.expires_at_ms < now);
            let profile = ClientProfile {
                family_id: credential.family_id,
                bearer_file: directory.join(format!("{name}.token")),
                ..tenant.clone()
            };
            private_files::create(&profile.bearer_file, credential.token.as_bytes())?;
            let path = directory.join(format!("{name}.json"));
            private_files::create(&path, &serde_json::to_vec_pretty(&profile)?)?;
            issued.push((path, profile));
        }
        owner
            .credentials
            .revoke(issued[3].1.family_id, "administrator")?;
        Ok(issued)
    }
    .await;
    let issued = owner.finish(issued).await?;
    drop(owner);
    let [expired, watched, stale, revoked] = <[_; 4]>::try_from(issued)
        .map_err(|_| anyhow::anyhow!("fixture issued another number of families"))?;

    crate::standalone::configure_test_topology(&config, storage.clone()).await;
    drop(listeners);
    let runtime = NodeRuntime::open_using_storage(
        config.clone(),
        crate::runtime::file_secret,
        storage.clone(),
    )
    .await?;
    let audit = runtime.security_audit().clone();
    let registry = runtime.registry().clone();
    let (stop, shutdown) = tokio::sync::watch::channel(false);
    let serving = tokio::spawn(runtime.serve(shutdown));
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while registry.database(&context("tenant-a")).is_err() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;

    // A one-shot renewal of a credential that expired an hour ago recovers
    // it online; the recovered credential authenticates and renews normally.
    let (path, profile) = &expired;
    let before = profile.bearer()?;
    crate::standalone_cli::command(&renewal("renew", path)).await?;
    let recovered = profile.bearer()?;
    ensure!(recovered.as_str() != before.as_str());
    ensure!(!profile.bearer_file.with_extension("renewal.json").exists());
    let mut admin = kasumi_client::KasumiAdminClient::connect(&profile.connection(true)?).await?;
    let reference = kasumi_types::CredentialReference {
        family_id: profile.family_id,
    };
    let status = admin.credential_status(&recovered, &reference).await?;
    ensure!(status.revoked_at_ms.is_none());
    crate::standalone_cli::command(&renewal("renew", path)).await?;
    ensure!(profile.bearer()?.as_str() != recovered.as_str());
    // The expired credential the recovery superseded cannot recover again.
    let Err(refused) = admin
        .recover_credential(
            &before,
            &kasumi_types::RenewCredential {
                family_id: profile.family_id,
                renewal_id: Uuid::new_v4(),
            },
        )
        .await
    else {
        anyhow::bail!("a superseded expired credential recovered its family");
    };
    ensure!(
        refused.to_string().contains("superseded"),
        "superseded recovery refused for another reason: {refused}"
    );

    // A watcher recovers its expired credential on its own and keeps going.
    let (path, profile) = &watched;
    let before = profile.bearer()?;
    let arguments = renewal("watch", path);
    let mut watcher = tokio::spawn(async move { crate::standalone_cli::command(&arguments).await });
    tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while profile.bearer().unwrap().as_str() == before.as_str()
            || profile.bearer_file.with_extension("renewal.json").exists()
        {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await?;
    tokio::select! {
        stopped = &mut watcher => anyhow::bail!("credential watch stopped after recovering: {stopped:?}"),
        _ = tokio::time::sleep(std::time::Duration::from_millis(200)) => {}
    }
    watcher.abort();
    ensure!(watcher.await.unwrap_err().is_cancelled());

    // Outside the window, or once revoked, recovery is refused, the bearer
    // and pending journal are kept, and the operator is told what to run.
    for ((path, profile), reason) in [(&stale, "window has closed"), (&revoked, "revoked")] {
        let before = profile.bearer()?;
        let error = crate::standalone_cli::command(&renewal("renew", path))
            .await
            .unwrap_err();
        let message = format!("{error:#}");
        ensure!(
            message.contains("online recovery refused it")
                && message.contains("recover-existing-credentials")
                && message.contains(reason),
            "{message}"
        );
        ensure!(profile.bearer()?.as_str() == before.as_str());
        ensure!(profile.bearer_file.with_extension("renewal.json").exists());
    }

    // Each verified recovery is audited under the family's identity: started
    // then succeeded for the two recoveries, started then denied for the
    // superseded one the issuer refused, and denied at verification for the
    // two outside the window or revoked.
    let mut recoveries = BTreeMap::<String, Vec<String>>::new();
    for record in exported(&audit).await? {
        if record.event.kind == SecurityEventKind::KeyAdministration
            && record.event.tenant.as_deref() == Some("tenant-a")
        {
            ensure!(record.event.principal.as_deref() == Some("administrator"));
            recoveries
                .entry(record.event.request_id)
                .or_default()
                .push(format!("{:?}", record.event.outcome));
        }
    }
    let mut outcomes = recoveries.into_values().collect::<Vec<_>>();
    outcomes.sort();
    let outcome = |outcomes: &[SecurityOutcome]| {
        outcomes
            .iter()
            .map(|outcome| format!("{outcome:?}"))
            .collect::<Vec<_>>()
    };
    ensure!(
        outcomes
            == [
                outcome(&[SecurityOutcome::Denied]),
                outcome(&[SecurityOutcome::Denied]),
                outcome(&[SecurityOutcome::Started, SecurityOutcome::Denied]),
                outcome(&[SecurityOutcome::Started, SecurityOutcome::Succeeded]),
                outcome(&[SecurityOutcome::Started, SecurityOutcome::Succeeded]),
            ],
        "recovery audit outcomes: {outcomes:?}"
    );
    // The ledger names the recovered issuance and the client certificate.
    let pin = hex::encode(tenant.identity.load()?.certificate_pin());
    let mut ledger = Vec::new();
    audit
        .store()
        .visit("local-credential-events", 128 << 10, |_, value| {
            let event: serde_json::Value = serde_json::from_slice(value)?;
            if event["operation"] == "recover" {
                ledger.push(event);
            }
            Ok(())
        })?;
    ensure!(ledger.len() == 2, "recovery ledger rows: {ledger:?}");
    for event in &ledger {
        ensure!(event["client_certificate_sha256"] == pin.as_str());
        ensure!(event["recovered_expires_at_ms"].as_u64().is_some());
    }

    drop(admin);
    stop.send_replace(true);
    serving.await??;
    Ok(())
}
