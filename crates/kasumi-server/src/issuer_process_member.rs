//! A native child hosts exactly one installed Authority member. A separate
//! surviving process issues each administrative probe through the normal SDK.
use super::*;
use kasumi_client::{KasumiAuthorityClient, KasumiClientConfig};
use kasumi_types::{AuthorityCommand, IssuerStopQuery, IssuerStopStatus, TargetStopReference};
use serde::Deserialize;
use serde_json::{Value, json};
use std::io::{BufRead, Write};

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
enum Probe {
    Metrics,
    Execute {
        member: u64,
        command: Box<AuthorityCommand>,
    },
    Status {
        member: u64,
        query: IssuerStopQuery,
    },
    Verify {
        member: u64,
        reference: TargetStopReference,
    },
    AwaitStop {
        member: u64,
        reference: TargetStopReference,
    },
    ColdSlot {
        query: IssuerStopQuery,
    },
    Shutdown,
}

fn reply(value: Value) -> Result<()> {
    let mut out = std::io::stdout().lock();
    writeln!(
        out,
        "KASUMI_NATIVE_ISSUER {}",
        serde_json::to_string(&value)?
    )?;
    out.flush()?;
    Ok(())
}

struct Operator {
    configs: Vec<AuthorityRuntimeConfig>,
    caller: usize,
    trust: kasumi_serving::AuthorityTrust,
    bearer: zeroize::Zeroizing<String>,
}
impl Operator {
    async fn client(&self, member: u64) -> Result<KasumiAuthorityClient> {
        let target = self
            .configs
            .iter()
            .find(|config| config.replication.node_id == member)
            .context("unknown fixture member")?;
        let caller = &self.configs[self.caller];
        let installed = caller
            .replication
            .peers
            .iter()
            .find(|peer| peer.node_id == member)
            .context("fixture issuer is outside the installed peer roster")?;
        let config = KasumiClientConfig {
            endpoint: format!("https://localhost:{}", target.native.listen.port()),
            identity: caller.native.tls.load()?,
            trusted_ca_pem: kasumi_store::private_files::read_trusted(
                &target.native.client_ca,
                1 << 20,
            )?,
            server_certificate_pins: installed
                .certificate_pins
                .iter()
                .map(|pin| crate::runtime::parse_certificate_pin(pin))
                .collect::<Result<_>>()?,
        };
        Ok(KasumiAuthorityClient::connect(&config, self.trust.clone()).await?)
    }
    async fn probe(
        &self,
        request: Probe,
        authority: &IndependentAuthority,
        store: &TenantStore,
    ) -> Result<Value> {
        match request {
            Probe::Metrics => {
                let metrics = authority.raft_group().raft().metrics().borrow().clone();
                Ok(
                    json!({"leader":metrics.current_leader,"term":metrics.current_term,"applied":metrics.last_applied.map(|log|log.index)}),
                )
            }
            Probe::Execute { member, command } => Ok(serde_json::to_value(
                self.client(member)
                    .await?
                    .execute(&self.bearer, &command)
                    .await?,
            )?),
            Probe::Verify { member, reference } => Ok(serde_json::to_value(
                self.client(member)
                    .await?
                    .verify_target_stop(&self.bearer, &reference)
                    .await?
                    .signed(),
            )?),
            Probe::Status { member, query } => Ok(serde_json::to_value(
                self.client(member)
                    .await?
                    .read_issuer_stop(&self.bearer, &query)
                    .await?,
            )?),
            Probe::AwaitStop { member, reference } => {
                let mut client = self.client(member).await?;
                let first = client.verify_target_stop(&self.bearer, &reference).await;
                let Err(kasumi_client::ClientError::Transport(ref refusal)) = first else {
                    anyhow::bail!("expected an original pending native issuer refusal");
                };
                anyhow::ensure!(
                    refusal.code() == tonic::Code::Unavailable,
                    "issuer did not refuse a pending interval"
                );
                reply(
                    json!({"pending_verify":true,"caller_pid":std::process::id(),"member":member,
                    "command_id":reference.command_id,"code":refusal.code().to_string()}),
                )?;
                // This application-level client retains the same identity and
                // exactly pinned channel while the supervisor faults its peer.
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
                loop {
                    match tokio::time::timeout_at(
                        deadline,
                        client.verify_target_stop(&self.bearer, &reference),
                    )
                    .await
                    {
                        Ok(Ok(signed)) => return Ok(serde_json::to_value(signed.signed())?),
                        Ok(Err(error)) => {
                            if tokio::time::Instant::now() >= deadline {
                                return Err(error.into());
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                }
            }
            Probe::ColdSlot { query } => {
                // Independent read of the physical encrypted member's bounded
                // trace. This yields a historical row and cannot grant a lease.
                query.validate()?;
                let digest =
                    kasumi_types::staged_digest(&("kasumi.issuer-stop-slot.v1", &query))?.0;
                let slot = u8::from_str_radix(&digest[..2], 16)?;
                let found = store
                    .get_bounded("kasumi.authority.local-stop-observations", &[slot], 2048)?
                    .map(|bytes| serde_json::from_slice::<IssuerStopStatus>(&bytes))
                    .transpose()?;
                if let Some(row) = &found {
                    row.validate_for(&query)?;
                    anyhow::ensure!(
                        row.node_id == self.configs[self.caller].replication.node_id,
                        "foreign cold physical owner"
                    );
                }
                Ok(serde_json::to_value(found)?)
            }
            Probe::Shutdown => anyhow::bail!("shutdown is owned by the process supervisor"),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 3)]
#[ignore = "native issuer process fixture; run with three installed private child configurations"]
async fn host_one_original_issuer_member() -> Result<()> {
    let directory =
        std::env::var_os("KASUMI_ISSUER_CRASH_DIRECTORY").context("fixture directory missing")?;
    let root = std::path::Path::new(&directory);
    let caller = std::env::var("KASUMI_ISSUER_CRASH_MEMBER")?
        .parse::<usize>()?
        .checked_sub(1)
        .context("invalid member")?;
    let configs: Vec<_> = (1..=3)
        .map(|id| AuthorityRuntimeConfig::load(root.join(format!("member-{id}.json"))))
        .collect::<Result<_>>()?;
    let config = configs
        .get(caller)
        .context("member outside fixture")?
        .clone();
    if std::env::var_os("KASUMI_ISSUER_CRASH_PROVISION").is_some() {
        if let Err(original) = config.provision_node().await {
            eprintln!("issuer member enrollment failed: {original:?}");
            std::panic::panic_any(original);
        }
    }
    let runtime = AuthorityRuntime::open(config).await?;
    let authority = runtime.authority.clone();
    let store = runtime.stores.application().clone();
    let trust = runtime
        .signer_verifier
        .trust(configs[caller].installation.manifest.clone())?;
    let bearer = zeroize::Zeroizing::new(String::from_utf8(
        kasumi_store::private_files::read_trusted(&root.join("operator.jwt"), 8192)?,
    )?);
    let operator = Operator {
        configs,
        caller,
        trust,
        bearer,
    };
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let service = tokio::spawn(runtime.serve(stopped));
    reply(json!({"ready":true,"pid":std::process::id(),"member":caller+1}))?;
    loop {
        let line = tokio::task::spawn_blocking(|| {
            let mut line = String::new();
            std::io::stdin().lock().read_line(&mut line)?;
            Ok::<_, std::io::Error>(line)
        })
        .await??;
        if line.is_empty() {
            break;
        }
        anyhow::ensure!(line.len() <= 8192, "fixture probe exceeds input limit");
        let request: Probe = serde_json::from_str(&line)?;
        if matches!(request, Probe::Shutdown) {
            break;
        }
        let result = operator.probe(request, &authority, &store).await;
        reply(match result {
            Ok(value) => json!({"ok":true,"result":value}),
            Err(error) => json!({"ok":false,"error":format!("{error:#}")}),
        })?;
    }
    drop((operator, store, authority));
    stop.send_replace(true);
    service.await??;
    reply(json!({"drained":true,"pid":std::process::id(),"member":caller+1}))?;
    Ok(())
}
