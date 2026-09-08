use anyhow::{Context, Result, bail};
use kasumi_server::runtime::{NodeRuntime, RuntimeConfig, example_config};

#[tokio::main]
async fn main() -> std::process::ExitCode {
    if kasumi_server::logging::initialize().is_err() {
        eprintln!("{{\"level\":\"ERROR\",\"event\":\"logging_initialization_failed\"}}");
        return std::process::ExitCode::FAILURE;
    }
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let daemon = arguments.first().is_some_and(|value| value == "serve");
    if daemon {
        kasumi_server::logging::daemon_starting();
    }
    match run(&arguments).await {
        Ok(()) => {
            if daemon {
                kasumi_server::logging::daemon_stopped();
            }
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            if daemon {
                kasumi_server::logging::daemon_failed();
            } else {
                // An invoked CLI command retains its human-readable operator error.
                eprintln!("{error:#}");
            }
            std::process::ExitCode::FAILURE
        }
    }
}
async fn run(arguments: &[String]) -> Result<()> {
    if kasumi_server::standalone_cli::command(arguments).await? {
        return Ok(());
    }
    match arguments {
        [command] if command == "example-config" => {
            println!("{}", serde_json::to_string_pretty(&example_config())?);
            Ok(())
        }
        [command, path] if command == "check-config" => {
            RuntimeConfig::load(path)?;
            println!(
                "Configuration and installed local keyring identities are valid; external services were not contacted."
            );
            Ok(())
        }
        [command, path] if command == "serve" => {
            let config = RuntimeConfig::load(path)?;
            let runtime = NodeRuntime::open(config)
                .await
                .context("opening encrypted node runtime")?;
            let reload = runtime.tls_reload_handle()?;
            let (stop, shutdown) = tokio::sync::watch::channel(false);
            let signal = tokio::spawn(async move {
                #[cfg(unix)]
                {
                    let mut terminate =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                    let mut hangup =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
                    loop {
                        tokio::select! {
                            result=tokio::signal::ctrl_c()=>{ result?; break; },
                            _=terminate.recv()=>break,
                            _=hangup.recv()=>{ if reload.reload().await.is_err() { kasumi_server::logging::tls_reload_failed(); } }
                        }
                    }
                }
                #[cfg(not(unix))]
                tokio::signal::ctrl_c().await?;
                stop.send_replace(true);
                Ok::<_, std::io::Error>(())
            });
            let result = runtime.serve(shutdown).await;
            signal.abort();
            result
        }
        _ => bail!(
            "usage: kasumid init --mode standalone <absolute-directory> [--tenant name] | example-config | check-config <configuration.json> | serve <configuration.json> | credential create <control-profile> <request.json> <output-profile> | credential renew|watch <profile> | credential status|revoke <control-profile> <family-uuid> | maintenance rotate-wrapping-keys|rotate-signer|rotate-certificates <configuration.json> | recover-administrator <configuration.json> <new-private-directory> | backup-operator-keys <configuration.json> <new-private-directory> | verify-operator-keys <private-directory> | backup create <database-profile> <destination> <checkpoint.json> | backup status|verify <database-profile> <destination> <session-uuid> | backup abort <database-profile> <destination> <session-uuid> <reason> | backup cleanup <database-profile> <destination> <session-uuid> <max-objects> | audit status <control-profile> | audit export|archives <control-profile> <request.json> <output.json> | audit verify <control-profile> <stream-uuid> <index> | local-recovery start|status|resume|stop <configuration.json> <request.json-or-operation-uuid>"
        ),
    }
}
