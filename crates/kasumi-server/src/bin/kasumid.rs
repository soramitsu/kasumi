use anyhow::{Context, Result, bail};
use kasumi_server::runtime::{NodeRuntime, RuntimeConfig, example_config};

#[tokio::main]
async fn main() -> Result<()> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    if kasumi_server::standalone_cli::command(&arguments).await? {
        return Ok(());
    }
    match arguments.as_slice() {
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
            let (stop, shutdown) = tokio::sync::watch::channel(false);
            let signal = tokio::spawn(async move {
                #[cfg(unix)]
                {
                    let mut terminate =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                    tokio::select! { result=tokio::signal::ctrl_c()=>result?, _=terminate.recv()=>{} }
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
            "usage: kasumid init --mode standalone <absolute-directory> [--tenant name] | example-config | check-config <configuration.json> | serve <configuration.json> | credential create <control-profile> <request.json> <output-profile> | credential renew|watch <profile> | credential status|revoke <control-profile> <family-uuid> | maintenance rotate-wrapping-keys|rotate-signer|rotate-certificates <configuration.json> | recover-administrator <configuration.json> <new-private-directory> | backup-operator-keys <configuration.json> <new-private-directory>"
        ),
    }
}
