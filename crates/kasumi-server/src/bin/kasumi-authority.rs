use anyhow::{Context, Result, bail};
use kasumi_server::authority_runtime::{AuthorityRuntime, AuthorityRuntimeConfig};
#[tokio::main]
async fn main() -> std::process::ExitCode {
    if kasumi_server::logging::initialize().is_err() {
        eprintln!("{{\"level\":\"ERROR\",\"event\":\"logging_initialization_failed\"}}");
        return std::process::ExitCode::FAILURE;
    }
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    let daemon = args.first().is_some_and(|value| value == "serve");
    if daemon {
        kasumi_server::logging::daemon_starting();
    }
    match run(&args).await {
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
async fn run(args: &[String]) -> Result<()> {
    match args {
        [command, path] if command == "check-config" => {
            AuthorityRuntimeConfig::load(path)?;
            Ok(())
        }
        [command, path] if command == "provision-node" => {
            AuthorityRuntimeConfig::load(path)?.provision_node_file()?;
            println!(
                "Created the configured authority node file. Issuer catalogs and bootstrap state require separate initialization."
            );
            Ok(())
        }
        [command, path] if command == "serve" => {
            let runtime = AuthorityRuntime::open(AuthorityRuntimeConfig::load(path)?)
                .await
                .context("opening independent authority")?;
            let reload = runtime.tls_reload_handle();
            let (stop, shutdown) = tokio::sync::watch::channel(false);
            let signal = tokio::spawn(async move {
                let mut term =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
                let mut hangup =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
                loop {
                    tokio::select! {
                        result=tokio::signal::ctrl_c()=>{ result?; break; },
                        _=term.recv()=>break,
                        _=hangup.recv()=>{ if reload.reload().await.is_err() { kasumi_server::logging::tls_reload_failed(); } }
                    }
                }
                stop.send_replace(true);
                Ok::<_, std::io::Error>(())
            });
            let result = runtime.serve(shutdown).await;
            signal.abort();
            result
        }
        _ => bail!(
            "usage: kasumi-authority check-config <config.json> | provision-node <config.json> | serve <config.json>"
        ),
    }
}
