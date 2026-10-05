use anyhow::Context;
use kasumi_server::authority_runtime::EnrollmentFailure;
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
enum CommandFailure {
    Operation(anyhow::Error),
    Enrollment(EnrollmentFailure),
}
impl From<anyhow::Error> for CommandFailure {
    fn from(original: anyhow::Error) -> Self {
        Self::Operation(original)
    }
}
impl From<EnrollmentFailure> for CommandFailure {
    fn from(original: EnrollmentFailure) -> Self {
        Self::Enrollment(original)
    }
}
impl std::fmt::Display for CommandFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Operation(original) => std::fmt::Display::fmt(original, f),
            Self::Enrollment(original) => std::fmt::Display::fmt(original, f),
        }
    }
}
async fn run(args: &[String]) -> std::result::Result<(), CommandFailure> {
    match args {
        [command, path] if command == "check-config" => {
            AuthorityRuntimeConfig::load(path)?;
            Ok(())
        }
        [command, path] if command == "provision-node" => {
            AuthorityRuntimeConfig::load(path)?.provision_node().await?;
            println!(
                "Enrolled the configured authority node, audit, independent catalogs and immutable issuer genesis. Membership uses the retained original voter handshake."
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
            result.map_err(CommandFailure::Operation)
        }
        _ => Err(anyhow::anyhow!(
            "usage: kasumi-authority check-config <config.json> | provision-node <config.json> | serve <config.json>"
        ).into()),
    }
}
