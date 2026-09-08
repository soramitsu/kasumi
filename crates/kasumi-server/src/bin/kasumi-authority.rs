use anyhow::{Context, Result, bail};
use kasumi_server::authority_runtime::{AuthorityRuntime, AuthorityRuntimeConfig};
#[tokio::main]
async fn main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    match args.as_slice() {
        [command, path] if command == "check-config" => {
            AuthorityRuntimeConfig::load(path)?;
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
                        _=hangup.recv()=>{ if reload.reload().await.is_err() { eprintln!("TLS reload failed; inspect installed TLS files and protected audit"); } }
                    }
                }
                stop.send_replace(true);
                Ok::<_, std::io::Error>(())
            });
            let result = runtime.serve(shutdown).await;
            signal.abort();
            result
        }
        _ => bail!("usage: kasumi-authority check-config <config.json> | serve <config.json>"),
    }
}
