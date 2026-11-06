#![recursion_limit = "256"]

use anyhow::{Context, Result, bail};
use kasumi_server::runtime::{NodeRuntime, RuntimeConfig, example_config};
use kasumi_server::serve_options::{self, ServeCommand, ServeOptions};
use kasumi_server::startup_progress::{self, Retained};

const USAGE: &str = "\
usage: kasumid <command> [arguments]

Daemon:
  serve <configuration.json> [options]       run the node (kasumid serve --help)

Installation and configuration:
  init --mode standalone <absolute-directory> --directory-policy <policy.json>
       --file-allocation-policy <allocation.json> --network <network.json>
       --tenant-audit-placements <placements.json> [--tenant <name>]
  example-config --directory-policy <policy.json> --file-allocation-policy <allocation.json>
  check-config <configuration.json>
  provision-node <configuration.json>
  initialize-target-journal <runtime.json>
  enroll-backup-destination <configuration.json> <request.json> <new-receipt.json>
  tenant stage <configuration.json> <request.json>
  tenant stage-status <configuration.json> <operation-uuid>

Credentials and keys:
  credential create <control-profile> <request.json> <output-profile>
  credential renew|watch|inspect <profile>
  credential status|revoke <control-profile> <family-uuid>
  recover-existing-credentials <configuration.json> <private-manifest.json>
  recover-administrator <configuration.json> <new-private-directory>
  backup-operator-keys <configuration.json> <new-private-directory>
  verify-operator-keys <private-directory>
  maintenance rotate-wrapping-keys|rotate-signer|rotate-certificates <configuration.json>
  client-certificate list|enable <configuration.json>
  client-certificate enroll <configuration.json> <certificate.pem> <name>
  client-certificate remove <configuration.json> <certificate.pem-or-sha256-pin>
                                             admit only listed client certificates on the
                                             native and administrative listeners; apply
                                             with SIGHUP (enable: at the next start)
  maintenance split-credentials <configuration.json>
                                             give an installation from before the credential
                                             split separate application and operator profiles
                                             (daemon and default.json watcher stopped; resumable)

Storage:
  maintenance move-tenant-audit-cache <configuration.json> <current-cache-directory>
                                             move the audit archive cache to the configured
                                             tenant_audit_cache (daemon stopped; resumable)

Backups, audit and recovery:
  backup create <operator-profile> <destination> <checkpoint.json>
  backup status|verify <operator-profile> <destination> <session-uuid>
  backup abort <operator-profile> <destination> <session-uuid> <reason>
  backup cleanup <operator-profile> <destination> <session-uuid> <max-objects>
  audit status <control-profile>
  audit export|archives <control-profile> <request.json> <output.json>
  audit verify <control-profile> <stream-uuid> <index>
  audit prune <control-profile> <export-page.json> <through-index> <output.json>
  maintenance export-service-audit <configuration.json> <request.json> <new-directory>
  maintenance prune-service-audit <configuration.json> <export-page.json> <through-index> <output.json>
                                             export or prune a service audit that refuses
                                             records (daemon stopped)
  control-recovery configuration-digest|start|status|resume|stop|phase <arguments>
  local-recovery start|status|resume|stop <configuration.json> <request.json-or-operation-uuid>

  help, --help, -h                           print this help";

fn main() -> std::process::ExitCode {
    kasumi_server::process_runtime::block_on(async_main)
}

async fn async_main() -> std::process::ExitCode {
    if kasumi_server::logging::initialize().is_err() {
        eprintln!("{{\"level\":\"ERROR\",\"event\":\"logging_initialization_failed\"}}");
        return std::process::ExitCode::FAILURE;
    }
    // Every command but `serve` keeps each tenant's stored snapshot form and
    // converts nothing. An offline command (credential or administrator
    // recovery, key rotation, staging) that opened its tenants embedded would
    // copy each by-reference tenant's whole audit archive into node.kv, and one
    // that opened them by reference would undo a rollback's embedded start.
    kasumi_engine::set_local_snapshot_archive(serve_options::process_snapshot_archive(None));
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match arguments.first().map(String::as_str) {
        None => {
            eprintln!("{USAGE}");
            return std::process::ExitCode::FAILURE;
        }
        Some("help" | "--help" | "-h") => {
            println!("{USAGE}");
            return std::process::ExitCode::SUCCESS;
        }
        _ => {}
    }
    let options = match serve_options::parse(&arguments) {
        Ok(Some(ServeCommand::Help)) => {
            println!("{}", serve_options::USAGE);
            return std::process::ExitCode::SUCCESS;
        }
        Ok(Some(ServeCommand::Serve(options))) => options,
        Ok(None) => {
            return match run(&arguments).await {
                Ok(()) => std::process::ExitCode::SUCCESS,
                Err(error) => {
                    // An invoked CLI command retains its human-readable operator error.
                    eprintln!("{error:#}");
                    std::process::ExitCode::FAILURE
                }
            };
        }
        Err(error) => {
            eprintln!("{error:#}");
            return std::process::ExitCode::FAILURE;
        }
    };
    kasumi_server::logging::daemon_starting();
    startup_progress::begin();
    match serve(options).await {
        Ok(()) => {
            kasumi_server::logging::daemon_stopped();
            std::process::ExitCode::SUCCESS
        }
        Err(error) => {
            // Only the typed figures leave the chain, which may also hold
            // provider details that stay out of the daemon log.
            if let Some(refusal) = error.chain().find_map(|cause| {
                cause.downcast_ref::<kasumi_engine::admission::TotalExceedsHighWater>()
            }) {
                kasumi_server::logging::admission_exceeds_high_water(refusal);
            }
            kasumi_server::logging::daemon_failed(&error);
            std::process::ExitCode::FAILURE
        }
    }
}

async fn serve(options: ServeOptions) -> Result<()> {
    // Engines read this when they are constructed: set it before any tenant opens.
    kasumi_engine::set_local_snapshot_archive(serve_options::process_snapshot_archive(Some(
        &options,
    )));
    kasumi_server::logging::serve_options(&options);
    let config = RuntimeConfig::load(&options.configuration)?;
    let opening = NodeRuntime::open_with_storage_maintenance(config, options.storage_maintenance);
    let runtime = tokio::select! {
        result = opening => result.context("opening encrypted node runtime")?,
        during = startup_progress::retained_for(Retained::Startup, RETAINED_GRACE) => {
            startup_progress::exit_with_retained_owners(during, RETAINED_GRACE)
        }
    };
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
    let result = tokio::select! {
        result = runtime.serve(shutdown) => result,
        during = startup_progress::retained_for(Retained::Drain, RETAINED_GRACE) => {
            startup_progress::exit_with_retained_owners(during, RETAINED_GRACE)
        }
    };
    signal.abort();
    result
}

/// How long a failed open or an incomplete drain may keep retrying before the
/// daemon exits instead (see `startup_progress::retained_for`).
const RETAINED_GRACE: std::time::Duration = std::time::Duration::from_secs(60);

async fn run(arguments: &[String]) -> Result<()> {
    if kasumi_server::standalone_cli::command(arguments).await? {
        return Ok(());
    }
    match arguments {
        [command, policy_flag, policy, allocation_flag, allocation]
            if command == "example-config"
                && policy_flag == "--directory-policy"
                && allocation_flag == "--file-allocation-policy" =>
        {
            let policy =
                kasumi_server::standalone_cli::directory_policy(std::path::Path::new(policy))?;
            let allocation = kasumi_server::standalone_cli::file_allocation_policy(
                std::path::Path::new(allocation),
            )?;
            println!(
                "{}",
                serde_json::to_string_pretty(&example_config(policy, allocation)?)?
            );
            Ok(())
        }
        [command, path] if command == "check-config" => {
            RuntimeConfig::load(path)?;
            println!(
                "Configuration structure is valid; selected installed key identities are verified when their explicit operation opens them."
            );
            Ok(())
        }
        [command, path] if command == "provision-node" => {
            RuntimeConfig::load(path)?.provision_node().await?;
            println!(
                "Enrolled the configured HA node, audit and immutable Control/application genesis. Membership initializes only after the original voters verify their retained fingerprints."
            );
            Ok(())
        }
        [command, ..] => bail!("unknown or incomplete kasumid command {command:?}\n\n{USAGE}"),
        [] => bail!("{USAGE}"),
    }
}
