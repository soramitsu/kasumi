//! Daemon diagnostics contain operational events, never request bodies or secrets.
use tracing_subscriber::{filter::Targets, layer::SubscriberExt, util::SubscriberInitExt};

fn targets() -> Targets {
    // Dependencies can trace entire commands/documents. They must remain disabled
    // even when the host has an unrelated RUST_LOG setting. OpenRaft formats
    // storage error chains, so its fatal outcomes surface only through Kasumi's
    // fixed closure classes. Kasumi's own engine, Raft and store warnings carry
    // fixed labels and component names, never error chains or tenant data.
    Targets::new()
        .with_target("kasumi_server", tracing::Level::INFO)
        .with_target("kasumi_engine", tracing::Level::WARN)
        .with_target("kasumi_raft", tracing::Level::WARN)
        .with_target("kasumi_store", tracing::Level::WARN)
}

/// Install JSON diagnostics on stderr. CLI result documents remain on stdout.
pub fn initialize() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(targets())
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_ansi(false)
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(std::io::stderr),
        )
        .try_init()
        .map_err(|_| anyhow::anyhow!("structured daemon logging could not be installed"))
}

/// Deliberately does not accept an error value: provider errors may contain URLs,
/// key names or transport details that belong only in protected operator output.
pub fn tls_reload_failed() {
    tracing::warn!(
        event = "tls_reload_failed",
        "installed TLS replacement rejected"
    );
}

pub fn daemon_failed() {
    tracing::error!(
        event = "daemon_failed",
        "daemon failed; inspect the protected audit and installed configuration"
    );
}

pub fn daemon_starting() {
    tracing::info!(
        event = "daemon_starting",
        "opening installed daemon configuration"
    );
}

pub fn daemon_stopped() {
    tracing::info!(event = "daemon_stopped", "daemon owners drained");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };

    #[derive(Clone)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);
    impl Write for Buffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Buffer {
        type Writer = Self;
        fn make_writer(&'a self) -> Self {
            self.clone()
        }
    }

    #[test]
    fn json_diagnostics_exclude_dependency_payloads_and_span_fields() {
        let bytes = Buffer(Arc::new(Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::registry().with(targets()).with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_ansi(false)
                .with_current_span(false)
                .with_span_list(false)
                .with_writer(bytes.clone()),
        );
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("request", token = "secret-span-token");
            let _entered = span.enter();
            tracing::info!(target: "openraft", document = "private-document", "replicated command");
            tracing::error!(target: "openraft", error = "private-storage-chain", "quit");
            tracing::info!(target: "kasumi_engine", document = "private-engine", "applied");
            tracing::debug!(token = "private-debug", "debug details");
            tls_reload_failed();
            tracing::warn!(target: "kasumi_engine", event = "engine_warning", "fixed");
        });
        let lines = bytes.0.lock().unwrap().clone();
        let values = lines
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice::<serde_json::Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(values.len(), 2);
        assert_eq!(values[0]["fields"]["event"], "tls_reload_failed");
        assert_eq!(values[1]["fields"]["event"], "engine_warning");
        for value in values {
            let encoded = value.to_string();
            assert!(!encoded.contains("private-") && !encoded.contains("secret-span-token"));
        }
    }
}
