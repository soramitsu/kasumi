//! Owner-triggered listener certificate/trust replacement. Complete candidates
//! are checked before publication. Replication trust has separate membership
//! approval and cannot be changed by reloading public listener files.
use crate::runtime::{MutualTlsEndpoint, TlsFiles};
use anyhow::{Context, Result};
use kasumi_engine::{Database, SecurityAudit, SecurityEvent, SecurityEventKind, SecurityOutcome};
use kasumi_transport::{CertificatePin, ClientAuthentication, ReloadableServerConfig};
use kasumi_types::{Precondition, RequestContext};
use std::{collections::BTreeSet, sync::Arc};

#[derive(Clone)]
pub(crate) enum ListenerSource {
    OAuth(TlsFiles),
    Mutual(MutualTlsEndpoint),
}
impl ListenerSource {
    fn load(&self) -> Result<(CertificatePin, Arc<rustls::ServerConfig>)> {
        match self {
            Self::OAuth(files) => {
                let identity = files.load()?;
                Ok((
                    identity.certificate_pin(),
                    kasumi_transport::server_config(&identity, ClientAuthentication::OAuth)?,
                ))
            }
            Self::Mutual(endpoint) => {
                let identity = endpoint.tls.load()?;
                let ca = crate::runtime::read_bounded(&endpoint.client_ca, 1 << 20)?;
                Ok((
                    identity.certificate_pin(),
                    kasumi_transport::server_config(
                        &identity,
                        ClientAuthentication::Required {
                            trusted_ca_pem: &ca,
                        },
                    )?,
                ))
            }
        }
    }
}
#[derive(Clone)]
pub struct RuntimeTlsReload {
    sources: Vec<(ListenerSource, ReloadableServerConfig)>,
    local_control: Option<(Arc<Database>, RequestContext)>,
    audit: Arc<SecurityAudit>,
    serial: Arc<tokio::sync::Mutex<()>>,
}
impl RuntimeTlsReload {
    pub(crate) fn new(
        sources: Vec<(ListenerSource, ReloadableServerConfig)>,
        local_control: Option<(Arc<Database>, RequestContext)>,
        audit: Arc<SecurityAudit>,
    ) -> Self {
        Self {
            sources,
            local_control,
            audit,
            serial: Arc::new(tokio::sync::Mutex::new(())),
        }
    }
    /// Each listener atomically switches its certificate/key/client-CA together.
    /// If any candidate is invalid, all old listener generations remain active.
    /// Existing connections are signaled to drain within the listener drain limit.
    pub async fn reload(&self) -> Result<Vec<u64>> {
        let _serial = self.serial.lock().await;
        let request_id = uuid::Uuid::new_v4().to_string();
        let event = |outcome| SecurityEvent {
            kind: SecurityEventKind::KeyAdministration,
            principal: None,
            tenant: None,
            request_id: format!("tls-reload-{request_id}"),
            outcome,
        };
        let candidates = match self
            .sources
            .iter()
            .map(|(source, _)| source.load())
            .collect::<Result<Vec<_>>>()
        {
            Ok(candidates) => candidates,
            Err(error) => {
                self.audit.record(event(SecurityOutcome::Failed)).await?;
                tracing::warn!("TLS reload rejected; active listener generations retained");
                return Err(
                    error.context("replacement TLS material is invalid; prior generation retained")
                );
            }
        };
        self.audit.record(event(SecurityOutcome::Started)).await?;
        // A standalone Control topology stores the MCP identity. Commit its new
        // pin before publication so a restart under the installed files agrees.
        if let Some((database, context)) = &self.local_control {
            let plane = kasumi_engine::control::ControlPlane::new(database.clone())?;
            let current = plane
                .topology(context)
                .await?
                .context("local Control topology is not initialized")?;
            let mut topology = current.topology;
            let node = topology
                .nodes
                .get_mut(&1)
                .context("local Control node absent")?;
            let pins = BTreeSet::from([hex::encode(
                candidates.first().context("MCP TLS candidate absent")?.0,
            )]);
            if node.certificate_pins != pins {
                node.certificate_pins = pins;
                plane
                    .replace_topology(
                        context.clone(),
                        topology,
                        Precondition::Version(current.version),
                        format!("tls-reload-{request_id}"),
                    )
                    .await?;
            }
        }
        let generations = self
            .sources
            .iter()
            .zip(candidates)
            .map(|((_, target), (_, config))| target.replace(config))
            .collect::<Result<Vec<_>>>()?;
        self.audit.record(event(SecurityOutcome::Succeeded)).await?;
        tracing::info!(
            ?generations,
            "TLS listener generations replaced; prior connections draining"
        );
        Ok(generations)
    }
    pub fn generations(&self) -> Result<Vec<u64>> {
        self.sources
            .iter()
            .map(|(_, target)| target.generation())
            .collect()
    }
}
