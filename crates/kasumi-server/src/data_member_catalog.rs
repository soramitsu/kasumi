//! The separate read-only Control principal permitted to inspect physical Data services.
use crate::remote_control::RemoteControlConfig;
use anyhow::{Result, ensure};
use kasumi_types::{Action, DataMemberCatalogRead, Error, ErrorCode, RequestContext};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogReaderGrant {
    pub principal: String,
    pub client_certificate_pins: BTreeSet<String>,
    pub groups: BTreeMap<String, Uuid>,
}

impl CatalogReaderGrant {
    pub(crate) fn validate(&self, remote: &RemoteControlConfig) -> Result<()> {
        kasumi_types::validate_name(&self.principal)?;
        ensure!(
            self.principal != remote.principal && !remote.observers.contains(&self.principal),
            "catalog reader must have a separately enrolled principal"
        );
        ensure!(
            (1..=8).contains(&self.client_certificate_pins.len()),
            "catalog reader requires approved certificate pins"
        );
        for pin in &self.client_certificate_pins {
            kasumi_types::validate_sha256(pin)?;
        }
        if let Some(backup) = &remote.backup {
            ensure!(
                self.principal != backup.principal
                    && self.principal != backup.callback_principal
                    && self
                        .client_certificate_pins
                        .is_disjoint(&backup.source_certificate_pins)
                    && self
                        .client_certificate_pins
                        .is_disjoint(&backup.callback_certificate_pins),
                "catalog reader reuses an enrolled backup identity"
            );
        }
        ensure!(
            (1..=10_000).contains(&self.groups.len()),
            "catalog reader group count exceeds the installed Data limit"
        );
        for (tenant, incarnation) in &self.groups {
            kasumi_types::validate_name(tenant)?;
            ensure!(
                !tenant.starts_with("__kasumi_") && !incarnation.is_nil(),
                "invalid catalog reader Data group"
            );
        }
        Ok(())
    }

    pub(crate) fn authorize(
        &self,
        root: Uuid,
        actor: &RequestContext,
        peer: &str,
        read: &DataMemberCatalogRead,
    ) -> kasumi_types::Result<()> {
        let denied = || Error::new(ErrorCode::Forbidden, "Data inventory reader refused");
        actor.authorization.check_live()?;
        if actor.tenant != crate::runtime::CONTROL_TENANT
            || actor.principal != self.principal
            || actor.scopes.len() != 1
            || !actor.scopes.contains(&Action::Audit)
            || actor.authorization.expires_at_ms().is_none()
            || !self.client_certificate_pins.contains(peer)
            || self.groups.get(&read.tenant) != Some(&read.incarnation)
        {
            return Err(denied());
        }
        actor
            .authorization
            .resource()
            .ok_or_else(denied)?
            .require_control(&root.to_string())
    }
}

use crate::runtime::{TlsFiles, credential_path};
use crate::serving_runtime::AuthorityEndpoint;
use anyhow::Context;
use kasumi_client::{FileCredentialSource, KasumiAdminClient, KasumiClientConfig};
use kasumi_engine::{
    RemoteDataCatalogReader,
    admission::{NodeAdmission, Reservation},
    control::ControlTopology,
};
use kasumi_types::{DataCatalogGroup, DataMemberCatalogPage, TrustVerifierIdentity};
use std::{path::PathBuf, sync::Arc};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataCatalogSource {
    pub verifier: TrustVerifierIdentity,
    pub admin: AuthorityEndpoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataCatalogSources {
    pub tls: TlsFiles,
    pub server_ca: PathBuf,
    pub principal: String,
    pub bearer_file: String,
    pub client_certificate_pins: BTreeSet<String>,
    #[serde(deserialize_with = "kasumi_types::deserialize_u64_map")]
    pub members: BTreeMap<u64, DataCatalogSource>,
    pub groups: BTreeMap<String, DataCatalogGroup>,
}

impl DataCatalogSources {
    pub(crate) fn validate(
        &self,
        topology: &ControlTopology,
        backup: Option<&crate::remote_backup::BackupSources>,
    ) -> Result<()> {
        self.tls.validate()?;
        credential_path(&self.bearer_file)?;
        kasumi_types::validate_name(&self.principal)?;
        ensure!(
            self.server_ca.is_absolute() && (1..=8).contains(&self.client_certificate_pins.len()),
            "catalog reader must pin its client identity and name its CA"
        );
        for pin in &self.client_certificate_pins {
            kasumi_types::validate_sha256(pin)?;
        }
        if let Some(backup) = backup {
            ensure!(
                self.principal != backup.callback_principal
                    && self.bearer_file != backup.bearer_file
                    && self.tls != backup.tls
                    && backup.members.values().all(|route| self.principal
                        != route.writer_principal
                        && self
                            .client_certificate_pins
                            .is_disjoint(&route.source_certificate_pins)),
                "catalog reader reuses an installed backup identity"
            );
        }
        ensure!(
            self.members.keys().eq(topology.nodes.keys())
                && self.groups.keys().eq(topology.tenants.keys())
                && !self.groups.is_empty(),
            "catalog sources must enroll every dedicated Data installation and group"
        );
        let mut used = BTreeSet::new();
        for (tenant, group) in &self.groups {
            let route = &topology.tenants[tenant];
            ensure!(
                uuid::Uuid::parse_str(&route.incarnation)? == group.incarnation
                    && !group.incarnation.is_nil()
                    && !group.members.is_empty()
                    && group.members.len() <= kasumi_types::DATA_CATALOG_MAX_MEMBERS
                    && route.voters.is_subset(&group.members)
                    && group.members.iter().all(|id| self.members.contains_key(id)),
                "catalog sources differ from enrolled Data membership"
            );
            used.extend(group.members.iter().copied());
        }
        ensure!(
            used.iter().eq(self.members.keys()),
            "catalog reader has a route without a Data group"
        );
        let mut origins = BTreeSet::new();
        let mut pins = BTreeSet::new();
        let mut installations = BTreeSet::new();
        for (&id, source) in &self.members {
            source.verifier.validate()?;
            ensure!(
                source.verifier.node_id == id
                    && installations.insert(source.verifier.installation_id),
                "catalog source verifier is duplicated or belongs to another node"
            );
            crate::installed_clients::validate(&BTreeMap::from([(id, source.admin.clone())]))?;
            let origin = crate::runtime::origin(&source.admin.endpoint)?
                .origin()
                .ascii_serialization();
            ensure!(
                origins.insert(origin)
                    && source
                        .admin
                        .certificate_pins
                        .iter()
                        .all(|p| pins.insert(p.clone()))
                    && source
                        .admin
                        .certificate_pins
                        .is_disjoint(&self.client_certificate_pins)
                    && topology.nodes[&id]
                        .certificate_pins
                        .is_disjoint(&self.client_certificate_pins),
                "catalog source reuses an administrative endpoint or peer identity"
            );
        }
        Ok(())
    }
}

pub(crate) struct InstalledReader {
    sources: DataCatalogSources,
    routes: BTreeMap<u64, KasumiClientConfig>,
    bearer: FileCredentialSource,
    _routes_budget: Reservation,
}

impl InstalledReader {
    pub(crate) fn open(
        config: &DataCatalogSources,
        admission: &Arc<NodeAdmission>,
    ) -> Result<Arc<Self>> {
        let (_, bytes) = kasumi_types::staged_digest(config)?;
        let bytes = config.members.len() as u64 * (4 << 20) + bytes as u64 * 4 + 65536;
        let mut budget = admission.reserve_resident(bytes + (8 << 20))?;
        let ca = crate::runtime::read_bounded(&config.server_ca, 1 << 20)?;
        let mut routes = BTreeMap::new();
        for (&id, member) in &config.members {
            let endpoints = BTreeMap::from([(id, member.admin.clone())]);
            let mut resolved =
                crate::installed_clients::connections_with_ca(&endpoints, &config.tls, &ca)?;
            let route = resolved
                .remove(&id)
                .context("catalog source resolution failed")?;
            ensure!(
                config
                    .client_certificate_pins
                    .contains(&hex::encode(route.identity.certificate_pin())),
                "catalog reader TLS identity differs from enrollment"
            );
            routes.insert(id, route);
        }
        budget.retain(bytes);
        Ok(Arc::new(Self {
            sources: config.clone(),
            routes,
            bearer: FileCredentialSource::new(&config.bearer_file)?,
            _routes_budget: budget,
        }))
    }
}

impl RemoteDataCatalogReader for InstalledReader {
    fn groups(&self) -> &BTreeMap<String, DataCatalogGroup> {
        &self.sources.groups
    }
    fn verifier(&self, id: u64) -> Option<&TrustVerifierIdentity> {
        self.sources.members.get(&id).map(|route| &route.verifier)
    }
    fn read<'a>(
        &'a self,
        voters: &'a BTreeSet<u64>,
        input: &'a DataMemberCatalogRead,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<DataMemberCatalogPage>> + Send + 'a>,
    > {
        Box::pin(async move {
            let group = self
                .groups()
                .get(&input.tenant)
                .context("missing catalog group enrollment")?;
            ensure!(
                group.incarnation == input.incarnation
                    && group.members.contains(&input.verifier.node_id)
                    && self.verifier(input.verifier.node_id) == Some(&input.verifier)
                    && !voters.is_empty()
                    && voters.is_subset(&group.members),
                "catalog read differs from installed route"
            );
            let mut last = None;
            for id in voters {
                let route = self
                    .routes
                    .get(id)
                    .context("missing enrolled Data voter listener")?;
                let token = kasumi_transport::credentials::token(&self.bearer)?;
                let call = async {
                    let mut client = KasumiAdminClient::connect(route).await?;
                    client.read_data_member_catalog(&token, input).await
                };
                match tokio::time::timeout(std::time::Duration::from_secs(3), call).await {
                    Ok(Ok(page)) => {
                        ensure!(
                            page.membership.leader == *id,
                            "catalog reader contacted a different Data leader"
                        );
                        return Ok(page);
                    }
                    Ok(Err(error)) => last = Some(anyhow::Error::from(error)),
                    Err(error) => last = Some(anyhow::Error::from(error)),
                }
            }
            Err(last.context("no enrolled Data voters available")?)
        })
    }
}

#[derive(Clone)]
pub(crate) struct DataCatalogListener {
    pub(crate) control: Uuid,
    pub(crate) grant: Arc<CatalogReaderGrant>,
    pub(crate) admission: Arc<NodeAdmission>,
}
