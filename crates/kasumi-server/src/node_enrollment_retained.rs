//! Immutable facts in a completed enrollment's original configuration. Runtime
//! resource policy is deliberately not decoded: historical bytes are authenticated
//! by the retained head and genesis origins, never rewritten as today's config.
use super::*;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use std::{collections::BTreeSet, fmt};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum RetainedInput {
    Data { configuration: Box<DataIdentity> },
    Authority { configuration: AuthorityIdentity },
}
#[derive(Deserialize)]
pub(super) struct DataIdentity {
    database_id: Uuid,
    mode: crate::runtime::DeploymentMode,
    /// Every input written before data-only enrollment names its hosted Control.
    #[serde(default)]
    control: Option<ControlIdentity>,
    #[serde(default)]
    remote_control: Option<RemoteControlIdentity>,
    tenants: Vec<TenantIdentity>,
}
#[derive(Deserialize)]
struct RemoteControlIdentity {
    #[serde(default)]
    catalog_reader: Option<crate::data_member_catalog::CatalogReaderGrant>,
    root: RemoteRootIdentity,
    #[serde(default)]
    backup: Option<crate::remote_backup::BackupAccess>,
    #[serde(default, deserialize_with = "kasumi_types::deserialize_u64_map")]
    endpoints: std::collections::BTreeMap<u64, crate::serving_runtime::AuthorityEndpoint>,
    #[serde(default)]
    server_ca: Option<std::path::PathBuf>,
}
#[derive(Deserialize)]
struct RemoteRootIdentity {
    control_incarnation: Uuid,
    #[serde(default)]
    public_key: Option<String>,
}
#[derive(Debug, PartialEq, Eq)]
pub(super) enum ControlPlacement {
    Hosted,
    Remote(Uuid),
}
#[derive(Deserialize)]
pub(super) struct AuthorityIdentity {
    database_id: Uuid,
}
#[derive(Deserialize)]
struct ControlIdentity {
    incarnation: Uuid,
    #[serde(default)]
    backup_sources: Option<crate::remote_backup::BackupSources>,
    #[serde(default)]
    catalog_sources: Option<crate::data_member_catalog::DataCatalogSources>,
}
#[derive(Deserialize)]
struct TenantIdentity {
    tenant: String,
    incarnation: Uuid,
}
impl RetainedInput {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_INPUT,
            "node enrollment input exceeds limit"
        );
        // Ignored operational fields must not conceal duplicate JSON keys.
        serde_json::from_slice::<UniqueKeys>(bytes)
            .context("invalid retained node enrollment input")?;
        let input: Self =
            serde_json::from_slice(bytes).context("invalid retained node enrollment identity")?;
        ensure!(!input.identity().1.is_nil(), "nil node enrollment identity");
        if let Self::Data { configuration } = &input {
            match (&configuration.control, &configuration.remote_control) {
                (Some(control), None) => {
                    ensure!(!control.incarnation.is_nil(), "nil Control incarnation")
                }
                (None, Some(remote)) => ensure!(
                    configuration.mode == crate::runtime::DeploymentMode::Replicated
                        && !remote.root.control_incarnation.is_nil(),
                    "invalid remote Control enrollment"
                ),
                _ => anyhow::bail!("node enrollment Control placement is ambiguous"),
            }
            let mut names = BTreeSet::new();
            if configuration.mode == crate::runtime::DeploymentMode::Replicated
                && configuration.control.is_some()
            {
                names.insert(crate::runtime::CONTROL_TENANT);
            }
            for tenant in &configuration.tenants {
                kasumi_types::validate_name(&tenant.tenant)?;
                ensure!(
                    names.insert(&tenant.tenant),
                    "duplicate genesis tenant identity"
                );
                ensure!(
                    !tenant.incarnation.is_nil(),
                    "nil genesis tenant incarnation"
                );
            }
        }
        Ok(input)
    }
    pub(super) fn identity(&self) -> (Kind, Uuid) {
        match self {
            Self::Data { configuration } => (Kind::Data, configuration.database_id),
            Self::Authority { configuration } => (Kind::Authority, configuration.database_id),
        }
    }
    pub(super) fn control_placement(&self) -> Result<ControlPlacement> {
        match self {
            Self::Data { configuration } => Ok(match &configuration.remote_control {
                Some(remote) => ControlPlacement::Remote(remote.root.control_incarnation),
                None => ControlPlacement::Hosted,
            }),
            Self::Authority { .. } => {
                anyhow::bail!("authority enrollment has no Control placement")
            }
        }
    }
    pub(super) fn require_backup_placement(
        &self,
        config: &crate::runtime::RuntimeConfig,
    ) -> Result<()> {
        let Self::Data { configuration } = self else {
            anyhow::bail!("data enrollment required")
        };
        if let (Some(original), Some(current)) = (&configuration.control, &config.control) {
            ensure!(
                original.backup_sources == current.backup_sources
                    && original.catalog_sources == current.catalog_sources,
                "configured backup callback or catalog reader enrollment changed"
            );
        }
        if let (Some(original), Some(current)) =
            (&configuration.remote_control, &config.remote_control)
        {
            ensure!(
                original.catalog_reader.as_ref() == current.catalog_reader.as_deref()
                    && original.backup == current.backup
                    && ((original.backup.is_none() && original.catalog_reader.is_none())
                        || (original.root.public_key.as_ref() == Some(&current.root.public_key)
                            && original.endpoints == current.endpoints
                            && original.server_ca.as_ref() == Some(&current.server_ca))),
                "configured backup Control or catalog reader enrollment changed"
            );
        }
        Ok(())
    }
    pub(super) fn require_genesis(&self, store: &TenantStore, digest: &str) -> Result<()> {
        if let Self::Data { configuration } = self {
            if configuration.mode == crate::runtime::DeploymentMode::Replicated
                && let Some(control) = &configuration.control
            {
                require_genesis_record(
                    store,
                    crate::runtime::CONTROL_TENANT,
                    Some(control.incarnation),
                    digest,
                )?;
            }
            for tenant in &configuration.tenants {
                require_genesis_record(store, &tenant.tenant, Some(tenant.incarnation), digest)?;
            }
        }
        Ok(())
    }
}

// Decode these fields only for an opted-in journal exclusion, after the normal
// retained reader authenticated the full bytes and every original genesis.
pub(super) fn require_dedicated_journal_exclusion(
    bytes: &[u8],
    verifier: &kasumi_types::TrustVerifierIdentity,
    root: &kasumi_types::ControlSigningRoot,
) -> Result<()> {
    #[derive(Deserialize)]
    struct Original {
        configuration: Dedicated,
    }
    #[derive(Deserialize)]
    struct Dedicated {
        mode: crate::runtime::DeploymentMode,
        tenants: Vec<serde::de::IgnoredAny>,
        #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
        target_recovery: Option<serde::de::IgnoredAny>,
        remote_control: Option<serde::de::IgnoredAny>,
        control: Hosted,
        replication: Replica,
        signer_verifier: Signer,
    }
    #[derive(Deserialize)]
    struct Hosted {
        incarnation: Uuid,
        remote_data: Option<serde::de::IgnoredAny>,
        lifecycle: Lifecycle,
        catalog_sources: Catalogs,
    }
    #[derive(Deserialize)]
    struct Replica {
        node_id: u64,
    }
    #[derive(Deserialize)]
    struct Signer {
        identity: kasumi_types::TrustVerifierIdentity,
    }
    #[derive(Deserialize)]
    struct Lifecycle {
        installation: Installation,
    }
    #[derive(Deserialize)]
    struct Installation {
        root: kasumi_types::ControlSigningRoot,
    }
    #[derive(Deserialize)]
    struct Catalogs {
        target_journals: bool,
    }
    let original: Original = serde_json::from_slice(bytes)?;
    let config = original.configuration;
    let hosted = config.control;
    ensure!(
        config.mode == crate::runtime::DeploymentMode::Replicated
            && config.target_recovery.is_none()
            && config.tenants.is_empty()
            && config.remote_control.is_none()
            && hosted.remote_data.is_some()
            && hosted.catalog_sources.target_journals
            && hosted.incarnation == root.control_incarnation
            && &hosted.lifecycle.installation.root == root
            && config.replication.node_id == verifier.node_id
            && &config.signer_verifier.identity == verifier,
        "original dedicated Control enrollment does not prove exclusion of this journal"
    );
    Ok(())
}

// This preflight retains only keys for each active object and relies on the
// JSON decoder's depth bound. It does not reinterpret any operational setting.
struct UniqueKeys;
impl<'de> Deserialize<'de> for UniqueKeys {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        struct Keys;
        impl<'de> Visitor<'de> for Keys {
            type Value = UniqueKeys;
            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("JSON without duplicate object keys")
            }
            fn visit_unit<E: de::Error>(self) -> std::result::Result<UniqueKeys, E> {
                Ok(UniqueKeys)
            }
            fn visit_bool<E: de::Error>(self, _: bool) -> std::result::Result<UniqueKeys, E> {
                Ok(UniqueKeys)
            }
            fn visit_i64<E: de::Error>(self, _: i64) -> std::result::Result<UniqueKeys, E> {
                Ok(UniqueKeys)
            }
            fn visit_u64<E: de::Error>(self, _: u64) -> std::result::Result<UniqueKeys, E> {
                Ok(UniqueKeys)
            }
            fn visit_f64<E: de::Error>(self, _: f64) -> std::result::Result<UniqueKeys, E> {
                Ok(UniqueKeys)
            }
            fn visit_str<E: de::Error>(self, _: &str) -> std::result::Result<UniqueKeys, E> {
                Ok(UniqueKeys)
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> std::result::Result<UniqueKeys, A::Error> {
                while sequence.next_element::<UniqueKeys>()?.is_some() {}
                Ok(UniqueKeys)
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut object: A,
            ) -> std::result::Result<UniqueKeys, A::Error> {
                let mut keys = BTreeSet::new();
                while let Some(key) = object.next_key::<String>()? {
                    if !keys.insert(key) {
                        return Err(de::Error::custom("duplicate node enrollment object key"));
                    }
                    object.next_value::<UniqueKeys>()?;
                }
                Ok(UniqueKeys)
            }
        }
        deserializer.deserialize_any(Keys)
    }
}
