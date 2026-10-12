//! Immutable facts in a completed enrollment's original configuration. Runtime
//! resource policy is deliberately not decoded: historical bytes are authenticated
//! by the retained head and genesis origins, never rewritten as today's config.
use super::*;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use std::{collections::BTreeSet, fmt};

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum RetainedInput {
    Data { configuration: DataIdentity },
    Authority { configuration: AuthorityIdentity },
}
#[derive(Deserialize)]
pub(super) struct DataIdentity {
    database_id: Uuid,
    mode: crate::runtime::DeploymentMode,
    control: ControlIdentity,
    tenants: Vec<TenantIdentity>,
}
#[derive(Deserialize)]
pub(super) struct AuthorityIdentity {
    database_id: Uuid,
}
#[derive(Deserialize)]
struct ControlIdentity {
    incarnation: Uuid,
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
            ensure!(
                !configuration.control.incarnation.is_nil(),
                "nil Control incarnation"
            );
            let mut names = BTreeSet::new();
            if configuration.mode == crate::runtime::DeploymentMode::Replicated {
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
    pub(super) fn require_genesis(&self, store: &TenantStore, digest: &str) -> Result<()> {
        if let Self::Data { configuration } = self {
            if configuration.mode == crate::runtime::DeploymentMode::Replicated {
                require_genesis_record(
                    store,
                    crate::runtime::CONTROL_TENANT,
                    Some(configuration.control.incarnation),
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
