//! Closed installed member maps shared by administrative client entry points.
use crate::{
    runtime::{TlsFiles, origin, parse_certificate_pin, read_bounded},
    serving_runtime::AuthorityEndpoint,
};
use anyhow::{Result, ensure};
use kasumi_client::KasumiClientConfig;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

pub(crate) fn validate(members: &BTreeMap<u64, AuthorityEndpoint>) -> Result<()> {
    ensure!(
        (1..=64).contains(&members.len()) && !members.contains_key(&0),
        "installed service requires one to 64 nonzero member IDs"
    );
    let mut origins = BTreeSet::new();
    for member in members.values() {
        origin(&member.endpoint)?;
        let canonical = url::Url::parse(&member.endpoint)?.to_string();
        ensure!(
            origins.insert(canonical) && (1..=8).contains(&member.certificate_pins.len()),
            "installed service needs unique origins and bounded explicit pins"
        );
        for pin in &member.certificate_pins {
            parse_certificate_pin(pin)?;
        }
    }
    Ok(())
}

pub(crate) fn connections(
    members: &BTreeMap<u64, AuthorityEndpoint>,
    tls: &TlsFiles,
    ca: &Path,
) -> Result<BTreeMap<u64, KasumiClientConfig>> {
    validate(members)?;
    tls.validate()?;
    ensure!(
        ca.is_absolute(),
        "installed service CA path must be absolute"
    );
    let identity = tls.load()?;
    let trusted_ca_pem = read_bounded(ca, 1 << 20)?;
    members
        .iter()
        .map(|(id, member)| {
            Ok((
                *id,
                KasumiClientConfig {
                    endpoint: member.endpoint.clone(),
                    identity: identity.clone(),
                    trusted_ca_pem: trusted_ca_pem.clone(),
                    server_certificate_pins: member
                        .certificate_pins
                        .iter()
                        .map(|pin| parse_certificate_pin(pin))
                        .collect::<Result<_>>()?,
                },
            ))
        })
        .collect()
}
