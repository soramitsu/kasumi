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
    let trusted_ca_pem = read_bounded(ca, 1 << 20)?;
    connections_with_ca(members, tls, &trusted_ca_pem)
}

/// Build exact pinned routes using the CA bytes already checked against an
/// immutable recovery binding. No path reread can substitute trust at dispatch.
pub(crate) fn connections_with_ca(
    members: &BTreeMap<u64, AuthorityEndpoint>,
    tls: &TlsFiles,
    trusted_ca_pem: &[u8],
) -> Result<BTreeMap<u64, KasumiClientConfig>> {
    validate(members)?;
    tls.validate()?;
    let identity = tls.load()?;
    members
        .iter()
        .map(|(id, member)| {
            Ok((
                *id,
                KasumiClientConfig {
                    endpoint: member.endpoint.clone(),
                    identity: identity.clone(),
                    trusted_ca_pem: trusted_ca_pem.to_vec(),
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
