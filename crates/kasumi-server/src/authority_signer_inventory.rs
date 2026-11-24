//! Collect each physical issuer member over its installed connection. A
//! missing learner, unresponsive voter or changed catalog invalidates the
//! entire partition observation.
use super::*;
use kasumi_client::KasumiAuthorityClient;
use kasumi_engine::{AuthoritySignerKeyInventory, AuthoritySignerKeys};
use kasumi_types::{KeyCatalogDomain, KeyReference, KeyRetentionEntry, ReadKeyRetentionRequest};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use uuid::Uuid;

#[async_trait::async_trait]
impl AuthoritySignerKeyInventory for ControlSignerRuntime {
    async fn read_partition(
        &self,
        authority_id: Uuid,
        partition: u16,
        request: &ReadKeyRetentionRequest,
    ) -> Result<AuthoritySignerKeys> {
        let mut routes = self.authorities.iter().filter(|(_, config)| {
            config.manifest.authority_id == authority_id
                && config.manifest.partitions.contains_key(&partition)
        });
        let (name, config) = routes.next().context("issuer partition is not installed")?;
        ensure!(
            routes.next().is_none(),
            "multiple installed routes for issuer partition"
        );
        let members = &config.endpoints[&partition];
        let token_file = config
            .catalog_bearer_files
            .get(&partition)
            .context("issuer catalog credential is not installed for this partition")?;
        let tls = config.tls.load()?;
        let ca = read_bounded(&config.server_ca, 1 << 20)?;
        let mut position = None;
        let mut catalogs = BTreeSet::new();
        let mut entries = BTreeSet::new();
        let mut observed = BTreeMap::new();
        let mut audit_owners = BTreeMap::new();
        let scope = match request.scope {
            kasumi_types::KeyRetentionScope::Signer {} => AuthorityCatalogScope::Wrapping,
            kasumi_types::KeyRetentionScope::SecurityAudit {} => {
                AuthorityCatalogScope::ServiceAudit
            }
            _ => anyhow::bail!("unsupported issuer inventory scope"),
        };
        for recheck in [false, true] {
            for (&node_id, endpoint) in members {
                let connection = KasumiClientConfig {
                    endpoint: endpoint.endpoint.clone(),
                    identity: tls.clone(),
                    trusted_ca_pem: ca.clone(),
                    server_certificate_pins: endpoint
                        .certificate_pins
                        .iter()
                        .map(|pin| parse_certificate_pin(pin))
                        .collect::<Result<_>>()?,
                };
                let mut client =
                    KasumiAuthorityClient::connect(&connection, self.trusts[name].clone()).await?;
                let mut cursor = None;
                loop {
                    let query = AuthorityCatalogRequest {
                        authority_id,
                        scope,
                        partition,
                        node_id,
                        limit: AUTHORITY_CATALOG_PAGE_LIMIT,
                        nonce: Uuid::new_v4(),
                        cursor: cursor.take(),
                    };
                    let bearer = (self.credential)(token_file)?;
                    let response = client
                        .maintenance(
                            &bearer,
                            &AuthorityMaintenanceRequest::MemberCatalog { query },
                        )
                        .await?;
                    let AuthorityMaintenanceResponse::MemberCatalog { page } = response else {
                        anyhow::bail!("unexpected issuer key inventory response");
                    };
                    ensure!(
                        page.members.iter().eq(members.keys()),
                        "issuer membership differs from installed endpoint roster"
                    );
                    let current = (page.term, page.membership_index, page.membership_sha256);
                    ensure!(
                        position.get_or_insert_with(|| current.clone()) == &current,
                        "issuer group position changed during collection"
                    );
                    let physical = page
                        .operational_catalogs
                        .context("issuer member has no installed operational catalogs")?;
                    if let Some(previous) = observed.get(&node_id) {
                        ensure!(
                            previous == &page.inventory_sha256,
                            "issuer member catalog changed during collection"
                        );
                    } else {
                        for id in [
                            page.application_catalog,
                            page.custody_catalog,
                            physical.security_audit,
                            physical.live_signer_trust,
                        ] {
                            ensure!(
                                catalogs.insert(id),
                                "issuer physical catalog belongs to multiple members"
                            );
                        }
                        if let Some(stream) = page.audit_stream {
                            audit_owners.insert(physical.security_audit, stream);
                        }
                        observed.insert(node_id, page.inventory_sha256);
                    }
                    if recheck {
                        break;
                    }
                    for entry in page.entries {
                        let selected = scope == AuthorityCatalogScope::ServiceAudit
                            || matches!(
                                entry.reference,
                                KeyReference::Catalog {
                                    domain: KeyCatalogDomain::IndependentAuthority
                                        | KeyCatalogDomain::RetirementCustody
                                        | KeyCatalogDomain::LiveSignerTrust,
                                    ..
                                }
                            );
                        if selected
                            && request
                                .cursor
                                .as_ref()
                                .is_none_or(|cursor| entry > cursor.after)
                        {
                            retain_entry(&mut entries, entry, request.limit);
                        }
                    }
                    cursor = page.next;
                    if cursor.is_none() {
                        break;
                    }
                }
            }
        }
        let mut digest = Sha256::new();
        serde_json::to_writer(
            &mut digest,
            &(
                "kasumi.issuer-key-inventory.v2",
                authority_id,
                partition,
                scope,
                position,
                observed,
            ),
        )?;
        Ok(AuthoritySignerKeys {
            audit_owners,
            inventory_sha256: digest.finalize().into(),
            entries: entries.into_iter().collect(),
        })
    }
}

fn retain_entry(entries: &mut BTreeSet<KeyRetentionEntry>, entry: KeyRetentionEntry, limit: u16) {
    entries.insert(entry);
    if entries.len() > usize::from(limit) + 1 {
        entries.pop_last();
    }
}
