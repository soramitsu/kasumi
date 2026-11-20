//! One enrolled Authority member's physical application and custody catalogs.
use anyhow::{Result, ensure};
use kasumi_types::{
    KeyCatalogDomain, KeyReference, KeyRetentionEntry, staged_digest, validate_sha256,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const AUTHORITY_CATALOG_PAGE_LIMIT: u16 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityCatalogScope {
    Wrapping,
    ServiceAudit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCatalogCursor {
    pub inventory_sha256: String,
    pub after: KeyRetentionEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCatalogRequest {
    pub nonce: Uuid,
    pub scope: AuthorityCatalogScope,
    pub authority_id: Uuid,
    pub partition: u16,
    pub node_id: u64,
    pub limit: u16,
    pub cursor: Option<AuthorityCatalogCursor>,
}

impl AuthorityCatalogRequest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.nonce.is_nil()
                && !self.authority_id.is_nil()
                && self.node_id != 0
                && (1..=AUTHORITY_CATALOG_PAGE_LIMIT).contains(&self.limit),
            "invalid Authority catalog request"
        );
        if let Some(cursor) = &self.cursor {
            validate_sha256(&cursor.inventory_sha256)?;
            cursor.after.validate()?;
            ensure!(
                match &cursor.after.reference {
                    KeyReference::Catalog {
                        node_id, domain, ..
                    } =>
                        *node_id == self.node_id
                            && match self.scope {
                                AuthorityCatalogScope::Wrapping => matches!(
                                    domain,
                                    KeyCatalogDomain::IndependentAuthority
                                        | KeyCatalogDomain::RetirementCustody
                                        | KeyCatalogDomain::SecurityAudit
                                        | KeyCatalogDomain::LiveSignerTrust
                                ),
                                AuthorityCatalogScope::ServiceAudit =>
                                    *domain == KeyCatalogDomain::SecurityAudit,
                            },
                    KeyReference::AuditArchive { .. } =>
                        self.scope == AuthorityCatalogScope::ServiceAudit,
                    _ => false,
                },
                "cursor belongs to another Authority catalog"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityOperationalCatalogs {
    pub security_audit: Uuid,
    pub live_signer_trust: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityCatalogPage {
    pub request_sha256: String,
    pub term: u64,
    pub membership_index: u64,
    pub applied_index: u64,
    /// The live installed voters and learners at the observed Raft membership.
    pub members: Vec<u64>,
    pub membership_sha256: String,
    pub application_catalog: Uuid,
    pub custody_catalog: Uuid,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub operational_catalogs: Option<AuthorityOperationalCatalogs>,
    #[serde(deserialize_with = "kasumi_types::require_explicit_option")]
    pub audit_stream: Option<Uuid>,
    pub inventory_sha256: String,
    pub entries: Vec<KeyRetentionEntry>,
    pub next: Option<AuthorityCatalogCursor>,
}

impl AuthorityCatalogPage {
    pub fn validate(&self, query: &AuthorityCatalogRequest) -> Result<()> {
        query.validate()?;
        validate_sha256(&self.inventory_sha256)?;
        validate_sha256(&self.membership_sha256)?;
        ensure!(
            self.request_sha256 == staged_digest(query)?.0
                && self.term > 0
                && self.applied_index >= self.membership_index
                && (3..=64).contains(&self.members.len())
                && self.members[0] > 0
                && self.members.windows(2).all(|ids| ids[0] < ids[1])
                && self.members.binary_search(&query.node_id).is_ok()
                && !self.application_catalog.is_nil()
                && !self.custody_catalog.is_nil()
                && self.application_catalog != self.custody_catalog
                && self.entries.len() <= usize::from(query.limit)
                && self.entries.windows(2).all(|w| w[0] < w[1]),
            "Authority catalog page differs from requested position or bounds"
        );
        if let Some(cursor) = &query.cursor {
            ensure!(
                self.inventory_sha256 == cursor.inventory_sha256
                    && self
                        .entries
                        .first()
                        .is_none_or(|entry| *entry > cursor.after),
                "Authority catalog continuation changed or repeated an entry"
            );
            if let KeyReference::AuditArchive { stream_id, .. } = cursor.after.reference {
                ensure!(
                    self.audit_stream == Some(stream_id),
                    "Authority cursor belongs to another audit stream"
                );
            }
        }
        ensure!(
            match query.scope {
                AuthorityCatalogScope::Wrapping => self.audit_stream.is_none(),
                AuthorityCatalogScope::ServiceAudit =>
                    self.operational_catalogs.is_some()
                        && self.audit_stream.is_some_and(|id| !id.is_nil()),
            },
            "Authority audit stream differs from requested scope"
        );
        if let Some(catalogs) = &self.operational_catalogs {
            let ids = [
                self.application_catalog,
                self.custody_catalog,
                catalogs.security_audit,
                catalogs.live_signer_trust,
            ];
            ensure!(
                ids.iter()
                    .enumerate()
                    .all(|(i, id)| !id.is_nil() && !ids[..i].contains(id)),
                "Authority operational catalogs must be distinct installed identities"
            );
        }
        for entry in &self.entries {
            entry.validate()?;
            if query.scope == AuthorityCatalogScope::ServiceAudit {
                ensure!(
                    match entry.reference {
                        KeyReference::AuditArchive { stream_id, .. } =>
                            self.audit_stream == Some(stream_id),
                        KeyReference::Catalog {
                            node_id,
                            catalog_id,
                            domain: KeyCatalogDomain::SecurityAudit,
                        } =>
                            node_id == query.node_id
                                && self
                                    .operational_catalogs
                                    .as_ref()
                                    .is_some_and(|c| c.security_audit == catalog_id),
                        _ => false,
                    },
                    "entry belongs to another physical Authority audit"
                );
                continue;
            }
            ensure!(
                matches!(&entry.reference, KeyReference::Catalog { node_id, catalog_id, domain }
                if *node_id == query.node_id && match domain {
                    KeyCatalogDomain::IndependentAuthority => *catalog_id == self.application_catalog,
                    KeyCatalogDomain::RetirementCustody => *catalog_id == self.custody_catalog,
                    KeyCatalogDomain::SecurityAudit => self.operational_catalogs.as_ref().is_some_and(|c| c.security_audit == *catalog_id),
                    KeyCatalogDomain::LiveSignerTrust => self.operational_catalogs.as_ref().is_some_and(|c| c.live_signer_trust == *catalog_id),
                    _ => false,
                }),
                "entry belongs to another installed catalog"
            );
        }
        if let Some(next) = &self.next {
            ensure!(
                next.inventory_sha256 == self.inventory_sha256
                    && self.entries.last() == Some(&next.after)
                    && self.entries.len() == usize::from(query.limit),
                "Authority catalog continuation differs from its page"
            );
        }
        Ok(())
    }
}
