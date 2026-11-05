//! A flood of traffic that identifies no client, through the real
//! authentication and TLS audit adapters, is counted rather than recorded one
//! by one. It cannot take the hot capacity that a valid token, a client
//! certificate's accept and administrative records need, even while no
//! archive can drain, and every event stays in an exact count.
use crate::{
    auth::{AuthConfig, AuthKeySource, Authenticator},
    runtime::{CONTROL_TENANT, SECURITY_TENANT, SecurityAudit, SecurityEvent, SecurityEventKind},
    tls::{TlsHandshakeAudit, TlsHandshakeEvent, TlsHandshakeOutcome},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use kasumi_store::{TenantStore, test_utils::LocalKeyProvider};
use kasumi_types::{AuditRetentionBudget, CountedEvent, SecurityAuditRecord, SecurityOutcome};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

/// Each round is one counting window of this many events of each kind.
const EVENTS_PER_ROUND: u32 = 1000;
const ROUNDS: u32 = 5;
/// More source addresses than one window records peers for.
const TLS_PEERS: u32 = 300;

async fn authenticator() -> (Arc<Authenticator>, EncodingKey) {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    let keys = serde_json::from_value(serde_json::json!({"keys":[{"kty":"OKP","crv":"Ed25519","alg":"EdDSA","use":"sig","kid":"flood-key","x":URL_SAFE_NO_PAD.encode(key.public_key_raw())}]})).unwrap();
    let auth = Authenticator::with_test_keys(
        AuthConfig {
            issuer: "https://issuer.example".into(),
            audience: "https://kasumi.example/mcp".into(),
            source: AuthKeySource::ExternalOAuth {
                jwks_uri: "https://issuer.example/keys".into(),
                trusted_ca_pem: None,
            },
            algorithms: vec![Algorithm::EdDSA],
            access_token_types: BTreeSet::from(["at+jwt".into()]),
        },
        keys,
    )
    .await;
    (
        auth,
        EncodingKey::from_ed_pem(key.serialize_pem().as_bytes()).unwrap(),
    )
}

fn bearer(key: &EncodingKey) -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = serde_json::json!({"iss":"https://issuer.example","aud":"https://kasumi.example/mcp","sub":"operator","tenant":CONTROL_TENANT,"kasumi_resource":{"kind":"database","incarnation":"00000000-0000-0000-0000-000000000001"},"scope":"kasumi:admin","exp":now+300,"nbf":now-1,"token_use":"access"});
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("flood-key".into());
    header.typ = Some("at+jwt".into());
    format!("Bearer {}", encode(&header, &claims, key).unwrap())
}

fn administration(request_id: String) -> SecurityEvent {
    SecurityEvent {
        kind: SecurityEventKind::Administration,
        principal: Some("operator".into()),
        tenant: Some(CONTROL_TENANT.into()),
        request_id,
        outcome: SecurityOutcome::Succeeded,
    }
}

fn handshake(
    peer: u32,
    round: u32,
    pin: Option<[u8; 32]>,
    outcome: TlsHandshakeOutcome,
) -> TlsHandshakeEvent {
    TlsHandshakeEvent {
        connection_id: uuid::Uuid::new_v4().to_string(),
        peer_address: SocketAddr::from((
            [10, round as u8, (peer >> 8) as u8, peer as u8],
            40_000 + (peer % 20_000) as u16,
        )),
        certificate_pin: pin,
        outcome,
        timestamp_ms: 0,
    }
}

/// One window of refused tokens, identity-less refusals (as for a bad MCP
/// `Origin`), failed TLS handshakes, and TLS accepts without a client
/// certificate (as on the MCP listener), the TLS events from TLS_PEERS
/// addresses.
async fn flood(audit: &SecurityAudit, auth: &Authenticator, round: u32) {
    for index in 0..EVENTS_PER_ROUND {
        assert!(auth.authenticate("Bearer not-a-token").await.is_err());
        auth.anonymous_denial().await;
        let peer = index % TLS_PEERS;
        let failed = if index % 2 == 0 {
            TlsHandshakeOutcome::Rejected
        } else {
            TlsHandshakeOutcome::TimedOut
        };
        for outcome in [failed, TlsHandshakeOutcome::Accepted] {
            TlsHandshakeAudit::record(audit, &handshake(peer, round, None, outcome))
                .await
                .unwrap();
        }
    }
}

/// Events that identify no client, per kind; each record of its own counts one.
fn unidentified(
    records: impl IntoIterator<Item = SecurityAuditRecord>,
) -> BTreeMap<&'static str, u64> {
    let name = |event| match event {
        CountedEvent::TransportAuthenticated => "anonymous accept",
        CountedEvent::TransportDenied => "failed handshake",
        CountedEvent::AuthenticationDenied => "refused token",
        CountedEvent::AccessDenied => "identity-less refusal",
    };
    let mut events = BTreeMap::new();
    for record in records {
        let (kind, count) = match record.event.kind {
            SecurityEventKind::TransportAuthenticated
                if record
                    .transport
                    .as_ref()
                    .is_some_and(|transport| transport.certificate_pin.is_none()) =>
            {
                (name(CountedEvent::TransportAuthenticated), 1)
            }
            SecurityEventKind::TransportDenied => (name(CountedEvent::TransportDenied), 1),
            SecurityEventKind::AuthenticationDenied => {
                (name(CountedEvent::AuthenticationDenied), 1)
            }
            SecurityEventKind::AccessDenied => (name(CountedEvent::AccessDenied), 1),
            SecurityEventKind::EventsCounted { event, count, .. } => (name(event), count),
            _ => continue,
        };
        assert!(record.event.principal.is_none() && record.event.tenant.is_none());
        *events.entry(kind).or_default() += count;
    }
    events
}

/// Every hot and archived record, through the operator export.
async fn exported(audit: &SecurityAudit) -> Vec<SecurityAuditRecord> {
    let mut records = Vec::new();
    let mut cursor = None;
    loop {
        let page = audit.export_page(cursor, 1024).await.unwrap();
        cursor = page.cursor();
        records.extend(page.records);
        if cursor.is_none() {
            return records;
        }
    }
}

fn hot_records(audit: &SecurityAudit) -> Vec<SecurityAuditRecord> {
    audit
        .store()
        .scan("security.audit")
        .unwrap()
        .iter()
        .map(|(_, bytes)| serde_json::from_slice(bytes).unwrap())
        .collect()
}

#[tokio::test]
async fn an_unauthenticated_flood_leaves_room_for_a_valid_token_and_administrative_records() {
    let directory = kasumi_store::test_utils::private_tempdir().unwrap();
    let physical =
        crate::runtime_storage_fixtures::physical(directory.path(), Default::default()).unwrap();
    let node = physical
        .create_new(
            directory.path().join("persistent/node.kv"),
            kasumi_store::test_utils::NODE_STORE_ID,
        )
        .unwrap();
    let store = TenantStore::initialize_catalog_fixture(
        node.clone(),
        SECURITY_TENANT.into(),
        Arc::new(LocalKeyProvider::new([29; 32])),
    )
    .await
    .unwrap();
    // The smallest hot range a budget allows: a few hundred records fill it.
    let budget = AuditRetentionBudget {
        hot_bytes: 128 << 10,
        archive_bytes: 8 << 20,
    };
    let audit =
        SecurityAudit::initialize(store, budget.clone(), physical.admission.clone()).unwrap();
    let (auth, key) = authenticator().await;
    auth.install_audit(audit.clone()).unwrap();

    // While this is held no archive can drain the hot range, as when the
    // archive budget is exhausted. Recorded one by one, the first round alone
    // would fill the hot budget several times over.
    let maintenance = audit.quiescent_jobs_for_test().await;
    for round in 0..ROUNDS {
        flood(&audit, &auth, round).await;
        audit.flush_counts().await.unwrap();
        // This traffic alone never takes the hot range above the threshold.
        assert!(audit.status().unwrap().position.hot_bytes <= budget.starts_at());
    }
    let issued = u64::from(EVENTS_PER_ROUND * ROUNDS);
    let expected = BTreeMap::from([
        ("anonymous accept", issued),
        ("failed handshake", issued),
        ("identity-less refusal", issued),
        ("refused token", issued),
    ]);
    let hot = hot_records(&audit);
    assert!(
        hot.len() < 1000,
        "{} records for {} events",
        hot.len(),
        issued * 4
    );
    // The threshold refused records; their events are counted and pending.
    let recorded = unidentified(hot);
    assert!(
        expected
            .iter()
            .any(|(kind, issued)| recorded.get(kind).copied().unwrap_or(0) < *issued),
        "{recorded:?}"
    );

    // A client certificate's accept is still recorded before its connection
    // is served, a valid token still authenticates, and administrative
    // records still fit, repeatedly, in the capacity above the threshold.
    TlsHandshakeAudit::record(
        &*audit,
        &handshake(1, 99, Some([7; 32]), TlsHandshakeOutcome::Accepted),
    )
    .await
    .unwrap();
    let pin = "07".repeat(32);
    assert!(hot_records(&audit).iter().any(|record| {
        record.event.kind == SecurityEventKind::TransportAuthenticated
            && record.transport.as_ref().unwrap().certificate_pin.as_ref() == Some(&pin)
    }));
    let token = bearer(&key);
    for index in 0..20 {
        let context = auth.authenticate(&token).await.unwrap();
        assert_eq!(context.principal, "operator");
        audit
            .record(administration(format!("recovery-{index}")))
            .await
            .unwrap();
    }
    assert!(audit.status().unwrap().position.hot_bytes > budget.starts_at());

    // Once archives drain again, the pending counts are written and every
    // event is accounted for exactly once. The archive worker may be writing
    // counts of a window it found ended, so an export can briefly trail; it
    // never exceeds an event's single record or count.
    drop(maintenance);
    while audit.status().unwrap().position.hot_bytes > budget.drains_to() {
        audit.maintain().await.unwrap();
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        audit.flush_counts().await.unwrap();
        let accounted = unidentified(exported(&audit).await);
        for (kind, issued) in &expected {
            assert!(
                accounted.get(kind).copied().unwrap_or(0) <= *issued,
                "{accounted:?}"
            );
        }
        if accounted == expected {
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "{accounted:?}");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(audit.status().unwrap().archive_segments > 0);

    audit.shutdown().await.unwrap();
    node.shutdown().await.unwrap();
}
