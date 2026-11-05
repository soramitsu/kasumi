//! Events that identify no client are counted instead of recorded one by one
//! once the current window holds a record of the first one of their kind from
//! their peer: TLS accepts on a listener that takes no client certificate,
//! failed TLS handshakes, refused bearer tokens and requests refused before
//! any identity was verified. A flood of them therefore writes a bounded
//! number of records per window, whatever its rate or number of source
//! addresses. Their records, counts included, are admitted only while the hot
//! range stays at or below the archive start threshold, so the hot capacity
//! above it stays free for authentication, administration and lifecycle
//! records while archives are behind or full.
use super::*;
use kasumi_types::CountedEvent;
use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
    net::IpAddr,
    time::{Duration, Instant},
};

/// The archive worker writes a window's counts on its first turn after the
/// window ends; an idle worker turns every 250 ms.
pub(super) const COUNT_WINDOW: Duration = Duration::from_secs(60);
/// Peers whose first event in a window gets a record of its own. Events from
/// further peers share one peerless count per kind, so rotating source
/// addresses cannot raise the number of records.
pub(super) const MAX_COUNTED_PEERS: usize = 64;

/// A record of an event that identifies no client, refused because the hot
/// range is at its archive start threshold. The event is counted instead;
/// the audit has not failed.
#[derive(Debug)]
pub(super) struct CountThreshold;
impl std::fmt::Display for CountThreshold {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("service audit hot range is at its archive start threshold")
    }
}
impl std::error::Error for CountThreshold {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct CountKey {
    event: CountedEvent,
    peer: Option<IpAddr>,
}
impl CountKey {
    fn peerless(self) -> Self {
        Self { peer: None, ..self }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Count {
    count: u64,
    first_observed_ms: u64,
    last_observed_ms: u64,
}
impl Count {
    fn one(observed_ms: u64) -> Self {
        Self {
            count: 1,
            first_observed_ms: observed_ms,
            last_observed_ms: observed_ms,
        }
    }
    fn merge(&mut self, other: Self) {
        self.count = self.count.saturating_add(other.count);
        self.first_observed_ms = self.first_observed_ms.min(other.first_observed_ms);
        self.last_observed_ms = self.last_observed_ms.max(other.last_observed_ms);
    }
}

/// The open window's recorded keys and every count not yet written. Each
/// holds at most MAX_COUNTED_PEERS peer keys plus one peerless key per kind.
#[derive(Default)]
pub(super) struct Counts {
    window_started: Option<Instant>,
    recorded: HashSet<CountKey>,
    recorded_peers: usize,
    pending: HashMap<CountKey, Count>,
    pending_peers: usize,
}

impl Counts {
    /// Count an event, or return the key under which it is the window's
    /// first and must be recorded on its own. A window opens with its first
    /// event and lasts until the worker turn that takes its counts.
    fn admit(&mut self, key: CountKey, now: Instant, observed_ms: u64) -> Option<CountKey> {
        self.window_started.get_or_insert(now);
        let key = if key.peer.is_some()
            && self.recorded_peers >= MAX_COUNTED_PEERS
            && !self.recorded.contains(&key)
        {
            key.peerless()
        } else {
            key
        };
        if self.recorded.insert(key) {
            self.recorded_peers += usize::from(key.peer.is_some());
            Some(key)
        } else {
            self.count(key, Count::one(observed_ms));
            None
        }
    }

    /// Add to a pending count. Once MAX_COUNTED_PEERS peers have counts, a
    /// further peer's count joins the peerless count of its kind.
    fn count(&mut self, key: CountKey, count: Count) {
        let key = if key.peer.is_some()
            && self.pending_peers >= MAX_COUNTED_PEERS
            && !self.pending.contains_key(&key)
        {
            key.peerless()
        } else {
            key
        };
        match self.pending.entry(key) {
            Entry::Occupied(mut entry) => entry.get_mut().merge(count),
            Entry::Vacant(entry) => {
                self.pending_peers += usize::from(key.peer.is_some());
                entry.insert(count);
            }
        }
    }

    /// Keep a count whose record was not written. It is written with the
    /// counts of a later window, which this opens when none is open.
    fn restore(&mut self, key: CountKey, count: Count, now: Instant) {
        self.window_started.get_or_insert(now);
        self.count(key, count);
    }

    /// The counts of a window that has ended by `now`, which closes it.
    fn take_ended(&mut self, now: Instant) -> Vec<(CountKey, Count)> {
        match self.window_started {
            Some(started) if now.saturating_duration_since(started) >= COUNT_WINDOW => {
                self.take_all()
            }
            _ => Vec::new(),
        }
    }

    /// Every pending count, closing the open window.
    fn take_all(&mut self) -> Vec<(CountKey, Count)> {
        self.window_started = None;
        self.recorded.clear();
        self.recorded_peers = 0;
        self.pending_peers = 0;
        self.pending.drain().collect()
    }
}

/// One `EventsCounted` event per pending count.
fn count_events(counts: &[(CountKey, Count)]) -> Vec<SecurityEvent> {
    counts
        .iter()
        .map(|(key, count)| SecurityEvent {
            kind: SecurityEventKind::EventsCounted {
                event: key.event,
                peer: key.peer,
                count: count.count,
                first_observed_ms: count.first_observed_ms,
                last_observed_ms: count.last_observed_ms,
            },
            principal: None,
            tenant: None,
            request_id: uuid::Uuid::new_v4().to_string(),
            outcome: key.event.outcome(),
        })
        .collect()
}

fn now_ms() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

impl SecurityAudit {
    /// Record an event that identifies no client: a TLS accept without a
    /// client certificate, a failed TLS handshake, a refused bearer token, or
    /// a refused request that presented no verified identity. The window's
    /// first such event of its kind from its peer is recorded like any
    /// event. Later ones are counted, and one `EventsCounted` record per kind
    /// and peer is written once the window (60 s) ends. A record that would
    /// take the hot range above the archive start threshold is counted
    /// instead.
    ///
    /// Returns Ok once the event is recorded or counted. Counts live in
    /// memory until written, so a crash loses them, as it loses a record
    /// whose write had not finished. An error means the audit itself failed
    /// (the event is still counted).
    pub async fn record_unauthenticated(
        &self,
        event: SecurityEvent,
        transport: Option<TransportAuditMetadata>,
    ) -> Result<()> {
        let counted = match event.kind {
            SecurityEventKind::TransportAuthenticated
                if transport
                    .as_ref()
                    .is_some_and(|metadata| metadata.certificate_pin.is_none()) =>
            {
                CountedEvent::TransportAuthenticated
            }
            SecurityEventKind::TransportDenied => CountedEvent::TransportDenied,
            SecurityEventKind::AuthenticationDenied => CountedEvent::AuthenticationDenied,
            SecurityEventKind::AccessDenied => CountedEvent::AccessDenied,
            _ => anyhow::bail!("only an event that identifies no client can be counted"),
        };
        ensure!(
            event.principal.is_none()
                && event.tenant.is_none()
                && event.outcome == counted.outcome(),
            "a counted event claims no identity"
        );
        event.validate()?;
        if let Some(metadata) = &transport {
            metadata.validate()?;
        }
        let key = CountKey {
            event: counted,
            peer: transport
                .as_ref()
                .map(|metadata| metadata.peer_address.ip()),
        };
        let observed_ms = now_ms()?;
        let Some(key) = self.counts().admit(key, Instant::now(), observed_ms) else {
            return Ok(());
        };
        let recorded = self
            .run_owned(move |work, id| async move {
                let owner = work.writer.clone();
                let outcome = tokio::task::spawn_blocking(move || {
                    work.record_class(event, transport, RecordClass::Unauthenticated)
                })
                .await;
                owner.observe_join("audit record", id, outcome)
            })
            .await;
        match recorded {
            Ok(()) => Ok(()),
            Err(error) => {
                self.counts()
                    .restore(key, Count::one(observed_ms), Instant::now());
                if error.is::<CountThreshold>() {
                    Ok(())
                } else {
                    Err(error)
                }
            }
        }
    }

    /// Close the counting window now and write every pending count, as
    /// orderly shutdown does. A count the hot range cannot take stays pending.
    pub async fn flush_counts(&self) -> Result<()> {
        let counts = self.counts().take_all();
        self.write_counts(counts).await
    }

    /// Shutdown's pending counts, taken with the registration that writes
    /// them before admission closes, so a cancelled shutdown still leaves
    /// the fence closed and its drain waits for this write.
    pub(super) fn take_final_counts(&self) -> Option<(AuditWork, Vec<SecurityEvent>)> {
        let counts = self.counts().take_all();
        if counts.is_empty() {
            return None;
        }
        Some((self.begin().ok()?, count_events(&counts)))
    }

    /// No listener remains to count anything; a count the audit cannot take
    /// now is lost.
    pub(super) async fn write_final_counts(&self, work: AuditWork, events: Vec<SecurityEvent>) {
        let outcome = tokio::task::spawn_blocking(move || Ok(work.record_counts(events))).await;
        let _ = self.observe_join("audit record", 0, outcome);
    }

    /// Write the counts of a window that has ended. Each archive worker turn
    /// calls this; the worker keeps nothing from a failure but the counts.
    pub(super) async fn write_ended_counts(&self) {
        let counts = self.counts().take_ended(Instant::now());
        let _ = self.write_counts(counts).await;
    }

    fn counts(&self) -> std::sync::MutexGuard<'_, Counts> {
        self.writer
            .counts
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Counts whose record is refused, at the threshold or by a failure, are
    /// restored for a later window.
    async fn write_counts(&self, counts: Vec<(CountKey, Count)>) -> Result<()> {
        if counts.is_empty() {
            return Ok(());
        }
        let events = count_events(&counts);
        let written = self
            .run_owned(move |work, id| async move {
                let owner = work.writer.clone();
                let outcome =
                    tokio::task::spawn_blocking(move || Ok(work.record_counts(events))).await;
                owner.observe_join("audit record", id, outcome)
            })
            .await;
        let outcomes = match written {
            Ok(outcomes) => outcomes,
            Err(error) => {
                let mut pending = self.counts();
                for (key, count) in counts {
                    pending.restore(key, count, Instant::now());
                }
                return Err(error);
            }
        };
        let mut failure = None;
        let mut pending = self.counts();
        for ((key, count), outcome) in counts.into_iter().zip(outcomes) {
            if let Err(error) = outcome {
                pending.restore(key, count, Instant::now());
                if !error.is::<CountThreshold>() {
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(()), Err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(event: CountedEvent, peer: Option<u32>) -> CountKey {
        CountKey {
            event,
            peer: peer.map(|peer| IpAddr::from(std::net::Ipv4Addr::from(peer))),
        }
    }

    /// Every admitted event is either the record its admission asked for or
    /// in exactly one pending count.
    fn assert_exact(counts: &mut Counts, admitted: u64, recorded: u64) -> Vec<(CountKey, Count)> {
        let taken = counts.take_all();
        let pending: u64 = taken.iter().map(|(_, count)| count.count).sum();
        assert_eq!(recorded + pending, admitted);
        taken
    }

    #[test]
    fn a_window_records_each_peer_once_and_counts_the_rest() {
        let start = Instant::now();
        let mut counts = Counts::default();
        let transport = key(CountedEvent::TransportDenied, Some(1));
        let token = key(CountedEvent::AuthenticationDenied, None);
        assert_eq!(counts.admit(transport, start, 10), Some(transport));
        assert_eq!(counts.admit(token, start, 10), Some(token));
        for observed_ms in 11..=13 {
            assert_eq!(counts.admit(transport, start, observed_ms), None);
            assert_eq!(counts.admit(token, start, observed_ms), None);
        }
        // The same peer's other kind of event is a key of its own.
        let accepted = key(CountedEvent::TransportAuthenticated, Some(1));
        assert_eq!(counts.admit(accepted, start, 14), Some(accepted));

        // The window lasts until a worker turn after its length.
        let within = start + COUNT_WINDOW - Duration::from_millis(1);
        assert!(counts.take_ended(within).is_empty());
        assert_eq!(counts.admit(transport, within, 15), None);
        let mut ended = counts.take_ended(start + COUNT_WINDOW);
        ended.sort_by_key(|(key, _)| key.event as u8);
        assert_eq!(
            ended,
            [
                (
                    transport,
                    Count {
                        count: 4,
                        first_observed_ms: 11,
                        last_observed_ms: 15
                    }
                ),
                (
                    token,
                    Count {
                        count: 3,
                        first_observed_ms: 11,
                        last_observed_ms: 13
                    }
                ),
            ]
        );
        // The next window records each peer's first event again.
        let next = start + COUNT_WINDOW * 2;
        assert!(counts.take_ended(next).is_empty());
        assert_eq!(counts.admit(transport, next, 20), Some(transport));
    }

    #[test]
    fn rotating_peers_cannot_raise_the_number_of_records_or_counts() {
        let now = Instant::now();
        let mut counts = Counts::default();
        let mut admitted = 0;
        let mut recorded = Vec::new();
        for round in 0..3 {
            for peer in 0..(MAX_COUNTED_PEERS as u32 * 4) {
                for event in [
                    CountedEvent::TransportAuthenticated,
                    CountedEvent::TransportDenied,
                ] {
                    admitted += 1;
                    if let Some(own) = counts.admit(key(event, Some(peer)), now, round) {
                        recorded.push(own);
                    }
                }
            }
        }
        // MAX_COUNTED_PEERS peer keys across both kinds, then one peerless
        // record per kind.
        assert_eq!(recorded.len(), MAX_COUNTED_PEERS + 2);
        assert_eq!(recorded.iter().filter(|key| key.peer.is_none()).count(), 2);
        assert!(counts.pending.len() <= MAX_COUNTED_PEERS + 2);
        let taken = assert_exact(&mut counts, admitted, recorded.len() as u64);
        assert!(taken.len() <= MAX_COUNTED_PEERS + 2);
        assert!(counts.pending.is_empty() && counts.recorded.is_empty());
    }

    #[test]
    fn refused_records_and_counts_are_kept_for_a_later_window() {
        let start = Instant::now();
        let mut counts = Counts::default();
        let refused = key(CountedEvent::TransportDenied, Some(7));
        // A first event whose record was refused is counted instead.
        assert_eq!(counts.admit(refused, start, 5), Some(refused));
        counts.restore(refused, Count::one(5), start);
        assert_eq!(counts.admit(refused, start, 6), None);
        let taken = counts.take_ended(start + COUNT_WINDOW);
        assert_eq!(
            taken,
            [(
                refused,
                Count {
                    count: 2,
                    first_observed_ms: 5,
                    last_observed_ms: 6
                }
            )]
        );
        // A count refused after its window closed opens a window to retry in.
        let later = start + COUNT_WINDOW * 3;
        counts.restore(refused, taken[0].1, later);
        assert!(
            counts
                .take_ended(later + COUNT_WINDOW - Duration::from_millis(1))
                .is_empty()
        );
        assert_eq!(counts.take_ended(later + COUNT_WINDOW), taken);

        // Restored counts of many peers stay bounded too.
        for peer in 0..(MAX_COUNTED_PEERS as u32 * 2) {
            counts.restore(
                key(CountedEvent::AccessDenied, Some(peer)),
                Count::one(9),
                later,
            );
        }
        assert_eq!(counts.pending.len(), MAX_COUNTED_PEERS + 1);
        assert_exact(&mut counts, MAX_COUNTED_PEERS as u64 * 2, 0);
    }

    #[tokio::test]
    async fn shutdown_writes_pending_counts_that_a_strict_reopen_reads() {
        use kasumi_store::test_utils::{LocalKeyProvider, NODE_STORE_ID};
        let directory = kasumi_store::test_utils::private_tempdir().unwrap();
        let (persistent_config, scratch_config) =
            crate::test_utils::fixture_disk_configs(directory.path()).unwrap();
        let storage = crate::test_utils::FixtureStorage::open(
            &persistent_config,
            &scratch_config,
            Default::default(),
        )
        .unwrap();
        let path = directory.path().join("persistent/counted-security.kv");
        let provider = Arc::new(LocalKeyProvider::new([94; 32]));
        let node = storage.create_new(&path, NODE_STORE_ID).unwrap();
        let store = TenantStore::initialize_catalog_fixture(
            node.clone(),
            SECURITY_TENANT.into(),
            provider.clone(),
        )
        .await
        .unwrap();
        let audit = SecurityAudit::initialize(
            store.clone(),
            AuditRetentionBudget::default(),
            storage.admission.clone(),
        )
        .unwrap();
        let denial = || SecurityEvent {
            kind: SecurityEventKind::AuthenticationDenied,
            principal: None,
            tenant: None,
            request_id: uuid::Uuid::new_v4().to_string(),
            outcome: SecurityOutcome::Denied,
        };
        for _ in 0..10 {
            audit.record_unauthenticated(denial(), None).await.unwrap();
        }
        // An event that names a verified identity is never counted, and
        // neither is an accept with a client certificate or without its
        // transport.
        let identified = SecurityEvent {
            principal: Some("person".into()),
            tenant: Some("tenant-a".into()),
            ..denial()
        };
        assert!(
            audit
                .record_unauthenticated(identified, None)
                .await
                .is_err()
        );
        let accepted = SecurityEvent {
            kind: SecurityEventKind::TransportAuthenticated,
            outcome: SecurityOutcome::Succeeded,
            ..denial()
        };
        let pinned = TransportAuditMetadata {
            peer_address: "127.0.0.1:4000".parse().unwrap(),
            certificate_pin: Some("a".repeat(64)),
            observed_at_ms: 1,
        };
        assert!(
            audit
                .record_unauthenticated(accepted.clone(), Some(pinned))
                .await
                .is_err()
        );
        assert!(audit.record_unauthenticated(accepted, None).await.is_err());
        assert_eq!(store.scan("security.audit").unwrap().len(), 1);

        audit.shutdown().await.unwrap();
        node.shutdown().await.unwrap();
        drop(audit);
        drop(store);
        drop(node);
        let node = storage.open_existing(&path, NODE_STORE_ID).unwrap();
        let store =
            TenantStore::open_existing_fixture(node.clone(), SECURITY_TENANT.into(), provider)
                .await
                .unwrap();
        // Reopening decodes every hot record exactly, the count included.
        let audit = SecurityAudit::open(
            store.clone(),
            AuditRetentionBudget::default(),
            storage.admission.clone(),
        )
        .unwrap();
        let records: Vec<SecurityAuditRecord> = store
            .scan("security.audit")
            .unwrap()
            .iter()
            .map(|(_, bytes)| serde_json::from_slice(bytes).unwrap())
            .collect();
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[0].event.kind,
            SecurityEventKind::AuthenticationDenied
        );
        assert!(
            matches!(
                records[1].event.kind,
                SecurityEventKind::EventsCounted {
                    event: CountedEvent::AuthenticationDenied,
                    peer: None,
                    count: 9,
                    first_observed_ms,
                    last_observed_ms,
                } if first_observed_ms <= last_observed_ms
            ),
            "{:?}",
            records[1]
        );
        audit.shutdown().await.unwrap();
        node.shutdown().await.unwrap();
    }
}
