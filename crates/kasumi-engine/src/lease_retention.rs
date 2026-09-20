//! Local coherent roots, serialized with publication. Whole roots never escape
//! this manager into an asynchronous page worker.
use super::*;
use crate::admission::{NodeAdmission, Reservation};
use kasumi_clock::LeaseClock;
use kasumi_query::ReadIds;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

// imbl 7's ordered tree has at most 16 keys/values and 17 child pointers per
// node. Native keys are at most 256 bytes; values below are Arc handles. This
// deliberately rounds allocator, Arc, branch and copied key storage upward.
const TREE_NODE_BYTES: usize = 8192;
const LEASE_HANDLE_BYTES: usize = 4096;
const RETAINED_ENTRY_BYTES: usize = 1024;

pub(crate) struct LeaseHandle {
    pub header: SnapshotLease,
    pub principal: String,
    pub term: u64,
    pub strict_read_audit: bool,
    created: Duration,
    ttl: Duration,
    clock: Arc<dyn LeaseClock>,
    expired: AtomicBool,
    _reservation: Reservation,
}
impl LeaseHandle {
    pub(crate) fn live(&self) -> bool {
        !self.expired.load(Ordering::Acquire)
            && self.clock.now().saturating_sub(self.created) < self.ttl
    }
    fn expire(&self) {
        self.expired.store(true, Ordering::Release);
    }
}

pub(crate) struct SelectedSnapshot {
    pub handle: Arc<LeaseHandle>,
    pub generation: Arc<Generation>,
    pub scan_ids: Vec<String>,
    pub scan_has_more: bool,
    pub reservation: Reservation,
}

#[derive(Default)]
struct Paths {
    documents: usize,
    archived: usize,
    ids: usize,
}
struct Roots {
    handle: Arc<LeaseHandle>,
    generation: Generation,
    ids: ReadIds,
    paths: BTreeMap<String, Paths>,
    archive_paths: usize,
    // Payload costs are evaluated only when a version first diverges. They
    // retain no values; whole values live solely in the original shared roots.
    payloads: BTreeMap<(u8, String, String), usize>,
    payload_bytes: usize,
    metadata_bytes: usize,
    bytes: usize,
    reservation: Reservation,
}
impl Drop for Roots {
    fn drop(&mut self) {
        self.handle.expire();
    }
}

#[derive(Default)]
pub(crate) struct LeaseManager {
    entries: Mutex<BTreeMap<String, Roots>>,
}

fn expired() -> Error {
    Error::new(
        ErrorCode::CursorExpired,
        "snapshot lease expired or retention budget exhausted",
    )
}
fn quota() -> Error {
    Error::new(
        ErrorCode::ResourceExhausted,
        "snapshot lease retention budget exhausted",
    )
}
fn add(total: &mut usize, n: usize, budget: usize) -> Result<()> {
    *total = total
        .checked_add(n)
        .filter(|n| *n <= budget)
        .ok_or_else(quota)?;
    Ok(())
}

// Counts allocated payloads without serialization or another body buffer.
fn value_heap(value: &serde_json::Value, total: &mut usize, budget: usize) -> Result<()> {
    use serde_json::Value;
    match value {
        Value::String(value) => add(total, value.capacity(), budget),
        Value::Array(values) => {
            add(
                total,
                values
                    .capacity()
                    .saturating_mul(std::mem::size_of::<Value>()),
                budget,
            )?;
            for value in values {
                value_heap(value, total, budget)?;
            }
            Ok(())
        }
        Value::Object(values) => {
            // Includes unused BTreeMap slots/edges as well as each inline Value.
            add(total, values.len().saturating_mul(1024), budget)?;
            for (key, value) in values {
                add(total, key.capacity(), budget)?;
                value_heap(value, total, budget)?;
            }
            Ok(())
        }
        Value::Number(number) => add(
            total,
            crate::accounting::encoded_len(number)?
                .saturating_mul(2)
                .saturating_add(64),
            budget,
        ),
        _ => Ok(()),
    }
}
pub(crate) fn document_heap(document: &Document, budget: usize) -> Result<usize> {
    let mut bytes = 128usize;
    add(&mut bytes, document.id.capacity(), budget)?;
    value_heap(&document.body, &mut bytes, budget)?;
    Ok(bytes)
}
fn archive_reference_heap(document: &ArchivedDocument, budget: usize) -> Result<usize> {
    let mut bytes = 256usize;
    add(
        &mut bytes,
        document
            .archive_id
            .capacity()
            .saturating_add(document.document_sha256.capacity()),
        budget,
    )?;
    for (key, value) in &document.indexed_fields {
        add(&mut bytes, 1024usize.saturating_add(key.capacity()), budget)?;
        value_heap(value, &mut bytes, budget)?;
    }
    Ok(bytes)
}
fn history_archive_heap(archive: &RetainedHistoryArchive, budget: usize) -> Result<usize> {
    let mut bytes = std::mem::size_of::<RetainedHistoryArchive>().saturating_add(128);
    let manifest = &archive.manifest;
    for value in [
        &archive.storage_destination,
        &archive.manifest_object_id,
        &archive.manifest_ciphertext_sha256,
        &manifest.archive_id,
        &manifest.tenant,
        &manifest.source_incarnation,
        &manifest.collection,
        &manifest.destination,
    ] {
        add(&mut bytes, value.capacity(), budget)?;
    }
    add(
        &mut bytes,
        manifest
            .chunks
            .capacity()
            .saturating_mul(std::mem::size_of::<ArchiveChunkDescriptor>()),
        budget,
    )?;
    for chunk in &manifest.chunks {
        for value in [
            &chunk.object_id,
            &chunk.ciphertext_sha256,
            &chunk.plaintext_sha256,
            &chunk.first_id,
            &chunk.last_id,
        ] {
            add(&mut bytes, value.capacity(), budget)?;
        }
    }
    Ok(bytes)
}
fn metadata_bytes(state: &TenantState, budget: usize) -> Result<usize> {
    let mut bytes = std::mem::size_of::<Roots>().saturating_add(4096);
    add(
        &mut bytes,
        state.tenant.len().saturating_add(state.incarnation.len()),
        budget,
    )?;
    for grant in &state.policy.grants {
        add(
            &mut bytes,
            256usize
                .saturating_add(grant.principal.len())
                .saturating_add(grant.collection.as_ref().map_or(0, String::len))
                .saturating_add(grant.actions.len().saturating_mul(128)),
            budget,
        )?;
    }
    // These optional cloned records are individually bounded typed metadata.
    for size in [
        state
            .pending_restore
            .as_ref()
            .map(crate::accounting::encoded_len)
            .transpose()?,
        state
            .restored_from
            .as_ref()
            .map(crate::accounting::encoded_len)
            .transpose()?,
        state
            .lifecycle_control
            .as_ref()
            .map(|c| crate::accounting::encoded_len(&(&c.installation, &c.installation_policy)))
            .transpose()?,
        state
            .audit_retention
            .archive_head
            .as_ref()
            .map(crate::accounting::encoded_len)
            .transpose()?,
    ]
    .into_iter()
    .flatten()
    {
        add(&mut bytes, size.saturating_mul(32), budget)?;
    }
    for (name, collection) in &state.collections {
        add(
            &mut bytes,
            1024usize.saturating_add(name.len().saturating_mul(4)),
            budget,
        )?;
        value_heap(&collection.definition.schema, &mut bytes, budget)?;
        add(
            &mut bytes,
            crate::accounting::encoded_len(&collection.definition.indexes)?.saturating_mul(32),
            budget,
        )?;
    }
    Ok(bytes)
}
fn path_bytes(entries: usize, touches: usize) -> usize {
    if entries == 0 || touches == 0 {
        return 0;
    }
    let paths = touches
        .saturating_mul(entries.ilog2() as usize + 1)
        .min(entries);
    paths.saturating_mul(TREE_NODE_BYTES)
}

impl Roots {
    fn account_payload(
        &mut self,
        kind: u8,
        collection: &str,
        id: &str,
        cost: impl FnOnce(usize) -> Result<usize>,
        budget: usize,
    ) -> Result<()> {
        let key = (kind, collection.to_owned(), id.to_owned());
        if !self.payloads.contains_key(&key) {
            let bytes = cost(budget)?
                .checked_add(RETAINED_ENTRY_BYTES)
                .ok_or_else(quota)?;
            add(&mut self.payload_bytes, bytes, budget)?;
            self.payloads.insert(key, bytes);
        }
        Ok(())
    }
    fn refresh(&mut self, previous: &Generation, next: &Generation) -> Result<()> {
        let budget = next.state.limits.atomic.max_snapshot_lease_bytes;
        if !self.handle.live()
            || self.handle.header.incarnation != next.state.incarnation
            || self.handle.header.policy_epoch != next.state.policy_epoch
            || self.handle.header.schema_epoch != next.state.schema_epoch
            || next.state.suspended
            || next.state.retired
        {
            return Err(expired());
        }
        for (name, old) in &previous.state.collections {
            let Some(new) = next.state.collections.get(name) else {
                return Err(expired());
            };
            let Some(original) = self.generation.state.collections.get(name) else {
                continue;
            };
            let documents = original.documents.clone();
            let archived = original.archived_documents.clone();
            for difference in old.documents.diff(&new.documents) {
                use imbl::ordmap::DiffItem;
                let id = match difference {
                    DiffItem::Add(k, _) | DiffItem::Remove(k, _) => k,
                    DiffItem::Update { old: (k, _), .. } => k,
                };
                let paths = self.paths.entry(name.clone()).or_default();
                paths.documents = paths.documents.saturating_add(1).min(documents.len());
                if (old.documents.contains_key(id) || old.archived_documents.contains_key(id))
                    != (new.documents.contains_key(id) || new.archived_documents.contains_key(id))
                {
                    paths.ids = paths
                        .ids
                        .saturating_add(1)
                        .min(documents.len().saturating_add(archived.len()));
                }
                if let Some(value) = documents.get(id)
                    && new
                        .documents
                        .get(id)
                        .is_none_or(|current| !Arc::ptr_eq(value, current))
                {
                    self.account_payload(0, name, id, |limit| document_heap(value, limit), budget)?;
                }
            }
            for difference in old.archived_documents.diff(&new.archived_documents) {
                use imbl::ordmap::DiffItem;
                let id = match difference {
                    DiffItem::Add(k, _) | DiffItem::Remove(k, _) => k,
                    DiffItem::Update { old: (k, _), .. } => k,
                };
                let paths = self.paths.entry(name.clone()).or_default();
                paths.archived = paths.archived.saturating_add(1).min(archived.len());
                // Archive-only removals also change the primary ID root. A hot
                // document difference already counted its corresponding path.
                if old.documents.get(id) == new.documents.get(id)
                    && (old.documents.contains_key(id) || old.archived_documents.contains_key(id))
                        != (new.documents.contains_key(id)
                            || new.archived_documents.contains_key(id))
                {
                    paths.ids = paths
                        .ids
                        .saturating_add(1)
                        .min(documents.len().saturating_add(archived.len()));
                }
                if let Some(value) = archived.get(id)
                    && new
                        .archived_documents
                        .get(id)
                        .is_none_or(|current| !Arc::ptr_eq(value, current))
                {
                    self.account_payload(
                        1,
                        name,
                        id,
                        |limit| archive_reference_heap(value, limit),
                        budget,
                    )?;
                }
            }
        }
        let archives = self.generation.state.history_archives.clone();
        for difference in previous
            .state
            .history_archives
            .diff(&next.state.history_archives)
        {
            use imbl::ordmap::DiffItem;
            let id = match difference {
                DiffItem::Add(k, _) | DiffItem::Remove(k, _) => k,
                DiffItem::Update { old: (k, _), .. } => k,
            };
            self.archive_paths = self.archive_paths.saturating_add(1).min(archives.len());
            if let Some(archive) = archives.get(id) {
                self.account_payload(
                    2,
                    "",
                    id,
                    |limit| history_archive_heap(archive, limit),
                    budget,
                )?;
            }
        }
        let mut bytes = self.metadata_bytes;
        add(&mut bytes, self.payload_bytes, budget)?;
        for (name, paths) in &self.paths {
            let collection = &self.generation.state.collections[name];
            for charge in [
                path_bytes(collection.documents.len(), paths.documents),
                path_bytes(collection.archived_documents.len(), paths.archived),
                path_bytes(
                    collection
                        .documents
                        .len()
                        .saturating_add(collection.archived_documents.len()),
                    paths.ids,
                ),
            ] {
                add(&mut bytes, charge, budget)?;
            }
        }
        add(
            &mut bytes,
            path_bytes(archives.len(), self.archive_paths),
            budget,
        )?;
        if bytes > self.bytes {
            self.reservation
                .reserve_additional((bytes - self.bytes) as u64)?;
        }
        self.bytes = bytes;
        Ok(())
    }
}

impl LeaseManager {
    pub(crate) fn replace(&self, slot: &ArcSwapOption<Generation>, next: Arc<Generation>) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries.clear();
        slot.store(Some(next));
    }
    // The lock includes ArcSwap publication: neither capture nor page selection
    // can observe the old root after accounting its successor.
    pub(crate) fn publish(&self, slot: &ArcSwapOption<Generation>, next: Option<Arc<Generation>>) {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        match (slot.load_full(), next.as_ref()) {
            (Some(previous), Some(next)) => {
                entries.retain(|_, root| root.refresh(&previous, next).is_ok());
                Self::bound(
                    &mut entries,
                    next.state.limits.atomic.max_snapshot_lease_bytes,
                    next.state.limits.atomic.max_snapshot_leases,
                );
            }
            _ => entries.clear(),
        }
        slot.store(next);
    }
    fn bound(entries: &mut BTreeMap<String, Roots>, budget: usize, max_leases: usize) {
        let mut total = entries.values().fold(0usize, |n, r| {
            n.saturating_add(r.bytes).saturating_add(LEASE_HANDLE_BYTES)
        });
        while total > budget || entries.len() > max_leases {
            let Some(key) = entries
                .iter()
                .min_by_key(|(_, r)| r.handle.created)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            if let Some(root) = entries.remove(&key) {
                total = total.saturating_sub(root.bytes.saturating_add(LEASE_HANDLE_BYTES));
            }
        }
    }
    pub(crate) fn expire_idle(&self, pressured: bool, term: u64) {
        self.entries
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .retain(|_, root| !pressured && root.handle.live() && root.handle.term == term);
    }
    fn checked<'a>(
        entries: &'a BTreeMap<String, Roots>,
        state: &TenantState,
        context: &RequestContext,
        id: &str,
        term: u64,
    ) -> Result<&'a Roots> {
        authorize_discovery_state(state, context, Action::Read)?;
        let root = entries.get(id).ok_or_else(expired)?;
        let h = &root.handle;
        if !h.live()
            || h.principal != context.principal
            || h.term != term
            || h.header.incarnation != state.incarnation
            || h.header.policy_epoch != state.policy_epoch
            || h.header.schema_epoch != state.schema_epoch
        {
            return Err(expired());
        }
        Ok(root)
    }
    pub(crate) fn checked_handle(
        &self,
        engine: &TenantEngine,
        context: &RequestContext,
        id: &str,
        term: u64,
    ) -> Result<Arc<LeaseHandle>> {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let current = engine.generation()?;
        Ok(Self::checked(&entries, &current.state, context, id, term)?
            .handle
            .clone())
    }
    pub(crate) fn open(
        &self,
        engine: &TenantEngine,
        context: &RequestContext,
        ttl_ms: u64,
        clock: Arc<dyn LeaseClock>,
        term: u64,
        node: &Arc<NodeAdmission>,
    ) -> Result<Arc<LeaseHandle>> {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let current = engine.generation()?;
        let state = &current.state;
        authorize_discovery_state(state, context, Action::Read)?;
        if ttl_ms == 0 || ttl_ms > state.limits.cursor_ttl_ms {
            return Err(Error::new(
                ErrorCode::InvalidArgument,
                "snapshot lease TTL outside bounds",
            ));
        }
        entries.retain(|_, r| r.handle.live() && r.handle.term == term);
        let budget = state.limits.atomic.max_snapshot_lease_bytes;
        let bytes = metadata_bytes(state, budget)?;
        let total = entries
            .values()
            .fold(bytes.saturating_add(LEASE_HANDLE_BYTES), |n, r| {
                n.saturating_add(r.bytes).saturating_add(LEASE_HANDLE_BYTES)
            });
        if total > budget || entries.len() >= state.limits.atomic.max_snapshot_leases {
            return Err(quota());
        }
        let mut reservation = node.reserve(bytes as u64, None)?;
        reservation.retain_workspace();
        let mut header_reservation = node.reserve(LEASE_HANDLE_BYTES as u64, None)?;
        header_reservation.retain_workspace();
        let id = uuid::Uuid::new_v4().to_string();
        let handle = Arc::new(LeaseHandle {
            header: SnapshotLease {
                lease_id: id.clone(),
                revision: state.revision,
                incarnation: state.incarnation.clone(),
                policy_epoch: state.policy_epoch,
                schema_epoch: state.schema_epoch,
                ttl_ms,
            },
            principal: context.principal.clone(),
            created: clock.now(),
            ttl: Duration::from_millis(ttl_ms),
            clock,
            term,
            strict_read_audit: state.policy.strict_read_audit,
            expired: AtomicBool::new(false),
            _reservation: header_reservation,
        });
        context.authorization.check_live()?;
        entries.insert(
            id,
            Roots {
                handle: handle.clone(),
                generation: current.lease_view(),
                ids: current.indexes.read_ids(),
                paths: BTreeMap::new(),
                archive_paths: 0,
                payloads: BTreeMap::new(),
                payload_bytes: 0,
                metadata_bytes: bytes,
                bytes,
                reservation,
            },
        );
        Ok(handle)
    }
    pub(crate) fn close(&self, context: &RequestContext, id: &str) -> Result<()> {
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        if entries
            .get(id)
            .is_some_and(|root| root.handle.principal != context.principal)
        {
            return Err(Error::new(
                ErrorCode::Forbidden,
                "snapshot lease belongs to another principal",
            ));
        }
        entries.remove(id);
        Ok(())
    }
}

pub(crate) struct PageAccess<'a> {
    pub context: &'a RequestContext,
    pub term: u64,
    pub node: &'a Arc<NodeAdmission>,
    pub cancellation: &'a kasumi_query::QueryCancellation,
}

pub(crate) enum PageSelection {
    Points(Vec<DocumentKey>),
    Scan(ScanSnapshotPage),
}
impl LeaseManager {
    pub(crate) fn select(
        &self,
        engine: &TenantEngine,
        id: &str,
        request: PageSelection,
        access: PageAccess<'_>,
    ) -> Result<SelectedSnapshot> {
        let PageAccess {
            context,
            term,
            node,
            cancellation,
        } = access;
        context.authorization.check_live()?;
        cancellation.check()?;
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let current = engine.generation()?;
        let root = Self::checked(&entries, &current.state, context, id, term)?;
        let original = &root.generation.state;
        let initial = original
            .limits
            .max_result_bytes
            .saturating_mul(3)
            .saturating_add(root.metadata_bytes)
            .saturating_add(4096);
        let mut reservation = node.reserve(initial as u64, Some(cancellation.clone()))?;
        let mut scan_has_more = false;
        let (keys, scan_ids) = match request {
            PageSelection::Points(keys) => {
                if keys.is_empty() || keys.len() > 256 {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "snapshot point page outside bounds",
                    ));
                }
                let mut unique = BTreeSet::new();
                for key in &keys {
                    validate_name(&key.collection)?;
                    validate_name(&key.id)?;
                    if !unique.insert(key) {
                        return Err(Error::new(
                            ErrorCode::InvalidArgument,
                            "duplicate snapshot point",
                        ));
                    }
                }
                (keys, vec![])
            }
            PageSelection::Scan(request) => {
                if request.lease_id != id {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "snapshot scan lease identity differs",
                    ));
                }
                validate_name(&request.collection)?;
                if let Some(after) = &request.after_id {
                    validate_name(after)?;
                }
                if request.limit == 0 || request.limit > original.limits.max_page_size {
                    return Err(Error::new(
                        ErrorCode::InvalidArgument,
                        "snapshot scan limit outside bounds",
                    ));
                }
                authorize_state(
                    &current.state,
                    context,
                    Some(&request.collection),
                    Action::Read,
                )?;
                let collection =
                    original
                        .collections
                        .get(&request.collection)
                        .ok_or_else(|| {
                            Error::new(ErrorCode::NotFound, "snapshot collection not found")
                        })?;
                let candidates = root.ids.document_ids_after(
                    &request.collection,
                    request.after_id.as_deref(),
                    request.limit + 1,
                )?;
                let mut bytes = crate::accounting::encoded_len(&SnapshotScanPage {
                    snapshot: root.handle.header.clone(),
                    collection: request.collection.clone(),
                    data_epoch: collection.data_epoch,
                    documents: vec![],
                    next_after_id: None,
                })?
                .saturating_add(256);
                let mut keys = Vec::new();
                let mut ids = Vec::new();
                for id in candidates {
                    cancellation.check()?;
                    let document_bytes = if let Some(document) = collection.documents.get(&id) {
                        crate::accounting::encoded_len(document)?
                    } else {
                        collection
                            .archived_documents
                            .get(&id)
                            .ok_or_else(|| {
                                Error::new(ErrorCode::Corruption, "snapshot ID reference missing")
                            })?
                            .document_bytes
                    };
                    if keys.len() >= request.limit
                        || bytes.saturating_add(document_bytes + 1)
                            > original.limits.max_result_bytes
                    {
                        if keys.is_empty() {
                            return Err(Error::new(
                                ErrorCode::ResourceExhausted,
                                "snapshot document cannot fit page budget",
                            ));
                        }
                        scan_has_more = true;
                        break;
                    }
                    bytes += document_bytes + 1;
                    keys.push(DocumentKey {
                        collection: request.collection.clone(),
                        id: id.clone(),
                    });
                    ids.push(id);
                }
                // An empty scan still includes its collection epoch and policy.
                if keys.is_empty() {
                    let mut state = crate::snapshot_codec::metadata(original);
                    state.collections.insert(
                        request.collection,
                        CollectionState {
                            definition: collection.definition.clone(),
                            data_epoch: collection.data_epoch,
                            documents: Default::default(),
                            archived_documents: Default::default(),
                            archived_document_bytes: 0,
                        },
                    );
                    cancellation.check()?;
                    context.authorization.check_live()?;
                    return Ok(SelectedSnapshot {
                        handle: root.handle.clone(),
                        generation: Arc::new(Generation {
                            terminals: root.generation.terminals.clone(),
                            target_resolutions: root.generation.target_resolutions.clone(),
                            state,
                            indexes: Arc::new(QueryIndexes::default()),
                            receipts: root.generation.receipts.clone(),
                            snapshot_accounting: Default::default(),
                            _read_reservations: vec![],
                        }),
                        scan_ids: ids,
                        scan_has_more: false,
                        reservation,
                    });
                }
                (keys, ids)
            }
        };
        let mut state = crate::snapshot_codec::metadata(original);
        let mut retained_bytes = root.metadata_bytes;
        let mut charged_bytes = initial;
        for key in &keys {
            cancellation.check()?;
            authorize_state(&current.state, context, Some(&key.collection), Action::Read)?;
            let source = original
                .collections
                .get(&key.collection)
                .ok_or_else(|| Error::new(ErrorCode::NotFound, "snapshot collection not found"))?;
            let selected = state
                .collections
                .entry(key.collection.clone())
                .or_insert_with(|| CollectionState {
                    definition: source.definition.clone(),
                    data_epoch: source.data_epoch,
                    documents: Default::default(),
                    archived_documents: Default::default(),
                    archived_document_bytes: 0,
                });
            if let Some(document) = source.documents.get(&key.id) {
                add(
                    &mut retained_bytes,
                    document_heap(document, usize::MAX)?
                        .saturating_mul(3)
                        .saturating_add(1024),
                    usize::MAX,
                )?;
                if retained_bytes > charged_bytes {
                    reservation.reserve_additional((retained_bytes - charged_bytes) as u64)?;
                    charged_bytes = retained_bytes;
                }
                selected.documents.insert(key.id.clone(), document.clone());
            } else if let Some(reference) = source.archived_documents.get(&key.id) {
                let archive = original
                    .history_archives
                    .get(&reference.archive_id)
                    .ok_or_else(|| {
                        Error::new(ErrorCode::Corruption, "snapshot archive manifest missing")
                    })?;
                add(
                    &mut retained_bytes,
                    archive_reference_heap(reference, usize::MAX)?.saturating_add(1024),
                    usize::MAX,
                )?;
                if !state.history_archives.contains_key(&reference.archive_id) {
                    add(
                        &mut retained_bytes,
                        history_archive_heap(archive, usize::MAX)?,
                        usize::MAX,
                    )?;
                }
                if retained_bytes > charged_bytes {
                    reservation.reserve_additional((retained_bytes - charged_bytes) as u64)?;
                    charged_bytes = retained_bytes;
                }
                selected
                    .archived_documents
                    .insert(key.id.clone(), reference.clone());
                state
                    .history_archives
                    .insert(reference.archive_id.clone(), archive.clone());
            }
        }
        cancellation.check()?;
        context.authorization.check_live()?;
        Ok(SelectedSnapshot {
            handle: root.handle.clone(),
            generation: Arc::new(Generation {
                terminals: root.generation.terminals.clone(),
                target_resolutions: root.generation.target_resolutions.clone(),
                state,
                indexes: Arc::new(QueryIndexes::default()),
                receipts: root.generation.receipts.clone(),
                snapshot_accounting: Default::default(),
                _read_reservations: vec![],
            }),
            scan_ids,
            scan_has_more,
            reservation,
        })
    }
}

#[cfg(test)]
#[path = "lease_retention_tests.rs"]
mod tests;
