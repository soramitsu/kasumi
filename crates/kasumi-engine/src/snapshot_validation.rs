//! Independent application snapshot validation with encrypted point lookups.
//! No document, receipt, staged payload, or retained-history map is materialized.
use super::*;
use crate::{
    backup_verify::VerificationPhase, snapshot_codec::Record, snapshot_index::StagedSnapshot,
};
use anyhow::{Context, ensure};
use kasumi_store::{EncryptedTable, SnapshotImage};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub(crate) struct ValidatedApplicationSnapshot {
    index: StagedSnapshot,
    // This is specifically the bounded metadata record, never a complete state.
    header: Box<TenantState>,
    lineage: EncryptedTable,
}
impl ValidatedApplicationSnapshot {
    pub(crate) fn validate(
        image: SnapshotImage,
        index_disk_bytes: u64,
        mut check: impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<Self> {
        let phase = VerificationPhase::start("snapshot.structural_index", None);
        let index = StagedSnapshot::new(image, index_disk_bytes, &mut check)?;
        phase.complete();
        let phase = VerificationPhase::start("snapshot.semantic_setup", None);
        let Some(Record::Header(header)) = index.get(0, "", "")? else {
            anyhow::bail!("snapshot metadata absent");
        };
        phase.complete();
        let phase = VerificationPhase::start("snapshot.header", None);
        // Header semantics use only the bounded metadata and structural index.
        // Reject invalid application input before allocating lineage scratch.
        Self::validate_header(&header, &index)?;
        phase.complete();
        let phase = VerificationPhase::start("snapshot.lineage", None);
        let scratch = EncryptedTable::new(
            index.image().disk(),
            index_disk_bytes,
            index.image().disk().native_cache_config(),
        )?;
        let result = Self {
            index,
            header,
            lineage: scratch,
        };
        result.validate_lineage(&mut check)?;
        phase.complete();
        let phase = VerificationPhase::start("snapshot.receipts", None);
        result.validate_receipts(&mut check)?;
        phase.complete();
        let phase = VerificationPhase::start("snapshot.documents", None);
        result.validate_documents(&mut check)?;
        phase.complete();
        let phase = VerificationPhase::start("snapshot.staging", None);
        result.validate_staging(&mut check)?;
        phase.complete();
        let phase = VerificationPhase::start("snapshot.change_feed", None);
        result.validate_change_feed(&mut check)?;
        phase.complete();
        let phase = VerificationPhase::start("snapshot.history", None);
        result.validate_history(&mut check)?;
        phase.complete();
        let phase = VerificationPhase::start("snapshot.permanent", None);
        result.validate_permanent(&mut check)?;
        phase.complete();
        let phase = VerificationPhase::start("snapshot.audits", None);
        result.validate_audits(&mut check)?;
        phase.complete();
        let phase = VerificationPhase::start("snapshot.targets", None);
        result.validate_targets(&mut check)?;
        phase.complete();
        let phase = VerificationPhase::start("snapshot.target_resolutions", None);
        result.validate_target_resolutions(&mut check)?;
        phase.complete();
        check()?;
        Ok(result)
    }

    pub(crate) fn header(&self) -> &TenantState {
        &self.header
    }
    pub(crate) fn index(&self) -> &StagedSnapshot {
        &self.index
    }
    pub(crate) fn image(&self) -> &SnapshotImage {
        self.index.image()
    }
    pub(crate) fn into_image(self) -> SnapshotImage {
        self.index.image().clone()
    }
    pub(crate) fn relocate(
        self,
        alias: &str,
        backup_id: uuid::Uuid,
        mut admit: impl FnMut(&crate::snapshot_codec::StreamSummary) -> anyhow::Result<()>,
        mut check: impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<Self> {
        if self.index.count(11)? == 0 {
            // Semantic validation already proved zero catalog bytes and no
            // archived references without a catalog entry. Relocation changes
            // nothing in this case, so retain the exact verified image and its
            // indexes while preserving the caller's admission and live checks.
            check()?;
            admit(&self.index.summary())?;
            check()?;
            return Ok(self);
        }
        let mut history_bytes = 0u64;
        self.index.visit(11, |record| {
            check()?;
            let Record::Archive(id, mut archive) = record else {
                unreachable!()
            };
            Arc::make_mut(&mut archive).storage_destination = alias.to_owned();
            Arc::make_mut(&mut archive).storage_backup_session = Some(backup_id);
            history_bytes = history_bytes
                .checked_add(history::metadata_entry(&id, &archive)? as u64)
                .context("restored history catalog size overflow")?;
            Ok(())
        })?;
        let image = SnapshotImage::capture(
            self.image().disk(),
            crate::target_resolution::snapshot_limit(&self.header)?,
            |writer| {
                let mut encoder = crate::snapshot_codec::Encoder::new(writer)?;
                crate::snapshot_codec::visit(&mut self.image().reader(), |_, mut record| {
                    check()?;
                    match &mut record {
                        Record::Header(header) => {
                            header.history_archive_bytes = usize::try_from(history_bytes)?
                        }
                        Record::Archive(_, archive) => {
                            Arc::make_mut(archive).storage_destination = alias.to_owned();
                            Arc::make_mut(archive).storage_backup_session = Some(backup_id);
                        }
                        _ => {}
                    }
                    encoder.record(record)
                })?;
                check()?;
                encoder.finish()
            },
        )?;
        // The old image/index are released before constructing the replacement
        // point index. No logical tenant is materialized for relocation.
        drop(self);
        let disk = image
            .len()
            .checked_mul(8)
            .and_then(|v| v.checked_add(64 << 20))
            .context("snapshot index disk budget overflow")?;
        let layout = StagedSnapshot::inspect(&image, &mut check)?;
        admit(&layout)?;
        let validated = Self::validate(image, disk, check)?;
        ensure!(
            validated.index.summary() == layout,
            "relocated backup differs from admitted typed framing"
        );
        Ok(validated)
    }
    pub(crate) fn authorize_source(
        &self,
        root: &kasumi_store::StoragePurpose,
        source: &kasumi_store::StoragePurpose,
    ) -> anyhow::Result<()> {
        crate::audit_source::authorize_checked_lineage(
            &self.header.tenant,
            &self.header.incarnation,
            root,
            source,
            |incarnation| Ok(self.lineage_source(incarnation)?.is_some()),
            |incarnation| {
                Ok(self
                    .lineage_target(incarnation)?
                    .map(|link| link.checkpoint))
            },
        )
    }

    pub(crate) fn collection(&self, name: &str) -> anyhow::Result<CollectionState> {
        match self.index.get(2, name, "")? {
            Some(Record::Collection(_, collection)) => Ok(collection),
            _ => anyhow::bail!("snapshot collection absent"),
        }
    }
    pub(crate) fn archived(
        &self,
        collection: &str,
        id: &str,
    ) -> anyhow::Result<Arc<ArchivedDocument>> {
        match self.index.get(4, collection, id)? {
            Some(Record::Archived(_, _, reference)) => Ok(reference),
            _ => anyhow::bail!("snapshot archived reference absent"),
        }
    }
    fn archive(&self, id: &str) -> anyhow::Result<Arc<RetainedHistoryArchive>> {
        match self.index.get(11, id, "")? {
            Some(Record::Archive(_, archive)) => Ok(archive),
            _ => anyhow::bail!("snapshot history archive absent"),
        }
    }
    fn stage(&self, id: &str) -> anyhow::Result<StagedTransaction> {
        match self.index.get(6, id, "")? {
            Some(Record::Stage(_, stage)) => Ok(stage),
            _ => anyhow::bail!("snapshot staged identity absent"),
        }
    }
    fn change(&self, sequence: u64) -> anyhow::Result<Arc<ChangeCommit>> {
        match self.index.get(9, &format!("{sequence:020}"), "")? {
            Some(Record::Change(_, commit)) => Ok(commit),
            _ => anyhow::bail!("snapshot change commit absent"),
        }
    }
    pub(crate) fn lineage_target(
        &self,
        incarnation: &str,
    ) -> anyhow::Result<Option<RestoreLineageLink>> {
        self.lineage_lookup("lineage-target", incarnation)
    }
    pub(crate) fn lineage_source(
        &self,
        incarnation: &str,
    ) -> anyhow::Result<Option<RestoreLineageLink>> {
        self.lineage_lookup("lineage-source", incarnation)
    }
    fn lineage_lookup(
        &self,
        kind: &str,
        incarnation: &str,
    ) -> anyhow::Result<Option<RestoreLineageLink>> {
        let Some(ordinal) = get::<u64>(&self.lineage, &(kind, incarnation))? else {
            return Ok(None);
        };
        match self.index.get(1, &format!("{ordinal:020}"), "")? {
            Some(Record::Lineage(_, link)) => Ok(Some(link)),
            _ => anyhow::bail!("snapshot indexed lineage absent"),
        }
    }
    fn validate_header(h: &TenantState, index: &StagedSnapshot) -> anyhow::Result<()> {
        validate_name(&h.tenant)?;
        validate_name(&h.incarnation)?;
        validate_limits(&h.limits)?;
        validate_policy(&h.policy, &h.limits)?;
        ensure!(
            h.lifecycle_control.is_none()
                && index.count(15)? == 0
                && index.count(16)? == 0
                && h.recovery_control.is_empty()
                && index.count(18)? == 0
                && index.count(19)? == 0
                && index.count(20)? == 0
                && index.count(23)? == 0
                && index.count(24)? == 0
                && h.backup_binding_head
                    == BackupBindingHead::empty(&h.backup_binding_head.origin_incarnation)?,
            "Control state cannot be an application backup"
        );
        ensure!(
            h.revision >= h.revision_base
                && h.schema_epoch <= h.policy_epoch
                && (index.count(2)? == 0 || h.schema_epoch > 0),
            "snapshot revision or schema epoch differs"
        );
        ensure!(
            !h.retired || h.suspended,
            "retired incarnation must be suspended"
        );
        ensure!(
            h.pending_restore.as_ref().is_none_or(|p| h.suspended
                && p.source_revision < h.revision_base
                && uuid::Uuid::parse_str(&p.backup_id).is_ok()),
            "invalid pending restore marker"
        );
        if let Some(origin) = &h.restored_from {
            origin.validate()?;
            ensure!(
                origin.tenant == h.tenant
                    && origin.source_incarnation != h.incarnation
                    && origin.revision < h.revision_base
                    && h.pending_restore
                        .as_ref()
                        .is_none_or(|p| p.backup_id == origin.backup_id.to_string()
                            && p.source_revision == origin.revision),
                "restored origin binding differs"
            );
        } else {
            ensure!(
                h.pending_restore.is_none(),
                "pending restore lacks authenticated origin"
            );
        }
        let headroom = crate::accounting::snapshot_headroom(&target_budget_state(h, index)?)?
            .checked_add(20 - h.revision.to_string().len() as u64)
            .context("snapshot headroom overflow")?;
        let permanent_receipt_bytes = index.framed_bytes(5)?;
        ensure!(
            index
                .summary()
                .bytes
                .checked_sub(index.framed_bytes(22)?)
                .and_then(|n| n.checked_sub(permanent_receipt_bytes))
                .and_then(|n| n.checked_add(headroom))
                .is_some_and(|n| n <= h.limits.max_snapshot_bytes),
            "snapshot exceeds serialized byte quota"
        );
        ensure!(
            index.count(5)? == h.mutation_receipt_head.count
                && h.mutation_receipt_head.encoded_bytes <= h.limits.max_mutation_receipt_bytes
                && index.count(2)? <= h.limits.max_collections as u64,
            "snapshot record quota exceeded"
        );
        Ok(())
    }
    fn validate_lineage(
        &self,
        check: &mut impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let h = &self.header;
        ensure!(
            self.index.count(1)? <= MAX_RESTORE_LINEAGE_LINKS as u64,
            "restore lineage link bound reached"
        );
        let mut last: Option<RestoreLineageLink> = None;
        let mut bytes = 2u64;
        self.index.visit(1, |record| {
            check()?;
            let Record::Lineage(ordinal, link) = record else {
                unreachable!()
            };
            link.checkpoint.validate()?;
            validate_name(&link.target_incarnation)?;
            ensure!(
                link.checkpoint.tenant == h.tenant,
                "restore lineage crosses tenants"
            );
            if let Some(previous) = &last {
                ensure!(
                    previous.target_incarnation == link.checkpoint.source_incarnation
                        && previous.checkpoint.revision < link.checkpoint.revision,
                    "restore lineage is discontinuous"
                );
            } else {
                insert(
                    &self.lineage,
                    &("incarnation", &link.checkpoint.source_incarnation),
                    &(),
                )?;
            }
            insert(
                &self.lineage,
                &("incarnation", &link.target_incarnation),
                &(),
            )?;
            insert(
                &self.lineage,
                &("lineage-source", &link.checkpoint.source_incarnation),
                &ordinal,
            )?;
            insert(
                &self.lineage,
                &("lineage-target", &link.target_incarnation),
                &ordinal,
            )?;
            bytes = bytes
                .checked_add(encoded_len(&link)? as u64)
                .and_then(|n| n.checked_add(u64::from(ordinal != 0)))
                .context("lineage byte overflow")?;
            ensure!(
                bytes <= MAX_RESTORE_LINEAGE_BYTES as u64,
                "restore lineage byte bound reached"
            );
            last = Some(link);
            Ok(())
        })?;
        ensure!(
            last.as_ref().map(|v| &v.checkpoint) == h.restored_from.as_ref(),
            "restore lineage origin differs"
        );
        ensure!(
            last.as_ref().is_none_or(
                |v| v.target_incarnation == h.incarnation && v.checkpoint.revision < h.revision
            ),
            "restore lineage current incarnation differs"
        );
        ensure!(
            h.backup_binding_head.origin_incarnation == h.incarnation
                || self
                    .lineage_source(&h.backup_binding_head.origin_incarnation)?
                    .is_some(),
            "backup binding origin is outside verified lineage"
        );
        Ok(())
    }
    fn validate_receipts(
        &self,
        check: &mut impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let h = &self.header;
        let mut head =
            MutationReceiptHead::empty(&h.tenant, &h.mutation_receipt_head.origin_incarnation)?;
        ensure!(
            head.origin_incarnation == h.incarnation
                || self.lineage_source(&head.origin_incarnation)?.is_some(),
            "receipt origin is outside verified lineage"
        );
        self.index.visit(5, |record| {
            check()?;
            let Record::Receipt(row) = record else {
                unreachable!()
            };
            let proof = self.staging_lineage(
                &row.receipt.scope.incarnation,
                Some(&row.applied.incarnation),
            )?;
            row.validate(&proof)?;
            ensure!(
                get::<u64>(&self.lineage, &("mutation-receipt-key", &row.key))?.is_none(),
                "duplicate immutable mutation identity"
            );
            insert(
                &self.lineage,
                &("mutation-receipt-key", &row.key),
                &row.ordinal,
            )?;
            crate::mutation_receipt::advance(&mut head, &row)?;
            Ok(())
        })?;
        ensure!(
            head == h.mutation_receipt_head
                && head.count == self.index.count(5)?
                && head.encoded_bytes == self.index.framed_bytes(5)?,
            "receipt snapshot chain/count/bytes differ"
        );
        Ok(())
    }

    fn validate_documents(
        &self,
        check: &mut impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let h = &self.header;
        let mut schema_bytes = 0u64;
        self.index.visit(2, |record| {
            check()?;
            let Record::Collection(name, collection) = record else {
                unreachable!()
            };
            ensure!(
                name == collection.definition.name && collection.data_epoch <= h.revision,
                "snapshot collection identity or epoch differs"
            );
            let source = crate::index_source::StateCollection::new(h, &name, &collection);
            validate_collection(&source).map_err(kasumi_query::ReadFailure::into_query_error)?;
            schema_bytes = schema_bytes
                .checked_add(encoded_len(&collection.definition)? as u64)
                .context("schema byte overflow")?;
            ensure!(
                schema_bytes <= h.limits.max_schema_bytes as u64,
                "snapshot schema byte quota exceeded"
            );
            Ok(())
        })?;
        let mut bytes = 0u64;
        let mut current: Option<(String, CollectionState, QueryIndexes)> = None;
        self.index.visit(3, |record| {
            check()?;
            let Record::Document(name, document) = record else {
                unreachable!()
            };
            if current.as_ref().is_none_or(|(key, _, _)| key != &name) {
                let collection = self.collection(&name)?;
                // Only the current collection's empty indexes keep its compiled
                // schema alive while documents are checked individually.
                let validators = QueryIndexes::build([crate::index_source::StateCollection::new(
                    h,
                    &name,
                    &collection,
                )])
                .map_err(kasumi_query::ReadFailure::into_query_error)?;
                current = Some((name.clone(), collection, validators));
            }
            let (_, collection, validators) =
                current.as_ref().context("snapshot collection missing")?;
            validate_name(&document.id)?;
            ensure!(
                document.version <= collection.data_epoch,
                "snapshot document version differs"
            );
            validators.validate_document(&collection.definition, &document.body)?;
            let size = encoded_len(&document.body)? as u64;
            ensure!(
                size <= h.limits.max_document_bytes as u64,
                "snapshot document exceeds byte quota"
            );
            bytes = bytes
                .checked_add(size)
                .context("snapshot logical byte overflow")?;
            ensure!(
                bytes <= h.limits.max_logical_bytes,
                "snapshot logical byte quota exceeded"
            );
            for index in collection.definition.indexes.iter().filter(|i| i.unique) {
                if let Some(key) = kasumi_query::unique_index_key(index, &document.body)? {
                    let mut digest = Sha256::new();
                    digest.update(b"kasumi.snapshot-unique.v1\0");
                    digest.update(serde_json::to_vec(&(&name, &index.name))?);
                    digest.update(key);
                    // A digest collision also rejects; it can never make a
                    // duplicate unique value acceptable.
                    insert(
                        &self.lineage,
                        &("unique", hex::encode(digest.finalize())),
                        &(),
                    )?;
                }
            }
            Ok(())
        })?;
        let count = self
            .index
            .count(3)?
            .checked_add(self.index.count(4)?)
            .context("document count overflow")?;
        ensure!(
            count == h.document_count
                && count <= h.limits.max_documents
                && bytes == h.logical_bytes,
            "snapshot logical accounting mismatch"
        );
        Ok(())
    }
    fn validate_staging(
        &self,
        check: &mut impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let h = &self.header;
        ensure!(
            h.permanent_staged_bytes
                .checked_add(h.reserved_staged_terminal_bytes)
                .is_some_and(|n| n <= h.limits.atomic.max_permanent_staged_bytes)
                && self.index.count(8)? <= h.limits.atomic.max_active_transactions as u64,
            "staged transaction quota exceeded"
        );
        self.index.visit(7, |record| {
            check()?;
            let Record::StageChunk(key, ordinal, chunk) = record else {
                unreachable!()
            };
            let stage = self.stage(&key)?;
            let accumulator = ("stage", &key);
            let mut counts =
                get::<staging::SnapshotChunks>(&self.lineage, &accumulator)?.unwrap_or_default();
            counts.add(ordinal, &chunk, &stage, &h.limits)?;
            set(&self.lineage, &accumulator, &counts)
        })?;
        let mut active = 0u64;
        let mut reserved = 0u64;
        let mut permanent_bytes = h.staged_terminal_head.encoded_bytes;
        let mut terminal_reserved = 0u64;
        self.index.visit(6, |record| {
            check()?;
            let Record::Stage(key, stage) = record else {
                unreachable!()
            };
            let counts = get::<staging::SnapshotChunks>(&self.lineage, &("stage", &key))?
                .unwrap_or_default();
            let proof_state = self.staging_lineage(&stage.scope.incarnation, None)?;
            let uploading = staging::validate_snapshot_record(&key, &stage, &proof_state, &counts)?;
            ensure!(uploading, "resident staged record is terminal");
            let charge = staging::permanent_charge(&key, &stage)?;
            permanent_bytes = permanent_bytes
                .checked_add(charge.0)
                .context("permanent staged bytes overflow")?;
            terminal_reserved = terminal_reserved
                .checked_add(charge.1)
                .context("staged terminal reserve overflow")?;
            ensure!(
                uploading == self.index.get(8, &key, "")?.is_some(),
                "staged active index differs"
            );
            if uploading {
                staging::validate_manifest(&stage.manifest, &h.limits)?;
                active = active
                    .checked_add(1)
                    .context("active staged count overflow")?;
                reserved = reserved
                    .checked_add(stage.manifest.encoded_chunk_bytes as u64)
                    .context("staging reservation overflow")?;
            }
            Ok(())
        })?;
        let mut terminal_head =
            StagedTerminalHead::empty(&h.tenant, &h.staged_terminal_head.origin_incarnation)?;
        ensure!(
            terminal_head.origin_incarnation == h.incarnation
                || self
                    .lineage_source(&terminal_head.origin_incarnation)?
                    .is_some(),
            "terminal origin is outside verified lineage"
        );
        self.index.visit(21, |record| {
            check()?;
            let Record::Terminal(row) = record else {
                unreachable!()
            };
            let proof_state =
                self.staging_lineage(&row.stage.scope.incarnation, Some(&row.applied.incarnation))?;
            row.validate(&proof_state)?;
            ensure!(
                self.index.get(6, &row.key, "")?.is_none(),
                "identity is both uploading and terminal"
            );
            insert(&self.lineage, &("terminal-key", &row.key), &row.ordinal)?;
            crate::staged_terminal::advance(&mut terminal_head, &row)?;
            Ok(())
        })?;
        ensure!(
            terminal_head == h.staged_terminal_head
                && terminal_head.count == self.index.count(21)?,
            "terminal snapshot chain/count/bytes differ"
        );
        ensure!(
            active == self.index.count(8)?
                && reserved <= h.limits.atomic.max_reserved_staging_bytes as u64
                && permanent_bytes == h.permanent_staged_bytes
                && terminal_reserved == h.reserved_staged_terminal_bytes,
            "staged reservation or active count differs"
        );
        Ok(())
    }
    /// One row needs the subject's closing link and both the applying
    /// incarnation's genesis and closing links. Fetch those exact links from
    /// the verified encrypted index without materializing the full lineage.
    fn staging_lineage(&self, subject: &str, applied: Option<&str>) -> anyhow::Result<TenantState> {
        let mut state = self.header.as_ref().clone();
        for incarnation in [Some(subject), applied].into_iter().flatten() {
            if incarnation != state.incarnation
                && !state
                    .restore_lineage
                    .iter()
                    .any(|link| link.checkpoint.source_incarnation == incarnation)
            {
                state.restore_lineage.push(
                    self.lineage_source(incarnation)?
                        .context("staged incarnation is outside verified lineage")?,
                );
            }
        }
        if let Some(applied) = applied.filter(|id| *id != state.incarnation)
            && let Some(genesis) = self.lineage_target(applied)?
            && !state
                .restore_lineage
                .iter()
                .any(|link| link.target_incarnation == applied)
        {
            state.restore_lineage.push(genesis);
        }
        Ok(state)
    }
    fn validate_change_feed(
        &self,
        check: &mut impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let h = &self.header;
        let feed = &h.change_feed;
        ensure!(
            feed.next_sequence > 0
                && feed.event_count <= h.limits.history.max_feed_events
                && feed.encoded_commit_bytes <= h.limits.history.max_feed_bytes,
            "change feed outside limits"
        );
        self.index.visit(10, |record| {
            check()?;
            let Record::ChangeItem(sequence, _, record) = record else {
                unreachable!()
            };
            let commit = self.change(sequence)?;
            validate_name(&record.collection)?;
            validate_name(&record.id)?;
            ensure!(
                self.index.get(2, &record.collection, "")?.is_some()
                    && record
                        .document
                        .as_ref()
                        .is_none_or(|doc| doc.id == record.id && doc.version == commit.revision),
                "invalid retained change record"
            );
            insert(
                &self.lineage,
                &("change-identity", sequence, &record.collection, &record.id),
                &(),
            )?;
            let key = ("change", sequence);
            let mut count = get::<Counts>(&self.lineage, &key)?.unwrap_or_default();
            count.add(encoded_len(&record)? as u64)?;
            set(&self.lineage, &key, &count)
        })?;
        let mut expected = None;
        let mut revision = 0;
        let mut total = Counts::default();
        self.index.visit(9, |record| {
            check()?;
            let Record::Change(sequence, commit) = record else {
                unreachable!()
            };
            let count = get::<Counts>(&self.lineage, &("change", sequence))?.unwrap_or_default();
            ensure!(
                expected.is_none_or(|v| v == sequence)
                    && commit.first_sequence == sequence
                    && count.count > 0
                    && commit.revision > revision
                    && commit.revision <= h.revision,
                "change feed sequence or revision differs"
            );
            ensure!(
                count.bytes == commit.record_bytes as u64,
                "change record accounting mismatch"
            );
            expected = Some(
                sequence
                    .checked_add(count.count)
                    .context("change sequence overflow")?,
            );
            revision = commit.revision;
            let bytes = (crate::change_feed_state::entry_bytes(sequence, &commit)? as u64)
                .checked_add(count.count - 1)
                .context("change commit byte overflow")?;
            total.count = total
                .count
                .checked_add(count.count)
                .context("change event count overflow")?;
            total.bytes = total
                .bytes
                .checked_add(bytes)
                .context("change feed bytes overflow")?;
            Ok(())
        })?;
        ensure!(
            expected.unwrap_or(feed.next_sequence) == feed.next_sequence
                && total.count == feed.event_count as u64
                && total.bytes == feed.encoded_commit_bytes as u64,
            "change feed accounting mismatch"
        );
        Ok(())
    }
    fn validate_history(
        &self,
        check: &mut impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let h = &self.header;
        ensure!(
            self.index.count(11)? <= h.limits.history.max_archive_segments as u64,
            "archive catalog exceeds quota"
        );
        self.index.visit(4, |record| {
            check()?;
            let Record::Archived(name, id, reference) = record else {
                unreachable!()
            };
            let collection = self.collection(&name)?;
            ensure!(
                collection.definition.retention_class
                    == CollectionRetentionClass::ArchivableHistory
                    && collection.definition.write_mode == CollectionWriteMode::AppendOnly
                    && collection
                        .definition
                        .indexes
                        .iter()
                        .all(|index| index.text.is_none()),
                "ineligible collection has archived history"
            );
            validate_name(&id)?;
            validate_sha256(&reference.document_sha256)?;
            let archive = self.archive(&reference.archive_id)?;
            let descriptor = archive
                .manifest
                .chunks
                .get(reference.chunk_index)
                .context("archived identity has no chunk")?;
            ensure!(
                archive.manifest.collection == name
                    && reference.version <= archive.manifest.cutoff_revision
                    && reference.version <= collection.data_epoch
                    && self.index.get(3, &name, &id)?.is_none()
                    && id >= descriptor.first_id
                    && id <= descriptor.last_id
                    && reference.document_bytes > 0
                    && reference.document_bytes <= (1 << 20) + 4096
                    && reference.indexed_fields.keys().all(|field| collection
                        .definition
                        .indexes
                        .iter()
                        .flat_map(|index| &index.fields)
                        .any(|f| &f.path == field)),
                "invalid archived identity or index metadata"
            );
            let key = ("archived", &name);
            let mut bytes = get::<u64>(&self.lineage, &key)?.unwrap_or_default();
            bytes = bytes
                .checked_add(history::metadata_entry(&id, &reference)? as u64)
                .context("archive metadata overflow")?;
            set(&self.lineage, &key, &bytes)?;
            let key = (
                "archive-chunk",
                &reference.archive_id,
                reference.chunk_index,
            );
            let mut counts = get::<Interval>(&self.lineage, &key)?.unwrap_or_default();
            counts.count = counts
                .count
                .checked_add(1)
                .context("archive reference count overflow")?;
            if counts.first.as_ref().is_none_or(|first| &id < first) {
                counts.first = Some(id.clone());
            }
            if counts.last.as_ref().is_none_or(|last| &id > last) {
                counts.last = Some(id);
            }
            set(&self.lineage, &key, &counts)
        })?;
        self.index.visit(2, |record| {
            check()?;
            let Record::Collection(name, collection) = record else {
                unreachable!()
            };
            ensure!(
                get::<u64>(&self.lineage, &("archived", name))?.unwrap_or_default()
                    == collection.archived_document_bytes as u64,
                "archive reference byte accounting mismatch"
            );
            Ok(())
        })?;
        let mut bytes = 0u64;
        self.index.visit(11, |record| {
            check()?;
            let Record::Archive(id, archive) = record else {
                unreachable!()
            };
            validate_name(&archive.storage_destination)?;
            history::validate_manifest(&archive.manifest)?;
            validate_sha256(&archive.manifest_ciphertext_sha256)?;
            uuid::Uuid::parse_str(&archive.manifest_object_id)?;
            ensure!(
                id == archive.manifest.archive_id
                    && archive.manifest.tenant == h.tenant
                    && archive.storage_backup_session.is_none_or(|id| !id.is_nil())
                    && archive.published_revision <= h.revision,
                "invalid archive manifest identity"
            );
            for (i, descriptor) in archive.manifest.chunks.iter().enumerate() {
                check()?;
                let counts = get::<Interval>(&self.lineage, &("archive-chunk", &id, i))?
                    .context("archive manifest has no referenced rows")?;
                ensure!(
                    counts.count == descriptor.document_count as u64
                        && counts.first.as_ref() == Some(&descriptor.first_id)
                        && counts.last.as_ref() == Some(&descriptor.last_id),
                    "archive referenced interval mismatch"
                );
            }
            bytes = bytes
                .checked_add(history::metadata_entry(&id, &archive)? as u64)
                .context("archive catalog overflow")?;
            Ok(())
        })?;
        ensure!(
            bytes == h.history_archive_bytes as u64,
            "archive catalog accounting mismatch"
        );
        Ok(())
    }
    fn validate_permanent(
        &self,
        check: &mut impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let h = &self.header;
        ensure!(
            h.schema_activation_bytes <= h.limits.max_schema_activation_bytes
                && h.retirement_bytes <= h.limits.max_retirement_bytes,
            "permanent record quota exceeded"
        );
        let mut activation_bytes = 0u64;
        self.index.visit(12, |record| {
            check()?;
            let Record::Activation(key, record) = record else {
                unreachable!()
            };
            activation_bytes = activation_bytes
                .checked_add(schema::validate_snapshot_record(&key, &record, h.revision)?)
                .context("schema activation bytes overflow")?;
            Ok(())
        })?;
        let mut retirement_bytes = 0u64;
        let mut successes = 0u64;
        self.index.visit(13, |record| {
            check()?;
            let Record::Retirement(key, record) = record else {
                unreachable!()
            };
            let (bytes, current) = retirement::validate_snapshot_record(h, &key, &record)?;
            retirement_bytes = retirement_bytes
                .checked_add(bytes)
                .context("retirement byte count overflow")?;
            successes = successes
                .checked_add(u64::from(current))
                .context("retirement count overflow")?;
            Ok(())
        })?;
        ensure!(
            activation_bytes == h.schema_activation_bytes
                && retirement_bytes == h.retirement_bytes
                && successes == u64::from(h.retired),
            "permanent record accounting or fence differs"
        );
        Ok(())
    }
    fn validate_audits(
        &self,
        check: &mut impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let h = &self.header;
        h.audit_retention.validate()?;
        ensure!(
            crate::accounting::audit_fits(&self.target_budget_state()?)
                && h.audit_retention.archive_bytes <= h.limits.audit_retention.archive_bytes,
            "audit history exceeds configured byte budgets"
        );
        let mut bytes = 0u64;
        self.index.visit(14, |record| {
            check()?;
            let Record::Audit(_, event) = record else {
                unreachable!()
            };
            let size = encoded_len(&event)? as u64;
            ensure!(
                size <= MAX_AUDIT_EVENT_BYTES as u64,
                "audit event exceeds record budget"
            );
            bytes = bytes
                .checked_add(size)
                .context("audit byte count overflow")?;
            Ok(())
        })?;
        ensure!(
            bytes == h.audit_retention.hot_bytes
                && h.audit_retention
                    .next_sequence
                    .checked_sub(h.audit_retention.pruned_before)
                    == Some(self.index.count(14)?),
            "audit retention accounting differs"
        );
        Ok(())
    }
    fn validate_target_resolutions(
        &self,
        check: &mut impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let h = &self.header;
        let mut selected = TargetResolutionPrefixHead::empty(
            &h.tenant,
            &h.target_resolution_head.origin_incarnation,
        )?;
        ensure!(
            selected.origin_incarnation == h.incarnation
                || self.lineage_source(&selected.origin_incarnation)?.is_some(),
            "target terminal prefix origin is outside lineage"
        );
        self.index.visit(22, |record| {
            check()?;
            let Record::TargetResolution(row) = record else {
                unreachable!()
            };
            let incarnation = row.record.origin().input.target_incarnation.to_string();
            let mut state = self.staging_lineage(&incarnation, None)?;
            let Record::Target(_, target) = self
                .index
                .get(17, &incarnation, "")?
                .context("target terminal origin is absent")?
            else {
                unreachable!()
            };
            state.target_lifecycle.insert(incarnation.clone(), *target);
            row.validate(&state)?;
            let mut causal: crate::target_resolution::CausalHead =
                get(&self.lineage, &("target-terminal-causal", &incarnation))?.unwrap_or_default();
            crate::target_resolution::validate_causal(h, &row, &mut causal, |key| {
                let Some(ordinal) = get::<u64>(&self.lineage, &("target-terminal-key", key))?
                else {
                    return Ok(None);
                };
                match self.index.get(22, &format!("{ordinal:020}"), "")? {
                    Some(Record::TargetResolution(row)) => Ok(Some(*row)),
                    _ => anyhow::bail!("target causal key redirected"),
                }
            })?;
            ensure!(
                get::<u64>(&self.lineage, &("target-terminal-key", &row.key))?.is_none(),
                "duplicate permanent target terminal identity"
            );
            insert(
                &self.lineage,
                &("target-terminal-key", &row.key),
                &row.ordinal,
            )?;
            crate::target_resolution::advance(&mut selected, &row)?;
            set(
                &self.lineage,
                &("target-terminal-causal", &incarnation),
                &causal,
            )?;
            Ok(())
        })?;
        ensure!(
            selected == h.target_resolution_head && selected.count == self.index.count(22)?,
            "target terminal snapshot prefix count/root/bytes differ"
        );
        ensure!(
            self.index.framed_bytes(22)? <= selected.encoded_bytes,
            "target terminal table charge does not cover its snapshot framing"
        );
        let current = self.target_budget_state()?;
        let causal: crate::target_resolution::CausalHead =
            get(&self.lineage, &("target-terminal-causal", &h.incarnation))?.unwrap_or_default();
        crate::target_resolution::validate_causal_current(&current, &causal, |key| {
            let Some(ordinal) = get::<u64>(&self.lineage, &("target-terminal-key", key))? else {
                return Ok(None);
            };
            match self.index.get(22, &format!("{ordinal:020}"), "")? {
                Some(Record::TargetResolution(row)) => Ok(Some(*row)),
                _ => anyhow::bail!("target current causal key redirected"),
            }
        })?;
        crate::target_resolution::validate_current(&current, |key| {
            check()?;
            let Some(ordinal) = get::<u64>(&self.lineage, &("target-terminal-key", key))? else {
                return Ok(None);
            };
            let Some(Record::TargetResolution(row)) =
                self.index.get(22, &format!("{ordinal:020}"), "")?
            else {
                anyhow::bail!("target terminal key redirected outside ordinal prefix");
            };
            Ok(Some(*row))
        })
    }

    fn target_budget_state(&self) -> anyhow::Result<TenantState> {
        target_budget_state(&self.header, &self.index)
    }

    fn validate_targets(
        &self,
        check: &mut impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<()> {
        let h = &self.header;
        ensure!(
            self.index.count(17)? <= MAX_TARGET_HISTORY as u64,
            "target history count exceeded"
        );
        let mut bytes = 2u64;
        let mut count = 0u64;
        self.index.visit(17, |record| {
            check()?;
            let Record::Target(id, entry) = record else {
                unreachable!()
            };
            entry.validate()?;
            let origin = &entry.origin.materialization.request;
            ensure!(
                id == origin.target_incarnation.to_string()
                    && origin.tenant == h.tenant
                    && self
                        .lineage_target(&id)?
                        .is_some_and(|link| link.checkpoint == origin.checkpoint),
                "target history differs from restoration lineage"
            );
            ensure!(
                entry
                    .completion
                    .as_ref()
                    .is_none_or(|v| v.revision <= h.revision)
                    && entry
                        .activation
                        .as_ref()
                        .is_none_or(|v| v.revision <= h.revision),
                "target history revision exceeds snapshot"
            );
            if let Some(completed) = &entry.completion {
                ensure!(
                    kasumi_serving::verify_target_materializations(
                        &entry.origin,
                        &completed.materialized
                    )? == completed.bootstrap_sha256,
                    "snapshot target bootstrap differs"
                );
            }
            if id == h.incarnation {
                ensure!(
                    h.restored_from.as_ref() == Some(&origin.checkpoint)
                        && entry.completion.is_none() == h.pending_restore.is_some()
                        && (entry.activation.is_some() || h.suspended),
                    "current target state differs"
                );
            }
            bytes = bytes
                .checked_add(encoded_len(&id)? as u64)
                .and_then(|v| v.checked_add(1 + u64::from(count > 0)))
                .and_then(|v| v.checked_add(encoded_len(&entry).ok()? as u64))
                .context("target history byte count overflow")?;
            count = count
                .checked_add(1)
                .context("target history count overflow")?;
            ensure!(
                bytes
                    .checked_add(crate::accounting::target_completion_reserve(
                        &self.target_budget_state()?
                    ))
                    .is_some_and(|bytes| bytes <= MAX_TARGET_HISTORY_BYTES as u64),
                "target history bytes exceeded"
            );
            Ok(())
        })?;
        Ok(())
    }
}

fn target_budget_state(
    header: &TenantState,
    index: &StagedSnapshot,
) -> anyhow::Result<TenantState> {
    let mut state = header.clone();
    if let Some(Record::Target(_, target)) = index.get(17, &state.incarnation, "")? {
        state
            .target_lifecycle
            .insert(state.incarnation.clone(), *target);
    }
    Ok(state)
}

#[derive(Default, Serialize, Deserialize)]
struct Counts {
    count: u64,
    bytes: u64,
}
impl Counts {
    fn add(&mut self, bytes: u64) -> anyhow::Result<()> {
        self.count = self
            .count
            .checked_add(1)
            .context("snapshot accumulator count overflow")?;
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .context("snapshot accumulator bytes overflow")?;
        Ok(())
    }
}
#[derive(Default, Serialize, Deserialize)]
struct Interval {
    count: u64,
    first: Option<String>,
    last: Option<String>,
}
fn get<T: DeserializeOwned>(
    table: &EncryptedTable,
    key: &impl Serialize,
) -> anyhow::Result<Option<T>> {
    table
        .get(&serde_json::to_vec(key)?)?
        .map(|bytes| serde_json::from_slice(&bytes).map_err(Into::into))
        .transpose()
}
fn insert(
    table: &EncryptedTable,
    key: &impl Serialize,
    value: &impl Serialize,
) -> anyhow::Result<()> {
    table.insert(&serde_json::to_vec(key)?, &serde_json::to_vec(value)?)
}
fn set(table: &EncryptedTable, key: &impl Serialize, value: &impl Serialize) -> anyhow::Result<()> {
    table.set(&serde_json::to_vec(key)?, &serde_json::to_vec(value)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // These fixtures hold the image, structural index and semantic scratch
    // table together. Match the other multi-table fixtures' bounded slot count;
    // the 64 MiB byte cap and semantic/admission assertions remain unchanged.
    fn empty_state() -> TenantState {
        TenantEngine::new(
            "tenant".into(),
            "generation".into(),
            Policy {
                grants: vec![Grant {
                    principal: "owner".into(),
                    collection: None,
                    actions: [Action::Admin].into_iter().collect(),
                }],
                strict_read_audit: false,
            },
            Limits::default(),
        )
        .unwrap()
        .generation()
        .unwrap()
        .state
        .clone()
    }
    fn state() -> TenantState {
        let mut state = empty_state();
        state.revision = 3;
        state.schema_epoch = 1;
        state.policy_epoch = 1;
        let documents: imbl::OrdMap<String, Arc<Document>> = [
            Arc::new(Document {
                id: "a".into(),
                version: 3,
                body: json!({"v": "1.00"}),
            }),
            Arc::new(Document {
                id: "b".into(),
                version: 3,
                body: json!({"v": "2e0"}),
            }),
        ]
        .into_iter()
        .map(|doc| (doc.id.clone(), doc))
        .collect();
        let records: Vec<_> = documents
            .values()
            .map(|doc| ChangeRecord {
                collection: "rows".into(),
                id: doc.id.clone(),
                document: Some(doc.clone()),
            })
            .collect();
        let commit = Arc::new(ChangeCommit {
            revision: 3,
            first_sequence: 1,
            record_bytes: records.iter().map(|r| encoded_len(r).unwrap()).sum(),
            records,
        });
        state.change_feed.event_count = commit.records.len();
        state.change_feed.encoded_commit_bytes =
            crate::change_feed_state::entry_bytes(1, &commit).unwrap();
        state.change_feed.next_sequence = 3;
        state.change_feed.commits.insert(1, commit);
        state.document_count = documents.len() as u64;
        state.logical_bytes = documents
            .values()
            .map(|doc| encoded_len(&doc.body).unwrap() as u64)
            .sum();
        state.collections.insert(
            "rows".into(),
            CollectionState {
                definition: CollectionDefinition {
                    name: "rows".into(),
                    write_mode: CollectionWriteMode::Mutable,
                    retention_class: CollectionRetentionClass::Operational,
                    schema: json!({"type":"object"}),
                    strict_read_audit: false,
                    indexes: vec![IndexDefinition {
                        name: "unique".into(),
                        fields: vec![IndexField {
                            path: "/v".into(),
                            kind: ScalarType::Decimal,
                        }],
                        unique: true,
                        text: None,
                    }],
                },
                data_epoch: 3,
                documents,
                archived_documents: Default::default(),
                archived_document_bytes: 0,
            },
        );
        let chunk = Arc::new(StagedChunk {
            read_set: vec![],
            operations: vec![Mutation::Put {
                collection: "rows".into(),
                id: "future".into(),
                body: json!({"v":"3"}),
                expected: Precondition::Absent,
            }],
        });
        let (chunk_digest, chunk_bytes) = staged_digest(chunk.as_ref()).unwrap();
        let manifest = StagedManifest {
            chunk_digests: vec![chunk_digest],
            encoded_chunk_bytes: chunk_bytes,
            operation_count: 1,
            read_assertion_count: 0,
            read_collections: Default::default(),
            write_collections: ["rows".into()].into_iter().collect(),
        };
        let stage_key = staging::identity("owner", "upload").unwrap();
        let scope = StagedTransactionScope {
            tenant: state.tenant.clone(),
            incarnation: state.incarnation.clone(),
            principal: "owner".into(),
        };
        staging::replace_record(
            &mut state,
            stage_key,
            StagedTransaction {
                scope,
                transaction_id: "upload".into(),
                manifest_digest: staged_digest(&manifest).unwrap().0,
                manifest,
                chunks: BTreeMap::from([(0, chunk)]),
                stored_chunk_bytes: encoded_len(&"0").unwrap() + 1 + chunk_bytes,
                uploaded_payload_bytes: chunk_bytes,
                uploaded_operations: 1,
                uploaded_read_assertions: 0,
                expires_at_ms: Some(120_000),
                ttl_ms: 60_000,
                outcome: StagedOutcome::Uploading,
            },
        )
        .unwrap();
        state
    }
    fn image(disk: &Arc<kasumi_store::ScratchDisk>, state: &TenantState) -> SnapshotImage {
        SnapshotImage::capture(disk, 128 << 20, |writer| {
            crate::snapshot_codec::write(
                state,
                &crate::mutation_receipt::View::empty(
                    &state.tenant,
                    &state.mutation_receipt_head.origin_incarnation,
                )
                .unwrap(),
                &crate::backup_binding::View::empty(&state.backup_binding_head.origin_incarnation)?,
                &crate::staged_terminal::View::empty(
                    &state.tenant,
                    &state.staged_terminal_head.origin_incarnation,
                )?,
                &crate::target_resolution::View::empty(
                    &state.tenant,
                    &state.target_resolution_head.origin_incarnation,
                )?,
                writer,
            )
        })
        .unwrap()
    }
    fn indexed(
        disk: &Arc<kasumi_store::ScratchDisk>,
        state: &TenantState,
    ) -> anyhow::Result<ValidatedApplicationSnapshot> {
        ValidatedApplicationSnapshot::validate(image(disk, state), 128 << 20, || Ok(()))
    }
    #[test]
    fn indexed_terminal_provenance_retains_the_intermediate_incarnation_genesis() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
        use crate::staged_terminal::{AppliedIdentity, AppliedOrigin, Row};

        fn link(source: &str, target: &str, revision: u64) -> RestoreLineageLink {
            RestoreLineageLink {
                checkpoint: FullBackupCheckpoint {
                    tenant: "tenant".into(),
                    source_incarnation: source.into(),
                    revision,
                    resident_sha256: "01".repeat(32),
                    backup_id: uuid::Uuid::from_u128(u128::from(revision)),
                    manifest_ciphertext_sha256: "02".repeat(32),
                    key_lineage_digest: "03".repeat(32),
                },
                target_incarnation: target.into(),
            }
        }
        fn proof(
            disk: &Arc<kasumi_store::ScratchDisk>,
            state: &TenantState,
            row: &Row,
        ) -> ValidatedApplicationSnapshot {
            let mut header = crate::snapshot_codec::metadata(state);
            crate::staged_terminal::advance(&mut header.staged_terminal_head, row).unwrap();
            header.permanent_staged_bytes = header.staged_terminal_head.encoded_bytes;
            let image = SnapshotImage::capture(disk, 128 << 20, |writer| {
                let mut encoder = crate::snapshot_codec::Encoder::new(writer)?;
                encoder.record(Record::Header(Box::new(header.clone())))?;
                for (ordinal, link) in state.restore_lineage.iter().enumerate() {
                    encoder.record(Record::Lineage(ordinal as u64, link.clone()))?;
                }
                encoder.record(Record::Terminal(Box::new(row.clone())))?;
                encoder.finish()
            })
            .unwrap();
            let proof = ValidatedApplicationSnapshot {
                index: StagedSnapshot::new(image, 128 << 20, || Ok(())).unwrap(),
                header: Box::new(header),
                lineage: EncryptedTable::new(disk, 128 << 20, disk.native_cache_config()).unwrap(),
            };
            proof.validate_lineage(&mut || Ok(())).unwrap();
            proof
        }

        let mut state = state();
        let key = staging::identity("owner", "upload").unwrap();
        let mut stage = state.staged_transactions.remove(&key).unwrap();
        stage.scope.incarnation = "middle".into();
        stage.chunks.clear();
        stage.stored_chunk_bytes = 0;
        stage.uploaded_payload_bytes = 0;
        stage.uploaded_operations = 0;
        stage.uploaded_read_assertions = 0;
        stage.expires_at_ms = None;
        stage.outcome = StagedOutcome::Aborted {
            receipt: WriteReceipt {
                revision: 12,
                versions: Default::default(),
            },
        };
        state.active_staged_transactions.clear();
        state.reserved_staged_terminal_bytes = 0;
        state.permanent_staged_bytes = 0;
        state.incarnation = "current".into();
        state.revision_base = 21;
        state.revision = 25;
        state.restore_lineage = vec![
            link("generation", "middle", 10),
            link("middle", "current", 20),
        ];
        state.restored_from = Some(state.restore_lineage[1].checkpoint.clone());
        let row = Row {
            ordinal: 1,
            key,
            previous_sha256: state.staged_terminal_head.sha256.clone(),
            applied: AppliedIdentity {
                incarnation: "middle".into(),
                revision: 12,
                timestamp_ms: 1000,
                command_sha256: "ab".repeat(32),
                origin: AppliedOrigin::Raft {
                    term: 1,
                    leader: 1,
                    index: 1,
                    context_sha256: "cd".repeat(32),
                },
            },
            stage,
        };
        row.validate(&state).unwrap();
        let indexed = proof(disk, &state, &row);
        indexed.validate_staging(&mut || Ok(())).unwrap();
        let selected = indexed.staging_lineage("middle", Some("middle")).unwrap();
        assert_eq!(selected.restore_lineage.len(), 2);
        assert!(selected.restore_lineage.contains(&state.restore_lineage[0]));
        // The selected lineage is owned metadata. Release the unused scratch
        // proof before constructing independent malformed snapshots.
        drop(indexed);

        // Recompute the stream's final root for each substituted row, so these
        // failures must come from provenance rather than a stale digest.
        let mut relabelled = row.clone();
        relabelled.applied.incarnation = "current".into();
        assert!(relabelled.validate(&state).is_err());
        assert!(
            proof(disk, &state, &relabelled)
                .validate_staging(&mut || Ok(()))
                .is_err()
        );
        let mut wrong_position = row;
        if let AppliedOrigin::Raft { index, .. } = &mut wrong_position.applied.origin {
            *index = 2;
        }
        assert!(wrong_position.validate(&state).is_err());
        assert!(
            proof(disk, &state, &wrong_position)
                .validate_staging(&mut || Ok(()))
                .is_err()
        );
    }

    fn target_resolution_proof(
        disk: &Arc<kasumi_store::ScratchDisk>,
        state: &TenantState,
        rows: &[crate::target_resolution::Row],
    ) -> ValidatedApplicationSnapshot {
        let mut header = crate::snapshot_codec::metadata(state);
        header.target_resolution_head = TargetResolutionPrefixHead::empty(
            &state.tenant,
            &state.target_resolution_head.origin_incarnation,
        )
        .unwrap();
        for row in rows {
            row.validate(state).unwrap();
            crate::target_resolution::advance(&mut header.target_resolution_head, row).unwrap();
        }
        // This proof isolates target-terminal semantics. The shared fixture
        // independently validates the source rows and current target selectors.
        let image = SnapshotImage::capture(disk, 128 << 20, |writer| {
            let mut encoder = crate::snapshot_codec::Encoder::new(writer)?;
            encoder.record(Record::Header(Box::new(header.clone())))?;
            for (incarnation, target) in &state.target_lifecycle {
                encoder.record(Record::Target(
                    incarnation.clone(),
                    Box::new(target.clone()),
                ))?;
            }
            for row in rows {
                encoder.record(Record::TargetResolution(Box::new(row.clone())))?;
            }
            encoder.finish()
        })
        .unwrap();
        ValidatedApplicationSnapshot {
            index: StagedSnapshot::new(image, 128 << 20, || Ok(())).unwrap(),
            header: Box::new(header),
            lineage: EncryptedTable::new(disk, 128 << 20, disk.native_cache_config()).unwrap(),
        }
    }

    #[test]
    fn indexed_target_resolutions_preserve_linked_seals_for_one_incarnation() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
        let (state, rows) = crate::target_resolution::tests::linked_sealed_successor_rows();
        let proof = target_resolution_proof(disk, &state, &rows);
        proof.validate_target_resolutions(&mut || Ok(())).unwrap();
        assert_eq!(
            proof.header.target_resolution_head,
            state.target_resolution_head
        );
        for row in &rows {
            assert_eq!(
                get::<u64>(&proof.lineage, &("target-terminal-key", &row.key)).unwrap(),
                Some(row.ordinal)
            );
            let Some(Record::TargetResolution(actual)) = proof
                .index
                .get(22, &format!("{:020}", row.ordinal), "")
                .unwrap()
            else {
                panic!("verified target terminal row missing");
            };
            assert_eq!(actual.as_ref(), row);
        }
        drop(proof);
        assert_eq!(disk.snapshot().live_files, 0);
        assert_eq!(disk.snapshot().charged_bytes, 0);
    }

    #[test]
    fn indexed_target_resolutions_reject_changed_predecessors_and_duplicate_identity() {
        use crate::target_completion_machine::{CompletionMachine, tests as fixture};

        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
        let (mut state, rows) = crate::target_resolution::tests::linked_sealed_successor_rows();
        for missing in [true, false] {
            let mut changed = rows.clone();
            let TargetResolutionRecord::Completion(fact) = &mut changed[1].record else {
                unreachable!()
            };
            if missing {
                fact.input.attempt.input.predecessor = None;
            } else {
                fact.input
                    .attempt
                    .input
                    .predecessor
                    .as_mut()
                    .unwrap()
                    .fact_sha256 = "ab".repeat(32);
            }
            fact.input.attempt.intent.request.phase_input_sha256 =
                fact.input.attempt.input.digest().unwrap();
            fact.input.attempt.intent.request_sha256 =
                staged_digest(&fact.input.attempt.intent.request).unwrap().0;
            fact.resolution_intent.request.phase_input_sha256 = fact.input.digest().unwrap();
            fact.resolution_intent.request_sha256 =
                staged_digest(&fact.resolution_intent.request).unwrap().0;
            fact.validate().unwrap();
            // The point-index stream and final root are recomputed around the
            // typed-valid substitution, so rejection must come from causality.
            let proof = target_resolution_proof(disk, &state, &changed);
            let error = proof
                .validate_target_resolutions(&mut || Ok(()))
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("exact ordered sealed predecessor"),
                "{error:#}"
            );
            assert!(
                get::<u64>(&proof.lineage, &("target-terminal-key", &rows[1].key))
                    .unwrap()
                    .is_none()
            );
            drop(proof);
            assert_eq!(disk.snapshot().live_files, 0);
            assert_eq!(disk.snapshot().charged_bytes, 0);
        }

        let TargetResolutionRecord::Completion(first) = &rows[0].record else {
            unreachable!()
        };
        let TargetResolutionRecord::Completion(second) = &rows[1].record else {
            unreachable!()
        };
        let origin = second.input.attempt.origin.clone();
        let mut successor = fixture::attempt(
            &origin,
            Some(second.sealed_reference().unwrap()),
            7,
            7,
            820,
            850,
        );
        // Reuse an earlier immutable identity while otherwise advancing the
        // valid predecessor, Control revision and actual applying position.
        successor.intent.request.command_id = first.input.attempt.intent.request.command_id;
        successor.intent.request_sha256 = staged_digest(&successor.intent.request).unwrap().0;
        successor.validate().unwrap();
        let (input, mut intent) = fixture::resolution(&successor, 8);
        intent.accepted_at_ms = 840;
        let mut machine = CompletionMachine {
            origin: &origin,
            head: state.target_completion_head.as_mut().unwrap(),
            completion: None,
            terminal_bytes: state.target_resolution_head.encoded_bytes,
            maximum_bytes: state.limits.max_target_resolution_bytes,
        };
        machine.prepare(successor, Some(second), None).unwrap();
        let fact = machine
            .resolve(input, fixture::applied(intent, 850, 9), None)
            .unwrap();
        state.revision = fact.revision;
        let applied = kasumi_raft::AppliedEntryContext {
            log_id: openraft::LogId::new(
                openraft::CommittedLeaderId::new(fact.position.term, fact.position.leader_node_id),
                fact.position.index,
            ),
            previous: None,
            membership: Default::default(),
            command_sha256: fact.position.command_sha256.clone(),
            retirement_seed: None,
        };
        let duplicate = crate::target_resolution::Row::ordered(
            &state.target_resolution_head,
            TargetResolutionRecord::Completion(Box::new(fact)),
            &applied,
        )
        .unwrap();
        duplicate.validate(&state).unwrap();
        assert_eq!(duplicate.key, rows[0].key);
        let proof =
            target_resolution_proof(disk, &state, &[rows[0].clone(), rows[1].clone(), duplicate]);
        let error = proof
            .validate_target_resolutions(&mut || Ok(()))
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate permanent target terminal identity"),
            "{error:#}"
        );
        assert_eq!(
            get::<u64>(&proof.lineage, &("target-terminal-key", &rows[0].key)).unwrap(),
            Some(rows[0].ordinal)
        );
        drop(proof);
        assert_eq!(disk.snapshot().live_files, 0);
        assert_eq!(disk.snapshot().charged_bytes, 0);
    }

    #[test]
    fn indexed_verification_keeps_all_staging_on_the_image_owner_until_drain() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
        let initial = image(disk, &state());
        let disk = initial.disk().clone();
        let image_bytes = disk.snapshot().charged_bytes;
        let image_files = disk.snapshot().live_files;
        assert_eq!(image_files, 1);
        let verified =
            ValidatedApplicationSnapshot::validate(initial, 128 << 20, || Ok(())).unwrap();
        // Each native table owns a root, log and directory, potentially more
        // after rolling. Test custody independently of that physical layout.
        assert!(disk.snapshot().live_files > image_files);
        assert!(disk.snapshot().charged_bytes > image_bytes);
        let retained_image = verified.into_image();
        assert_eq!(disk.snapshot().live_files, image_files);
        assert_eq!(disk.snapshot().charged_bytes, image_bytes);
        drop(retained_image);
        assert_eq!(disk.snapshot().live_files, 0);
        assert_eq!(disk.snapshot().charged_bytes, 0);

        let invalid = image(&disk, &state());
        let disk = invalid.disk().clone();
        let mut checks = 0;
        assert!(
            ValidatedApplicationSnapshot::validate(invalid, 128 << 20, || {
                checks += 1;
                anyhow::ensure!(checks < 5, "cancelled staged validation");
                Ok(())
            })
            .is_err()
        );
        assert_eq!(disk.snapshot().live_files, 0);
        assert_eq!(disk.snapshot().charged_bytes, 0);
    }

    #[test]
    fn archive_free_relocation_preserves_verified_image_and_admission() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
        let original = image(disk, &state());
        let image_bytes = disk.snapshot().charged_bytes;
        let image_files = disk.snapshot().live_files;
        let verified =
            ValidatedApplicationSnapshot::validate(original.clone(), 128 << 20, || Ok(())).unwrap();
        assert_eq!(verified.index.count(11).unwrap(), 0);
        assert_eq!(verified.index.count(4).unwrap(), 0);
        assert_eq!(verified.header.history_archive_bytes, 0);
        let header_owner = std::ptr::from_ref(verified.header());
        let header_bytes = serde_json::to_vec(verified.header()).unwrap();
        let summary = verified.index.summary();
        let before = disk.snapshot();
        let callbacks = std::cell::RefCell::new(Vec::new());
        let relocated = verified
            .relocate(
                "new-destination",
                uuid::Uuid::from_u128(81),
                |layout| {
                    callbacks.borrow_mut().push("admit");
                    assert_eq!(*layout, summary);
                    assert_eq!(disk.snapshot().live_files, before.live_files);
                    assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
                    Ok(())
                },
                || {
                    callbacks.borrow_mut().push("check");
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(*callbacks.borrow(), ["check", "admit", "check"]);
        assert_eq!(std::ptr::from_ref(relocated.header()), header_owner);
        assert_eq!(
            serde_json::to_vec(relocated.header()).unwrap(),
            header_bytes
        );
        assert_eq!(relocated.index.summary(), summary);
        assert_eq!(relocated.image(), &original);
        assert_eq!(
            relocated.image().read_bounded(1 << 20).unwrap(),
            original.read_bounded(1 << 20).unwrap()
        );
        // Keeping the original image alive makes any replacement spool visible
        // in these counts even after the former proof's indexes have drained.
        assert_eq!(disk.snapshot().live_files, before.live_files);
        assert_eq!(disk.snapshot().charged_bytes, before.charged_bytes);
        drop(relocated);
        assert_eq!(disk.snapshot().live_files, image_files);
        assert_eq!(disk.snapshot().charged_bytes, image_bytes);
        drop(original);
        assert_eq!(disk.snapshot().live_files, 0);
        assert_eq!(disk.snapshot().charged_bytes, 0);
    }

    #[test]
    fn archive_free_relocation_propagates_callbacks_and_releases_proof() {
        #[derive(Debug)]
        struct RelocationFailure(Arc<()>);
        impl std::fmt::Display for RelocationFailure {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("original relocation callback failure")
            }
        }
        impl std::error::Error for RelocationFailure {}

        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
        let state = empty_state();
        // Fail the initial live check, admission, then the live check after
        // admission. Each error must retain its exact typed identity.
        for failed_callback in 0..3 {
            let original = image(disk, &state);
            let image_bytes = disk.snapshot().charged_bytes;
            let image_files = disk.snapshot().live_files;
            let verified =
                ValidatedApplicationSnapshot::validate(original.clone(), 128 << 20, || Ok(()))
                    .unwrap();
            let summary = verified.index.summary();
            let marker = Arc::new(());
            let callbacks = std::cell::RefCell::new(Vec::new());
            let callback = |name| {
                let mut calls = callbacks.borrow_mut();
                calls.push(name);
                if calls.len() - 1 == failed_callback {
                    Err(anyhow::Error::new(RelocationFailure(marker.clone())))
                } else {
                    Ok(())
                }
            };
            let result = verified.relocate(
                "new-destination",
                uuid::Uuid::from_u128(82),
                |layout| {
                    assert_eq!(*layout, summary);
                    callback("admit")
                },
                || callback("check"),
            );
            let Err(error) = result else {
                panic!("relocation ignored a failed callback");
            };
            assert!(Arc::ptr_eq(
                &error.downcast_ref::<RelocationFailure>().unwrap().0,
                &marker
            ));
            assert_eq!(
                callbacks.borrow().as_slice(),
                &["check", "admit", "check"][..=failed_callback]
            );
            assert_eq!(disk.snapshot().live_files, image_files);
            assert_eq!(disk.snapshot().charged_bytes, image_bytes);
            drop(original);
            assert_eq!(disk.snapshot().live_files, 0);
            assert_eq!(disk.snapshot().charged_bytes, 0);
        }
    }

    #[test]
    fn indexed_validation_matches_full_restore_and_canonical_closure() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
        let state = state();
        let valid = image(disk, &state);
        TenantEngine::verify_logical_snapshot(&valid, &state).unwrap();
        let mut wrong_state = state.clone();
        wrong_state.document_count += 1;
        assert!(TenantEngine::verify_logical_snapshot(&valid, &wrong_state).is_err());
        let indexed = indexed(disk, &state).unwrap();
        let records = indexed
            .index
            .cursor(3, Some("rows"))
            .unwrap()
            .collect::<anyhow::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(records.len(), 2);
        assert_eq!(indexed.index.count(10).unwrap(), 2);
        assert_eq!(indexed.header.document_count, 2);
        assert!(indexed.header.collections.is_empty());
        assert!(indexed.index.get(3, "rows", "absent").unwrap().is_none());
        assert!(
            indexed
                .index
                .cursor(3, Some("absent"))
                .unwrap()
                .next()
                .is_none()
        );
        let verified = crate::backup_verify::VerifiedState::Indexed(Box::new(indexed));
        assert_eq!(
            crate::retirement_closure::digest(&state, || Ok(())).unwrap(),
            crate::retirement_closure::digest_verified(&verified, || Ok(())).unwrap()
        );
    }

    #[test]
    fn zero_version_snapshot_passes_indexed_validation_and_full_restore() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let mut state = state();
        Arc::make_mut(
            state
                .collections
                .get_mut("rows")
                .unwrap()
                .documents
                .get_mut("a")
                .unwrap(),
        )
        .version = 0;
        let image = image(&scratch.disk, &state);
        let validated =
            ValidatedApplicationSnapshot::validate(image.clone(), 128 << 20, || Ok(())).unwrap();
        let Some(Record::Document(_, document)) = validated.index.get(3, "rows", "a").unwrap()
        else {
            panic!("validated zero-version document absent");
        };
        assert_eq!(document.version, 0);
        assert_eq!(document.body, state.collections["rows"].documents["a"].body);
        // This path reconstructs the real runtime QueryIndexes after the same
        // canonical snapshot checks, so both input adapters are exercised.
        TenantEngine::verify_logical_snapshot(&image, &state).unwrap();
    }
    #[test]
    fn receipt_original_scope_and_position_are_checked_in_both_snapshot_paths() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
        use crate::mutation_receipt::{Row, advance};
        use crate::staged_terminal::{AppliedIdentity, AppliedOrigin};
        fn encoded(
            disk: &Arc<kasumi_store::ScratchDisk>,
            state: &TenantState,
            row: &Row,
        ) -> SnapshotImage {
            let mut header = state.clone();
            header.mutation_receipt_head = MutationReceiptHead::empty(
                &state.tenant,
                &state.mutation_receipt_head.origin_incarnation,
            )
            .unwrap();
            // Recompute the frame/root on purpose. Semantic defects must be
            // rejected even when every transport count and digest is consistent.
            advance(&mut header.mutation_receipt_head, row).unwrap();
            SnapshotImage::capture(disk, 128 << 20, |writer| {
                let mut encoder = crate::snapshot_codec::Encoder::new(writer)?;
                for kind in (0..21).chain(std::iter::once(23)) {
                    if kind == 5 {
                        encoder.record(Record::Receipt(Box::new(row.clone())))?;
                    }
                    for record in crate::snapshot_codec::records(&header, kind, None)? {
                        encoder.record(record?)?;
                    }
                }
                encoder.finish()
            })
            .unwrap()
        }
        fn verify(
            disk: &Arc<kasumi_store::ScratchDisk>,
            state: &TenantState,
            row: &Row,
            accepted: bool,
            case: &str,
        ) {
            let image = encoded(disk, state, row);
            let full = crate::snapshot_codec::read(image.disk(), &mut image.reader()).and_then(
                |decoded| {
                    TenantEngine::verify_logical_snapshot(&image, &decoded.state)
                        .map_err(Into::into)
                },
            );
            assert_eq!(full.is_ok(), accepted, "full {case}: {full:?}");
            let indexed = ValidatedApplicationSnapshot::validate(image, 128 << 20, || Ok(()));
            assert_eq!(indexed.is_ok(), accepted, "indexed {case}");
        }
        let original = state();
        let row = Row {
            ordinal: 1,
            key: staged_digest(&("owner", "original")).unwrap().0,
            previous_sha256: original.mutation_receipt_head.sha256.clone(),
            applied: AppliedIdentity {
                incarnation: original.incarnation.clone(),
                revision: original.revision,
                timestamp_ms: 1000,
                command_sha256: "ab".repeat(32),
                origin: AppliedOrigin::Raft {
                    term: 1,
                    leader: 1,
                    index: original.revision,
                    context_sha256: "cd".repeat(32),
                },
            },
            receipt: StoredReceipt {
                scope: MutationReceiptScope {
                    tenant: original.tenant.clone(),
                    incarnation: original.incarnation.clone(),
                    principal: "owner".into(),
                },
                idempotency_key: "original".into(),
                recorded_revision: original.revision,
                request_digest: "12".repeat(32),
                collections: vec!["rows".into()],
                outcome: Ok(WriteReceipt {
                    revision: original.revision,
                    versions: BTreeMap::from([("/rows/a".into(), original.revision)]),
                }),
            },
        };
        verify(disk, &original, &row, true, "original");
        for case in 0..9 {
            let mut candidate = row.clone();
            match case {
                0 => candidate.receipt.scope.tenant = "another-tenant".into(),
                1 => candidate.receipt.scope.principal = "another-owner".into(),
                2 => candidate.receipt.scope.incarnation = "unretained-source".into(),
                3 => candidate.receipt.idempotency_key = "another-key".into(),
                4 => candidate.receipt.recorded_revision += 1,
                5 => candidate.receipt.outcome.as_mut().unwrap().revision -= 1,
                6 => candidate.receipt.request_digest.clear(),
                7 => candidate.applied.revision -= 1,
                _ => {
                    if let AppliedOrigin::Raft { index, .. } = &mut candidate.applied.origin {
                        *index -= 1;
                    }
                }
            }
            verify(
                disk,
                &original,
                &candidate,
                false,
                &format!("substitution {case}"),
            );
        }
        let binding_origin = original.backup_binding_head.origin_incarnation.clone();
        let mut restored = original;
        // The state deliberately retains the original point head across each
        // new genesis; original rows and their applying positions never relabel.
        for incarnation in ["intermediate", "current-target"] {
            let checkpoint = FullBackupCheckpoint {
                tenant: restored.tenant.clone(),
                source_incarnation: restored.incarnation.clone(),
                revision: restored.revision,
                resident_sha256: "12".repeat(32),
                backup_id: uuid::Uuid::new_v4(),
                manifest_ciphertext_sha256: "34".repeat(32),
                key_lineage_digest: "56".repeat(32),
            };
            TenantEngine::rebind_restored_state(
                &mut restored,
                incarnation.into(),
                checkpoint,
                None,
            )
            .unwrap();
            restored.pending_restore = None;
            restored.suspended = false;
            restored.revision += 2;
        }
        assert_eq!(
            restored.backup_binding_head.origin_incarnation,
            binding_origin
        );
        assert_ne!(
            restored.backup_binding_head.origin_incarnation,
            restored.incarnation
        );
        verify(disk, &restored, &row, true, "unchanged two-hop source");
        let mut unrelated = restored.clone();
        unrelated.backup_binding_head =
            BackupBindingHead::empty("unretained-binding-origin").unwrap();
        verify(
            disk,
            &unrelated,
            &row,
            false,
            "unrelated empty backup binding origin",
        );
        for incarnation in ["intermediate", "current-target"] {
            let mut candidate = row.clone();
            candidate.receipt.scope.incarnation = incarnation.into();
            candidate.applied.incarnation = incarnation.into();
            verify(disk, &restored, &candidate, false, incarnation);
        }
    }
    #[test]
    fn authenticated_semantic_substitutions_fail_both_validation_paths() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
        for case in 0..18 {
            let mut candidate = state();
            match case {
                0 => candidate.document_count += 1,
                1 => candidate.logical_bytes += 1,
                2 => candidate.collections.get_mut("rows").unwrap().data_epoch = 2,
                3 => {
                    Arc::make_mut(
                        candidate
                            .collections
                            .get_mut("rows")
                            .unwrap()
                            .documents
                            .get_mut("b")
                            .unwrap(),
                    )
                    .body = json!({"v": "1e0"});
                    candidate.logical_bytes = candidate.collections["rows"]
                        .documents
                        .values()
                        .map(|d| encoded_len(&d.body).unwrap() as u64)
                        .sum();
                }
                4 => candidate.change_feed.event_count += 1,
                5 => candidate.change_feed.encoded_commit_bytes += 1,
                6 => {
                    Arc::make_mut(candidate.change_feed.commits.get_mut(&1).unwrap()).records[1]
                        .id = "a".into();
                }
                7 => candidate.schema_epoch = 0,
                8 => candidate.retirement_bytes += 1,
                9 => candidate.active_staged_transactions.clear(),
                16 => candidate.permanent_staged_bytes += 1,
                17 => candidate.reserved_staged_terminal_bytes += 1,
                10 => {
                    candidate
                        .staged_transactions
                        .get_mut(&staging::identity("owner", "upload").unwrap())
                        .unwrap()
                        .uploaded_payload_bytes += 1
                }
                11 => {
                    candidate
                        .staged_transactions
                        .get_mut(&staging::identity("owner", "upload").unwrap())
                        .unwrap()
                        .manifest_digest = "00".repeat(32)
                }
                13..=15 => {
                    let scope = &mut candidate
                        .staged_transactions
                        .get_mut(&staging::identity("owner", "upload").unwrap())
                        .unwrap()
                        .scope;
                    match case {
                        13 => scope.principal = "replacement".into(),
                        14 => scope.tenant = "other-tenant".into(),
                        _ => scope.incarnation = "unretained-incarnation".into(),
                    }
                }
                _ => {
                    candidate
                        .staged_transactions
                        .get_mut(&staging::identity("owner", "upload").unwrap())
                        .unwrap()
                        .outcome = StagedOutcome::Aborted {
                        receipt: WriteReceipt {
                            revision: 3,
                            versions: Default::default(),
                        },
                    }
                }
            }
            assert!(
                TenantEngine::verify_logical_snapshot(&image(disk, &candidate), &candidate)
                    .is_err(),
                "resident case {case}"
            );
            assert!(indexed(disk, &candidate).is_err(), "indexed case {case}");
        }
    }
    #[test]
    fn indexing_never_returns_a_proof_after_cancellation_or_corrupt_footer() {
        let scratch = crate::codec_fixture::ScratchScope::new(
            kasumi_store::test_utils::TestDiskMemory::new(64 << 20, 64),
        )
        .unwrap();
        let disk = &scratch.disk;
        let state = state();
        let image = image(disk, &state);
        let mut calls = 0;
        assert!(
            ValidatedApplicationSnapshot::validate(image.clone(), 128 << 20, || {
                calls += 1;
                anyhow::ensure!(calls < 8, "cancelled");
                Ok(())
            })
            .is_err()
        );
        assert!(calls >= 8);
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut image.reader(), &mut bytes).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        let corrupt = SnapshotImage::capture(disk, 128 << 20, |writer| {
            writer.write_all(&bytes)?;
            Ok(())
        })
        .unwrap();
        assert!(TenantEngine::verify_logical_snapshot(&corrupt, &state).is_err());
        assert!(ValidatedApplicationSnapshot::validate(corrupt, 128 << 20, || Ok(())).is_err());
    }
}
