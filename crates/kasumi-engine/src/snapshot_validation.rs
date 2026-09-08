//! Independent application snapshot validation with encrypted point lookups.
//! No document, receipt, staged payload, or retained-history map is materialized.
use super::*;
use crate::{snapshot_codec::Record, snapshot_index::StagedSnapshot};
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
        let index = StagedSnapshot::new(image, index_disk_bytes, &mut check)?;
        let Some(Record::Header(header)) = index.get(0, "", "")? else {
            anyhow::bail!("snapshot metadata absent");
        };
        let scratch = EncryptedTable::new(index.image().disk(), index_disk_bytes)?;
        let result = Self {
            index,
            header,
            lineage: scratch,
        };
        result.validate_header()?;
        result.validate_lineage(&mut check)?;
        result.validate_documents(&mut check)?;
        result.validate_staging(&mut check)?;
        result.validate_change_feed(&mut check)?;
        result.validate_history(&mut check)?;
        result.validate_permanent(&mut check)?;
        result.validate_audits(&mut check)?;
        result.validate_targets(&mut check)?;
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
        mut check: impl FnMut() -> anyhow::Result<()>,
    ) -> anyhow::Result<Self> {
        let mut history_bytes = 0u64;
        self.index.visit(11, |record| {
            check()?;
            let Record::Archive(id, mut archive) = record else {
                unreachable!()
            };
            archive.storage_destination = alias.to_owned();
            archive.storage_backup_session = Some(backup_id);
            history_bytes = history_bytes
                .checked_add(history::metadata_entry(&id, &archive)? as u64)
                .context("restored history catalog size overflow")?;
            Ok(())
        })?;
        let image = SnapshotImage::capture(
            self.image().disk(),
            self.header.limits.max_snapshot_bytes,
            |writer| {
                let mut encoder = crate::snapshot_codec::Encoder::new(writer)?;
                crate::snapshot_codec::visit(&mut self.image().reader(), |_, mut record| {
                    check()?;
                    match &mut record {
                        Record::Header(header) => {
                            header.history_archive_bytes = usize::try_from(history_bytes)?
                        }
                        Record::Archive(_, archive) => {
                            archive.storage_destination = alias.to_owned();
                            archive.storage_backup_session = Some(backup_id);
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
        Self::validate(image, disk, check)
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
    pub(crate) fn archived(&self, collection: &str, id: &str) -> anyhow::Result<ArchivedDocument> {
        match self.index.get(4, collection, id)? {
            Some(Record::Archived(_, _, reference)) => Ok(reference),
            _ => anyhow::bail!("snapshot archived reference absent"),
        }
    }
    fn archive(&self, id: &str) -> anyhow::Result<RetainedHistoryArchive> {
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
    fn validate_header(&self) -> anyhow::Result<()> {
        let h = &self.header;
        validate_name(&h.tenant)?;
        validate_name(&h.incarnation)?;
        validate_limits(&h.limits)?;
        validate_policy(&h.policy, &h.limits)?;
        ensure!(
            h.lifecycle_control.is_none()
                && self.index.count(15)? == 0
                && self.index.count(16)? == 0
                && h.recovery_control.is_empty()
                && self.index.count(18)? == 0
                && self.index.count(19)? == 0
                && self.index.count(20)? == 0,
            "Control state cannot be an application backup"
        );
        ensure!(
            h.revision >= h.revision_base
                && h.schema_epoch <= h.policy_epoch
                && (self.index.count(2)? == 0 || h.schema_epoch > 0),
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
        let headroom = self
            .index
            .count(8)?
            .checked_mul(STAGED_OUTCOME_HEADROOM as u64)
            .and_then(|n| n.checked_add(20 - h.revision.to_string().len() as u64))
            .context("snapshot headroom overflow")?;
        ensure!(
            self.index
                .summary()
                .bytes
                .checked_add(headroom)
                .is_some_and(|n| n <= h.limits.max_snapshot_bytes),
            "snapshot exceeds serialized byte quota"
        );
        ensure!(
            self.index.count(5)? <= h.limits.max_receipts as u64
                && self.index.count(2)? <= h.limits.max_collections as u64,
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
            validate_collection(&collection.definition, &Default::default())?;
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
                let validators =
                    QueryIndexes::build(&BTreeMap::from([(name.clone(), collection.clone())]))?;
                current = Some((name.clone(), collection, validators));
            }
            let (_, collection, _) = current.as_ref().context("snapshot collection missing")?;
            validate_name(&document.id)?;
            ensure!(
                document.version <= collection.data_epoch,
                "snapshot document version differs"
            );
            validate_document(&collection.definition, &document.body)?;
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
            self.index.count(6)? <= h.limits.atomic.max_transaction_records as u64
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
        self.index.visit(6, |record| {
            check()?;
            let Record::Stage(key, stage) = record else {
                unreachable!()
            };
            let counts = get::<staging::SnapshotChunks>(&self.lineage, &("stage", &key))?
                .unwrap_or_default();
            let uploading = staging::validate_snapshot_record(&key, &stage, h.revision, &counts)?;
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
        ensure!(
            active == self.index.count(8)?
                && reserved <= h.limits.atomic.max_reserved_staging_bytes as u64,
            "staged reservation or active count differs"
        );
        Ok(())
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
            self.index.count(12)? <= h.limits.max_schema_activations as u64
                && self.index.count(13)? <= h.limits.max_retirements as u64,
            "permanent record quota exceeded"
        );
        let mut activation_bytes = 0u64;
        self.index.visit(12, |record| {
            check()?;
            let Record::Activation(key, record) = record else {
                unreachable!()
            };
            activation_bytes = activation_bytes
                .checked_add(schema::validate_snapshot_record(&key, &record, h.revision)? as u64)
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
                .checked_add(bytes as u64)
                .context("retirement byte count overflow")?;
            successes = successes
                .checked_add(u64::from(current))
                .context("retirement count overflow")?;
            Ok(())
        })?;
        ensure!(
            activation_bytes == h.schema_activation_bytes as u64
                && retirement_bytes == h.retirement_bytes as u64
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
            h.audit_retention.hot_bytes <= h.limits.audit_retention.hot_bytes
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
                bytes <= MAX_TARGET_HISTORY_BYTES as u64,
                "target history bytes exceeded"
            );
            Ok(())
        })?;
        Ok(())
    }
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

    fn state() -> TenantState {
        let mut state = TenantEngine::new(
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
        .clone();
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
        state.staged_transactions.insert(
            stage_key.clone(),
            StagedTransaction {
                principal: "owner".into(),
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
        );
        state.active_staged_transactions.insert(stage_key);
        state
    }
    fn image(state: &TenantState) -> SnapshotImage {
        SnapshotImage::capture(&kasumi_store::ScratchDisk::fixture(), 128 << 20, |writer| {
            crate::snapshot_codec::write(state, writer)
        })
        .unwrap()
    }
    fn indexed(state: &TenantState) -> anyhow::Result<ValidatedApplicationSnapshot> {
        ValidatedApplicationSnapshot::validate(image(state), 128 << 20, || Ok(()))
    }
    #[test]
    fn indexed_validation_matches_full_restore_and_canonical_closure() {
        let state = state();
        TenantEngine::verify_logical_snapshot(&image(&state), &state).unwrap();
        let indexed = indexed(&state).unwrap();
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
    fn authenticated_semantic_substitutions_fail_both_validation_paths() {
        for case in 0..13 {
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
                TenantEngine::verify_logical_snapshot(&image(&candidate), &candidate).is_err(),
                "resident case {case}"
            );
            assert!(indexed(&candidate).is_err(), "indexed case {case}");
        }
    }
    #[test]
    fn indexing_never_returns_a_proof_after_cancellation_or_corrupt_footer() {
        let state = state();
        let image = image(&state);
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
        let corrupt =
            SnapshotImage::capture(&kasumi_store::ScratchDisk::fixture(), 128 << 20, |writer| {
                writer.write_all(&bytes)?;
                Ok(())
            })
            .unwrap();
        assert!(ValidatedApplicationSnapshot::validate(corrupt, 128 << 20, || Ok(())).is_err());
    }
}
