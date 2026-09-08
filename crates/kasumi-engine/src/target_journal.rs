//! Independently encrypted target metadata. A terminal stop is stored before
//! local owners are drained; it never claims that physical cleanup has finished.
use crate::TargetOperation;
use anyhow::{Context, Result, ensure};
use kasumi_serving::{NodeIdentity, VerifiedTargetStop};
use kasumi_store::{TenantStore, WriteOp};
use kasumi_types::TargetJournalLimits;
use kasumi_types::{
    ControlAuthorityPartition, ControlSigningRoot, LifecycleIntent, LifecyclePhase,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
const NS: &str = "target.journal";
const MAX_RECORD: usize = 256 << 10;
const COMPLETION_RESERVE: u64 = MAX_RECORD as u64;
// Each generation independently reserves a stop and an activation projection.
const GENERATION_RESERVE: u64 = COMPLETION_RESERVE * 2;
#[path = "target_projection.rs"]
mod projection;
pub use projection::VerifiedTargetServingProjection;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetJournalInstallation {
    pub root: ControlSigningRoot,
    pub node: NodeIdentity,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetJournalIntent {
    intent: LifecycleIntent,
    authority_partition: ControlAuthorityPartition,
    partition_set_sha256: String,
    node: NodeIdentity,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetJournalStop {
    intent: TargetJournalIntent,
    stopped: kasumi_serving::SignedTargetStop,
    authority: kasumi_serving::AuthorityManifest,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationBinding {
    tenant: String,
    source_incarnation: Uuid,
    source_epoch: u64,
    target_incarnation: Uuid,
    checkpoint: kasumi_types::FullBackupCheckpoint,
    nodes: std::collections::BTreeMap<u64, kasumi_types::LifecycleNode>,
    control_incarnation: Uuid,
    partition: ControlAuthorityPartition,
}
impl GenerationBinding {
    fn from_intent(i: &TargetJournalIntent) -> Self {
        let r = &i.intent.request;
        Self {
            tenant: r.tenant.clone(),
            source_incarnation: r.source_incarnation,
            source_epoch: r.source_authority_epoch,
            target_incarnation: r.target_incarnation,
            checkpoint: r.checkpoint.clone(),
            nodes: r.target_nodes.clone(),
            control_incarnation: i.intent.control_incarnation,
            partition: i.authority_partition.clone(),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Metadata {
    format: u32,
    installation: TargetJournalInstallation,
    intents: u64,
    generations: u64,
    charged_bytes: u64,
}
/// The unique store catalog owns the mutation lock; runtime retains this one
/// journal handle. No application provider is constructed by opening it.
pub struct TargetJournal {
    store: Arc<TenantStore>,
    installed: TargetJournalInstallation,
    limits: TargetJournalLimits,
    admission: Arc<crate::admission::NodeAdmission>,
    mutation: Mutex<()>,
}
impl TargetJournal {
    pub fn open(
        store: Arc<TenantStore>,
        installed: TargetJournalInstallation,
        limits: TargetJournalLimits,
        admission: Arc<crate::admission::NodeAdmission>,
    ) -> Result<Arc<Self>> {
        type Owner = Arc<Mutex<std::sync::Weak<TargetJournal>>>;
        static OWNERS: std::sync::OnceLock<Mutex<std::collections::HashMap<usize, Owner>>> =
            std::sync::OnceLock::new();
        let gate = {
            let mut owners = OWNERS
                .get_or_init(Default::default)
                .lock()
                .map_err(|_| anyhow::anyhow!("target journal owner registry poisoned"))?;
            owners.retain(|_, owner| owner.try_lock().map_or(true, |old| old.strong_count() > 0));
            owners
                .entry(Arc::as_ptr(&store) as usize)
                .or_default()
                .clone()
        };
        let mut owner = gate
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal owner poisoned"))?;
        if let Some(existing) = owner.upgrade() {
            ensure!(
                existing.installed == installed
                    && existing.limits == limits
                    && Arc::ptr_eq(&existing.admission, &admission),
                "live target journal installation differs"
            );
            existing.store.check_access()?;
            return Ok(existing);
        }
        let _workspace = admission.reserve((MAX_RECORD * 8) as u64, None)?;
        installed.root.validate()?;
        installed.node.validate()?;
        limits.validate()?;
        ensure!(
            matches!(store.storage_access().purpose(), kasumi_store::StoragePurpose::TargetJournal {control_root,node}
            if *control_root==installed.root && *node==installed.node),
            "independent target journal storage identity differs"
        );
        let journal = Arc::new(Self {
            store,
            installed,
            limits,
            admission,
            mutation: Mutex::new(()),
        });
        if journal
            .store
            .get_bounded(NS, b"metadata", MAX_RECORD)?
            .is_none()
        {
            // An absent head cannot initialize over retained records or an
            // unsupported journal. Reject before writing any replacement head.
            journal.store.visit(NS, MAX_RECORD, |_, _| {
                anyhow::bail!("target journal records exist without a canonical head")
            })?;
            let metadata = Metadata {
                format: 1,
                installation: journal.installed.clone(),
                intents: 0,
                generations: 0,
                charged_bytes: MAX_RECORD as u64,
            };
            journal.store.write_batch(&[WriteOp::put(
                NS,
                b"metadata",
                serde_json::to_vec(&metadata)?,
            )])?;
        }
        let metadata = journal.metadata()?;
        // Streaming startup verification retains one bounded encrypted record at
        // a time. Permanent identities are never silently dropped or truncated.
        let mut intents = 0u64;
        let mut generations = 0u64;
        let mut charged = MAX_RECORD as u64;
        journal.store.visit(NS, MAX_RECORD, |key, value| {
            if key.starts_with(b"intent/") {
                intents = intents.checked_add(1).context("journal count exhausted")?;
                let i: TargetJournalIntent = serde_json::from_slice(value)?;
                journal.validate_intent(&i)?;
                ensure!(
                    key == intent_key(i.intent.request.command_id),
                    "journal intent key differs"
                );
                charged = charged
                    .checked_add(value.len() as u64 + COMPLETION_RESERVE)
                    .context("journal bytes exhausted")?;
            } else if key.starts_with(b"generation/") {
                generations = generations
                    .checked_add(1)
                    .context("journal count exhausted")?;
                let target: GenerationBinding = serde_json::from_slice(value)?;
                ensure!(
                    key == generation_key(&target.tenant, target.target_incarnation),
                    "journal generation key differs"
                );
                charged = charged
                    .checked_add(value.len() as u64 + GENERATION_RESERVE)
                    .context("journal bytes exhausted")?;
            } else if key.starts_with(b"serving/") {
                journal.decode_serving_candidate(key, value)?;
            } else if key.starts_with(b"activation/") {
                journal.decode_projection_record(key, value)?;
            } else if key.starts_with(b"stop/") {
                let stop: TargetJournalStop = serde_json::from_slice(value)?;
                journal.validate_stop(&stop)?;
                ensure!(
                    key == stop_key(
                        &stop.intent.intent.request.tenant,
                        stop.intent.intent.request.target_incarnation
                    ),
                    "journal stop key differs"
                );
            } else {
                ensure!(key == b"metadata", "unknown target journal record");
            }
            Ok(())
        })?;
        ensure!(
            metadata.intents == intents
                && metadata.generations == generations
                && metadata.charged_bytes == charged,
            "target journal accounting differs"
        );
        *owner = Arc::downgrade(&journal);
        Ok(journal)
    }
    fn metadata(&self) -> Result<Metadata> {
        let value = self
            .store
            .get_bounded(NS, b"metadata", MAX_RECORD)?
            .context("target journal metadata missing")?;
        let m: Metadata = serde_json::from_slice(&value)?;
        ensure!(
            m.format == 1
                && m.installation == self.installed
                && m.charged_bytes <= self.limits.max_metadata_bytes,
            "target journal binding or capacity differs"
        );
        Ok(m)
    }
    fn validate_intent(&self, i: &TargetJournalIntent) -> Result<()> {
        i.intent.request.validate()?;
        ensure!(
            i.node == self.installed.node
                && i.intent.control_incarnation == self.installed.root.control_incarnation
                && i.intent.request.authority_partition == i.authority_partition.key()
                && i.intent.request_sha256 == kasumi_serving::digest(&i.intent.request)?
                && i.intent.accepted_at_ms < i.intent.original_credential_expires_at_ms,
            "journal original intent binding differs"
        );
        kasumi_types::validate_sha256(&i.partition_set_sha256)?;
        Ok(())
    }
    fn intent(&self, op: &TargetOperation) -> Result<TargetJournalIntent> {
        op.check()?;
        let lease = op.invocation().gate().current()?;
        let c = lease.commitment();
        ensure!(
            c.root == self.installed.root
                && lease.signed().claims.request.target_node == self.installed.node,
            "phase belongs to another installed journal"
        );
        let result = TargetJournalIntent {
            intent: c.intent.clone(),
            authority_partition: c.authority_partition.clone(),
            partition_set_sha256: c.partition_set_sha256.clone(),
            node: self.installed.node.clone(),
        };
        self.validate_intent(&result)?;
        Ok(result)
    }
    pub fn prepare(
        &self,
        op: &TargetOperation,
        exact_input_sha256: &str,
    ) -> Result<TargetJournalIntent> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let intent = self.intent(op)?;
        ensure!(
            intent.intent.request.phase != LifecyclePhase::StopLocal
                && intent.intent.request.phase_input_sha256 == exact_input_sha256,
            "target input differs from original control intent"
        );
        ensure!(
            self.store
                .get_bounded(
                    NS,
                    &stop_key(
                        &intent.intent.request.tenant,
                        intent.intent.request.target_incarnation
                    ),
                    MAX_RECORD
                )?
                .is_none(),
            "target incarnation permanently stopped locally"
        );
        if let Some(old) = self.store.get_bounded(
            NS,
            &intent_key(intent.intent.request.command_id),
            MAX_RECORD,
        )? {
            ensure!(
                serde_json::from_slice::<TargetJournalIntent>(&old)? == intent,
                "target command identity already bound"
            );
            op.check()?;
            return Ok(intent);
        }
        let encoded = serde_json::to_vec(&intent)?;
        ensure!(
            encoded.len() <= MAX_RECORD,
            "target intent exceeds metadata bound"
        );
        let mut metadata = self.metadata()?;
        let target = intent.intent.request.target_incarnation;
        let binding = GenerationBinding::from_intent(&intent);
        let mut writes = vec![WriteOp::put(
            NS,
            intent_key(intent.intent.request.command_id),
            encoded.clone(),
        )];
        metadata.intents = metadata
            .intents
            .checked_add(1)
            .context("target journal count exhausted")?;
        metadata.charged_bytes = metadata
            .charged_bytes
            .checked_add(encoded.len() as u64 + COMPLETION_RESERVE)
            .context("journal bytes exhausted")?;
        if let Some(old) =
            self.store
                .get_bounded(NS, &generation_key(&binding.tenant, target), MAX_RECORD)?
        {
            ensure!(
                serde_json::from_slice::<GenerationBinding>(&old)? == binding,
                "target generation binding differs"
            );
        } else {
            let encoded = serde_json::to_vec(&binding)?;
            metadata.generations = metadata
                .generations
                .checked_add(1)
                .context("target generation count exhausted")?;
            metadata.charged_bytes = metadata
                .charged_bytes
                .checked_add(encoded.len() as u64 + GENERATION_RESERVE)
                .context("journal bytes exhausted")?;
            writes.push(WriteOp::put(
                NS,
                generation_key(&binding.tenant, target),
                encoded,
            ));
        }
        ensure!(
            metadata.charged_bytes <= self.limits.max_metadata_bytes,
            "target journal permanent capacity exhausted"
        );
        writes.push(WriteOp::put(
            NS,
            b"metadata",
            serde_json::to_vec(&metadata)?,
        ));
        op.check()?;
        self.store.write_batch(&writes).map_err(journal_unknown)?;
        op.check().map_err(journal_unknown)?;
        Ok(intent)
    }
    fn validate_stop(&self, stop: &TargetJournalStop) -> Result<()> {
        self.validate_intent(&stop.intent)?;
        let intent = &stop.intent.intent.request;
        let trust = kasumi_serving::AuthorityTrust::install(stop.authority.clone())?;
        ensure!(
            stop.authority
                .control_partition(stop.authority.partition(&intent.tenant)?)?
                == stop.intent.authority_partition
                && stop
                    .authority
                    .lifecycle_controls
                    .get(&self.installed.root.control_incarnation)
                    == Some(&self.installed.root.public_key),
            "target stop issuer differs from committed control partition"
        );
        let proof =
            trust.verify_target_stop(stop.stopped.clone(), &stop.stopped.observation.reference)?;
        let receipt = &proof.observation().stop;
        let kasumi_serving::AuthorityOutcome::TargetStopped {
            source_incarnation,
            source_epoch,
            target,
        } = &receipt.outcome
        else {
            anyhow::bail!("journal target stop is not a stopped outcome")
        };
        ensure!(
            intent.phase == LifecyclePhase::StopLocal
                && *source_incarnation == intent.source_incarnation
                && *source_epoch == intent.source_authority_epoch
                && target.incarnation == intent.target_incarnation
                && target.checkpoint == intent.checkpoint
                && target.nodes.len() == intent.target_nodes.len()
                && target.nodes.iter().all(|node| intent
                    .target_nodes
                    .get(&node.node_id)
                    .is_some_and(|expected| expected.verifier == node.verifier
                        && expected.principal == node.principal
                        && expected.certificate_sha256 == node.certificate_sha256))
                && intent.phase_input_sha256
                    == kasumi_serving::digest(&(
                        "kasumi.stop-local-target-input.v1",
                        proof.reference()
                    ))?,
            "drained target stop differs from exact original local phase"
        );
        Ok(())
    }
    /// Must precede local scope closure and any physical deletion. The returned
    /// value describes a permanent stop only, never completed local cleanup.
    pub fn stop(&self, op: &TargetOperation, proof: &VerifiedTargetStop) -> Result<()> {
        let _workspace = self.admission.reserve((MAX_RECORD * 8) as u64, None)?;
        let _guard = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("target journal poisoned"))?;
        let intent = self.intent(op)?;
        let lease = op.invocation().gate().current()?;
        let requested = TargetJournalStop {
            intent,
            stopped: proof.signed().clone(),
            authority: lease.authority().manifest().clone(),
        };
        self.validate_stop(&requested)?;
        let target = requested.intent.intent.request.target_incarnation;
        let binding = GenerationBinding::from_intent(&requested.intent);
        if let Some(bytes) =
            self.store
                .get_bounded(NS, &stop_key(&binding.tenant, target), MAX_RECORD)?
        {
            let old: TargetJournalStop = serde_json::from_slice(&bytes)?;
            self.validate_stop(&old)?;
            ensure!(
                old.stopped.observation.stop.digest()?
                    == requested.stopped.observation.stop.digest()?,
                "target incarnation has another terminal stop"
            );
            op.check()?;
            return Ok(());
        }
        let encoded = serde_json::to_vec(&requested)?;
        ensure!(
            encoded.len() <= MAX_RECORD - 4096,
            "target stop exceeds reserved completion capacity"
        );
        let mut metadata = self.metadata()?;
        let mut writes = vec![WriteOp::put(NS, stop_key(&binding.tenant, target), encoded)];
        // Each generation reserves its terminal stop record, including the
        // original StopLocal identity. Stop consumes no normal phase slot or
        // extra capacity for an already reserved generation.
        if let Some(old) =
            self.store
                .get_bounded(NS, &generation_key(&binding.tenant, target), MAX_RECORD)?
        {
            ensure!(
                serde_json::from_slice::<GenerationBinding>(&old)? == binding,
                "target generation binding differs"
            );
        } else {
            let encoded = serde_json::to_vec(&binding)?;
            metadata.generations = metadata
                .generations
                .checked_add(1)
                .context("journal count exhausted")?;
            metadata.charged_bytes = metadata
                .charged_bytes
                .checked_add(encoded.len() as u64 + GENERATION_RESERVE)
                .context("journal bytes exhausted")?;
            writes.push(WriteOp::put(
                NS,
                generation_key(&binding.tenant, target),
                encoded,
            ));
        }
        ensure!(
            metadata.charged_bytes <= self.limits.max_metadata_bytes,
            "permanent stop publication capacity exhausted"
        );
        writes.push(WriteOp::put(
            NS,
            b"metadata",
            serde_json::to_vec(&metadata)?,
        ));
        op.check()?;
        self.store.write_batch(&writes).map_err(journal_unknown)?;
        op.check().map_err(journal_unknown)?;
        Ok(())
    }
}
fn intent_key(id: Uuid) -> Vec<u8> {
    format!("intent/{id}").into_bytes()
}
fn generation_key(tenant: &str, id: Uuid) -> Vec<u8> {
    format!("generation/{tenant}/{id}").into_bytes()
}
fn stop_key(tenant: &str, id: Uuid) -> Vec<u8> {
    format!("stop/{tenant}/{id}").into_bytes()
}

impl TargetJournalIntent {
    /// Permanent accepted metadata, never proof of any physical target effect.
    pub fn intent(&self) -> &LifecycleIntent {
        &self.intent
    }
}

fn journal_unknown(_: impl std::fmt::Display) -> anyhow::Error {
    kasumi_types::Error::new(
        kasumi_types::ErrorCode::UnknownOutcome,
        "target journal publication unresolved; recover the exact identity",
    )
    .into()
}
