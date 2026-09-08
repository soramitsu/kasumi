//! Permanent physical verifier enrollments. Stage freezes this complete table;
//! neither omitted receivers nor later admissions can hide behind signer roots.
use super::*;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FrozenSignerRoster {
    pub(super) operation_id: Uuid,
    pub(super) revision: u64,
    pub(super) roster: SignerVerifierRoster,
}
pub(super) fn roster_key(operation_id: Uuid) -> String {
    format!("signer-roster/{operation_id}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ControlVerifierRecord {
    pub(super) admission: ControlVerifierAdmission,
    operation_id: Uuid,
    pub(super) revision: u64,
}
pub(super) fn verifier_key(identity: &TrustVerifierIdentity) -> String {
    format!(
        "signer-verifier/{}/{:020}",
        identity.installation_id, identity.node_id
    )
}
pub(super) fn control_key(incarnation: Uuid) -> String {
    format!("signer-control/{incarnation}")
}
fn frozen(meta: &Meta) -> bool {
    meta.signing.staged.is_some() || meta.signing.retirement.is_some()
}

impl Backend {
    pub(crate) fn signer_verifier_page(
        &self,
        expected_revision: u64,
        after: Option<&TrustVerifierIdentity>,
        limit: u16,
    ) -> Result<SignerVerifierPage> {
        ensure!((1..=64).contains(&limit), "verifier page bound differs");
        let _lock = self
            .mutation
            .lock()
            .map_err(|_| anyhow::anyhow!("authority state poisoned"))?;
        ensure!(
            self.meta()?.operational.revision == expected_revision,
            "verifier pagination revision changed"
        );
        let mut page = BTreeMap::new();
        self.store.visit(NS, MAX_RECORD_BYTES, |key, bytes| {
            if key.starts_with(b"signer-verifier/") {
                let Record::Verifier(record) = serde_json::from_slice(bytes)? else {
                    anyhow::bail!("verifier table record differs")
                };
                if after.is_none_or(|identity| *identity < record.enrollment.verifier) {
                    page.insert(record.enrollment.verifier.clone(), record);
                    if page.len() > usize::from(limit) + 1 {
                        page.pop_last();
                    }
                }
            }
            Ok(())
        })?;
        let more = page.len() > usize::from(limit);
        if more {
            page.pop_last();
        }
        let next = if more {
            page.last_key_value().map(|(identity, _)| identity.clone())
        } else {
            None
        };
        Ok(SignerVerifierPage {
            registrations: page.into_values().collect(),
            next,
        })
    }
    pub(super) fn check_new_verifier_admission(meta: &Meta) -> kasumi_types::Result<()> {
        if frozen(meta) {
            return Err(conflict(
                "signer rotation froze physical verifier admissions",
            ));
        }
        Ok(())
    }
    pub(super) fn check_target_verifier_admission(
        &self,
        meta: &Meta,
        nodes: &BTreeSet<NodeIdentity>,
    ) -> kasumi_types::Result<()> {
        if frozen(meta) {
            for node in nodes {
                self.require_enrolled(&node.verifier).map_err(|_| {
                    conflict("target activation introduces a verifier outside the frozen roster")
                })?;
            }
        }
        Ok(())
    }
    pub(super) fn validate_roster_transition(
        &self,
        meta: &Meta,
        command: &AuthorityMaintenanceCommand,
    ) -> Result<()> {
        Self::check_new_verifier_admission(meta)?;
        match &command.action {
            AuthorityMaintenanceAction::EnrollSignerVerifier { enrollment } => {
                enrollment.validate()?;
                ensure!(
                    self.record(&verifier_key(&enrollment.verifier))?.is_none(),
                    "physical verifier identity is permanently allocated"
                );
                self.store.visit(NS, MAX_RECORD_BYTES, |key, bytes| {
                    if key.starts_with(b"signer-verifier/") {
                        let Record::Verifier(existing) = serde_json::from_slice(bytes)? else { anyhow::bail!("verifier record type differs") };
                        ensure!(existing.enrollment.endpoint != enrollment.endpoint
                            && existing.enrollment.certificate_pins.is_disjoint(&enrollment.certificate_pins),
                            "administrative origin or certificate already identifies another physical verifier");
                    }
                    Ok(())
                })?;
            }
            AuthorityMaintenanceAction::AdmitControlVerifiers { admission } => {
                self.validate_control_admission(admission)?;
                ensure!(
                    self.record(&control_key(admission.root.control_incarnation))?
                        .is_none(),
                    "Control verifier admission already has a permanent identity"
                );
                for node in &admission.nodes {
                    self.require_enrolled(&node.verifier)?;
                }
            }
            _ => anyhow::bail!("not a verifier enrollment transition"),
        }
        Ok(())
    }
    fn validate_control_admission(&self, admission: &ControlVerifierAdmission) -> Result<()> {
        admission.validate()?;
        ensure!(
            self.installation
                .manifest
                .lifecycle_controls
                .get(&admission.root.control_incarnation)
                == Some(&admission.root.public_key)
                && admission.partition
                    == self
                        .installation
                        .manifest
                        .control_partition(self.installation.partition)?,
            "Control verifier admission differs from the installed root and issuer partition"
        );
        Ok(())
    }
    fn require_enrolled(&self, verifier: &TrustVerifierIdentity) -> Result<()> {
        ensure!(
            matches!(self.record(&verifier_key(verifier))?, Some(Record::Verifier(record)) if record.enrollment.verifier == *verifier),
            "physical verifier lacks its exact permanent administrative enrollment"
        );
        Ok(())
    }
    pub(super) fn apply_roster_transition(
        &self,
        meta: &mut Meta,
        command: &AuthorityMaintenanceCommand,
        revision: u64,
        additions: &mut Vec<(String, Record)>,
    ) -> Result<()> {
        self.validate_roster_transition(meta, command)?;
        let (key, record) = match &command.action {
            AuthorityMaintenanceAction::EnrollSignerVerifier { enrollment } => {
                add_count(&mut meta.signer_verifiers, 1)?;
                (
                    verifier_key(&enrollment.verifier),
                    Record::Verifier(SignerVerifierRegistration {
                        enrollment: enrollment.clone(),
                        operation_id: command.operation_id,
                        revision,
                    }),
                )
            }
            AuthorityMaintenanceAction::AdmitControlVerifiers { admission } => {
                add_count(&mut meta.signer_controls, 1)?;
                (
                    control_key(admission.root.control_incarnation),
                    Record::ControlVerifier(ControlVerifierRecord {
                        admission: admission.clone(),
                        operation_id: command.operation_id,
                        revision,
                    }),
                )
            }
            _ => anyhow::bail!("not a verifier enrollment transition"),
        };
        additions.push((key, record));
        meta.operational.revision = revision;
        Ok(())
    }
    pub(super) fn retain_signer_roster(
        meta: &mut Meta,
        operation_id: Uuid,
        revision: u64,
        roster: &SignerVerifierRoster,
        additions: &mut Vec<(String, Record)>,
    ) -> Result<()> {
        add_count(&mut meta.signer_rosters, 1)?;
        additions.push((
            roster_key(operation_id),
            Record::SignerRoster(FrozenSignerRoster {
                operation_id,
                revision,
                roster: roster.clone(),
            }),
        ));
        Ok(())
    }
    pub(super) fn freeze_signer_roster(&self, meta: &Meta) -> Result<SignerVerifierRoster> {
        let mut hash = Sha256::new();
        hash.update(b"kasumi.physical-verifier-roster.v1");
        let (mut enrollments, mut controls) = (0, 0);
        for member in meta.operational.membership.members.values() {
            self.require_enrolled(&member.verifier)?;
        }
        for (incarnation, public_key) in &self.installation.manifest.lifecycle_controls {
            let Some(Record::ControlVerifier(record)) = self.record(&control_key(*incarnation))?
            else {
                anyhow::bail!("installed Control root lacks an exact physical replica admission")
            };
            ensure!(
                record.admission.root.public_key == *public_key,
                "Control roster root differs"
            );
        }
        let maximum = self
            .resource_budget_bytes
            .checked_mul(8)
            .and_then(|bytes| bytes.checked_add(64 << 20))
            .context("roster staging disk budget overflow")?;
        let records = kasumi_store::EncryptedTable::new(self.store.scratch_disk(), maximum)?;
        self.store
            .read_view()?
            .visit(NS, MAX_RECORD_BYTES, |key, bytes| {
                if key == META {
                    return Ok(());
                }
                let record: Record = serde_json::from_slice(bytes)?;
                Self::visit_verifier_references(&record, |verifier| {
                    self.require_enrolled(verifier)
                })?;
                if matches!(record, Record::Verifier(_) | Record::ControlVerifier(_)) {
                    records.insert(key, bytes)?;
                }
                Ok(())
            })?;
        records.visit(|key, bytes| {
            Self::hash_roster_record(
                key,
                &serde_json::from_slice(bytes)?,
                &mut hash,
                &mut enrollments,
                &mut controls,
            )
        })?;
        ensure!(
            enrollments == meta.signer_verifiers && controls == meta.signer_controls,
            "signer enrollment accounting differs"
        );
        let roster = SignerVerifierRoster {
            enrollment_count: enrollments,
            control_count: controls,
            sha256: hex::encode(hash.finalize()),
        };
        roster.validate()?;
        Ok(roster)
    }
    fn visit_verifier_references(
        record: &Record,
        mut require: impl FnMut(&TrustVerifierIdentity) -> Result<()>,
    ) -> Result<()> {
        match record {
            Record::Tenant(tenant) => {
                for node in &tenant.nodes {
                    require(&node.verifier)?;
                }
            }
            Record::Preparation(prepared) => {
                for node in &prepared.target.nodes {
                    require(&node.verifier)?;
                }
            }
            Record::Incarnation(incarnation) => match &incarnation.receipt.command.action {
                AuthorityAction::Enroll { nodes, .. } => {
                    for node in nodes {
                        require(&node.verifier)?;
                    }
                }
                AuthorityAction::Activate { target, .. }
                | AuthorityAction::ActivateCommitted { target, .. } => {
                    for node in &target.nodes {
                        require(&node.verifier)?;
                    }
                }
                _ => anyhow::bail!("incarnation does not identify admitted physical replicas"),
            },
            Record::Lifecycle(receipt) => {
                if let LifecycleAuthorityRequest::AcceptIntent(signed) = &receipt.request {
                    for node in signed.observation.intent.request.target_nodes.values() {
                        require(&node.verifier)?;
                    }
                }
            }
            Record::ControlVerifier(control) => {
                for node in &control.admission.nodes {
                    require(&node.verifier)?;
                }
            }
            Record::RevokedMember(member) => require(&member.member.verifier)?,
            _ => {}
        }
        Ok(())
    }
    fn hash_roster_record(
        key: &[u8],
        record: &Record,
        hash: &mut Sha256,
        enrollments: &mut u64,
        controls: &mut u64,
    ) -> Result<()> {
        match record {
            Record::Verifier(_) => add_count(enrollments, 1)?,
            Record::ControlVerifier(_) => add_count(controls, 1)?,
            _ => return Ok(()),
        }
        let bytes = serde_json::to_vec(record)?;
        hash.update((key.len() as u64).to_be_bytes());
        hash.update(key);
        hash.update((bytes.len() as u64).to_be_bytes());
        hash.update(bytes);
        Ok(())
    }
    pub(super) fn validate_roster_snapshot(&self, snapshot: &Snapshot) -> Result<()> {
        let (mut enrollments, mut controls, mut frozen_count) = (0, 0, 0);
        let mut hash = Sha256::new();
        hash.update(b"kasumi.physical-verifier-roster.v1");
        let current = snapshot
            .meta
            .signing
            .staged
            .as_ref()
            .map(|stage| (&stage.roster, stage.operation_id))
            .or_else(|| {
                snapshot
                    .meta
                    .signing
                    .retirement
                    .as_ref()
                    .map(|retirement| (&retirement.roster, retirement.stage_operation_id))
            });
        let frozen_record = current
            .map(|(roster, id)| -> Result<FrozenSignerRoster> {
                let Some(Record::SignerRoster(record)) = snapshot.records.get(&roster_key(id))?
                else {
                    anyhow::bail!("current rotation lacks its permanent frozen roster")
                };
                ensure!(
                    record.roster == *roster && record.operation_id == id,
                    "current signer roster differs from original freeze"
                );
                Ok(record)
            })
            .transpose()?;
        let frozen_roster = frozen_record
            .as_ref()
            .map(|record| (&record.roster, record.revision));
        let require = |verifier: &TrustVerifierIdentity| -> Result<()> {
            ensure!(
                matches!(snapshot.records.get(&verifier_key(verifier))?, Some(Record::Verifier(record)) if record.enrollment.verifier == *verifier),
                "frozen snapshot omits a physical verifier enrollment"
            );
            Ok(())
        };
        snapshot.records.visit(|key, record| {
            if let Record::SignerRoster(frozen) = record {
                add_count(&mut frozen_count, 1)?;
                frozen.roster.validate()?;
                ensure!(
                    key == roster_key(frozen.operation_id)
                        && frozen.revision > 0
                        && frozen.revision <= snapshot.meta.revision,
                    "frozen roster position or identity differs"
                );
                let Some(Record::Maintenance(status)) = snapshot
                    .records
                    .get(&maintenance_state::operation_key(frozen.operation_id))?
                else {
                    anyhow::bail!("frozen roster lacks its permanent stage command")
                };
                ensure!(
                    status.phase == AuthorityMaintenancePhase::Completed
                        && status.progress_revision == frozen.revision
                        && matches!(
                            status.command.action,
                            AuthorityMaintenanceAction::StageSignerGeneration { .. }
                        ),
                    "frozen roster stage outcome differs"
                );
                return Ok(());
            }
            if let Record::Maintenance(status) = record
                && status.phase == AuthorityMaintenancePhase::Completed
            {
                let key = match &status.command.action {
                    AuthorityMaintenanceAction::EnrollSignerVerifier { enrollment } => {
                        Some(verifier_key(&enrollment.verifier))
                    }
                    AuthorityMaintenanceAction::AdmitControlVerifiers { admission } => {
                        Some(control_key(admission.root.control_incarnation))
                    }
                    AuthorityMaintenanceAction::StageSignerGeneration { .. } => {
                        Some(roster_key(status.command.operation_id))
                    }
                    _ => None,
                };
                if let Some(key) = key {
                    ensure!(
                        snapshot.records.contains_key(&key)?,
                        "completed signer operation lost its permanent enrollment or freeze"
                    );
                }
            }
            let (operation_id, revision, expected) = match record {
                Record::Verifier(record) => {
                    record.enrollment.validate()?;
                    ensure!(
                        key == verifier_key(&record.enrollment.verifier),
                        "physical verifier record key differs"
                    );
                    (
                        record.operation_id,
                        record.revision,
                        AuthorityMaintenanceAction::EnrollSignerVerifier {
                            enrollment: record.enrollment.clone(),
                        },
                    )
                }
                Record::ControlVerifier(record) => {
                    self.validate_control_admission(&record.admission)?;
                    ensure!(
                        key == control_key(record.admission.root.control_incarnation),
                        "Control verifier record key differs"
                    );
                    for node in &record.admission.nodes {
                        require(&node.verifier)?;
                    }
                    (
                        record.operation_id,
                        record.revision,
                        AuthorityMaintenanceAction::AdmitControlVerifiers {
                            admission: record.admission.clone(),
                        },
                    )
                }
                _ => {
                    if frozen_roster.is_some() {
                        Self::visit_verifier_references(record, require)?;
                    }
                    return Ok(());
                }
            };
            let Some(Record::Maintenance(status)) = snapshot
                .records
                .get(&maintenance_state::operation_key(operation_id))?
            else {
                anyhow::bail!("verifier enrollment lacks its permanent command outcome")
            };
            ensure!(
                revision > 0
                    && revision <= snapshot.meta.revision
                    && status.phase == AuthorityMaintenancePhase::Completed
                    && status.command.action == expected
                    && status.progress_revision == revision,
                "verifier enrollment outcome or position differs"
            );
            if let Some((_, freeze_revision)) = frozen_roster {
                ensure!(
                    revision < freeze_revision,
                    "verifier admitted after rotation freeze"
                );
            }
            Self::hash_roster_record(
                key.as_bytes(),
                record,
                &mut hash,
                &mut enrollments,
                &mut controls,
            )
        })?;
        ensure!(
            enrollments == snapshot.meta.signer_verifiers
                && controls == snapshot.meta.signer_controls
                && frozen_count == snapshot.meta.signer_rosters,
            "snapshot signer enrollment counts differ"
        );
        if let Some((roster, _)) = frozen_roster {
            for member in snapshot.meta.operational.membership.members.values() {
                require(&member.verifier)?;
            }
            for incarnation in self.installation.manifest.lifecycle_controls.keys() {
                ensure!(
                    snapshot.records.contains_key(&control_key(*incarnation))?,
                    "frozen snapshot omits installed Control coverage"
                );
            }
            ensure!(
                *roster
                    == SignerVerifierRoster {
                        enrollment_count: enrollments,
                        control_count: controls,
                        sha256: hex::encode(hash.finalize())
                    },
                "frozen verifier roster digest or counts differ"
            );
        }
        Ok(())
    }
    pub(super) fn validate_roster_history(&self, snapshot: &Snapshot) -> Result<()> {
        self.store.visit(NS, MAX_RECORD_BYTES, |key, bytes| {
            if key.starts_with(b"signer-verifier/")
                || key.starts_with(b"signer-control/")
                || key.starts_with(b"signer-roster/")
            {
                ensure!(
                    snapshot
                        .records
                        .get(std::str::from_utf8(key)?)?
                        .as_ref()
                        .map(serde_json::to_vec)
                        .transpose()?
                        .as_deref()
                        == Some(bytes),
                    "permanent physical verifier identity cannot be removed or substituted"
                );
            }
            Ok(())
        })
    }
}
