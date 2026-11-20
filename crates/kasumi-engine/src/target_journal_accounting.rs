//! One interpretation of the installed journal rows for both cold opening and
//! administrative key inventory. Every non-header row belongs to one generation.
use super::*;

#[derive(Default)]
pub(super) struct JournalAccounting {
    intents: u64,
    generations: u64,
    dispatches: u64,
    dispatch_terminals: u64,
    dispatch_starts: u64,
    dispatch_initializes: u64,
    charged: u64,
}

impl JournalAccounting {
    pub(super) fn new() -> Self {
        Self { charged: MAX_RECORD as u64, ..Self::default() }
    }

    pub(super) fn observe(
        &mut self,
        journal: &TargetJournal,
        key: &[u8],
        value: &[u8],
        mut generation: impl FnMut(&GenerationBinding) -> Result<()>,
    ) -> Result<Option<Uuid>> {
            let incarnation = if key.starts_with(b"intent/") {
                self.intents = self.intents.checked_add(1).context("journal count exhausted")?;
                let i: TargetJournalIntent = decode_current(value)?;
                journal.validate_intent(&i)?;
                ensure!(
                    key == intent_key(i.intent.request.command_id),
                    "journal intent key differs"
                );
                self.charged = self.charged
                    .checked_add(value.len() as u64 + COMPLETION_RESERVE)
                    .context("journal bytes exhausted")?;
                i.intent.request.target_incarnation
            } else if key.starts_with(b"generation/") {
                self.generations = self.generations
                    .checked_add(1)
                    .context("journal count exhausted")?;
                let target: GenerationBinding = decode_current(value)?;
                ensure!(
                    journal
                        .installed
                        .audit_placement_bindings
                        .contains_key(&target.tenant),
                    "target generation has no installed audit placement"
                );
                ensure!(
                    key == generation_key(&target.tenant, target.target_incarnation),
                    "journal generation key differs"
                );
                self.charged = self.charged
                    .checked_add(value.len() as u64 + GENERATION_RESERVE)
                    .context("journal bytes exhausted")?;
                generation(&target)?;
                target.target_incarnation
            } else if key.starts_with(b"dispatch/") {
                self.dispatches = self.dispatches
                    .checked_add(1)
                    .context("journal dispatch count exhausted")?;
                let accepted = journal.validate_dispatch_record(key, value)?;
                self.charged = self.charged
                    .checked_add(value.len() as u64 + DISPATCH_TERMINAL_RESERVE)
                    .context("journal dispatch bytes exhausted")?;
                accepted.lifecycle.request.target_incarnation
            } else if key.starts_with(b"file/") {
                let file: FileCreation = decode_current(value)?;
                let intent = journal.validate_file_creation(key, &file)?;
                self.charged = self.charged
                    .checked_add(value.len() as u64)
                    .context("journal file bytes exhausted")?;
                intent.intent.request.target_incarnation
            } else if key.starts_with(b"dispatch-terminal/") {
                self.dispatch_terminals = self.dispatch_terminals
                    .checked_add(1)
                    .context("journal dispatch terminal count exhausted")?;

                // Its original dispatch already self.charged the full bounded
                // terminal reserve; publication never needs more capacity.
                journal.validate_dispatch_terminal(key, value)?.1
            } else if key.starts_with(b"dispatch-start/") {
                self.dispatch_starts = self.dispatch_starts
                    .checked_add(1)
                    .context("journal Start observation count exhausted")?;
                journal.validate_initial_start_record(key, value)?.prebind.target_incarnation
            } else if key.starts_with(b"dispatch-initialize/") {
                self.dispatch_initializes = self.dispatch_initializes
                    .checked_add(1)
                    .context("journal Initialize association count exhausted")?;
                journal.validate_initial_initialize_record(key, value)?.target_incarnation()
            } else if key.starts_with(b"serving/") {
                journal.decode_serving_candidate(key, value)?.incarnation
            } else if key.starts_with(b"activation/") {
                journal.decode_projection_record(key, value)?.intent.intent.request.target_incarnation
            } else if key.starts_with(b"binding/") {
                let binding: TargetFileBinding = decode_current(value)?;
                journal.validate_binding(&binding)?;
                ensure!(
                    key == binding_key(&binding.tenant, binding.target_incarnation),
                    "journal file binding key differs"
                );
                self.charged = self.charged
                    .checked_add(value.len() as u64)
                    .context("journal binding bytes exhausted")?;
                binding.target_incarnation
            } else if key.starts_with(b"cleanup/") {
                let cleanup: TargetCleanup = decode_current(value)?;
                journal.validate_cleanup(&cleanup)?;
                ensure!(
                    key == cleanup_key(&cleanup.tenant, cleanup.target_incarnation)
                        && value.len() <= CLEANUP_RESERVE,
                    "journal cleanup key differs"
                );
                self.charged = self.charged
                    .checked_add(CLEANUP_RESERVE as u64)
                    .context("journal cleanup bytes exhausted")?;
                cleanup.target_incarnation
            } else if key.starts_with(b"stop/") {
                let stop: TargetJournalStop = decode_current(value)?;
                journal.validate_stop(&stop)?;
                ensure!(
                    key == stop_key(
                        &stop.intent.intent.request.tenant,
                        stop.intent.intent.request.target_incarnation
                    ),
                    "journal stop key differs"
                );
                stop.intent.intent.request.target_incarnation
            } else {
                ensure!(key == b"metadata", "unknown target journal record");
                return Ok(None);
            };
            Ok(Some(incarnation))
    }

    pub(super) fn verify(&self, metadata: &Metadata) -> Result<()> {
        ensure!(
            metadata.intents == self.intents
                && metadata.generations == self.generations
                && metadata.dispatches == self.dispatches
                && metadata.dispatch_terminals == self.dispatch_terminals
                && metadata.dispatch_starts == self.dispatch_starts
                && metadata.dispatch_initializes == self.dispatch_initializes
                && metadata.charged_bytes == self.charged,
            "target journal accounting differs"
        );
        Ok(())
    }
}
