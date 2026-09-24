from pathlib import Path
p=Path('target/installed-disk-validation/directory-managed-namespace/proposed/crates/kasumi-store/src/node_disk')
f=p/'namespace.rs';s=f.read_text()
s=s.replace('    pub(super) fn ancestors(&self) -> &[Identity] {\n        &self.ancestors\n    }\n','')
pos=s.index('    /// Move the scalar registration')
s=s[:pos]+'''    pub(super) fn take_descriptor(&mut self) -> Option<File> {
        self.file.take()
    }
''' +s[pos:]
# Preserve current live-handle counts when a new directory's parent registration
# is acquired after the preflight snapshot but before the namespace effect.
s=s.replace('''            *state
                .accounted
                .get_mut(&change.identity)
                .and_then(AccountedInode::directory_mut)
                .expect("prepared parent") = change.before;''','''            let entry = state.accounted.get_mut(&change.identity)
                .and_then(AccountedInode::directory_mut).expect("prepared parent");
            *entry = AccountedDirectory { live_handles: entry.live_handles, ..change.before };''')
start=s.index('        let mut updated = [None, None];',s.index('pub(super) fn settle('))
s=s[:start]+'''        let mut observations = [None, None];
        for (slot, change) in observations.iter_mut().zip(self.changes.iter()) {
            let Some(change) = change else { continue };
            let parent = parents.iter().find(|parent| parent.identity == change.identity)
                .ok_or(io::ErrorKind::InvalidData)?;
            *slot = Some((change.identity, parent.file().metadata()?));
        }
        self.settle_observed(disk, state, observations)
    }

    /// The observations are taken from the operation's retained descriptors
    /// under the same State guard. This separates borrows without taking the
    /// unresolved operation out of its custody slot during fallible work.
    pub(super) fn settle_observed(
        self,
        disk: &NodeDisk,
        state: &mut State,
        observations: [Option<(Identity, std::fs::Metadata)>; 2],
    ) -> io::Result<()> {
''' +s[start:]
start=s.index('            let parent = parents',s.index('pub(super) fn settle_observed'))
end=s.index('            census::directory_nonallocating(&metadata)?;',start)
s=s[:start]+'''            let (_, metadata) = observations.iter().flatten()
                .find(|(identity, _)| *identity == change.identity)
                .ok_or(io::ErrorKind::InvalidData)?;
''' +s[end:]
s=s.replace('''            *state
                .accounted
                .get_mut(&identity)
                .and_then(AccountedInode::directory_mut)
                .expect("prepared parent") = entry;''','''            let current = state.accounted.get_mut(&identity)
                .and_then(AccountedInode::directory_mut).expect("prepared parent");
            *current = AccountedDirectory { live_handles: current.live_handles, ..entry };''')
f.write_text(s)
f=p.parent/'node_disk.rs';s=f.read_text().replace('    namespace_generation: u64,','    namespace_generation: u64,\n    pending_directory: Option<directory::PendingDirectory>,')
s=s.replace('                namespace_generation: 0,','                namespace_generation: 0,\n                pending_directory: None,')
s=s.replace('    NodeDiskDirectoryEntry, NodeDiskEntryKind,','    NodeDiskDirectoryEntry, NodeDiskEntryKind, NodeDiskDirectoryOperation,\n    NodeDiskDirectoryOperationKind, NodeDiskDirectoryOperationStep, NodeDiskDirectoryFailure,')
start=s.index('    pub fn reconcile(')
pos=s.index('        ensure!(\n            state.open_files',start)
end=s.index('        let (_, census_limit)',pos)
s=s[:pos]+'''        let internal_directories = u32::from(state.pending_directory.is_some());
        ensure!(
            state.open_files == 0
                && state.open_directories == internal_directories
                && state.open_directory_cursors == 0
                && state.census_streams.outstanding() == 0,
            "persistent file or directory owners are still live"
        );
        if let Some(operation) = &mut state.pending_directory {
            if let Err(error) = operation.close_resources() {
                self.fail_locked(&mut state);
                return Err(error.into());
            }
        }
''' +s[end:]
s=s.replace('''        state.live.clear();
        state.phase = NodeDiskPhase::Open;''','''        state.live.clear();
        // The candidate has accepted physical absence/presence after every
        // internal FD closed. Retire retained names, ancestry and Arc backing
        // before publishing the operational slot as available again.
        drop(state.pending_directory.take());
        state.open_directories = 0;
        state.phase = NodeDiskPhase::Open;''')
pos=s.index('    pub(crate) fn fail(&self)')
s=s[:pos]+'''    /// Original namespace failure and any independent native close failure.
    pub fn pending_directory_operation(&self) -> Option<NodeDiskDirectoryOperation> {
        self.lock_state().pending_directory.as_ref().map(|operation| operation.observed())
    }

''' +s[pos:];f.write_text(s)
f=p/'directory.rs';s=f.read_text().replace('pub use managed::{NodeDiskDirectoryOperation, NodeDiskDirectoryOperationKind, NodeDiskDirectoryOperationStep};','pub use managed::{NodeDiskDirectoryOperation, NodeDiskDirectoryOperationKind, NodeDiskDirectoryOperationStep, NodeDiskDirectoryFailure};\npub(super) use managed::PendingDirectory;')
f.write_text(s)
