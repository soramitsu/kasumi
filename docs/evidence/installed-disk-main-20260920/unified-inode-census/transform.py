from pathlib import Path
p=Path(__file__).resolve().parent/'proposed'
def edit(rel, replacements):
 f=p/rel;s=f.read_text()
 for a,b in replacements:
  assert a in s,(rel,a)
  s=s.replace(a,b)
 f.write_text(s)
node='crates/kasumi-store/src/node_disk.rs'
edit(node,[('mod file;\n','mod file;\nmod ledger;\n'),('use census::{Root, census, open_roots};','use census::{Root, census, open_roots};\nuse ledger::AccountedInode;'),('    directories: HashMap<Identity, AccountedDirectory>,','    directories: u64,'),('    accounted: HashMap<Identity, AccountedFile>,','    accounted: HashMap<Identity, AccountedInode>,'),('persistent_directories: state.directories.len() as u64,','persistent_directories: state.directories,'),('    /// Bounds census traversal work and retained file-accounting entries.\n    /// An incomplete census never opens admission; new files require a free slot.','    /// Bounds census traversal work and the separately admitted file count.\n    /// Directories also occupy the unified inode ledger. File creation retains\n    /// its full count allowance after census; it does not spend directory slots.\n    /// An incomplete census never opens admission; new files require a free slot.')])
ledger=p/'crates/kasumi-store/src/node_disk/ledger.rs'
ledger.write_text('''//! One physical-inode key space for file and directory enrollment.
//!
//! The retained owner can create up to N files after a census enrolled up to
//! N + R directories. A replacement census visits at most N non-root entries,
//! so its union is bounded by N + R. These different peaks must both be funded.
use super::{AccountedDirectory, AccountedFile, NamespaceBinding};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum AccountedInode {
    File(AccountedFile),
    Directory(AccountedDirectory),
}
impl AccountedInode {
    pub(super) fn binding(&self) -> NamespaceBinding {
        match self {
            Self::File(entry) => entry.binding,
            Self::Directory(entry) => entry.binding,
        }
    }
    pub(super) fn file(&self) -> Option<&AccountedFile> {
        match self { Self::File(entry) => Some(entry), Self::Directory(_) => None }
    }
    pub(super) fn file_mut(&mut self) -> Option<&mut AccountedFile> {
        match self { Self::File(entry) => Some(entry), Self::Directory(_) => None }
    }
    pub(super) fn directory(&self) -> Option<&AccountedDirectory> {
        match self { Self::Directory(entry) => Some(entry), Self::File(_) => None }
    }
    pub(super) fn directory_mut(&mut self) -> Option<&mut AccountedDirectory> {
        match self { Self::Directory(entry) => Some(entry), Self::File(_) => None }
    }
}

/// Checked cardinalities, independent of readdir's treatment of dot entries.
/// Do not replace the retained limit by `census`: that reduces file admission
/// when the owner retains directories from an earlier census.
pub(super) fn capacities(entries: u64, roots: u64) -> Option<(u64, u64)> {
    let census = entries.checked_add(roots)?;
    let retained = census.checked_add(entries)?;
    Some((retained, census))
}

#[cfg(test)]
mod tests;
''')
census='crates/kasumi-store/src/node_disk/census.rs'
edit(census,[('    AccountedDirectory, AccountedFile, CensusCancellation, Identity, NamespaceBinding,','    AccountedDirectory, AccountedFile, AccountedInode, CensusCancellation, Identity, NamespaceBinding,'),('pub(super) accounted: HashMap<Identity, AccountedFile>,','pub(super) accounted: HashMap<Identity, AccountedInode>,'),('pub(super) directories: HashMap<Identity, AccountedDirectory>,','pub(super) directories: u64,'),('                .directories\n                .get_mut(&parent)','                .accounted\n                .get_mut(&parent)\n                .and_then(AccountedInode::directory_mut)'),('                            AccountedFile::durable(binding, bytes, pending, verified.len()),','                            AccountedInode::File(AccountedFile::durable(\n                                binding, bytes, pending, verified.len(),\n                            )),')])
f=p/census;s=f.read_text();s=s.replace('        .directories\n        .try_reserve(1)','        .accounted\n        .try_reserve(1)').replace('            .directories\n            .insert(','            .accounted\n            .insert(').replace('                AccountedDirectory {','                AccountedInode::Directory(AccountedDirectory {').replace('                    live_handles: 0,\n                }','                    live_handles: 0,\n                })').replace('        .directories\n        .get(&cursor.identity)','        .accounted\n        .get(&cursor.identity)\n        .and_then(AccountedInode::directory)')
s=s.replace('    totals.bytes = next_bytes;','    totals.directories = totals\n        .directories\n        .checked_add(1)\n        .context("census directory count overflow")?;\n    totals.bytes = next_bytes;')
f.write_text(s)
directory='crates/kasumi-store/src/node_disk/directory.rs'
edit(directory,[('    AccountedDirectory, Identity, NamespaceBinding, NodeDisk, NodeDiskPhase, State, census,','    AccountedDirectory, AccountedInode, Identity, NamespaceBinding, NodeDisk, NodeDiskPhase, State, census,'),('state.directories.get(&identity)','state.accounted.get(&identity).and_then(AccountedInode::directory)'),('                let known = state\n                    .directories\n                    .values()\n                    .any(|entry| entry.binding == binding)\n                    || state\n                        .accounted\n                        .values()\n                        .any(|entry| entry.binding == binding);','                let known = state.accounted.values().any(|entry| entry.binding() == binding);'),('            .directories\n            .get_mut(&identity)','            .accounted\n            .get_mut(&identity)\n            .and_then(AccountedInode::directory_mut)'),('Ok(state.directories[&self.owner().identity].bytes)','Ok(state.accounted[&self.owner().identity].directory().expect("verified directory enrollment").bytes)'),('state.directories.get_mut(&self.identity)','state.accounted.get_mut(&self.identity).and_then(AccountedInode::directory_mut)')])
file='crates/kasumi-store/src/node_disk/file.rs'
edit(file,[('    AccountedFile, DiskWork, Identity, NamespaceBinding, NodeDisk, NodeDiskPhase, State, census,','    AccountedFile, AccountedInode, DiskWork, Identity, NamespaceBinding, NodeDisk, NodeDiskPhase, State, census,'),('                        .values()\n                        .any(|entry| entry.binding == self.binding)','                        .values()\n                        .filter_map(AccountedInode::file)\n                        .any(|entry| entry.binding == self.binding)'),('.is_some_and(|entry| entry.binding != self.binding)','.is_some_and(|entry| entry.binding() != self.binding)'),('                AccountedFile {\n                    settled: false,\n                    ..enrolled\n                },','                AccountedInode::File(AccountedFile {\n                    settled: false,\n                    ..enrolled\n                }),'),('                .get_mut(&identity)\n                .expect("new enrolled inode")','                .get_mut(&identity)\n                .and_then(AccountedInode::file_mut)\n                .expect("new enrolled inode")'),('self.state.accounted.get(&identity) != Some(&enrolled)','self.state.accounted.get(&identity).and_then(AccountedInode::file) != Some(&enrolled)'),('                .get_mut(&owner.identity)\n                .expect("validated publication enrollment")','                .get_mut(&owner.identity)\n                .and_then(AccountedInode::file_mut)\n                .expect("validated publication enrollment")'),('state.accounted.len() as u64 >= self.config.max_census_entries','state.files >= self.config.max_census_entries'),('                                        .get_mut(&owner.identity)\n                                        .expect("validated reclaimed inode")','                                        .get_mut(&owner.identity)\n                                        .and_then(AccountedInode::file_mut)\n                                        .expect("validated reclaimed inode")'),('        .iter()\n        .find(|(_, entry)| entry.binding == binding)','        .iter()\n        .filter_map(|(identity, entry)| entry.file().map(|file| (identity, file)))\n        .find(|(_, entry)| entry.binding == binding)'),('state.accounted.get(&self.identity) != Some(&budget.accounted(self.binding))','state.accounted.get(&self.identity).and_then(AccountedInode::file) != Some(&budget.accounted(self.binding))'),('            .get_mut(&self.identity)\n            .expect("validated enrolled inode")','            .get_mut(&self.identity)\n            .and_then(AccountedInode::file_mut)\n            .expect("validated enrolled inode")'),('state.accounted.get_mut(&self.identity) {','state.accounted.get_mut(&self.identity).and_then(AccountedInode::file_mut) {')])
