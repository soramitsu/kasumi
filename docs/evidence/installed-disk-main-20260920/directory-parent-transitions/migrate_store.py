from pathlib import Path
p=Path(__file__).resolve().parent/'proposed/crates/kasumi-store/src'
f=p/'node_disk/directory.rs';s=f.read_text();s=s.replace('    if entry.binding != binding','    if !entry.settled\n        || entry.binding != binding').replace('entry.bytes != census::directory_extent(&metadata)?','entry.bytes.checked_sub(entry.pending).ok_or(io::ErrorKind::InvalidData)? != census::directory_extent(&metadata)?')
a=s.index('fn walk(');s=s[:a]+s[a:].replace('fn walk(', 'fn walk_observe(',1)
a='''    absent_final: bool,
) -> Result<File, LookupFailure> {''';b='''    absent_final: bool,
    mut visited: impl FnMut(Identity),
) -> Result<File, LookupFailure> {''';assert a in s;s=s.replace(a,b,1)
s=s.replace('    let (mut parent, _) = checked_entry(state, &current, binding, None)?;','    let (mut parent, _) = checked_entry(state, &current, binding, None)?;\n    visited(parent);').replace('        parent = identity;','        visited(identity);\n        parent = identity;')
pos=s.index('fn names(');s=s[:pos]+'''fn walk(disk: &NodeDisk, state: &State, root: &str, names: &[CString], absent_final: bool) -> Result<File, LookupFailure> {
    walk_observe(disk, state, root, names, absent_final, |_| {})
}

pub(super) fn file_parent(disk: &NodeDisk, state: &State, root: &str, names: &[CString]) -> io::Result<(File, Box<[Identity]>)> {
    let count = names.len().checked_add(1).ok_or(io::ErrorKind::InvalidInput)?;
    let mut ancestors = Vec::new();
    ancestors.try_reserve_exact(count).map_err(|_| io::ErrorKind::OutOfMemory)?;
    let file = walk_observe(disk, state, root, names, false, |identity| ancestors.push(identity)).map_err(|failure| failure.error)?;
    Ok((file, ancestors.into_boxed_slice()))
}

'''+s[pos:]
a='''                .expect("verified directory enrollment")
                .bytes,''';b='''                .expect("verified directory enrollment")
                .bytes
                .checked_sub(state.accounted[&self.owner().identity].directory().expect("verified directory enrollment").pending)
                .ok_or(io::ErrorKind::InvalidData)?,'''
if a in s:s=s.replace(a,b)
else:print('OBSERVED BYTES MANUAL CHECK REQUIRED')
f.write_text(s)
# Census now retains the configured full allowance; existing excess remains charged.
f=p/'node_disk/census.rs';s=f.read_text();s=s.replace('            None,\n        )?;', '            None,\n            config.directory_policy,\n        )?;',1).replace('enroll_directory(&mut totals, &child, binding, Some(parent))?;', 'enroll_directory(&mut totals, &child, binding, Some(parent), config.directory_policy)?;')
s=s.replace('    parent: Option<Identity>,\n) -> Result<()> {', '    parent: Option<Identity>,\n    policy: super::DirectoryPolicy,\n) -> Result<()> {')
s=s.replace('    let bytes = directory_extent(&metadata)?;\n    let next_bytes', '    let observed = directory_extent(&metadata)?;\n    let bytes = policy.extent_bytes.max(observed);\n    let pending = bytes - observed;\n    let next_bytes')
s=s.replace('        .directory_bytes\n        .checked_add(bytes)', '        .directory_bytes\n        .checked_add(observed)')
s=s.replace('                    bytes,\n                    len: metadata.len(),', '                    bytes,\n                    pending,\n                    settled: true,\n                    len: metadata.len(),')
s=s.replace('    totals.bytes = next_bytes;\n    totals.directory_bytes', '    totals.pending = totals.pending.checked_add(pending).context("directory promises overflow")?;\n    totals.bytes = next_bytes;\n    totals.directory_bytes')
s=s.replace('directory_extent(&metadata)? == enrolled.bytes,', 'directory_extent(&metadata)? == enrolled.bytes.checked_sub(enrolled.pending).context("invalid directory promise")?,')
f.write_text(s)
f=p/'node_disk/tests.rs';s=f.read_text();s=s.replace('        max_open_directories: 16,','        max_open_directories: 16,\n        directory_policy: DirectoryPolicy::fixture(),');f.write_text(s)
f=p/'node_disk/ledger/tests.rs';s=f.read_text();s=s.replace('        bytes: 8192,','        bytes: 8192,\n        pending: 0,\n        settled: true,');f.write_text(s)
f=p/'node_disk/file.rs';s=f.read_text();s=s.replace('    extent, rounded,','    extent, namespace::{self, FileParent, ParentTransition}, rounded,')
s=s.replace('    parent: Option<File>,','    parent: Option<FileParent>,\n    // Publication keeps both real descriptors until durability settles. Only\n    // one registration is active, transferred after the old FD actually closes.\n    retiring_parent: Option<FileParent>,\n    retired_parent: Option<Identity>,',1)
s=s.replace('    parent: File,','    parent: FileParent,')
s=s.replace('self.parent.as_raw_fd()', 'self.parent.file().as_raw_fd()')
s=s.replace('census::open_at(&self.parent, &self.name, flags)','census::open_at(self.parent.file(), &self.name, flags)')
s=s.replace('                    &self.parent,\n                    &self.name,','                    self.parent.file(),\n                    &self.name,')
s=s.replace('                &parent,\n                &name,','                parent.file(),\n                &name,')
s=s.replace('                    parent.as_raw_fd(),','                    parent.file().as_raw_fd(),')
s=s.replace('                self.parent.sync_all()', '                self.parent.file().sync_all()')
s=s.replace('                parent: Some(self.parent),','                parent: Some(self.parent),\n                retiring_parent: None,\n                retired_parent: None,')
# Both preparation paths produce an enrolled exact parent and retain its ancestry.
a='''                io::Error::other(error)
            })?;'''
# File preparation has an extra comment; both end with the same conversion.
repl='''                io::Error::other(error)
            })?;
        let raw_parent = parent;
        let parent = FileParent::prepare(self, &state, root, &parent_names).inspect_err(|_| self.fail_locked(&mut state))?;
        if Identity::of(&raw_parent.metadata()?) != parent.identity() {
            self.fail_locked(&mut state);
            return Err(io::ErrorKind::InvalidData.into());
        }
        drop(raw_parent);'''
assert s.count(a)==2;s=s.replace(a,repl)
s=s.replace('        if state.open_files >= self.config.max_open_files {','        if state.open_files >= self.config.max_open_files\n            || state.open_directories >= self.config.max_open_directories {',1)
# Typed accessor keeps all existing private raw-FD consumers under FileOwner custody.
a='''    fn parent(&self) -> &File {
        self.parent.as_ref().expect("live parent descriptor")
    }''';b='''    fn parent(&self) -> &File { self.parent_custody().file() }
    fn parent_custody(&self) -> &FileParent {
        self.parent.as_ref().expect("live parent custody")
    }''';assert a in s;s=s.replace(a,b)
s=s.replace('            self.parent(),\n        )?;', '            self.parent_custody(),\n        )?;',1)
a='''fn verify_parent(root: &census::Root, names: &[CString], retained: &File) -> io::Result<()> {
    root.verify_nonallocating()?;
    let mut current = root.file.try_clone()?;
    for name in names {''';b='''fn verify_parent(root: &census::Root, names: &[CString], retained: &FileParent) -> io::Result<()> {
    root.verify_nonallocating()?;
    if retained.ancestors().len() != names.len() + 1 || retained.ancestors()[0] != root.identity {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut current = root.file.try_clone()?;
    for (index, name) in names.iter().enumerate() {''';assert a in s;s=s.replace(a,b)
s=s.replace('        if metadata.dev() != root.identity.0 {','        if metadata.dev() != root.identity.0 || Identity::of(&metadata) != retained.ancestors()[index + 1] {',1)
s=s.replace('Identity::of(&retained.metadata()?)', 'Identity::of(&retained.file().metadata()?)')
# Resource retirement closes both possible descriptors before their one scalar registration.
s=s.replace('        drop(self.parent.take());','''        for parent in [self.parent.take(), self.retiring_parent.take()].into_iter().flatten() {
            if let Some(identity) = parent.retire() {
                assert!(self.retired_parent.replace(identity).is_none(), "one file parent registration");
            }
        }''',1)
a='''        let Some(next) = state.open_files.checked_sub(1) else {
            return false;
        };''';b='''        let Some(next) = state.open_files.checked_sub(1) else {
            return false;
        };
        let Some(parent) = self.retired_parent else { return false; };
        if !namespace::can_retire_parent(state, parent) { return false; }''';assert a in s;s=s.replace(a,b,1)
s=s.replace('        self.registration = 0;\n        state.open_files = next;', '        self.registration = 0;\n        namespace::retire_parent(state, parent);\n        self.retired_parent = None;\n        state.open_files = next;',1)
f.write_text(s)
