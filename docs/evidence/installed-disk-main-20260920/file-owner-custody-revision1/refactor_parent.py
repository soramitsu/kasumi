from pathlib import Path
r=Path('target/installed-disk-validation/file-owner-custody-revision1')
p=r/'proposed/crates/kasumi-store/src/node_disk/namespace.rs'
s=p.read_text();base=(r/'base/crates/kasumi-store/src/node_disk/namespace.rs').read_text()
a=base.index('    pub(super) fn verify(');b=base.index('    pub(super) fn file(',a)
oldverify=base[a:b]
s=s.replace('    pub(super) fn verify(&self, root: &census::Root, names: &[CString])', '    pub(super) fn verify_file(&self, root: &census::Root, names: &[CString])')
a=s.index('    pub(super) fn verify_file(')
s=s[:a]+'''    // Existing directory verification remains outside the file-custody successor.
'''+oldverify+s[a:]
s=s.replace('''        let root = disk.roots.get(label).ok_or(io::ErrorKind::InvalidInput)?;
        let walk''','''        let root = disk.roots.get(label).ok_or(io::ErrorKind::InvalidInput)?;
        if let Some(outcome) = &self.close_outcome { return Err(native_file::projection(&outcome.error)); }
        if self.file.is_some() || self.ancestors.len() != names.len().checked_add(1).ok_or(io::ErrorKind::InvalidInput)? {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let walk''')
a=s.index('    pub(super) fn verify_file(');b=s.index('    pub(super) fn close_resources(',a)
f=s[a:b]
f=f.replace('''        let mut walk = self.walk.lock()''','''        if let Some(outcome) = &self.close_outcome { return Err(native_file::projection(&outcome.error)); }
        let file = self.file.as_ref().ok_or(io::ErrorKind::BrokenPipe)?;
        if self.ancestors.len() != names.len().checked_add(1).ok_or(io::ErrorKind::InvalidInput)?
            || self.ancestors.first() != Some(&root.identity) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut walk = self.walk.lock()''')
f=f.replace('self.file().metadata()', 'file.metadata()')
s=s[:a]+f+s[b:]
s=s.replace('''        self.close_outcome.is_some() || walk.failure''','''        self.walk.is_poisoned() || self.close_outcome.is_some() || walk.failure''')
s=s.replace('''    pub(super) fn retire(self) -> Option<Identity> {
        assert!''','''    pub(super) fn retire_drained(self) -> Option<Identity> {
        assert!''')
a=s.index('    pub(super) fn retire_drained(')
s=s[:a]+'''    // Existing directory retirement is unchanged and remains separately unqualified.
    pub(super) fn retire(self) -> Option<Identity> {
        let identity = self.identity;
        let registered = self.registered;
        drop(self);
        registered.then_some(identity)
    }
'''+s[a:]
p.write_text(s)
p=r/'proposed/crates/kasumi-store/src/node_disk/file.rs';s=p.read_text().replace('retained.verify(root, names)','retained.verify_file(root, names)');p.write_text(s)
# Fixed admitted geometry covers original-outcome mutex and both possible parent walks.
p=r/'proposed/crates/kasumi-store/src/node_disk/memory.rs';s=p.read_text();s=s.replace('''                add(NATIVE_HANDLE_WORKSPACE, add(parent_ancestry, add(paths, components)?)?)?,''','''                add(mul(3, NATIVE_HANDLE_WORKSPACE)?, add(parent_ancestry, add(paths, components)?)?)?,''',1);p.write_text(s)
