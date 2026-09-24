from pathlib import Path
r=Path('target/installed-disk-validation/directory-census-session/proposed/crates/kasumi-store/src'); p=r/'node_disk.rs';s=p.read_text()
a=s.index('    /// Bounds census traversal work');b=s.index('    /// Bounds traversal stack',a)
s=s[:a]+'''    /// Independent persistent regular-file cardinality, including closed files.
    pub max_persistent_files: u64,
    /// Persistent subdirectories, excluding the explicitly configured roots.
    pub max_persistent_subdirectories: u64,
    /// Maximum native readdir calls in one retained census step, including
    /// dot entries and EOF. The whole scan bound derives from F + 4D + 3R.
    pub census_work_per_step: u64,
'''+s[b:]
s=s.replace('        ensure!(self.max_census_entries > 0, "census work budget is zero");','''        ensure!(self.max_persistent_files > 0, "persistent file budget is zero");
        ensure!(self.max_persistent_subdirectories > 0, "persistent directory budget is zero");
        ensure!(self.census_work_per_step > 0, "census step budget is zero");
        self.census_work_bound()?;
        ledger::map_limits(self)?;''')
pos=s.index('    /// Resolve only an explicitly installed')
s=s[:pos]+'''    /// A tree with F files, D non-root directories and R configured roots has
    /// F+D child entries, 2(D+R) dot entries and D+R EOF observations. This is
    /// a checked whole-job bound, independent of the scheduling step budget.
    fn census_work_bound(&self) -> io::Result<u64> {
        let roots = u64::try_from(self.roots.len()).map_err(|_| disk_memory::overflow())?;
        self.max_persistent_files
            .checked_add(self.max_persistent_subdirectories.checked_mul(4).ok_or_else(disk_memory::overflow)?)
            .and_then(|n| roots.checked_mul(3).and_then(|r| n.checked_add(r)))
            .ok_or_else(disk_memory::overflow)
    }

'''+s[pos:]
s=s.replace('    pub open_directory_cursors: u32,','    pub open_directory_cursors: u32,\n    pub open_census_streams: u32,\n    pub census_close_errno: Option<i32>,')
s=s.replace('    open_directory_cursors: u32,','    open_directory_cursors: u32,\n    census_streams: census::Streams,')
s=s.replace('                open_directory_cursors: 0,','                open_directory_cursors: 0,\n                census_streams: census::Streams::default(),')
s=s.replace('            open_directory_cursors: state.open_directory_cursors,','            open_directory_cursors: state.open_directory_cursors,\n            open_census_streams: state.census_streams.outstanding(),\n            census_close_errno: state.census_streams.close_errno(),')
s=s.replace('&& snapshot.open_directory_cursors == 0','&& snapshot.open_directory_cursors == 0\n                && snapshot.open_census_streams == 0')
s=s.replace('&& state.open_directory_cursors == 0,','&& state.open_directory_cursors == 0\n                && state.census_streams.outstanding() == 0,')
s=s.replace('one million census entries and 4096 owners','one million files, one million subdirectories and 4096 owners')
s=s.replace('            max_census_entries: 16_384,','            max_persistent_files: 16_384,\n            max_persistent_subdirectories: 16_384,\n            census_work_per_step: 16_384,')
p.write_text(s)
p=r/'node_disk/ledger.rs';s=p.read_text();a=s.index('//! The retained');b=s.index('use super',a)
s=s[:a]+'''//! Both retained banks fund the entire permitted namespace F + D + R. Census
//! work includes dot and EOF observations but never spends logical inode slots.
'''+s[b:]
a=s.index('/// Checked cardinalities');b=s.index('#[cfg(test)]',a)
s=s[:a]+'''/// Retained and replacement banks have the same full logical inode capacity.
pub(super) fn capacities(files: u64, subdirectories: u64, roots: u64) -> Option<(u64, u64)> {
    let capacity = files.checked_add(subdirectories)?.checked_add(roots)?;
    Some((capacity, capacity))
}

'''+s[b:]
s=s.replace('/// Retained physical capacity and the smaller census logical cardinality.','/// Both retained bank capacities, independent of census step work.')
s=s.replace('capacities(config.max_census_entries, roots)','capacities(config.max_persistent_files, config.max_persistent_subdirectories, roots)')
p.write_text(s)
p=r/'node_disk/file.rs';s=p.read_text().replace('self.config.max_census_entries','self.config.max_persistent_files');p.write_text(s)
p=r/'node_disk/directory/cursor.rs';s=p.read_text().replace('if self.work > disk.config.max_census_entries {','''// This operational scan visits one enrolled directory. Its complete
                // returned-entry bound is the retained child count plus dots;
                // census_work_per_step is not a lifetime limit for this cursor.
                if self.work > self.expected_children.checked_add(2).ok_or(io::ErrorKind::InvalidData)? {''');p.write_text(s)
p=r/'node_disk/memory.rs';s=p.read_text().replace('''        // The inactive retained-capacity bank receives the logically smaller
        // N+R census. It is also the pre-effect tombstone rebuild workspace.''','''        // Both banks fund the full F+D+R namespace. The inactive bank receives
        // census and is also the pre-effect tombstone rebuild workspace.''');p.write_text(s)
# Migrate internal test literals directly; semantic single-field tests stay tied
# to file capacity except the directory-heavy test handled separately below.
for p in (r/'node_disk').rglob('*.rs'):
 if 'tests' not in p.parts and p.name!='tests.rs': continue
 s=p.read_text()
 import re
 s=re.sub(r'(?m)^(\s*)max_census_entries: ([^,]+),',r'\1max_persistent_files: \2,\n\1max_persistent_subdirectories: \2,\n\1census_work_per_step: \2,',s)
 s=s.replace('.max_census_entries', '.max_persistent_files')
 s=s.replace('cancelled_or_work_exhausted_census_publishes_no_partial_owner','cancelled_or_cardinality_exhausted_census_publishes_no_partial_owner')
 p.write_text(s)
