from pathlib import Path
p=Path('target/installed-disk-validation/directory-fixed-maps/proposed/crates/kasumi-store/src')
f=p/'node_disk/ledger.rs';s=f.read_text();s+='''
/// Retained physical capacity and the smaller census logical cardinality.
pub(super) fn map_limits(config: &super::NodeDiskConfig) -> std::io::Result<(usize, usize)> {
    let roots = u64::try_from(config.roots.len()).map_err(|_| crate::disk_memory::overflow())?;
    let (retained, census) = capacities(config.max_census_entries, roots).ok_or_else(crate::disk_memory::overflow)?;
    Ok((usize::try_from(retained).map_err(|_| crate::disk_memory::overflow())?,
        usize::try_from(census).map_err(|_| crate::disk_memory::overflow())?))
}
''';f.write_text(s)
f=p/'node_disk/census.rs';s=f.read_text().replace('collections::{BTreeMap, HashMap}', 'collections::BTreeMap');s=s.replace('    pub(super) accounted: HashMap<Identity, AccountedInode>,\n','');needle='pub(super) fn census(';s=s.replace(needle,'''struct Scan<'a> {
    counters: Totals,
    accounted: &'a mut super::fixed_map::Map<AccountedInode>,
}
impl std::ops::Deref for Scan<'_> {
    type Target = Totals;
    fn deref(&self) -> &Totals { &self.counters }
}
impl std::ops::DerefMut for Scan<'_> {
    fn deref_mut(&mut self) -> &mut Totals { &mut self.counters }
}

'''+needle)
s=s.replace('''    cancel: &CensusCancellation,
) -> Result<Totals> {
    let mut totals = Totals::default();''','''    cancel: &CensusCancellation,
    accounted: &mut super::fixed_map::Map<AccountedInode>,
) -> Result<Totals> {
    let mut totals = Scan { counters: Totals::default(), accounted };''')
s=s.replace('    Ok(totals)\n}', '    Ok(totals.counters)\n}')
s=s.replace('totals: &mut Totals,',"totals: &mut Scan<'_>,").replace('totals: &Totals,',"totals: &Scan<'_>,")
f.write_text(s)
f=p/'node_disk.rs';s=f.read_text().replace('collections::{BTreeMap, HashMap}', 'collections::BTreeMap').replace('mod file;','mod file;\nmod fixed_map;')
s=s.replace('live: HashMap<Identity, Weak<file::FileOwner>>', 'live: fixed_map::Banks<Weak<file::FileOwner>>').replace('accounted: HashMap<Identity, AccountedInode>', 'accounted: fixed_map::Banks<AccountedInode>')
s=s.replace('''        let totals = census(&roots, config, unit, cancel)?;
        cancel.check()?;''','''        let (retained_limit, census_limit) = ledger::map_limits(config)?;
        let mut accounted = fixed_map::Banks::new(retained_limit)?;
        let totals = census(&roots, config, unit, cancel, accounted.stage(census_limit)?)?;
        cancel.check()?;
        accounted.commit_stage();
        let live = fixed_map::Banks::new(usize::try_from(config.max_open_files).map_err(|_| disk_memory::overflow())?)?;''')
s=s.replace('                live: HashMap::new(),\n                accounted: totals.accounted,', '                live,\n                accounted,')
s=s.replace('''        let result = census(&self.roots, &self.config, self.unit, cancel);''','''        let (_, census_limit) = ledger::map_limits(&self.config)?;
        let result = census(&self.roots, &self.config, self.unit, cancel, state.accounted.stage(census_limit)?);''')
s=s.replace('''            Err(error) => {
                state.phase = NodeDiskPhase::Failed;
                self.device.lock().fail_owner();
                return Err(error);
            }
        };
        let mut promises''','''            Err(error) => {
                state.accounted.cancel_stage();
                state.phase = NodeDiskPhase::Failed;
                self.device.lock().fail_owner();
                return Err(error);
            }
        };
        let mut promises''')
s=s.replace('''        else {
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            anyhow::bail!("persistent census promise accounting overflow");''','''        else {
            state.accounted.cancel_stage();
            state.phase = NodeDiskPhase::Failed;
            promises.fail_owner();
            anyhow::bail!("persistent census promise accounting overflow");''')
s=s.replace('''        promises
            .set_pending(next)
            .inspect_err(|_| state.phase = NodeDiskPhase::Failed)?;''','''        if let Err(error) = promises.set_pending(next) {
            state.accounted.cancel_stage();
            state.phase = NodeDiskPhase::Failed;
            return Err(error.into());
        }
        // This is the publication boundary: the complete candidate and shared
        // promises are accepted. Swap fixed backing, then retire old entries.
        state.accounted.commit_stage();''')
s=s.replace('        state.accounted = totals.accounted;\n','')
f.write_text(s)
f=p/'node_disk/memory.rs';s=f.read_text().replace('directory, file, ledger', 'directory, file, fixed_map, ledger')
a=s.index('// Covers a bounded table');b=s.index('impl NodeDisk {',a);s=s[:a]+'''// A fixed HashMap bank has one pinned backing allocation. Keep the existing
// per-allocation platform allowance explicit; requested bytes alone do not
// prove allocator/RSS ownership. Two banks remain resident throughout census.
fn banks<V>(count: usize) -> io::Result<u64> {
    mul(2, add(fixed_map::bank_bytes::<V>(count)?, 4096)?)
}
'''+s[b:]
a=s.index('        // Census visits at most N');b=s.index('        let components',a);s=s[:a]+'''        let (retained, _replacement) = ledger::map_limits(config)?;
        // The inactive retained-capacity bank receives the logically smaller
        // N+R census. It is also the pre-effect tombstone rebuild workspace.
        // No third map and no post-publication expansion allocation exist.
        let ledgers = banks::<AccountedInode>(retained)?;
        let live = banks::<Weak<file::FileOwner>>(usize::try_from(handles).map_err(|_| disk_memory::overflow())?)?;
'''+s[b:]
s=s.replace('or the separate table-growth estimate.', 'or the allocator physical footprint.')
f.write_text(s)
