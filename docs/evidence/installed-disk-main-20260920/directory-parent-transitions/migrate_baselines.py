from pathlib import Path
import re
p=Path('/Users/mtakemiya/dev/kasumi/target/installed-disk-validation/directory-parent-transitions/proposed/crates/kasumi-store/src/node_disk/tests.rs')
s=p.read_text();at=s.index('\n#[test]')
s=s[:at]+'''
// Existing file workloads retain their exact byte budgets. Namespace accounting
// has its own independent assertions in namespace/tests.rs; these helpers add
// the retained directory component to file-specific expected totals.
fn namespace_charge(disk: &NodeDisk) -> u64 {
    disk.lock_state().accounted.values().filter_map(AccountedInode::directory)
        .map(|entry| entry.bytes).sum()
}
fn namespace_pending(disk: &NodeDisk) -> u64 {
    disk.lock_state().accounted.values().filter_map(AccountedInode::directory)
        .map(|entry| entry.pending).sum()
}
'''+s[at:]
pattern=r'(assert_eq!\(\s*(?:disk\.snapshot\(\)|before|charged|snapshot|after)\.charged_bytes,\s*)(\d+\s*<<\s*\d+|0|length\.unwrap_or\(0\))(\s*\);)'
s,n=re.subn(pattern,lambda m:m[1]+'namespace_charge(&disk) + ('+m[2]+')'+m[3],s)
s=re.sub(r'(assert_eq!\(\s*(?:disk\.snapshot\(\)|after)\.pending_bytes,\s*)0(\s*\);)',r'\1namespace_pending(&disk)\2',s)
s=s.replace('config.max_bytes = 3 * unit;', 'config.max_bytes = 3 * unit + config.directory_policy.extent_bytes.max(root.metadata().unwrap().blocks() * 512);')
s=s.replace('let available = 3 * disk.unit;', 'let available = 3 * disk.unit + namespace_pending(&disk);')
s=s.replace('scratch.snapshot().filesystem_pending_bytes, 2 * disk.unit','scratch.snapshot().filesystem_pending_bytes, 2 * disk.unit + namespace_pending(&disk)')
s=s.replace('            if failure == file::ShrinkFailure::Truncate {','            namespace_charge(&disk) + if failure == file::ShrinkFailure::Truncate {')
# At the post-close checkpoint only parent settlement has happened. File credit
# remains retained. Its parent may have materialized/released directory blocks.
a=s.index('fn reclaim_retires_parent_metadata_and_weak_backing_before_releasing_promises()');b=s.index('\n#[test]',a)
part=s[a:b]
part=part.replace('let disk = open(config, memory.clone());','let disk = open(config.clone(), memory.clone());')
part=part.replace('        let before = disk.snapshot();','        let before = disk.snapshot();\n        let old_parent_pending = namespace_pending(&disk);\n        let parent_charge = namespace_charge(&disk);')
part=part.replace('        assert_eq!(*disk.device.lock(), before.filesystem_pending_bytes);','''        let expected_parent_pending = if fail {
            old_parent_pending
        } else {
            parent_charge - config.roots["data"].metadata().unwrap().blocks() * 512
        };
        assert_eq!(*disk.device.lock(), before.filesystem_pending_bytes - old_parent_pending + expected_parent_pending);''')
s=s[:a]+part+s[b:];p.write_text(s);print('migrated file-only literal totals:',n)
