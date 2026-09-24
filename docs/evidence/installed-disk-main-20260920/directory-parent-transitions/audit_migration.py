from pathlib import Path
import re
r=Path('/Users/mtakemiya/dev/kasumi'); p=r/'target/installed-disk-validation/directory-parent-transitions'
def read(rel):
 q=p/'proposed'/rel
 if not q.exists():
  for side in ('base','proposed'):
   t=p/side/rel;t.parent.mkdir(parents=True,exist_ok=True);t.write_bytes((r/rel).read_bytes())
 return q,q.read_text()
def change(rel, old,new):
 q,s=read(rel);assert old in s,(rel,old);q.write_text(s.replace(old,new))
change('crates/kasumi-server/src/standalone_tests.rs','initialize_with_storage(&root.path().join("kasumi"), "tenant-a", storage.clone())','initialize_with_storage(&root.path().join("kasumi"), "tenant-a", kasumi_store::DirectoryPolicy::fixture(), storage.clone())')
change('crates/kasumi-bench/Cargo.toml','loopback-fixture = ["network",','loopback-fixture = ["network", "dep:kasumi-store", "kasumi-store/test-utils",')
change('crates/kasumi-bench/src/bin/loopback.rs','let mut config = example_config();','let mut config = example_config(kasumi_store::DirectoryPolicy::fixture())?;')
for rel in ('docs/standalone.md','docs/release-artifacts.md','docs/operations.md','docs/administration.md'):
 q,s=read(rel)
 s=s.replace('kasumid init --mode standalone /var/lib/kasumi --tenant default','kasumid init --mode standalone /var/lib/kasumi --directory-policy /etc/kasumi/directory-policy.json --tenant default')
 s=s.replace('kasumid init --mode standalone /var/lib/kasumi/installation','kasumid init --mode standalone /var/lib/kasumi/installation --directory-policy /etc/kasumi/directory-policy.json')
 s=s.replace('kasumid example-config`','kasumid example-config --directory-policy /etc/kasumi/directory-policy.json`')
 s=s.replace('kasumid example-config >','kasumid example-config --directory-policy /etc/kasumi/directory-policy.json >')
 if rel=='docs/standalone.md':
  s += '\nThe required `--directory-policy` file contains exactly `extent_bytes` and `max_entries`, both positive integers. The generated persistent disk configuration retains these explicit values; there is no production default. `extent_bytes` is a per-directory allocated-byte ceiling reserved before managed file namespace effects. `max_entries` limits positive membership changes; deletion retains cleanup access. Supply values qualified for the installed filesystem and supported namespace operations. Numeric validation alone does not establish that qualification. This target proposal has not yet established a supported filesystem growth bound, so production namespace admission remains a release blocker.\n'
 q.write_text(s)
