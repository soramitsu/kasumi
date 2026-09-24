from pathlib import Path
import re
pkg=Path(__file__).resolve().parent; root=Path.cwd();p=pkg/'proposed'
def get(rel):
 f=p/rel
 if not f.exists():
  for kind in ['base','proposed']:
   out=pkg/kind/rel;out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes((root/rel).read_bytes())
 return f
# Validated policy construction for operators, without a default.
f=get('crates/kasumi-store/src/node_disk.rs');s=f.read_text();s=s.replace('impl DirectoryPolicy {\n','''impl DirectoryPolicy {
    pub fn new(extent_bytes: u64, max_entries: u64) -> Result<Self> {
        let policy = Self { extent_bytes, max_entries };
        policy.validate()?;
        Ok(policy)
    }
''',1);f.write_text(s)
f=get('crates/kasumi-server/src/persistent_disk.rs');s=f.read_text();a='pub(crate) fn initial_config(roots: BTreeMap<String, PathBuf>) -> NodeDiskConfig {\n    NodeDiskConfig {';b='''pub(crate) fn initial_config(roots: BTreeMap<String, PathBuf>, directory_policy: kasumi_store::DirectoryPolicy) -> Result<NodeDiskConfig> {
    directory_policy.validate()?;
    Ok(NodeDiskConfig {''';assert a in s;s=s.replace(a,b);s=s.replace('        max_open_directories: 4096,','        max_open_directories: 4096,\n        directory_policy,')
start=s.index('pub(crate) fn initial_config(');end=s.index('\n}\n',start);section=s[start:end];assert section.endswith('    }');s=s[:start]+section[:-5]+'    })'+s[end:]
a='let mut config = initial_config(BTreeMap::from([("fixture".into(), root.to_path_buf())]));';b='let mut config = initial_config(BTreeMap::from([("fixture".into(), root.to_path_buf())]), kasumi_store::DirectoryPolicy::fixture()).unwrap();';assert a in s;s=s.replace(a,b);f.write_text(s)
f=get('crates/kasumi-server/src/runtime.rs');s=f.read_text();s=s.replace('pub fn example_config() -> RuntimeConfig {','pub fn example_config(directory_policy: kasumi_store::DirectoryPolicy) -> Result<RuntimeConfig> {\n    directory_policy.validate()?;',1)
start=s.index('pub fn example_config(');end=s.index('\n}\n',start);section=s[start:end];section=section.replace('    RuntimeConfig {','    Ok(RuntimeConfig {',1).replace('        ])),\n        scratch_disk:', '        ]), directory_policy)?,\n        scratch_disk:',1);assert section.endswith('    }');section=section[:-5]+'    })';s=s[:start]+section+s[end:];f.write_text(s)
f=get('crates/kasumi-server/src/runtime_memory.rs');s=f.read_text();s=s.replace('Self::fixture_disk_profile(crate::persistent_disk::initial_config(roots))','Self::fixture_disk_profile(crate::persistent_disk::initial_config(roots, kasumi_store::DirectoryPolicy::fixture()).unwrap())')
a='''        &self,
        roots: BTreeMap<String, PathBuf>,
    ) -> NodeDiskConfig {
        let config = crate::persistent_disk::initial_config(roots);
        match self.factory {''';b='''        &self,
        roots: BTreeMap<String, PathBuf>,
        directory_policy: kasumi_store::DirectoryPolicy,
    ) -> Result<NodeDiskConfig> {
        let config = crate::persistent_disk::initial_config(roots, directory_policy)?;
        Ok(match self.factory {''';assert a in s;s=s.replace(a,b);a='''            DiskFactory::IsolatedFixture => Self::fixture_disk_profile(config),
        }
    }
}''';b='''            DiskFactory::IsolatedFixture => Self::fixture_disk_profile(config),
        })
    }
}''';assert a in s;s=s.replace(a,b);f.write_text(s)
f=get('crates/kasumi-server/src/standalone.rs');s=f.read_text();s=s.replace('pub async fn initialize(directory: &Path, tenant: &str) -> Result<InitializedInstallation> {\n    let storage = crate::runtime_memory::RuntimeStorage::installed(&example_config().admission)?;\n    initialize_with_storage(directory, tenant, storage).await','pub async fn initialize(directory: &Path, tenant: &str, directory_policy: kasumi_store::DirectoryPolicy) -> Result<InitializedInstallation> {\n    let storage = crate::runtime_memory::RuntimeStorage::installed(&example_config(directory_policy)?.admission)?;\n    initialize_with_storage(directory, tenant, directory_policy, storage).await')
s=s.replace('''    tenant: &str,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<InitializedInstallation> {''','''    tenant: &str,
    directory_policy: kasumi_store::DirectoryPolicy,
    storage: crate::runtime_memory::RuntimeStorage,
) -> Result<InitializedInstallation> {
    directory_policy.validate()?;''',1)
s=s.replace('''            &tenant,
            InitializationOptions::default(),''','''            &tenant,
            directory_policy,
            InitializationOptions::default(),''',1)
s=s.replace('''    tenant: &str,
    options: InitializationOptions,''','''    tenant: &str,
    directory_policy: kasumi_store::DirectoryPolicy,
    options: InitializationOptions,''',1)
s=s.replace('    let mut config = example_config();','    let mut config = example_config(directory_policy)?;',1)
a='''    let persistent_config = storage.new_installation_disk_config(BTreeMap::from([
        ("data".into(), data.clone()),
        ("backups".into(), directory.join("backups")),
    ]));''';b='''    let persistent_config = storage.new_installation_disk_config(BTreeMap::from([
        ("data".into(), data.clone()),
        ("backups".into(), directory.join("backups")),
    ]), directory_policy)?;''';assert a in s;s=s.replace(a,b);f.write_text(s)
# Every remaining no-argument example-config caller in server source is a fixture.
# Production generator/initializer and daemon CLI are migrated explicitly above/below.
for original in (root/'crates/kasumi-server/src').rglob('*.rs'):
 rel=str(original.relative_to(root))
 if rel.endswith('/bin/kasumid.rs'):continue
 source=(p/rel).read_text() if (p/rel).exists() else original.read_text()
 if 'example_config()' not in source:continue
 f=get(rel);source=f.read_text();source=source.replace('example_config()', 'example_config(kasumi_store::DirectoryPolicy::fixture()).unwrap()');f.write_text(source)
# Direct standalone fixtures pass their explicit bounded policy along with storage.
for rel in ['crates/kasumi-server/src/runtime_storage_fixtures.rs','crates/kasumi-server/src/standalone_operator_tests.rs','crates/kasumi-server/src/standalone_provision_tests.rs']:
 f=get(rel);s=f.read_text()
 # Insert a third argument after each two leading expressions. These calls use
 # simple directory/tenant values; retain all other arguments/options exactly.
 s,n=re.subn(r'(initialize_with_storage\(\s*(?:&directory|directory),\s*(?:"documents"|tenant),)(\s*)',r'\1\2kasumi_store::DirectoryPolicy::fixture(), ',s)
 if 'initialize_owned(' in s:
  s,n2=re.subn(r'(initialize_owned\(\s*&directory,\s*"documents",)(\s*)',r'\1\2kasumi_store::DirectoryPolicy::fixture(), ',s)
 f.write_text(s)
# Required bounded policy file for both CLI generators; no guessed scalar values.
f=get('crates/kasumi-server/src/standalone_cli.rs');s=f.read_text();s += '''
/// Load the caller's explicit namespace bounds before any installation work.
/// Numeric validity does not replace qualification of the selected filesystem.
pub fn directory_policy(path: &Path) -> Result<kasumi_store::DirectoryPolicy> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?.take(4097).read_to_end(&mut bytes)?;
    anyhow::ensure!(bytes.len() <= 4096, "directory policy exceeds size limit");
    let policy: kasumi_store::DirectoryPolicy = serde_json::from_slice(&bytes)?;
    policy.validate()?;
    Ok(policy)
}
'''
a='''        [command, mode_flag, mode, directory]
            if command == "init" && mode_flag == "--mode" && mode == "standalone" =>''';b='''        [command, mode_flag, mode, directory, policy_flag, policy]
            if command == "init" && mode_flag == "--mode" && mode == "standalone" && policy_flag == "--directory-policy" =>''';assert a in s;s=s.replace(a,b,1)
s=s.replace('initialize(Path::new(directory), "default").await?', 'initialize(Path::new(directory), "default", directory_policy(Path::new(policy))?).await?',1)
a='''        [command, mode_flag, mode, directory, tenant_flag, tenant]
            if command == "init"''';b='''        [command, mode_flag, mode, directory, policy_flag, policy, tenant_flag, tenant]
            if command == "init"''';assert a in s;s=s.replace(a,b,1)
s=s.replace('''                && mode == "standalone"
                && tenant_flag == "--tenant" =>''','''                && mode == "standalone"
                && policy_flag == "--directory-policy"
                && tenant_flag == "--tenant" =>''',1)
s=s.replace('initialize(Path::new(directory), tenant).await?', 'initialize(Path::new(directory), tenant, directory_policy(Path::new(policy))?).await?',1);f.write_text(s)
f=get('crates/kasumi-server/src/bin/kasumid.rs');s=f.read_text();s=s.replace('[command] if command == "example-config" => {\n            println!("{}", serde_json::to_string_pretty(&example_config())?);', '[command, policy_flag, policy] if command == "example-config" && policy_flag == "--directory-policy" => {\n            let policy = kasumi_server::standalone_cli::directory_policy(std::path::Path::new(policy))?;\n            println!("{}", serde_json::to_string_pretty(&example_config(policy)?)?);')
s=s.replace('standalone <absolute-directory> [--tenant name]', 'standalone <absolute-directory> --directory-policy <policy.json> [--tenant name]').replace(' | example-config |',' | example-config --directory-policy <policy.json> |');f.write_text(s)
