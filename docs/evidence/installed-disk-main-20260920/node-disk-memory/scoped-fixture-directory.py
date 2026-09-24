from pathlib import Path
import re
root=Path(__file__).parent/'proposed/crates/kasumi-store'
p=root/'src/scratch_disk.rs';s=p.read_text()
s=s.replace('''    #[cfg(any(test, feature = "test-utils"))]
    _fixture: Option<Arc<tempfile::TempDir>>,
''','')
s=s.replace('''        Self::open_inner(
            config,
            memory,
            DeviceSelection::Installed,
            #[cfg(any(test, feature = "test-utils"))]
            None,
        )''','''        Self::open_inner(config, memory, DeviceSelection::Installed)''')
s=s.replace('Self::open_inner(config, memory, DeviceSelection::Isolated, None)','Self::open_inner(config, memory, DeviceSelection::Isolated)')
s=s.replace('''        #[cfg(any(test, feature = "test-utils"))] fixture: Option<Arc<tempfile::TempDir>>,
''','')
s=s.replace('''            #[cfg(any(test, feature = "test-utils"))]
            _fixture: fixture,
''','')
a=s.index('    #[cfg(any(test, feature = "test-utils"))]\n    pub fn fixture(');b=s.index('    #[cfg(test)]\n    pub(crate) fn test_with_device',a)
s=s[:a]+'''    /// Trusted fixture setup must retain the enclosing private directory for
    /// the full fixture scope. The installed owner never owns a TempDir cleanup.
    #[cfg(any(test, feature = "test-utils"))]
    pub fn fixture(
        directory: impl AsRef<std::path::Path>,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Arc<Self> {
        let config = ScratchDiskConfig {
            directory: directory.as_ref().to_owned(),
            max_bytes: 256 << 30,
            min_free_bytes: 0,
        };
        crate::test_utils::retry_disk_registry(|| Self::open_fixture(&config, memory.clone()))
            .expect("fixture scratch governor")
    }
    #[cfg(test)]
    pub(crate) fn isolated_fixture(
        directory: impl AsRef<std::path::Path>,
        max_bytes: u64,
        memory: Arc<dyn NodeDiskMemoryAdmission>,
    ) -> Arc<Self> {
        let config = ScratchDiskConfig {
            directory: directory.as_ref().to_owned(),
            max_bytes,
            min_free_bytes: 0,
        };
        crate::test_utils::retry_disk_registry(|| Self::open_fixture(&config, memory.clone()))
            .expect("isolated scratch governor")
    }
''' +s[b:]
s=s.replace('Self::open_inner(&config, memory, DeviceSelection::Existing(device), None)','Self::open_inner(&config, memory, DeviceSelection::Existing(device))')
s=s.replace('fn disk(max_bytes: u64, min_free_bytes: u64)', 'fn disk(directory: &std::path::Path, max_bytes: u64, min_free_bytes: u64)')
s=s.replace('        let directory = Arc::new(tempfile::tempdir().unwrap());\n','')
s=s.replace('directory: directory.path().join("scratch"),\n            max_bytes,','directory: directory.to_owned(),\n            max_bytes,')
s=s.replace('''                DeviceSelection::Isolated,
                Some(directory.clone()),''','''                DeviceSelection::Isolated,''')
s=re.sub(r'(?m)^(        let \w+ = )disk\(([^\n]+)\);',r'        let fixture_directory = crate::test_utils::private_tempdir().unwrap();\n\1disk(fixture_directory.path(), \2);',s)
p.write_text(s)
for p in root.rglob('*.rs'):
 if p.name=='scratch_disk.rs':continue
 s=p.read_text(); prefix='kasumi_store::' if str(p.relative_to(root)).startswith('tests/') else 'crate::'
 # Every generic fixture construction from the previous revision is now a
 # caller-owned local (or a retained Fixture field, handled below).
 s=re.sub(r'(?m)^(\s*)let fixture_scratch = ((?:crate::|kasumi_store::)?ScratchDisk)::fixture\(fixture_memory.clone\(\)\);',lambda m: m[1]+'let scratch_directory = '+prefix+'test_utils::private_tempdir().unwrap();\n'+m[1].split('\n')[-1]+'let fixture_scratch = '+m[2]+'::fixture(scratch_directory.path(), fixture_memory.clone());',s)
 # Deliberately foreign-core negative regression still has its own directory.
 s=s.replace('let scratch = crate::ScratchDisk::fixture(other_memory.clone());','let scratch_directory = crate::test_utils::private_tempdir().unwrap();\n    let scratch = crate::ScratchDisk::fixture(scratch_directory.path(), other_memory.clone());')
 if 'ScratchDisk::isolated_fixture(' in s:
  # Existing callers have one constrained scratch owner per test.
  s=re.sub(r'(?m)^(\s*)let fixture_memory = ([^;]+);',lambda m:m[0]+'\n'+m[1].split('\n')[-1]+'let scratch_directory = crate::test_utils::private_tempdir().unwrap();',s)
  s=s.replace('ScratchDisk::isolated_fixture(', 'ScratchDisk::isolated_fixture(scratch_directory.path(), ')
 if p.name=='live_trust_tests.rs':
  s=s.replace('    signers: Vec<GenerationSigner>,\n}', '    signers: Vec<GenerationSigner>,\n    scratch_directory: tempfile::TempDir,\n}')
  s=s.replace('            signers,\n        }','            signers,\n            scratch_directory,\n        }')
  s=s.replace('''        administrator,
        ..
    } = f;''','''        administrator,
        scratch_directory: _scratch_directory,
        ..
    } = f;''')
 if str(p.relative_to(root))=='src/storage_domains/existing_catalogs/tests.rs':
  s=s.replace('    node: Arc<NodeStore>,\n}', '    node: Arc<NodeStore>,\n    scratch_directory: tempfile::TempDir,\n}')
  s=s.replace('Ok(Self { directory, node })','Ok(Self { directory, node, scratch_directory })')
  s=s.replace('let Fixture { directory, node } =', 'let Fixture { directory, node, scratch_directory: _scratch_directory } =')
 p.write_text(s)
