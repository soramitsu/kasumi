from pathlib import Path
import hashlib,json,os,sys
ROOT=Path('/Users/mtakemiya/dev/kasumi');P=ROOT/'target/installed-disk-validation/disk-memory-lease-retirement';D=P/'standalone-01';D.mkdir(exist_ok=False)
sys.path.insert(0,str(ROOT/'scripts'))
import gate_process
from release_gate import sha256,write_json
S=P/'proposed/crates/kasumi-store/src'
text=(S/'disk_memory.rs').read_text()
start=text.index('/// Implementations retain')
stop=text.index('/// Registry contention')
helpers_start=text.index('pub(crate) type Lease')
helpers_stop=text.index('/// No global Vec')
fixture=(S/'test_utils.rs').read_text()
fixture_start=fixture.index('/// Explicit bounded memory owner')
fixture_stop=fixture.index('\nimpl crate::NodeStore')
(D/'lease-extracted.rs').write_text('use std::{io, sync::Arc};\n'+text[start:stop]+text[helpers_start:helpers_stop]+'\n#[cfg(test)]\n#[path = '+json.dumps(str(S/'disk_memory_tests.rs'))+']\nmod tests;\n')
(D/'provider-extracted.rs').write_text(fixture[fixture_start:fixture_stop])
(D/'harness.rs').write_text('#[path = '+json.dumps(str(S/'allocation_tests.rs'))+']\nmod allocation_tests;\n#[path = "lease-extracted.rs"]\nmod disk_memory;\npub use disk_memory::{DiskMemoryLease,NodeDiskMemoryAdmission};\n#[path = "provider-extracted.rs"]\nmod test_utils;\n')
write_json(D/'extraction.json',{'scope':'Literal reviewed production lease, fixture provider, allocator observer and three proposed tests; no full store/engine/workspace build, no Cargo.',
 'lease':{'path':str(S/'disk_memory.rs'),'sha256':sha256(S/'disk_memory.rs'),'selection':['Implementations retain ... Registry contention','type Lease ... No global Vec']},
 'fixture':{'path':str(S/'test_utils.rs'),'sha256':sha256(S/'test_utils.rs'),'selection':['Explicit bounded memory owner ... impl crate::NodeStore']},
 'included':{str(S/n):sha256(S/n) for n in ['allocation_tests.rs','disk_memory_tests.rs']}})
inputs={str(f):sha256(f) for f in list(S.glob('*.rs'))+list(D.glob('*.rs'))+[P/'box-order-probe.rs',Path(gate_process.__file__),ROOT/'scripts/release_gate.py',Path(__file__)]}
write_json(D/'source-before.json',inputs)
RUST='/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/rustc'
CLIPPY='/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/clippy-driver'
env=os.environ.copy();env['TMPDIR']=str(ROOT/'target/tmp');env['PYTHONDONTWRITEBYTECODE']='1'
commands=[('probe-debug-compile',[RUST,'--edition=2024',str(P/'box-order-probe.rs'),'-o',str(D/'probe-debug')]),
          ('probe-debug-run',[str(D/'probe-debug')]),
          ('probe-opt-compile',[RUST,'--edition=2024','-O',str(P/'box-order-probe.rs'),'-o',str(D/'probe-opt')]),
          ('probe-opt-run',[str(D/'probe-opt')]),
          ('tests-debug-compile',[RUST,'--edition=2024','--test',str(D/'harness.rs'),'-o',str(D/'tests-debug')]),
          ('tests-debug-run',[str(D/'tests-debug'),'--test-threads=1','--nocapture']),
          ('tests-opt-compile',[RUST,'--edition=2024','-O','--test',str(D/'harness.rs'),'-o',str(D/'tests-opt')]),
          ('tests-opt-run',[str(D/'tests-opt'),'--test-threads=1','--nocapture']),
          ('clippy-box-local',[CLIPPY,'--edition=2024','--test',str(D/'harness.rs'),'-D','clippy::boxed_local','-o',str(D/'tests-clippy')])]
results=[]
for name,command in commands:
 with (D/(name+'.stdout')).open('xb') as out,(D/(name+'.stderr')).open('xb') as err:
  result=gate_process.run(command,ROOT,env,out,120,lambda x:write_json(D/(name+'.process.json'),x),stderr=err)
 results.append({'name':name,'result':result})
 if result['exit_code']!=0:break
write_json(D/'results.json',results)
after={name:sha256(name) for name in inputs};write_json(D/'source-after.json',after)
assert after==inputs,'input source changed'
write_json(D/'raw-sha256.json',{str(f.relative_to(D)):sha256(f) for f in D.rglob('*') if f.is_file()})
print(json.dumps({'results':[(x['name'],x['result']['exit_code']) for x in results],'unchanged_source':after==inputs}))
raise SystemExit(0 if all(x['result']['exit_code']==0 for x in results) else 1)
