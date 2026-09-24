from pathlib import Path
import subprocess, difflib, hashlib, json
root=Path('/Users/mtakemiya/dev/kasumi')
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
pkg=root/'target/installed-disk-validation/redb-retained-terminal'
paths=['vendor/redb-4.2.0/src/transactions.rs','vendor/redb-4.2.0/src/lib.rs','vendor/redb-4.2.0/src/retained_transaction.rs','vendor/redb-4.2.0/src/retained_transaction_tests.rs']
original={p:(root/p).read_text() if (root/p).exists() else None for p in paths}
for path in paths[:2]:
 content=original[path]
 if path.endswith('/transactions.rs'):
  content='''#[cfg(all(not(redb_no_std), panic = "unwind"))]
#[path = "retained_transaction.rs"]
mod retained_transaction;
#[cfg(all(not(redb_no_std), panic = "unwind"))]
pub use retained_transaction::{
    RetainedWriteTransaction, TerminalObservation, WriteTerminalError, WriteTerminalOperation,
    WriteTerminalReport, WriteTerminalSettlement,
};

'''+content
 else:
  needle='pub use transactions::{DatabaseStats, ReadTransaction, WriteTransaction};\n'
  assert content.count(needle)==1
  content=content.replace(needle,needle+'''#[cfg(all(not(redb_no_std), panic = "unwind"))]
pub use transactions::{
    RetainedWriteTransaction, TerminalObservation, WriteTerminalError, WriteTerminalOperation,
    WriteTerminalReport, WriteTerminalSettlement,
};
''')
 dest=pkg/'proposed'/path
 dest.parent.mkdir(parents=True,exist_ok=True)
 dest.write_text(content)
for path,content in original.items():
 if content is not None:
  dest=pkg/'base'/path
  dest.parent.mkdir(parents=True,exist_ok=True)
  dest.write_text(content)
(pkg/'base-manifest.json').write_text(json.dumps({'workspace':str(root),'branch':'master','head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),'files':[{'path':p,'base_sha256':hashlib.sha256(s.encode()).hexdigest() if s is not None else None} for p,s in original.items()]},indent=2)+'\n')
