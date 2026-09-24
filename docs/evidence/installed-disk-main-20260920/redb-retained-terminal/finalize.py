from pathlib import Path
import difflib, hashlib, json, subprocess
root=Path('/Users/mtakemiya/dev/kasumi')
pkg=root/'target/installed-disk-validation/redb-retained-terminal'
base=json.loads((pkg/'base-manifest.json').read_text())
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
patch=[]
files=[]
for item in base['files']:
 p=item['path']
 actual=(root/p).read_bytes() if (root/p).exists() else None
 assert (hashlib.sha256(actual).hexdigest() if actual is not None else None)==item['base_sha256'],p
 proposed=(pkg/'proposed'/p).read_bytes()
 original=(pkg/'base'/p).read_bytes() if actual is not None else b''
 patch.append(''.join(difflib.unified_diff(original.decode().splitlines(True),proposed.decode().splitlines(True),fromfile='a/'+p if actual is not None else '/dev/null',tofile='b/'+p)))
 files.append({**item,'proposed_sha256':hashlib.sha256(proposed).hexdigest()})
patch=''.join(patch).encode()
(pkg/'terminal.patch').write_bytes(patch)
sources=['vendor/redb-4.2.0/src/transactions.rs','vendor/redb-4.2.0/src/lib.rs','vendor/redb-4.2.0/src/error.rs','vendor/redb-4.2.0/src/db.rs','vendor/redb-4.2.0/src/table.rs','vendor/redb-4.2.0/src/transaction_tracker.rs','vendor/redb-4.2.0/src/tree_store/table_tree.rs','vendor/redb-4.2.0/src/tree_store/page_store/page_manager.rs','vendor/redb-4.2.0/src/tree_store/page_store/cached_file.rs','vendor/redb-4.2.0/src/admission.rs','vendor/redb-4.2.0/src/admission/tests.rs','vendor/redb-4.2.0/tests/integration_tests.rs','target/installed-disk-validation/staging-batch-design/design.md','crates/kasumi-store/src/node_database.rs','crates/kasumi-store/src/lib.rs','crates/kasumi-store/src/scratch_table.rs','crates/kasumi-store/src/storage_domains.rs','crates/kasumi-store/src/storage_domains/catalog_initialization.rs','crates/kasumi-store/src/read_view.rs','crates/kasumi-store/src/live_trust.rs','crates/kasumi-store/src/single_catalog.rs']
manifest={**base,'status':'PREPARED_NOT_APPLIED_NOT_COMPILED_NOT_EXECUTED','files':files,'patch_sha256':hashlib.sha256(patch).hexdigest(),'prepared_tests':8,'unconverted_production_commit_calls':12,'source_sha256':{p:hashlib.sha256((root/p).read_bytes()).hexdigest() for p in sources}}
(pkg/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
print(json.dumps({'patch_sha256':manifest['patch_sha256'],'files':len(files),'lines':len(patch.splitlines()),'prepared_tests':8},indent=2))
