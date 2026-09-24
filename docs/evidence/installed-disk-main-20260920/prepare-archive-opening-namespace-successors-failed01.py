from pathlib import Path
import hashlib,json
root=Path('/Users/mtakemiya/dev/kasumi');out=root/'target/installed-disk-validation';new=out/'archive-opening-namespace-successors';new.mkdir(exist_ok=False)
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
packages=['153-vendor-all-features-correction','154-vendor-test-lint-correction','retained-opening-owner','retained-opening-owner-revision2','retained-opening-owner-revision3','retained-opening-owner-revision2-independent-review','redb-canonical-allocator-keys','redb-canonical-allocator-keys-opening-composed','redb-canonical-allocator-keys-root-review','directory-managed-namespace','directory-managed-namespace-root-review','directory-managed-namespace-generic','directory-managed-namespace-generic-root-review']
files=set();controls={}
for name in packages:
 folder=out/name;assert folder.is_dir()
 for p in folder.rglob('*'):
  if p.is_file():assert not p.is_symlink();files.add(p)
 for leaf in ['manifest.json','receipt.json','raw-sha256.json']:
  p=folder/leaf
  if p.exists():controls[str(p.relative_to(out))]=sha(p)
terminals={}
for number in range(152,162):
 p=out/f'{number}-result.json';result=json.loads(p.read_text());assert result['drained'] and result['inventoried_source_unchanged'] and type(result['exit_code']) is int
 terminals[str(number)]={'result_sha256':sha(p)}
 files.update(out.glob(f'{number}-*'));files.add(out/f'run{number}.py')
files.add(out/'format160.py')
inputs={'controls':controls,'files':{str(p.relative_to(out)):{'sha256':sha(p),'bytes':p.stat().st_size} for p in sorted(files)},'package_roots':packages,'terminal_runs':terminals,'unfinished_census_session_admission_payload_validation_excluded':True}
p=new/'inputs.json';p.write_text(json.dumps(inputs,indent=2,sort_keys=True)+'\n');input_sha=sha(p)
s=(out/'archive-allocator-encoding-successors.py').read_text().replace('Runs148–151','Runs152–161').replace('archive-allocator-encoding-successors/inputs.json','archive-opening-namespace-successors/inputs.json').replace('3523a5a0fb89311637a1bd05817e6226c1d3f29fb4c6f4c49d937c82c891f40f',input_sha).replace('3979','4041').replace('e0d48fe552dc7cae13be01b81501cf83306381c995c94321006ac72f508b9646','14a442c9a9e80e31d3e8bbb9cc4338537f83805df18902720d2abe99a309a997').replace('allocator-encoding-native-binary-omissions','opening-namespace-native-binary-omissions').replace('allocator-encoding-append-receipts','opening-namespace-append-receipts').replace('Append immutable allocator/public integration evidence','Append immutable opening, key and namespace evidence')
p=out/'archive-opening-namespace-successors.py';p.write_text(s)
print(json.dumps({'input_files':len(files),'input_sha256':input_sha,'script_sha256':sha(p)}))
