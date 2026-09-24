from pathlib import Path
import hashlib,json,re,shutil
ROOT=Path('/Users/mtakemiya/dev/kasumi');PKG=ROOT/'target/installed-disk-validation/redb-current-provenance-checkpoint';REL=Path('docs/evidence/redb-current-source-20260922');DEST=PKG/'proposed'/REL;ARCHIVE=Path('docs/evidence/installed-disk-main-20260920')
assert Path.cwd()==ROOT and (ROOT/'.git/HEAD').read_text().strip()=='ref: refs/heads/master'
assert not (PKG/'manifest.json').exists()
sha=lambda b:hashlib.sha256(b).hexdigest()
def write(p,d):p.write_text(json.dumps(d,indent=2)+'\n')
evidence=json.loads((DEST/'evidence-bindings.json').read_text());changes=json.loads((DEST/'changes-since-import.json').read_text());provenance=json.loads((DEST/'provenance.json').read_text());preparation=json.loads((PKG/'preparation.json').read_text())
assert sha((ROOT/'vendor/patch-manifest.json').read_bytes())==preparation['original_manifest_sha256']
added=[];paths={}
def bind(source,bundle):
 raw=(ROOT/source).read_bytes();rel=Path('bindings')/bundle/Path(source).name;out=DEST/rel;assert not out.exists();out.parent.mkdir(parents=True,exist_ok=True);out.write_bytes(raw)
 item={'id':str(rel),'original_repository_path':str(source),'path':str(REL/rel),'sha256':sha(raw),'bytes':len(raw),'category':'archived_historical_scoped_test_patch_or_review'};added.append(item)
 if str(source).endswith('.patch'):
  for name in re.findall(r'^\+\+\+ b/vendor/redb-4\.2\.0/(.+)$',raw.decode(),re.M):paths.setdefault(name,[]).append(item['id'])
for package in ['143-canonical-public-fixtures','145-public-failure-successor','146-observed-upstream-layout-rejection','154-vendor-test-lint-correction','102-redb-terminal-corrections','143-canonical-public-fixtures-independent-review']:
 for f in sorted((ROOT/ARCHIVE/package).iterdir()):
  if f.is_file() and (f.suffix in {'.patch','.md'} or f.name in {'manifest.json','receipt.json','static-checks.json'}):bind(f.relative_to(ROOT),'archived-'+package)
for name in ['107-prerequisites-applied.json','145-public-format-fixture-applied.json','146-public-failure-successor-applied.json','147-observed-layout-rejection-applied.json','155-vendor-test-lint-correction-applied.json']:
 bind(ARCHIVE/name,'archived-test-application-receipts')
evidence['bindings'].extend(added)
evidence['archived_test_history_scope']='Added exact archived packages 102, 143, 145, 146 and 154, the scoped143 review and matching root application receipts. These bind historical portions of the current changes only; no complete transformation chain or blanket current source review is claimed. Current Rust inputs are independently bound to completed runs162–164.'
for rows in [changes,provenance['files']]:
 for row in rows:
  if row['path'] in paths:row['review_history_bindings']=sorted(set(row['review_history_bindings']+paths[row['path']]))
write(DEST/'evidence-bindings.json',evidence);write(DEST/'changes-since-import.json',changes)
for key in ['changes_since_import','review_and_test_bindings']:
 item=provenance['checkpoint'][key];item['sha256']=sha((PKG/'proposed'/item['path']).read_bytes())
write(DEST/'provenance.json',provenance)
policy=json.loads((PKG/'proposed/vendor/patch-manifest.json').read_text());inventory=next(x for x in policy['inventories'] if x['path']=='vendor/redb-4.2.0');inventory['review']['sha256']=sha((DEST/'provenance.json').read_bytes());write(PKG/'redb-inventory-candidate.json',inventory);write(PKG/'proposed/vendor/patch-manifest.json',policy)
preparation['bindings']=len(evidence['bindings']);preparation['candidate_manifest_sha256']=sha((PKG/'proposed/vendor/patch-manifest.json').read_bytes());preparation['provenance_sha256']=sha((DEST/'provenance.json').read_bytes());write(PKG/'preparation.json',preparation)
readme=DEST/'README.md';s=readme.read_text();old='Five deltas have no matching historical patch file in the selected bound review history: CHANGELOG.md, KASUMI_PATCH.md, src/tree_store/page_store/checked_backend_tests.rs, tests/canonical_format.rs and tests/integration_tests.rs. The three Rust/test files match current gate inventories. This explicit gap requires the root\'s current-checkpoint review; no earlier patch approval is invented. Their current bytes are fully inventoried.';new='The archived packages 102, 143, 145, 146 and 154, applicable manifests, the scoped 143 review and corresponding root application receipts now bind historical changes to checked_backend_tests.rs, canonical_format.rs and integration_tests.rs, together with their other affected paths. This is partial historical coverage, not proof of a complete patch chain or blanket current-source review. All current Rust/test files match runs 162–164. CHANGELOG.md and KASUMI_PATCH.md have no source-patch history binding and require explicit root review of their current disposition text. Every current byte is inventoried.';assert old in s;readme.write_text(s.replace(old,new))
assert sha((ROOT/'vendor/patch-manifest.json').read_bytes())==preparation['original_manifest_sha256']
print(json.dumps({'added_bindings':len(added),'total_bindings':len(evidence['bindings']),'remaining_without_patch_history':[x['path'] for x in changes if not x['review_history_bindings']],'provenance_sha256':preparation['provenance_sha256']},indent=2))
