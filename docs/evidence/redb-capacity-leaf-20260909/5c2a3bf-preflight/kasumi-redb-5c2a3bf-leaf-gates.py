import hashlib,json,os,pathlib,re,signal,subprocess,time,shutil
root=pathlib.Path('/tmp/kasumi-redb-prepare-commit')
out=pathlib.Path('/tmp/kasumi-redb-5c2a3bf-leaf')
def sh(*args):return subprocess.check_output(args,cwd=root,text=True).strip()
def sha(p):return hashlib.file_digest(open(p,'rb'),'sha256').hexdigest()
def source():return {'head':sh('git','rev-parse','HEAD'),'tree':sh('git','rev-parse','HEAD^{tree}'),'status':sh('git','status','--porcelain=v1'),'lock_sha256':sha(root/'Cargo.lock'),'leaf_lock_sha256':sha(root/'vendor/redb-4.2.0/Cargo.lock'),'package_manifest_sha256':sha(root/'vendor/redb-4.2.0-capacity-inputs.json'),'patch_sha256':sha(root/'vendor/redb-4.2.0-capacity.patch'),'archive_sha256':sha(pathlib.Path('/Users/mtakemiya/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/redb-4.2.0.crate'))}
before=source();assert before['head']=='5c2a3bfc553acf21a5d11c046bbf76fc6e5a0d0a' and not before['status']
out.mkdir(exist_ok=False)
prior=pathlib.Path('/tmp/kasumi-redb-2886774-leaf/preserved-executables/redb-ba841ece6df4e8b1')
assert sha(prior)=='3400f1e467b83d9dfd27458dfb71140d593065a422af2e63a0df9ba0749e2127'
(out/'baseline-2886774').mkdir()
shutil.copy2(prior,out/'baseline-2886774'/prior.name)
assert sha(out/'baseline-2886774'/prior.name)==sha(prior)
subprocess.run(['python3','scripts/verify_redb_capacity_prototype.py','/Users/mtakemiya/.cargo/registry/cache/index.crates.io-1949cf8c6b5b557f/redb-4.2.0.crate'],cwd=root,check=True)

cargo=sh('rustup','which','--toolchain','1.97.1','cargo');rustc=sh('rustup','which','--toolchain','1.97.1','rustc');rustdoc=sh('rustup','which','--toolchain','1.97.1','rustdoc')
env=os.environ.copy();env.update(RUSTUP_TOOLCHAIN='1.97.1',RUSTC=rustc,RUSTDOC=rustdoc,CARGO_TARGET_DIR='/tmp/kasumi-redb-capacity-target',CARGO_BUILD_JOBS='1',RUST_TEST_THREADS='1');env['PATH']=str(pathlib.Path(cargo).parent)+':'+env['PATH']
record={'scope':'macOS ARM64 thirteen focused redb tests: original seven growth admission regressions plus six allocator candidate regressions. Frozen5c2a3bf source only; prior288 baseline preserved independently. No root dependency patch, Kasumi engine/store/server/Raft compilation, listener or provider. Shared host; full upstream just test, fuzzing, durable disk governor and production integration remain unrun.','source_before':before,'tools':{str(p):sha(p) for p in [cargo,rustc,rustdoc]},'runner_sha256':sha(__file__),'per_gate_timeout_seconds':300,'gates':[]}
(out/'evidence.json').write_text(json.dumps(record,indent=2))
expected=['transactions::growth_admission_tests::denied_growth_never_calls_resize_and_caught_error_cannot_commit', 'transactions::growth_admission_tests::split_failures_preserve_pinned_roots_and_successful_extent_charges', 'transactions::growth_admission_tests::replacement_denial_aborts_all_tables_and_retains_original_value', 'transactions::growth_admission_tests::explicit_abort_and_drop_after_capacity_denial_leave_database_usable', 'transactions::growth_admission_tests::actual_backend_failures_still_latch_and_never_claim_capacity_abort', 'transactions::growth_admission_tests::allocator_clones_and_system_namespace_share_the_capacity_abort_state', 'transactions::growth_admission_tests::commit_time_denial_keeps_failed_commit_latch_instead_of_claiming_rollback']
expected += [
 'transactions::growth_admission_tests::prepared_freed_records_are_rollback_valid_before_capacity_denial',
 'transactions::growth_admission_tests::deferred_frees_survive_quick_repair_and_pinned_reader_reopen',
 'transactions::growth_admission_tests::failed_root_io_discards_allocator_candidate_without_exposing_frees',
]
candidate=[
 'tree_store::page_store::allocator_commit::tests::discard_preserves_live_allocator_and_only_copies_changed_regions',
 'tree_store::page_store::allocator_commit::tests::publication_matches_prepared_quick_repair_bytes_and_preserves_other_pages',
 'tree_store::page_store::allocator_commit::tests::shrinking_is_private_until_publication_and_cannot_discard_live_pages',
]
def command(test_filter):
 return [cargo,'test','--manifest-path','vendor/redb-4.2.0/Cargo.toml','--locked','--offline','-j1','--features','experimental-precommit-growth-admission','--lib',test_filter,'--message-format=json-render-diagnostics','--','--test-threads=1']
commands=[('redb-allocator-candidate',command('tree_store::page_store::allocator_commit::tests'),candidate),('redb-growth-admission',command('transactions::growth_admission_tests'),expected)]

def group_alive(pgid):
 try:os.killpg(pgid,0);return True
 except ProcessLookupError:return False

def drain_group(process):
 actions=[]
 for sig in (signal.SIGTERM,signal.SIGKILL):
  if not group_alive(process.pid):break
  try:os.killpg(process.pid,sig);actions.append(sig.name)
  except ProcessLookupError:break
  deadline=time.monotonic()+10
  while time.monotonic()<deadline:
   process.poll()
   if not group_alive(process.pid):break
   time.sleep(.05)
 process.poll()
 return {'signals':actions,'process_returncode':process.returncode,'process_group_drained':not group_alive(process.pid)}

for name,cmd,expected in commands:
 log=out/(name+'.log');start=time.monotonic();print('Running',name,flush=True)
 problem=None;cleanup=None;process=None
 with log.open('wb') as f:
  try:
   process=subprocess.Popen(cmd,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
   print('Owned process group',process.pid,flush=True)
   code=process.wait(timeout=300)
   if group_alive(process.pid):
    problem='owned process group remained after command exit';code=1
    cleanup=drain_group(process)
   else:cleanup={'signals':[],'process_returncode':process.returncode,'process_group_drained':True}
  except BaseException as error:
   problem=type(error).__name__+': '+str(error)
   code=124 if isinstance(error,subprocess.TimeoutExpired) else 130 if isinstance(error,KeyboardInterrupt) else 1
   if process is not None:cleanup=drain_group(process)
  finally:
   f.flush();os.fsync(f.fileno())
 content=log.read_text(errors='replace');artifacts=[]
 for line in content.splitlines():
  try:item=json.loads(line)
  except ValueError:continue
  p=item.get('executable')
  if item.get('reason')=='compiler-artifact' and p and pathlib.Path(p).is_file():artifacts.append({'path':p,'sha256':sha(p),'profile':item.get('profile'),'features':item.get('features')})
 expected_ran=all(('test '+name+' ... ok') in content for name in expected) and f'test result: ok. {len(expected)} passed; 0 failed; 0 ignored;' in content
 features_match=bool(artifacts) and all(x['features']==['default','experimental-precommit-growth-admission','std'] for x in artifacts)
 if code==0 and not features_match:problem='unexpected or absent compiled feature evidence';code=1
 preservation=out/'preserved-executables';preservation.mkdir(exist_ok=True)
 for artifact in artifacts:
  original=pathlib.Path(artifact['path']);saved=preservation/(name+'-'+original.name)
  shutil.copy2(original,saved);assert sha(saved)==artifact['sha256'];artifact['preserved_path']=str(saved)

 code=code if code else (0 if expected_ran else 1)
 record['source_after']=source()
 if record['source_after']!=before:problem=(problem+'; ' if problem else '')+'source changed during gate';code=1
 if cleanup is not None and not cleanup['process_group_drained']:code=1
 record['gates'].append({'name':name,'command':cmd,'seconds':time.monotonic()-start,'process_group_id':process.pid if process else None,'process_exit_code':process.returncode if process else None,'exit_code':code,'problem':problem,'cleanup':cleanup,'required_test':expected,'required_test_passed':expected_ran,'compiled_features_match':features_match,'log_sha256':sha(log),'artifacts':artifacts})
 (out/'evidence.json').write_text(json.dumps(record,indent=2));print(name,code,flush=True)
 if code:raise SystemExit(code)

print('Focused cohort terminal; all owned groups drained',flush=True)
