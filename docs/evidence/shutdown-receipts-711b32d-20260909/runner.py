import hashlib,json,os,pathlib,re,signal,subprocess,time
root=pathlib.Path('/tmp/kasumi-production-drain-validation')
out=pathlib.Path('/tmp/kasumi-receipt-worker-711b32d')
def sh(*args):return subprocess.check_output(args,cwd=root,text=True).strip()
def sha(p):return hashlib.file_digest(open(p,'rb'),'sha256').hexdigest()
def source():return {'head':sh('git','rev-parse','HEAD'),'tree':sh('git','rev-parse','HEAD^{tree}'),'status':sh('git','status','--porcelain=v1'),'lock_sha256':sha(root/'Cargo.lock')}
before=source();assert before['head']=='711b32d962f7406820129dd53533c45a3c5fd2a8' and not before['status']
out.mkdir(exist_ok=False)
cargo=sh('rustup','which','--toolchain','1.97.1','cargo');rustc=sh('rustup','which','--toolchain','1.97.1','rustc');rustdoc=sh('rustup','which','--toolchain','1.97.1','rustdoc')
env=os.environ.copy();env.update(RUSTUP_TOOLCHAIN='1.97.1',RUSTC=rustc,RUSTDOC=rustdoc,CARGO_TARGET_DIR='/tmp/kasumi-production-root-target',CARGO_BUILD_JOBS='1',RUST_TEST_THREADS='1');env['PATH']=str(pathlib.Path(cargo).parent)+':'+env['PATH']
record={'scope':'macOS ARM64 focused original-receipt, shutdown, physical-memory and lease ownership regressions after explicit shared-host lane handoff. No performance/capacity or final release acceptance.','source_before':before,'tools':{str(p):sha(p) for p in [cargo,rustc,rustdoc]},'runner_sha256':sha(__file__),'per_gate_timeout_seconds':900,'gates':[]}
(out/'evidence.json').write_text(json.dumps(record,indent=2))
tests=[('verifier-worker-registration', 'kasumi-serving', ['--lib'], 'live_trust::background_tests', 'live_trust::background_tests::task_installation_is_atomic_with_close_and_cancelled_drain_retains_ownership'), ('audit-workers', 'kasumi-engine', ['--lib'], 'security_audit', 'security_audit::tests::archive_worker_before_registration_is_joined_through_cancelled_shutdown_and_reopen'), ('tenant-audit-worker', 'kasumi-engine', ['--lib'], 'service::audit_maintenance_service::tests', 'service::audit_maintenance_service::tests::tenant_audit_worker_keeps_its_owner_through_cancelled_shutdown'), ('memory-admission', 'kasumi-engine', ['--lib'], 'admission::tests', 'admission::tests::explicit_high_water_cannot_bypass_detected_memory_capacity'), ('lease-retention', 'kasumi-engine', ['--lib'], 'lease_retention_tests', None), ('snapshot-receipts', 'kasumi-engine', ['--lib'], 'snapshot_validation', 'state::snapshot_validation::tests::receipt_original_scope_and_position_are_checked_in_both_snapshot_paths'), ('shutdown-integration', 'kasumi-engine', ['--test', 'shutdown'], 'full_shutdown_reopens_immediately_with_receipts_and_retained_plaintext', 'full_shutdown_reopens_immediately_with_receipts_and_retained_plaintext'), ('restore-receipts', 'kasumi-engine', ['--test', 'contracts'], 'logical_backup_restores_suspended_with_new_incarnation_and_increasing_revisions', 'logical_backup_restores_suspended_with_new_incarnation_and_increasing_revisions'), ('target-materialization', 'kasumi-authority', ['--lib'], 'target_materialization_tests', 'target_materialization_tests::dropping_target_on_non_runtime_thread_retains_shutdown_work_until_real_drain'), ('target-worker-ownership', 'kasumi-server', ['--lib'], 'target_runtime::shutdown_tests', 'target_runtime::shutdown_tests::target_monitor_and_outer_owner_survive_cancelled_shutdown_until_journal_reopens'), ('signer-worker-ownership', 'kasumi-server', ['--lib'], 'signer_runtime::tests', 'signer_runtime::tests::verifier_shutdown_joins_renewal_after_setup_owner_is_dropped'), ('native-mcp-receipts', 'kasumi-server', ['--lib'], 'native_and_mcp_', 'api::tests::native_and_mcp_lost_committed_responses_resolve_without_reapplying'), ('rejected-native-receipt', 'kasumi-server', ['--lib'], 'long_schema_property_errors_match_native_mcp_and_durable_receipts', 'api::tests::long_schema_property_errors_match_native_mcp_and_durable_receipts'), ('runtime-restart', 'kasumi-server', ['--lib'], 'three_runtime_nodes_replicate_with_control_quorum_over_audited_pinned_mtls', 'runtime::lifecycle_tests::three_runtime_nodes_replicate_with_control_quorum_over_audited_pinned_mtls')]
commands=[(name,[cargo,'test','--locked','-j1','-p',package,*target,filter,'--message-format=json-render-diagnostics','--','--test-threads=1'],expected) for name,package,target,filter,expected in tests]
commands += [('strict',[cargo,'clippy','--locked','-j1','--workspace','--all-targets','--all-features','--message-format=json-render-diagnostics','--','-D','warnings'],None),('production-check',[cargo,'check','--locked','-j1','-p','kasumi-server','--no-default-features','--bins','--message-format=json-render-diagnostics'],None),('format',[cargo,'fmt','--all','--','--check'],None)]
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
   code=process.wait(timeout=900)
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
 expected_ran=(expected is None or ('test '+expected+' ... ok') in content) and ('test' not in cmd[1:2] or re.search(r'test result: ok\. [1-9][0-9]* passed',content) is not None)
 code=code if code else (0 if expected_ran else 1)
 record['source_after']=source()
 if record['source_after']!=before:problem=(problem+'; ' if problem else '')+'source changed during gate';code=1
 if cleanup is not None and not cleanup['process_group_drained']:code=1
 record['gates'].append({'name':name,'command':cmd,'seconds':time.monotonic()-start,'process_group_id':process.pid if process else None,'process_exit_code':process.returncode if process else None,'exit_code':code,'problem':problem,'cleanup':cleanup,'required_test':expected,'required_test_passed':expected_ran,'log_sha256':sha(log),'artifacts':artifacts})
 (out/'evidence.json').write_text(json.dumps(record,indent=2));print(name,code,flush=True)
 if code:raise SystemExit(code)
