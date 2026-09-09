import datetime,hashlib,json,os,pathlib,re,signal,subprocess,time
root=pathlib.Path('/tmp/kasumi-sdk-literal-boundaries')
out=pathlib.Path('/tmp/kasumi-sdk-literal-785dd7f-small')
def sh(*args):return subprocess.check_output(args,cwd=root,text=True).strip()
def sha(p):return hashlib.file_digest(open(p,'rb'),'sha256').hexdigest()
def source():return {'head':sh('git','rev-parse','HEAD'),'tree':sh('git','rev-parse','HEAD^{tree}'),'status':sh('git','status','--porcelain=v1'),'lock_sha256':sha(root/'Cargo.lock')}
before=source();assert before['head']=='785dd7f1afe64fdca5daf7c9c8a83f0c35fd30ae' and not before['status']
out.mkdir(exist_ok=False)
cargo=sh('rustup','which','--toolchain','1.97.1','cargo');rustc=sh('rustup','which','--toolchain','1.97.1','rustc');rustdoc=sh('rustup','which','--toolchain','1.97.1','rustdoc')
env=os.environ.copy();env.update(RUSTUP_TOOLCHAIN='1.97.1',RUSTC=rustc,RUSTDOC=rustdoc,CARGO_TARGET_DIR='/tmp/kasumi-production-root-target',CARGO_BUILD_JOBS='1',RUST_TEST_THREADS='1');env['PATH']=str(pathlib.Path(cargo).parent)+':'+env['PATH']
record={'scope':'macOS ARM64 bounded literal/read SDK pure tests and client-only compiler checks; no engine/store/server/Raft dependency, listener, provider or native process test. Shared host; no quiet-host performance, capacity or final release acceptance.','source_before':before,'tools':{str(p):sha(p) for p in [cargo,rustc,rustdoc]},'runner_sha256':sha(__file__),'per_gate_timeout_seconds':300,'gates':[]}
(out/'evidence.json').write_text(json.dumps(record,indent=2))
tests=[('snapshot-pure', 'kasumi-client', ['--lib', '--all-features'], 'snapshot_', ['snapshot_decode::tests::shared_response_retains_exact_original_reservation', 'snapshot_decode::tests::exact_points_scope_order_and_revision_are_checked_before_values', 'snapshot_decode::tests::cancelled_and_panicking_decoder_keeps_charge_until_actual_worker_exit', 'snapshot_decode::tests::literal_marker_keys_and_nested_payloads_round_trip_as_ordinary_documents', 'snapshot_decode::tests::outbound_borrowed_walk_and_nil_scope_fail_before_encoding_growth', 'snapshot_decode::tests::parser_error_payload_drops_before_worker_admission_is_released', 'snapshot_decode::tests::transport_error_retains_code_without_peer_message_details_or_metadata', 'snapshot_decode::tests::query_rows_cannot_advance_beyond_their_collection_epoch', 'snapshot_decode::tokens::tests::scans_ignored_duplicate_and_shallow_tokens_before_serde', 'snapshot_decode::transport::tests::framing_rejects_declared_size_compression_and_second_message_before_forwarding', 'snapshot_decode::transport::tests::bounded_envelope_rejects_duplicate_and_noncanonical_fields', 'snapshot_decode::transport::tests::oversized_initial_status_headers_are_removed_before_tonic_can_decode_them', 'data_pool::snapshot_error_tests::bounded_snapshot_errors_preserve_only_approved_retry_codes']), ('authorization-sensitive', 'kasumi-client', ['--lib', '--all-features'], 'authorization_tests::bearer_wire_value_is_unchanged_while_debug_is_redacted', ['authorization_tests::bearer_wire_value_is_unchanged_while_debug_is_redacted'])]
tests.insert(0, ('ordinary-literal-pure', 'kasumi-client', ['--lib', '--all-features'], 'literal_decode::tests::', ['literal_decode::tests::ordinary_query_preserves_literal_keys_numbers_and_original_page_revision', 'literal_decode::tests::query_budget_is_aggregate_across_rows_and_ignored_wire_is_rejected', 'literal_decode::tests::numeric_lexeme_and_request_clone_work_are_admitted_before_construction', 'literal_decode::tests::numeric_request_lexemes_do_not_consume_literal_string_key_limits', 'literal_decode::tests::change_feed_schema_and_audit_construct_values_from_literal_spans', 'literal_decode::tests::canonical_intent_helpers_preserve_body_predicates_schema_and_exact_digest', 'literal_decode::tests::change_feed_retention_gap_binds_original_position_and_checked_range', 'literal_decode::tests::change_feed_events_bind_scope_and_commit_metadata_without_rejecting_filtered_gaps', 'literal_decode::tests::cancelled_canonical_input_retains_reservation_until_worker_exit']))
tests[1][4].extend(['snapshot_decode::request::tests::canonical_wrapper_admission_bounds_actual_sorting_workspace','snapshot_decode::request::tests::map_workspace_admission_precedes_sorting_body','snapshot_decode::request::tests::map_workspace_sums_live_parents_and_releases_on_success_and_error'])
commands=[(name,[cargo,'test','--locked','-j1','-p',package,*target,filter,'--message-format=json-render-diagnostics','--','--test-threads=1'],expected) for name,package,target,filter,expected in tests]
commands += [('client-strict',[cargo,'clippy','--locked','-j1','-p','kasumi-client','--all-targets','--all-features','--message-format=json-render-diagnostics','--','-D','warnings'],None),('client-no-default-check',[cargo,'check','--locked','-j1','-p','kasumi-client','--no-default-features','--lib','--message-format=json-render-diagnostics'],None)]

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
 log=out/(name+'.log');start=time.monotonic();utc_start=datetime.datetime.now(datetime.timezone.utc).isoformat();print('Running',name,flush=True)
 problem=None;cleanup=None;process=None
 with log.open('wb') as f:
  try:
   process=subprocess.Popen(cmd,cwd=root,env=env,stdout=f,stderr=subprocess.STDOUT,start_new_session=True)
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
 content=log.read_text(errors='replace');artifacts=[];packages=[]
 for line in content.splitlines():
  try:item=json.loads(line)
  except ValueError:continue
  if item.get('reason')=='compiler-artifact':packages.append({'package_id':item.get('package_id'),'features':item.get('features'),'target':item.get('target',{}).get('name')})
  p=item.get('executable')
  if item.get('reason')=='compiler-artifact' and p and pathlib.Path(p).is_file():artifacts.append({'path':p,'sha256':sha(p),'profile':item.get('profile'),'features':item.get('features')})
 forbidden=[p for p in packages if re.search(r'(?:^|[/#])kasumi-(engine|store|server|raft)(?:[@/#]|$)',p['package_id'] or '')]
 if forbidden:problem=(problem+'; ' if problem else '')+'forbidden heavy package artifact';code=1
 expected_ran=(expected is None or all(('test '+name+' ... ok') in content for name in expected)) and ('test' not in cmd[1:2] or re.search(r'test result: ok\. [1-9][0-9]* passed',content) is not None)
 code=code if code else (0 if expected_ran else 1)
 record['source_after']=source()
 if record['source_after']!=before:problem=(problem+'; ' if problem else '')+'source changed during gate';code=1
 if cleanup is not None and not cleanup['process_group_drained']:code=1
 record['gates'].append({'name':name,'command':cmd,'utc_start':utc_start,'utc_end':datetime.datetime.now(datetime.timezone.utc).isoformat(),'compiled_packages':packages,'forbidden_packages':forbidden,'seconds':time.monotonic()-start,'process_group_id':process.pid if process else None,'process_exit_code':process.returncode if process else None,'exit_code':code,'problem':problem,'cleanup':cleanup,'required_test':expected,'required_test_passed':expected_ran,'log_sha256':sha(log),'artifacts':artifacts})
 (out/'evidence.json').write_text(json.dumps(record,indent=2));print(name,code,flush=True)
 if code:raise SystemExit(code)
