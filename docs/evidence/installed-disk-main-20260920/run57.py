from pathlib import Path
import subprocess, os, time, json, signal, hashlib
root=Path('/Users/mtakemiya/dev/kasumi'); os.chdir(root)
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
out=root/'target/installed-disk-validation'
def inventory():
 inputs=sorted(list((root/'crates').rglob('*.rs'))+list((root/'crates').rglob('Cargo.toml'))+list((root/'vendor').rglob('*.rs'))+list((root/'vendor').rglob('Cargo.toml'))+[root/'Cargo.toml',root/'Cargo.lock'])
 return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in inputs}

before=inventory(); (out/'57-source-before.json').write_text(json.dumps(before,indent=2)+'\n')
command=['/Users/mtakemiya/dev/kasumi/target/debug/deps/kasumi_engine-dc6dca13bbdbe0d0', '--test-threads=1', '--nocapture', 'bootstrap::existing_tests::existing_local_reopens_the_same_committed_standalone_after_complete_shutdown', 'security_audit::retention::tests::uncertain_publication_survives_restart_and_repeated_hot_budget_crossings_preserve_complete_history', 'security_audit::tests::uncertain_audit_commit_fences_queued_writers_until_sequence_recovery', 'service::tests::custody_observations_preserve_mutation_capacity_and_exhaustion_can_expand', 'service::tests::guarded_stop_queued_deadline_and_cancellation_leave_only_actual_durable_outcomes', 'service::tests::queued_staged_finalize_checks_fresh_time_and_canceled_callers_keep_durable_outcomes', 'service::tests::serving_expiry_rejects_queued_effect_and_late_read_or_committed_ack_then_reopens_exactly', 'state::restore_budget_tests::restored_identity_metadata_is_validated_before_bootstrap_persistence', 'state::snapshot_bundle::tests::control_archive_transfer_uses_exact_reserved_domain_without_application_authority']
env={**os.environ,'PATH':'/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin:'+os.environ['PATH'],'CARGO_TARGET_DIR':str(root/'target'),'CARGO_BUILD_JOBS':'2','TMPDIR':str(root/'target/tmp')}
def run():
 started=time.time(); signals=[]; timeout=False
 with (out/'57-engine-failures.log').open('wb') as log:
  process=subprocess.Popen(command,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
  print(json.dumps({'running_pid':process.pid,'deadline_seconds':1200,'log':str(out/'57-engine-failures.log')}),flush=True)
  try: rc=process.wait(timeout=1200)
  except subprocess.TimeoutExpired:
   timeout=True; os.killpg(process.pid,signal.SIGTERM); signals.append('SIGTERM')
   try: rc=process.wait(timeout=10)
   except subprocess.TimeoutExpired: os.killpg(process.pid,signal.SIGKILL); signals.append('SIGKILL'); rc=process.wait()
 def live():
  try: os.killpg(process.pid,0); return True
  except ProcessLookupError: return False
  except PermissionError:
   listing=subprocess.check_output(['ps','-axo','pid=,pgid='],text=True)
   return any(len(parts)==2 and int(parts[1])==process.pid for line in listing.splitlines() if (parts:=line.split()))
 if live():
  os.killpg(process.pid,signal.SIGTERM); signals.append('SIGTERM-remaining')
  until=time.monotonic()+10
  while live() and time.monotonic()<until: time.sleep(.1)
  if live(): os.killpg(process.pid,signal.SIGKILL); signals.append('SIGKILL-remaining')
 after=inventory(); result={'scope':'development replay of first nine observed failures with immediate diagnostics, concurrent with gate52; not performance or final release qualification','command':command,'cwd':str(root),'head':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'binary_sha256':hashlib.sha256(Path(command[0]).read_bytes()).hexdigest(),'process_group':process.pid,'exit_code':rc,'timeout':timeout,'signals':signals,'drained':not live(),'elapsed_seconds':time.time()-started,'inventoried_source_unchanged':before==after}
 (out/'57-result.json').write_text(json.dumps(result,indent=2)+'\n'); (out/'57-source-after.json').write_text(json.dumps(after,indent=2)+'\n'); print(json.dumps(result),flush=True)
 lines=(out/'57-engine-failures.log').read_text(errors='replace').splitlines(); print('\n'.join(lines[-100:]),flush=True)
 raise SystemExit(rc)

try:
 run()
except Exception as error:
 recovery={'scope':'runner failure; no passing gate', 'error_type':type(error).__name__, 'error':str(error), 'time':time.time(), 'process_inventory':subprocess.check_output(['ps','-axo','pid,ppid,pgid,uid,state,etime,comm'],text=True)}
 (out/'57-runner-failure.json').write_text(json.dumps(recovery,indent=2)+'\n')
 (out/'57-source-after-recovery.json').write_text(json.dumps(inventory(),indent=2)+'\n')
 raise
