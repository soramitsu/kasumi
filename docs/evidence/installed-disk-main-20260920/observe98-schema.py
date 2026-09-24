from pathlib import Path
import subprocess, json, time, hashlib
root=Path('/Users/mtakemiya/dev/kasumi'); out=root/'target/installed-disk-validation'
log=out/'98-engine-fixture-successors.log'
marker='test encrypted_restart_and_full_restore_preserve_permanent_activation_receipts ... '
deadline=time.monotonic()+480
while time.monotonic()<deadline:
    text=log.read_text(errors='replace')
    if marker in text:
        break
    if (out/'98-result.json').exists():
        raise SystemExit('run98 ended before schema marker')
    time.sleep(1)
else:
    raise SystemExit('schema marker not observed within diagnostic watch bound')
observed=time.monotonic()
for ordinal,offset in enumerate([10,35],1):
    while time.monotonic()-observed < offset:
        time.sleep(.5)
    tail=log.read_text(errors='replace').split(marker,1)[1]
    if '\n' in tail:
        print('schema test reached terminal output before further observation',flush=True)
        break
    listing=subprocess.check_output(['ps','-axo','pid=,pgid=,command='],text=True)
    matched=[row.split(None,2) for row in listing.splitlines() if len(row.split(None,2))==3 and row.split(None,2)[1]=='1099' and '/target/debug/deps/schema_activation-' in row.split(None,2)[2]]
    if len(matched)!=1:
        raise SystemExit('actual schema process inventory is not unique')
    pid=int(matched[0][0]);sample=out/f'98-schema-{ordinal}-sample.txt'
    command=['sample',str(pid),'1','1','-file',str(sample)]
    completed=subprocess.run(command,cwd=root,capture_output=True,text=True)
    receipt={'scope':'read-only native progress observation during original run98 schema restore case, not terminal or acceptance evidence','command':command,'actual_process_inventory_row':matched[0],'exit_code':completed.returncode,'stdout':completed.stdout,'stderr':completed.stderr,'sample_sha256':hashlib.sha256(sample.read_bytes()).hexdigest() if sample.exists() else None,'seconds_since_marker_observed':time.monotonic()-observed}
    (out/f'98-schema-{ordinal}-observation.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(receipt),flush=True)
