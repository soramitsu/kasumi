from pathlib import Path
import subprocess,time,json,os,signal
root=Path('/Users/mtakemiya/dev/kasumi'); out=root/'target/installed-disk-validation'
assert subprocess.check_output(['git','branch','--show-current'],cwd=root,text=True).strip()=='master'
def processes():
 result={}
 for line in subprocess.check_output(['ps','-axo','pid=,ppid=,pgid=,lstart=,comm='],text=True).splitlines():
  parts=line.split(None,8)
  if len(parts)==9: result[int(parts[0])]={'pid':int(parts[0]),'ppid':int(parts[1]),'pgid':int(parts[2]),'started':' '.join(parts[3:8]),'command':parts[8]}
 return result
now=processes(); known={pid:now[pid] for pid in [32363,32367,32366] if pid in now}
assert known and all('lldb' in x['command'] or 'debugserver' in x['command'] or 'lifecycle-377b80b89ca111b0' in x['command'] for x in known.values())
original=dict(known); signals=[]; started=time.monotonic(); deadline=started+1000
while True:
 current=processes()
 changed=True
 while changed:
  changed=False
  for pid,entry in current.items():
   parent=known.get(entry['ppid'])
   if pid not in known and parent and current.get(entry['ppid'],{}).get('started')==parent['started']:
    known[pid]=entry; changed=True
 live=[entry for pid,entry in current.items() if pid in known and entry['started']==known[pid]['started']]
 if not live: break
 if time.monotonic()>=deadline:
  for entry in live:
   os.kill(entry['pid'],signal.SIGTERM); signals.append({'pid':entry['pid'],'started':entry['started'],'signal':'SIGTERM'})
  time.sleep(3)
  current=processes()
  for pid,entry in known.items():
   if current.get(pid,{}).get('started')==entry['started']:
    os.kill(pid,signal.SIGKILL); signals.append({'pid':pid,'started':entry['started'],'signal':'SIGKILL'})
  time.sleep(1); break
 time.sleep(.25)
current=processes(); live=[entry for pid,entry in current.items() if pid in known and entry['started']==known[pid]['started']]
result={'scope':'Independent exact-start-identity descendant census for LLDB, debugserver and inferior; no diagnostic or acceptance pass inferred','original_processes':list(original.values()),'all_observed_processes':list(known.values()),'signals':signals,'remaining':live,'drained':not live,'elapsed_seconds':time.monotonic()-started}
(out/'120-descendant-result.json').write_text(json.dumps(result,indent=2)+'\n'); print(json.dumps(result))
