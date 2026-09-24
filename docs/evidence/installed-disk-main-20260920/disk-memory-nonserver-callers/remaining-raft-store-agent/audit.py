from pathlib import Path
import re,json
p=Path(__file__).parent;root=Path('crates/kasumi-raft');proposed=p/'proposed'
expected={'ScratchDisk::fixture':2,'NodeStore::create_new_fixture':4,'NodeStore::open_existing_fixture':4,'common::store':3,'new_fault_store':2,'existing_fault_store':2,'accepted_snapshot':1}
def argc(s,i):
 stack=['('];quote=False;esc=False;commas=0;start=i+1
 for j in range(start,len(s)):
  c=s[j]
  if quote:
   if esc:esc=False
   elif c=='\\':esc=True
   elif c=='"':quote=False
   continue
  if c=='"':quote=True;continue
  if c in '([{':stack.append(c)
  elif c in ')]}':
   stack.pop()
   if not stack:
    raw=s[start:j].strip();return 0 if not raw else commas+int(not raw.endswith(','))
  elif c==',' and len(stack)==1:commas+=1
 raise ValueError(i)
rows=[];bad=[]
for real in root.rglob('*.rs'):
 f=proposed/real;s=(f if f.exists() else real).read_text()
 for name,want in expected.items():
  for m in re.finditer(re.escape(name)+r'\(',s):
   if re.search(r'fn\s+$',s[max(0,m.start()-4):m.start()]):continue
   n=argc(s,m.end()-1);row={'path':str(real),'line':s[:m.start()].count('\n')+1,'call':name,'arity':n};rows.append(row)
   if n!=want:bad.append(row)
 assert 'ScratchDisk::fixture()' not in s,str(real)
 assert not re.search(r'\bNodeAdmission\b|\bMemoryCore\b',s) or not f.exists(),str(real)
result={'calls':len(rows),'failures':bad,'all_current_raft_sources_checked':True};(p/'arity-audit.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result,indent=2));assert not bad
