import hashlib,json,sys,unittest,plistlib,xml.parsers.expat
from pathlib import Path
p=Path(__file__).resolve().parent;source=p.parent/'proposed/scripts';sys.dont_write_bytecode=True;sys.path.insert(0,str(source));import test_small_native_smoke as tests

def imports():
 result={}
 for name,module in tuple(sys.modules.items()):
  file=getattr(module,'__file__',None)
  if file and Path(file).is_file():
   file=Path(file).resolve();result[str(file)]=hashlib.sha256(file.read_bytes()).hexdigest()
 return result
before=imports();(p/'imports-before.json').write_text(json.dumps(before,indent=2)+'\n')
result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(tests))
after=imports();(p/'imports-after.json').write_text(json.dumps(after,indent=2)+'\n');changed={k for k in before if before[k]!=after.get(k)};assert not changed,changed
print('imports unchanged:',len(before),'new paths:',len(set(after)-set(before)))
sys.exit(not result.wasSuccessful())
