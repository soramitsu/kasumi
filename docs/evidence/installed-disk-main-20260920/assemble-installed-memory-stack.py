from pathlib import Path
import subprocess,json,os,hashlib
root=Path('/Users/mtakemiya/dev/kasumi'); stage=root/'target/installed-disk-validation'; os.chdir(root)
assert subprocess.check_output(['git','branch','--show-current'],text=True).strip()=='master'
assert subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()=='600c0ca2b2c4c22b89b44ccd932eca02272c70f1'
assert not subprocess.check_output(['git','status','--porcelain'],text=True)
items=[
('node-disk-memory/metadata.patch','10ebc1c6ee2a0df7c65b67302757b537ddedcb000008ea5391a82d030fab5259'),
('store-fixture-backend-memory/backend.patch','2c9971827a928bd3dd412e944f4f55df2c235e5e9edf723514d5411b2ee53b84'),
('installed-disk-core-adapter/adapter.patch','9001501726d33c8041c837ffdcda2550131a02993da5bb8d86e6add772382c5d'),
('installed-memory-engine-guards/guards.patch','efeca43aa014510d6b078c5562bc7271cb85683d5b0b158e8ccf295c5695ed86'),
('database-construction/construction.patch','05d511887c479d3ac8e94e64a39d6c81ce6b905d78d6c538bfa9e313d54849b2'),
('engine-fixture-helper/helper.patch','e3bebad935c1fe5ddbe9a53a46fb8bbe68afe0a5b3cf99fe0439edd80535f844'),
('disk-memory-nonserver-callers/remaining-raft-store-agent/combined-raft-callers.patch','bacf3ac67ba6400d60ca71aff9a4acc19f8a627b4dc16395517d8d99832a4247'),
('authority-bench-callers/callers.patch','50418750e65460f8b832770e5792ade1c6eed1ffe0e10b0bad9fa13022b2fc7f'),
('installed-memory-callers/complete-600c0ca/server.patch','830269a7ef6023a21b63043c6ac4546ca7f733baa1f9ca42ec9edbb2cccb5e9c'),
('engine-integration-callers/root-callers.patch','ec254c91921d0b33f8f11b7bd63315e225fa01cb8f3aecfdb6fbe3f557d57f83'),
('engine-integration-store-agent/callers.patch','2b89e57670ab195966f8fc76fc6250d57a946e41ee4c5635742bf460c8403ecc'),
]
index=stage/'installed-memory-assembly.index';env={**os.environ,'GIT_INDEX_FILE':str(index)}
subprocess.run(['git','read-tree','HEAD'],env=env,check=True)
receipts=[]
for path,expected in items:
 p=stage/path;actual=hashlib.sha256(p.read_bytes()).hexdigest();assert actual==expected,(path,actual)
 r=subprocess.run(['git','apply','--cached',str(p)],env=env,capture_output=True,text=True)
 receipts.append({'path':path,'sha256':actual,'status':r.returncode,'stderr':r.stderr})
 (stage/'installed-memory-assembly.json').write_text(json.dumps({'status':'PARTIAL_TARGET_INDEX_ONLY_ENGINE_SRC_PENDING','actual_source_edited':False,'packages':receipts},indent=2)+'\n')
 assert r.returncode==0,(path,r.stderr)
print(json.dumps({'status':'PARTIAL_TARGET_INDEX_ONLY_ENGINE_SRC_PENDING','packages':len(receipts)}))
print(subprocess.check_output(['git','diff','--cached','--stat','HEAD'],env=env,text=True).splitlines()[-1])
