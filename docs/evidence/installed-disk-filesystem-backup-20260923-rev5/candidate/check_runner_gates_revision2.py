"""Execute only extracted pure acceptance predicates, never the native runner."""
from pathlib import Path
import ast,json,hashlib,copy
pkg=Path(__file__).resolve().parent
source=(pkg/'native-02/run.py').read_text();tree=ast.parse(source)
functions=[node for node in tree.body if isinstance(node,ast.FunctionDef) and node.name in ['dispatch_budget_remaining','qualified_stage','compiled_binary_matches']]
assert len(functions)==3
scope={};exec(compile(ast.Module(body=functions,type_ignores=[]),'pure-runner-gates','exec'),scope)
f=scope['qualified_stage'];budget=scope['dispatch_budget_remaining'];cases=[]
def check(name,value):
 assert value,name
 cases.append(name)
base={'exit_code':0,'drained':True,'timeout':False,'signals':[],'executable_before':{'sha256':'one'},'executable_after':{'sha256':'one'}}
check('positive-no-timeout-drained-stage',f(base))
for field,value in [('exit_code',1),('exit_code',-15),('drained',False),('timeout',True),('signals',['SIGTERM']),('signals',['SIGKILL']),('signals',['SIGTERM-remaining']),('executable_after',{'sha256':'two'}),('inventory_passed',False),('runtime_passed',False)]:
 trial=copy.deepcopy(base);trial[field]=value;check(f'reject-{field}-{value}',not f(trial))
for value in [0,-1,-100]:check(f'exhausted-deadline-{value}',budget(100,100-value)==0)
check('positive-remaining-time',budget(100,90)==10)
check('dispatch-gate-before-popen',source.index('if not dispatch_budget_remaining')<source.index('q=subprocess.Popen'))
check('complete-cohort-required',"len(results)==len(commands)" in source)
check('unchanged-inputs-required',"before==after and binary_unchanged and artifacts_unchanged and dispatch_denied is None" in source)
check('no-timeout-continuation',"if not qualified_stage(result):break" in source)
check('all-345-names',"len(actual)==345" in source and "len(expected)==345" in source)
check('full-no-filter-runtime-summary',"==(343,0,2,0,0)" in source)
check('fresh-provenance',"assert not selected['fresh']" in source and "selected['target']['src_path']" in source)
check('actual-group-drain',"remaining=group_rows(q.pid)" in source and "'drained':not remaining" in source)
check('original-1200s-bound',"deadline=cohort_start+1200" in source)
match=scope['compiled_binary_matches']
compiled={'path':'store-test-binary','sha256':'compiled','bytes':100}
check('compiled-binary-match',match(compiled,dict(compiled)))
for value in [None,{'path':'other','sha256':'compiled','bytes':100},{'path':'store-test-binary','sha256':'replaced','bytes':100},{'path':'store-test-binary','sha256':'compiled','bytes':99}]:
 check('reject-compiled-mismatch-'+str(value),not match(compiled,value))
check('reject-absent-compile-provenance',not match(None,compiled))
prepare=(pkg/'prepare_native_revision2.py').read_text();ptree=ast.parse(prepare)
pure=[node for node in ptree.body if isinstance(node,ast.FunctionDef) and node.name=='exact_nonselected_sources'];assert len(pure)==1
pscope={};exec(compile(ast.Module(body=pure,type_ignores=[]),'pure-source-gate','exec'),pscope);same=pscope['exact_nonselected_sources']
expected={'crates/a.rs':{'sha256':'a','bytes':1,'mode':'0o644'},'Cargo.toml':{'sha256':'cargo','bytes':3,'mode':'0o644'},'selected.rs':{'sha256':'before','bytes':2,'mode':'0o644'}}
check('exact-source-set-accepted',same(expected,copy.deepcopy(expected),{'selected.rs'}))
for action in ['added','missing','hash','mode','cargo','cargo-missing']:
 actual=copy.deepcopy(expected)
 if action=='added':actual['crates/new.rs']={'sha256':'new','bytes':1,'mode':'0o644'}
 elif action=='missing':del actual['crates/a.rs']
 elif action=='hash':actual['crates/a.rs']['sha256']='other'
 elif action=='mode':actual['crates/a.rs']['mode']='0o755'
 elif action=='cargo':actual['Cargo.toml']['sha256']='other'
 else:del actual['Cargo.toml']
 check('reject-source-'+action,not same(expected,actual,{'selected.rs'}))
actual=copy.deepcopy(expected);actual['selected.rs']['sha256']='reviewed-after'
check('selected-composition-excluded-for-separate-exact-check',same(expected,actual,{'selected.rs'}))
check('compiled-pin-before-dispatch',source.index('if not compiled_binary_matched:')<source.index('q=subprocess.Popen'))
check('final-binary-artifacts-gate',"and binary_unchanged and artifacts_unchanged" in source)
check('preflight-mode-binding',"item['mode']" in source)
check('preflight-exact-source-binding',"current_source_set==preflight['source_set']" in source)
result={'status':'PASS pure predicate/source gate regression; no native','case_count':len(cases),'cases':cases,'runner_sha256':hashlib.sha256(source.encode()).hexdigest(),'preparer_sha256':hashlib.sha256(prepare.encode()).hexdigest()}
(pkg/'native-02/runner-gate-tests.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result))
