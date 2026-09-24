from pathlib import Path
import subprocess,json,time
root=Path('/Users/mtakemiya/dev/kasumi');out=root/'target/installed-disk-validation';cargo='/Users/mtakemiya/.rustup/toolchains/1.97.1-aarch64-apple-darwin/bin/cargo'
commands=[[cargo,'fmt','--all','--','--check'],[cargo,'fmt','--manifest-path','vendor/redb-4.2.0/Cargo.toml','--all','--','--check']]
results=[]
for command in commands:
 start=time.time();result=subprocess.run(command,cwd=root);results.append({'command':command,'exit_code':result.returncode,'elapsed_seconds':time.time()-start})
(out/'160-format-phases.json').write_text(json.dumps(results,indent=2)+'\n')
raise SystemExit(max(r['exit_code'] for r in results))
