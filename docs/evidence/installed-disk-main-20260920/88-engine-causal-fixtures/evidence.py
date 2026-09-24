from pathlib import Path
import hashlib
root=Path('/Users/mtakemiya/dev/kasumi')
out=root/'target/installed-disk-validation/88-engine-causal-fixtures'
regions={
'crates/kasumi-store/src/node_disk/file.rs':[(170,230)],
'crates/kasumi-store/src/node_disk.rs':[(429,460),(495,563)],
'crates/kasumi-store/src/test_utils.rs':[(540,556)],
'crates/kasumi-engine/tests/lifecycle.rs':[(90,145),(167,190),(285,303)],
'crates/kasumi-engine/src/control.rs':[(216,238)],
'crates/kasumi-engine/src/service.rs':[(1790,1840),(1894,1920)],
'crates/kasumi-engine/src/state.rs':[(35,45),(1123,1169)],
'crates/kasumi-engine/src/lifecycle_state.rs':[(105,124)],
'crates/kasumi-engine/tests/common/recovery_control.rs':[(1375,1406),(1677,1737),(2047,2080)],
'crates/kasumi-engine/src/mutation_receipt.rs':[(150,172)],
'crates/kasumi-store/src/lib.rs':[(646,667)],
'crates/kasumi-engine/tests/schema_activation.rs':[(1150,1210)],
'crates/kasumi-engine/src/backup_verify.rs':[(135,158),(540,586)],
'crates/kasumi-engine/src/backup_restore.rs':[(335,392)],
'crates/kasumi-engine/src/snapshot_index.rs':[(143,157)],
'crates/kasumi-engine/src/snapshot_validation.rs':[(1106,1119)],
'crates/kasumi-store/src/scratch_table.rs':[(130,167)],
}
text=[]
for path,spans in regions.items():
    data=(root/path).read_bytes()
    text.append(f'{path} SHA256 {hashlib.sha256(data).hexdigest()}\n')
    lines=data.decode().splitlines()
    for start,end in spans:
        text.extend(f'{i}: {lines[i-1]}\n' for i in range(start,min(end,len(lines))+1))
    text.append('\n')
(out/'source-evidence.txt').write_text(''.join(text))
print('Saved source evidence.')
