// Compare two sealed read-only snapshots of the same final state. Does not
// import into a live system, and does not measure writable-engine durability.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const [traceArg, rocksArg, roundsArg = '3'] = process.argv.slice(2);
if (!traceArg || !rocksArg) throw Error('usage: frozen.mjs TRACE_JSONL ROCKSDB_JS_PACKAGE [READ_ROUNDS]');
const rounds = Number(roundsArg);
assert(Number.isSafeInteger(rounds) && rounds > 0 && rounds <= 100);
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, '../..');
const trace = fs.realpathSync(traceArg), rocks = fs.realpathSync(rocksArg);
const pkg = JSON.parse(fs.readFileSync(path.join(rocks, 'package.json')));
assert.equal(pkg.name,'@harperfast/rocksdb-js');
function run(cmd, args, argsExtra = {}) {
  const r = spawnSync(cmd, args, {cwd:root,encoding:'utf8',maxBuffer:32<<20,...argsExtra});
  if (r.error) throw r.error;
  if (r.status !== 0) throw Error([cmd, r.status, r.stderr, r.stdout].join('\n'));
  return r.stdout;
}
const binary = process.env.KASUMI_FROZEN_BENCH || (() => {
  const out = run('cargo', ['build','--locked','--release','-p','kasumi-frozen-run',
    '--example','polkaswap-frozen','--message-format=json'], {stdio:['ignore','pipe','inherit']});
  return out.trimEnd().split('\n').map(line => JSON.parse(line))
    .find(m => m.executable && m.target?.name === 'polkaswap-frozen').executable;
})();
const temp = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'kasumi-frozen-compare-'));
try {
  const kasumiPath = path.join(temp, 'stats.run'), rocksPath = path.join(temp, 'rocksdb');
  const kasumi = (phase, ...args) => JSON.parse(run(binary, [phase, trace, kasumiPath, ...args]));
  const rocksdb = phase => JSON.parse(run(process.execPath, [path.join(here, 'frozen-rocks.mjs'),
    phase, trace, rocks, rocksPath]));
  const sealed = kasumi('write');
  const stat = fs.statSync(kasumiPath);
  sealed.footprint = {allocated:stat.blocks*512, apparent:stat.size, files:1};
  const compacted = rocksdb('write');
  const results = [];
  let reference;
  for (let round = 0; round < rounds; round++) {
    for (const engine of round % 2 ? ['rocksdb','kasumi'] : ['kasumi','rocksdb']) {
      const read = engine === 'kasumi' ? kasumi('read', sealed.root) : rocksdb('read');
      const signature = [read.verified_rows ?? read.rows, read.state_sha256,
        read.page_sha256 ?? read.latest_blocks?.page_sha256, read.history_sha256];
      assert(signature[0] >= 24 && signature.slice(1).every(x => /^[0-9a-f]{64}$/.test(x)));
      reference ??= signature;
      assert.deepEqual(signature, reference, 'reopened result mismatch');
      results.push({engine, round, ...read});
    }
  }
  console.log(JSON.stringify({trace_sha256:createHash('sha256').update(fs.readFileSync(trace)).digest('hex'),
    benchmark:'sealed read-only history; no live writes', rounds, system:[os.type(),os.release(),os.arch()],
    node:process.version, rocksdb_js:pkg.version, rocksdb:pkg.rocksdb.version,
    binary_sha256:createHash('sha256').update(fs.readFileSync(binary)).digest('hex'),
    sealed, compacted, results},null,2));
} finally { fs.rmSync(temp,{recursive:true,force:true}); }
