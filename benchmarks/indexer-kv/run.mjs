// node benchmarks/indexer-kv/run.mjs TRACE_JSONL ABSOLUTE_ROCKSDB_JS_PACKAGE [ROUNDS] [after-ingest|inline] [fixed|lz4]
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const [traceArg, rocksArg, roundsArg = '1', kasumiMaintenance = 'after-ingest', pageFormat = 'fixed', ...extra] = process.argv.slice(2);
if (!traceArg || !rocksArg || extra.length || !['after-ingest', 'inline'].includes(kasumiMaintenance) ||
    !['fixed', 'lz4'].includes(pageFormat))
  throw Error('usage: run.mjs TRACE_JSONL ROCKSDB_JS_PACKAGE [ROUNDS] [after-ingest|inline] [fixed|lz4]');
const trace = fs.realpathSync(traceArg);
const rocks = fs.realpathSync(rocksArg);
const rounds = Number(roundsArg);
assert(Number.isSafeInteger(rounds) && rounds >= 1 && rounds <= 100);
const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../..');
const fixture = fs.readFileSync(trace);
const blocks = fixture.toString().trimEnd().split('\n').map(line => JSON.parse(line));
const validHex = value => typeof value === 'string' && /^(?:[0-9a-f]{2})*$/.test(value);
let operationCount = 0;
let inputBytes = 0;
for (const {ops} of blocks) {
  assert(Array.isArray(ops) && ops.length);
  for (const op of ops) {
    assert(Array.isArray(op) && op[1] && validHex(op[1]));
    assert((op.length === 2 && op[0] === 'del') ||
      (op.length === 3 && op[0] === 'put' && validHex(op[2])));
    operationCount++;
    inputBytes += (op[1].length + (op[2]?.length || 0)) / 2;
  }
}
const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, {cwd:repo, encoding:'utf8', maxBuffer:32 << 20, ...options});
  if (result.error) throw result.error;
  if (result.status !== 0) throw Error([command, result.status, result.stdout, result.stderr].join('\n'));
  return result.stdout;
};
function footprint(directory) {
  let allocated = 0, apparent = 0, files = 0;
  for (const name of fs.readdirSync(directory, {recursive:true})) {
    const stat = fs.lstatSync(path.join(directory, name));
    if (stat.isDirectory()) continue;
    assert(stat.isFile());
    allocated += stat.blocks * 512;
    apparent += stat.size;
    files++;
  }
  return {allocated, apparent, files};
}
const pkg = JSON.parse(fs.readFileSync(path.join(rocks, 'package.json')));
assert.equal(pkg.name, '@harperfast/rocksdb-js');
const trial = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'kasumi-indexer-bench-'));
try {
  // Point at another compatible optimized build to replay two engine revisions.
  let harness = process.env.INDEXER_KV_HARNESS;
  if (!harness) {
    const metadata = run('cargo', ['test','--locked','--release','-p','kasumi-store','--lib','--no-run',
      '--message-format=json'], {stdio:['ignore','pipe','inherit']});
    harness = metadata.trim().split('\n').map(line => JSON.parse(line))
      .find(item => item.target?.name === 'kasumi_store' && item.executable)?.executable;
  }
  assert(harness, 'could not find the Kasumi test binary');
  function freezeWorker(source, name) {
    const binary = path.join(trial, name);
    fs.copyFileSync(source, binary);
    fs.chmodSync(binary, 0o700);
    return {binary, sha256:createHash('sha256').update(fs.readFileSync(binary)).digest('hex')};
  }
  const current = freezeWorker(harness, 'kasumi-test');
  const baseline = process.env.INDEXER_KV_BASELINE_HARNESS
    ? freezeWorker(process.env.INDEXER_KV_BASELINE_HARNESS, 'kasumi-baseline-test') : undefined;
  const engines = baseline ? ['kasumi-baseline', 'kasumi', 'rocksdb'] : ['kasumi', 'rocksdb'];
  const usage = path.join(trial, 'process-usage');
  run(process.env.CC || 'cc', ['-O2',path.join(here,'process-usage.c'),'-o',usage]);
  const sync = path.join(trial,'sync.node');
  const headers = process.env.NODE_INCLUDE || path.resolve(path.dirname(process.execPath), '../include/node');
  run(process.env.CC || 'cc', ['-O2','-shared','-fPIC', ...(process.platform === 'darwin' ? ['-undefined','dynamic_lookup'] : []),
    '-I',headers,path.join(here,'sync.c'),'-o',sync]);
  const results = [];
  for (let round = 0; round < rounds; ++round) {
    // Rotate the first engine so each occupies each position once per full rotation.
    const start = round % engines.length;
    for (const engine of [...engines.slice(start), ...engines.slice(0, start)]) {
      const isBaseline = engine === 'kasumi-baseline';
      const worker = isBaseline ? baseline : current;
      const format = isBaseline ? 'fixed' : pageFormat;
      const directory = fs.mkdtempSync(path.join(trial,engine));
      const db = path.join(directory, 'group');
      const report = {engine, round};
      for (const phase of ['write','read','maintenance','reopen']) {
        const reportPath = path.join(trial, 'result.json');
        const env = {...process.env, INDEXER_KV_PHASE:phase, INDEXER_KV_DB:db, INDEXER_KV_TRACE:trace,
          INDEXER_KV_REPORT:reportPath, INDEXER_KV_ROCKS:rocks, INDEXER_KV_SYNC:sync,
          INDEXER_KV_MAINTENANCE:kasumiMaintenance, INDEXER_KV_DIRECTORY_FORMAT:format};
        const usagePath = path.join(trial, 'usage.json');
        const command = engine === 'rocksdb'
          ? [process.execPath,path.join(here,'rocks.mjs')]
          : [worker.binary,'paired_indexer_storage','--ignored','--nocapture','--test-threads=1'];
        run(usage,[usagePath,...command],{env});
        const resources = JSON.parse(fs.readFileSync(usagePath));
        fs.unlinkSync(usagePath);
        report[phase] = JSON.parse(fs.readFileSync(reportPath));
        if (engine !== 'rocksdb' && phase === 'write' &&
            (format !== 'fixed' || report[phase].directory_page_format !== undefined)) {
          assert.equal(report[phase].directory_page_format, format, 'worker did not create the selected format');
        }
        fs.unlinkSync(reportPath);
        report[phase].footprint = footprint(db);
        report[phase].process_usage = resources;
      }
      process.stderr.write(`round ${round + 1}/${rounds} ${engine}: ${report.read.verified_rows} verified rows; ${(report.write.ingest_ns / 1e9).toFixed(2)}s ingest; ${report.maintenance.footprint.allocated} bytes after maintenance\n`);
      results.push(report);
      fs.rmSync(directory, {recursive:true});
    }
  }
  for (const phase of ['read','reopen']) {
    const expected = results[0].read;
    for (const trialResult of results) {
      assert.equal(trialResult[phase].verified_rows, expected.verified_rows);
      assert.equal(trialResult[phase].latest_blocks?.page_sha256, expected.latest_blocks?.page_sha256);
    }
  }
  process.stdout.write(JSON.stringify({
    trace_sha256:createHash('sha256').update(fixture).digest('hex'),
    batches:blocks.length, operations:operationCount, logical_input_bytes:inputBytes,
    system:[os.type(), os.release(), os.arch()], node:process.version,
    kasumi_test_sha256:current.sha256,
    ...(baseline ? {kasumi_baseline_test_sha256:baseline.sha256, kasumi_baseline_directory_format:'fixed'} : {}),
    kasumi_maintenance:kasumiMaintenance, kasumi_directory_format:pageFormat,
    rocksdb_js:pkg.version, rocksdb:pkg.rocksdb.version,
    point_reads:1024, ranges_per_direction:64, max_rows_per_range:8, results,
  },null,2)+'\n');
} finally {
  fs.rmSync(trial, {recursive:true, force:true});
}
