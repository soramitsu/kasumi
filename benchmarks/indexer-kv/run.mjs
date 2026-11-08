// node benchmarks/indexer-kv/run.mjs TRACE_JSONL ROCKSDB_JS_PACKAGE [ROUNDS] [after-ingest|inline] [fixed|lz4|compact]
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import {spawnSync} from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

const [traceArg, rocksArg, roundsArg = '1', kasumiMaintenance = 'after-ingest', pageFormat = 'fixed', ...extra] = process.argv.slice(2);
if (!traceArg || !rocksArg || extra.length || !['after-ingest', 'inline'].includes(kasumiMaintenance) ||
    !['fixed', 'lz4', 'compact'].includes(pageFormat))
  throw Error('usage: run.mjs TRACE_JSONL ROCKSDB_JS_PACKAGE [ROUNDS] [after-ingest|inline] [fixed|lz4|compact]');
const compact = pageFormat === 'compact';
if (compact && kasumiMaintenance !== 'inline') throw Error('compact replay requires inline maintenance');
if (!compact && (process.env.INDEXER_KV_NATIVE_ROCKS || process.env.INDEXER_KV_ADDON))
  throw Error('the optional live comparators require compact mode');
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
const finalRows = new Map();
for (const {ops} of blocks) {
  assert(Array.isArray(ops) && ops.length);
  for (const op of ops) {
    assert(Array.isArray(op) && op[1] && validHex(op[1]));
    assert((op.length === 2 && op[0] === 'del') ||
      (op.length === 3 && op[0] === 'put' && validHex(op[2])));
    operationCount++;
    inputBytes += (op[1].length + (op[2]?.length || 0)) / 2;
    if (op[0] === 'put') finalRows.set(op[1], op[2]);
    else finalRows.delete(op[1]);
  }
}
assert(finalRows.size, 'trace must leave at least one live row');
const orderedKeys = [...finalRows.keys()].sort(); // Lowercase hex preserves unsigned byte order.
function digestRow(hash, keyHex, valueHex) {
  for (const field of [keyHex, valueHex]) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(field.length / 2);
    hash.update(length).update(Buffer.from(field, 'hex'));
  }
}
const stateHash = createHash('sha256');
for (const key of orderedKeys) digestRow(stateHash, key, finalRows.get(key));
const expectedState = stateHash.digest('hex');
const prefix = Buffer.from('x\0networkSnapshots\0y-t\0BLOCK\0').toString('hex');
const primary = Buffer.from('d\0networkSnapshots\0');
const latest = orderedKeys.filter(key => key.startsWith(prefix)).reverse().slice(0, 24);
const pageHash = createHash('sha256');
for (const key of latest) {
  const marker = Buffer.from(key, 'hex');
  const document = Buffer.concat([primary, marker.subarray(marker.lastIndexOf(0) + 1)]).toString('hex');
  assert(finalRows.has(document), 'timestamp index refers to a missing document');
  digestRow(pageHash, document, finalRows.get(document));
}
const expectedPage = latest.length ? pageHash.digest('hex') : undefined;
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
  let harness = compact ? process.env.INDEXER_KV_LIVE_HARNESS : process.env.INDEXER_KV_HARNESS;
  if (!harness) {
    const args = compact
      ? ['build','--locked','--release','-p','kasumi-frozen-run','--example','polkaswap-live']
      : ['test','--locked','--release','-p','kasumi-store','--lib','--no-run'];
    const metadata = run('cargo', [...args,'--message-format=json'], {stdio:['ignore','pipe','inherit']});
    harness = metadata.trim().split('\n').map(line => JSON.parse(line))
      .find(item => item.target?.name === (compact ? 'polkaswap-live' : 'kasumi_store') && item.executable)?.executable;
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
  const addon = process.env.INDEXER_KV_ADDON ? freezeWorker(process.env.INDEXER_KV_ADDON, 'kasumi-live.node') : undefined;
  const nativeRocks = process.env.INDEXER_KV_NATIVE_ROCKS
    ? freezeWorker(process.env.INDEXER_KV_NATIVE_ROCKS, 'rocksdb-native') : undefined;
  const nativeInput = nativeRocks
    ? (await import('./native-live-input.mjs')).prepareNativeInput(blocks, trial) : undefined;
  const engines = [...(baseline ? ['kasumi-baseline'] : []), compact ? 'kasumi-live' : 'kasumi', 'rocksdb',
    ...(addon ? ['kasumi-node'] : []), ...(nativeRocks ? ['rocksdb-native'] : [])];
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
        let command;
        if (engine === 'rocksdb') {
          command = [process.execPath,path.join(here,'rocks.mjs')];
        } else if (engine === 'kasumi-node') {
          env.INDEXER_KV_ADDON = addon.binary;
          command = [process.execPath,path.join(here,'compact-node.mjs')];
        } else if (engine === 'rocksdb-native') {
          const action = phase === 'write' ? 'live-write' : phase === 'maintenance' ? 'live-compact' : 'live-read';
          command = [nativeRocks.binary,action,nativeInput.rows,db,'lz4_32k'];
          if (phase === 'write') command.push(nativeInput.batches);
        } else if (engine === 'kasumi-live') {
          command = [worker.binary];
        } else {
          command = [worker.binary,'paired_indexer_storage','--ignored','--nocapture','--test-threads=1'];
        }
        run(usage,[usagePath,...command],{env});
        const resources = JSON.parse(fs.readFileSync(usagePath));
        fs.unlinkSync(usagePath);
        report[phase] = JSON.parse(fs.readFileSync(reportPath));
        if ((engine === 'kasumi' || isBaseline) && phase === 'write' &&
            (format !== 'fixed' || report[phase].directory_page_format !== undefined)) {
          assert.equal(report[phase].directory_page_format, format, 'worker did not create the selected format');
        }
        if (engine === 'kasumi-live' && phase === 'write') {
          assert.equal(report.write.committed_batches, blocks.length);
          assert.equal(report.write.committed_operations, operationCount);
          assert.equal(report.write.inline_maintenance, true);
          assert(report.write.device_syncs >= blocks.length);
        }
        if (engine === 'rocksdb-native' && phase === 'write') assert(report.write.rocksdb);
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
    for (const trialResult of results) {
      const result = trialResult[phase];
      assert.equal(result.verified_rows, finalRows.size);
      assert.equal(result.latest_blocks?.page_sha256, expectedPage);
      if (trialResult.engine === 'kasumi-live' || result.state_sha256 !== undefined) {
        assert.equal(result.state_sha256, expectedState);
      }
    }
  }
  process.stdout.write(JSON.stringify({
    trace_sha256:createHash('sha256').update(fixture).digest('hex'),
    batches:blocks.length, operations:operationCount, logical_input_bytes:inputBytes,
    system:[os.type(), os.release(), os.arch()], node:process.version,
    ...(compact ? {kasumi_live_sha256:current.sha256} : {kasumi_test_sha256:current.sha256}),
    ...(addon ? {kasumi_node_sha256:addon.sha256} : {}),
    ...(nativeRocks ? {rocksdb_native_sha256:nativeRocks.sha256,
      rocksdb_native_version:results.find(row => row.engine === 'rocksdb-native').write.rocksdb} : {}),
    ...(baseline ? {kasumi_baseline_test_sha256:baseline.sha256, kasumi_baseline_directory_format:'fixed'} : {}),
    kasumi_maintenance:kasumiMaintenance, ...(compact ? {kasumi_engine:'compact'} : {kasumi_directory_format:pageFormat}),
    expected_state_sha256:expectedState,
    rocksdb_js:pkg.version, rocksdb:pkg.rocksdb.version,
    point_reads:1024, ranges_per_direction:64, max_rows_per_range:8, results,
  },null,2)+'\n');
} finally {
  fs.rmSync(trial, {recursive:true, force:true});
}
