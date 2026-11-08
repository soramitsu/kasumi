// node paired-node.mjs TRACE_JSONL ROCKSDB_JS_PACKAGE KASUMI_ADDON [SYNC_ADDON|auto] [ROUNDS]
// With "auto", CC and NODE_INCLUDE control the compiler and Node-API headers for sync.c.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import {createRequire} from 'node:module';
import os from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {readTrace} from './live-js-replay.mjs';
import {durableRocksWriter} from './rocks-durable.mjs';

const [traceArg, rocksArg, addonArg, syncArg = 'auto', roundsArg = '1', ...extra] = process.argv.slice(2);
if (!traceArg || !rocksArg || !addonArg || extra.length)
  throw Error('usage: paired-node.mjs TRACE_JSONL ROCKSDB_JS_PACKAGE KASUMI_ADDON [SYNC_ADDON|auto] [ROUNDS]');
const rounds = Number(roundsArg);
assert(Number.isSafeInteger(rounds) && rounds >= 1 && rounds <= 100);
const trace = fs.realpathSync(traceArg);
const packagePath = fs.realpathSync(rocksArg);
const packageInfo = JSON.parse(fs.readFileSync(path.join(packagePath, 'package.json')));
assert.equal(packageInfo.name, '@harperfast/rocksdb-js');
const require = createRequire(import.meta.url);
const {RocksDatabase} = require(packagePath);
const addon = fs.realpathSync(addonArg);
const rocksBinary = Object.keys(require.cache).find(file => path.basename(file) === 'rocksdb-js.node');
assert(rocksBinary, 'installed Rocks native binary could not be identified');
let LiveDatabase;
const {batches, rows} = readTrace(trace);
assert(rows.length && batches.length, 'expected a nonempty trace with final rows');
const windowSize = 64;
const now = process.hrtime.bigint;
const elapsed = start => Number(now() - start);
const shaFile = file => createHash('sha256').update(fs.readFileSync(file)).digest('hex');
const rocksOptions = {encoding:'binary', keyEncoding:'binary', disableWAL:false};
RocksDatabase.config({blockCacheSize:8 << 20});

function digestRow(hash, {key, value}) {
  for (const field of [key, value]) {
    const length = Buffer.allocUnsafe(4);
    length.writeUInt32BE(field.length);
    hash.update(length).update(field);
  }
}
const expected = createHash('sha256');
for (const row of rows) digestRow(expected, row);
const expectedDigest = expected.digest('hex');

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

// A full traversal must also exercise native pagination across the Node result bound.
function* liveRows(db, reverse) {
  const options = {reverse, limit:256};
  for (;;) {
    const page = db.range(options);
    yield* page;
    if (page.length < options.limit) return;
    if (reverse) options.end = page.at(-1).key;
    else { options.start = page.at(-1).key; options.startExclusive = true; }
  }
}

function recover(directory, kind) {
  const kasumi = kind === 'kasumi';
  const db = kasumi ? LiveDatabase.open(directory) : RocksDatabase.open(directory, rocksOptions);
  try {
    if (kasumi) assert.equal(db.sequence(), BigInt(batches.length));
    for (const row of rows) {
      const value = kasumi ? db.get(row.key) : db.getSync(row.key);
      assert(value && row.value.equals(value), 'recovered point value mismatch');
    }
    const hash = createHash('sha256');
    for (const reverse of [false, true]) {
      const stream = kasumi ? liveRows(db, reverse) : db.getRange({reverse});
      let count = 0;
      for (const row of stream) {
        const index = reverse ? rows.length - count - 1 : count;
        assert(rows[index]?.key.equals(row.key) && rows[index].value.equals(row.value),
          'recovered ordered row mismatch');
        if (!reverse) digestRow(hash, row);
        count++;
      }
      assert.equal(count, rows.length, 'recovered row count mismatch');
    }
    const digest = hash.digest('hex');
    assert.equal(digest, expectedDigest);
    return {rows:rows.length, reverse_rows:rows.length, state_sha256:digest};
  } finally { db.close(); }
}

function runRound(directory, round, syncFile) {
  const dirs = Object.fromEntries(['kasumi','rocks'].map(kind => [kind, path.join(directory, kind)]));
  fs.mkdirSync(directory);
  const windows = [];
  const totals = {kasumi:0, rocks:0};
  const kasumi = LiveDatabase.create(dirs.kasumi);
  try {
    const rocks = RocksDatabase.open(dirs.rocks, rocksOptions);
    try {
      const durable = durableRocksWriter(rocks, dirs.rocks, syncFile);
      try {
        for (let first = 0; first < batches.length; first += windowSize) {
          const order = (windows.length + round) % 2 === 0 ? ['kasumi','rocks'] : ['rocks','kasumi'];
          const end = Math.min(first + windowSize, batches.length);
          const window = {first_batch:first, batches:end - first, order};
          for (const kind of order) {
            const started = now();
            if (kind === 'kasumi') {
              for (let i = first; i < end; i++)
                kasumi.commit(batches[i].map(([key, value]) => value === undefined ? {key} : {key, value}));
            } else {
              for (let i = first; i < end; i++) durable.commit(batches[i]);
            }
            const ns = elapsed(started);
            window[kind + '_ns'] = ns;
            totals[kind] += ns;
          }
          windows.push(window);
        }
        durable.verify();
        assert.equal(kasumi.sequence(), BigInt(batches.length));
      } finally { durable.close(); }
    } finally { rocks.close(); }
  } finally { kasumi.close(); }
  const engines = {};
  for (const kind of ['kasumi','rocks']) {
    const dbPath = dirs[kind];
    const engine = {ingest_ns:totals[kind], after_close:footprint(dbPath)};
    engine.reopened = recover(dbPath, kind);
    const db = kind === 'kasumi' ? LiveDatabase.open(dbPath) : RocksDatabase.open(dbPath, rocksOptions);
    try {
      const started = now();
      if (kind === 'kasumi') db.checkpoint();
      else { db.flushSync(); db.compactSync(); }
      engine.maintenance_ns = elapsed(started);
    } finally { db.close(); }
    engine.after_maintenance = footprint(dbPath);
    engine.after_maintenance_reopened = recover(dbPath, kind);
    engines[kind] = engine;
  }
  return {round, windows, engines};
}

const trial = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'kasumi-node-paired-'));
try {
  const frozenAddon = path.join(trial, 'kasumi-live.node');
  fs.copyFileSync(addon, frozenAddon);
  ({LiveDatabase} = require(frozenAddon));
  const sync = syncArg === 'auto' ? path.join(trial, 'sync.node') : fs.realpathSync(syncArg);
  if (syncArg === 'auto') {
    const headers = process.env.NODE_INCLUDE || path.resolve(path.dirname(process.execPath), '../include/node');
    execFileSync(process.env.CC || 'cc', ['-O2', '-shared', '-fPIC',
      ...(process.platform === 'darwin' ? ['-undefined', 'dynamic_lookup'] : []),
      '-I', headers, fileURLToPath(new URL('./sync.c', import.meta.url)), '-o', sync]);
  }
  const syncFile = require(sync);
  const results = [];
  for (let round = 0; round < rounds; round++) {
    const directory = path.join(trial, String(round));
    results.push(runRound(directory, round, syncFile));
    fs.rmSync(directory, {recursive:true});
  }
  console.log(JSON.stringify({
    node:process.version, platform:process.platform, arch:process.arch,
    rocksdb_js:packageInfo.version, rocksdb:packageInfo.rocksdb.version,
    trace_sha256:shaFile(trace), addon_sha256:shaFile(frozenAddon), rocks_addon_sha256:shaFile(rocksBinary), sync_sha256:shaFile(sync),
    window_size:windowSize, batches:batches.length, expected_rows:rows.length,
    expected_state_sha256:expectedDigest, results,
  }, null, 2));
} finally { fs.rmSync(trial, {recursive:true, force:true}); }
