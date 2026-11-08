// Build and verify one offline, immutable comparison database from a byte-exact indexer trace.
// node frozen-rocks.mjs write|read TRACE_JSONL ROCKSDB_JS_PACKAGE DATABASE
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import fs from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';

const [phase, trace, packagePath, database] = process.argv.slice(2);
if (!['write', 'read'].includes(phase) || !trace || !packagePath || !database) {
  throw Error('usage: frozen-rocks.mjs write|read TRACE_JSONL ROCKSDB_JS_PACKAGE DATABASE');
}
const require = createRequire(import.meta.url);
const packageRoot = fs.realpathSync(packagePath);
const pkg = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf8'));
assert.equal(pkg.name, '@harperfast/rocksdb-js');
const { RocksDatabase } = require(packageRoot);
const indexPrefix = Buffer.from('x\0networkSnapshots\0y-t\0BLOCK\0');
const indexEnd = Buffer.from('x\0networkSnapshots\0y-t\0BLOCK\x01');
const documentPrefix = Buffer.from('d\0networkSnapshots\0');
const now = process.hrtime.bigint;
const elapsed = start => Number(now() - start);

function decode(hex, allowEmpty) {
  assert.equal(typeof hex, 'string');
  assert((allowEmpty || hex.length !== 0) && /^(?:[0-9a-f]{2})*$/.test(hex), 'invalid trace hex');
  return Buffer.from(hex, 'hex');
}

function replay(text) {
  const expected = new Map();
  for (const line of text.trimEnd().split('\n')) {
    const { ops } = JSON.parse(line);
    assert(Array.isArray(ops) && ops.length);
    for (const op of ops) {
      assert(Array.isArray(op));
      const key = decode(op[1], false);
      if (op[0] === 'put' && op.length === 3) {
        expected.set(op[1], { key, value: decode(op[2], true) });
      } else {
        assert(op[0] === 'del' && op.length === 2);
        expected.delete(op[1]);
      }
    }
  }
  assert(expected.size > 0);
  return expected;
}

function footprint(directory) {
  const result = { allocated: 0, apparent: 0, files: 0, sst_allocated: 0, sst_apparent: 0, sst_files: 0 };
  for (const name of fs.readdirSync(directory, { recursive: true })) {
    const stat = fs.lstatSync(path.join(directory, name));
    if (stat.isDirectory()) continue;
    assert(stat.isFile());
    result.allocated += stat.blocks * 512;
    result.apparent += stat.size;
    result.files++;
    if (name.endsWith('.sst')) {
      result.sst_allocated += stat.blocks * 512;
      result.sst_apparent += stat.size;
      result.sst_files++;
    }
  }
  return result;
}

function timings(samples) {
  const ordered = [...samples].sort((a, b) => a - b);
  return {
    count: samples.length,
    ns: samples.reduce((sum, x) => sum + x, 0),
    p50_ns: ordered[Math.ceil(ordered.length * 0.50) - 1],
    p95_ns: ordered[Math.ceil(ordered.length * 0.95) - 1],
  };
}

function addRow(digest, key, value) {
  for (const bytes of [key, value]) {
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    digest.update(length).update(bytes);
  }
}

function digestPage(page) {
  const digest = createHash('sha256');
  for (const { key, value } of page) addRow(digest, key, value);
  return digest.digest('hex');
}

function latestPage(db, start = indexEnd) {
  // Copy iterator buffers before advancing and closing the iterator. Hydration
  // begins only after the bounded index page has been read.
  const ids = [];
  for (const { key } of db.getRange({ start, end: indexPrefix, reverse: true, limit: 24 })) {
    assert(key.subarray(0, indexPrefix.length).equals(indexPrefix));
    ids.push(Buffer.from(key.subarray(key.lastIndexOf(0) + 1)));
  }
  return ids.map(id => {
    const key = Buffer.concat([documentPrefix, id]);
    const value = db.getSync(key);
    assert(Buffer.isBuffer(value), 'missing indexed primary');
    return { key, value };
  });
}

const source = fs.readFileSync(trace);
const expected = replay(source.toString('utf8'));
const rows = [...expected.values()].sort((a, b) => Buffer.compare(a.key, b.key));
const report = {
  engine: 'rocksdb', phase, rows: rows.length, rocksdb_js: pkg.version, rocksdb: pkg.rocksdb.version,
  trace_sha256: createHash('sha256').update(source).digest('hex'),
};
RocksDatabase.config({ blockCacheSize: 8 << 20 });
const options = { encoding: 'binary', keyEncoding: 'binary', disableWAL: false };

if (phase === 'write') {
  // Reserve the destination exclusively so a concurrent builder cannot open it.
  fs.mkdirSync(database, { mode: 0o700 });
  const start = now();
  const db = RocksDatabase.open(database, options);
  try {
    for (let first = 0; first < rows.length; first += 1024) {
      db.transactionSync(tx => {
        for (const { key, value } of rows.slice(first, first + 1024)) tx.putSync(key, value);
      });
    }
    db.flushSync();
    db.compactSync();
  } finally { db.close(); }
  report.build_ns = elapsed(start);
} else {
  assert(fs.statSync(database).isDirectory());
  const db = RocksDatabase.open(database, { ...options, readOnly: true });
  try {
    const stateDigest = createHash('sha256');
    let pos = rows.length;
    for (const { key, value } of db.getRange({reverse:true})) {
      const wanted = rows[--pos];
      addRow(stateDigest, key, value);
      assert(wanted && key.equals(wanted.key) && value.equals(wanted.value), 'ordered snapshot mismatch');
    }
    assert.equal(pos, 0);
    report.state_sha256 = stateDigest.digest('hex');
    const pointSamples = [];
    for (let i = 0; i < 1024; i++) {
      const wanted = rows[(i * 197) % rows.length];
      const start = now();
      const actual = db.getSync(wanted.key);
      pointSamples.push(elapsed(start));
      assert(actual.equals(wanted.value));
    }
    report.points = timings(pointSamples);
    const indexRows = rows.filter(row => row.key.subarray(0, indexPrefix.length).equals(indexPrefix)).reverse();
    const documents = cursor => indexRows.slice(cursor, cursor + 24).map(({ key }) => expected.get(
      Buffer.concat([documentPrefix, key.subarray(key.lastIndexOf(0) + 1)]).toString('hex'),
    ));
    const wantPage = documents(0);
    const verifyPage = (page, wanted = wantPage) => {
      assert.equal(page.length, wanted.length);
      for (let i = 0; i < page.length; i++) {
        assert(page[i].key.equals(wanted[i].key) && page[i].value.equals(wanted[i].value));
      }
    };
    verifyPage(latestPage(db));
    const samples = [];
    let page;
    for (let i = 0; i < 64; i++) {
      const start = now();
      page = latestPage(db);
      samples.push(elapsed(start));
      verifyPage(page);
    }
    report.latest_blocks = {
      ...timings(samples), pages: samples.length, documents_per_page: page.length,
      page_sha256: digestPage(page),
    };
    assert.equal(report.latest_blocks.page_sha256, digestPage(wantPage));
    const history = [];
    const historyDigest = createHash('sha256');
    for (let i = 0; i < 64; i++) {
      const cursor = Math.floor(i * (indexRows.length - 24) / 63);
      const wanted = documents(cursor);
      const start = now();
      const found = latestPage(db, indexRows[cursor].key);
      history.push(elapsed(start));
      verifyPage(found, wanted);
      for (const {key,value} of found) addRow(historyDigest,key,value);
    }
    report.historical_pages = timings(history);
    report.history_sha256 = historyDigest.digest('hex');
  } finally { db.close(); }
}
report.footprint = footprint(database);
console.log(JSON.stringify(report));
