// Raw ordered bytes from the indexer's installed native binding, one transaction per block.
import assert from 'node:assert/strict';
import {readTrace, verifyReads} from './live-js-replay.mjs';
import {durableRocksWriter} from './rocks-durable.mjs';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';

const require = createRequire(import.meta.url);
const syncFile = require(process.env.INDEXER_KV_SYNC);
const {RocksDatabase} = require(process.env.INDEXER_KV_ROCKS);
const dbPath = process.env.INDEXER_KV_DB;
const writer = process.env.INDEXER_KV_PHASE === 'write';
const elapsed = (started) => Number(process.hrtime.bigint() - started);
const now = process.hrtime.bigint;
const {batches, expected, rows} = readTrace(process.env.INDEXER_KV_TRACE);
RocksDatabase.config({blockCacheSize: 8 << 20});
const report = {};
let started = now();
if (writer) assert(!fs.existsSync(dbPath), 'benchmark requires a fresh database');
const db = RocksDatabase.open(dbPath, {encoding:'binary', keyEncoding:'binary', disableWAL:false});
if (writer) {
  const durable = durableRocksWriter(db, dbPath, syncFile);
  try {
    started = now();
    for (const batch of batches) durable.commit(batch);
    report.ingest_ns = elapsed(started);
    report.device_syncs = batches.length;
    durable.verify();
  } finally { durable.close(); }
} else if (process.env.INDEXER_KV_PHASE === 'maintenance') {
  started = now();
  db.flushSync();
  db.compactSync();
  report.maintenance_ns = elapsed(started);
  report.reason = 'completed';
} else {
  report.open_ns = elapsed(started);
  verifyReads(db, expected, rows, report);
}
if (writer) {
  report.allocated_before_close = fs.readdirSync(dbPath, {recursive:true})
    .map(name => fs.lstatSync(path.join(dbPath,name)))
    .filter(stat => stat.isFile()).reduce((sum,stat) => sum + stat.blocks * 512, 0);
}
started = now();
db.close();
report.close_ns = elapsed(started);
fs.writeFileSync(process.env.INDEXER_KV_REPORT, JSON.stringify(report));
