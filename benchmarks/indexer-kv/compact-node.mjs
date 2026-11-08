// Use the indexer-facing Node-API addon, including JS-to-native conversion per commit.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createRequire} from 'node:module';
import {readTrace, verifyReads} from './live-js-replay.mjs';

const {LiveDatabase} = createRequire(import.meta.url)(process.env.INDEXER_KV_ADDON);
const {batches, expected, rows} = readTrace(process.env.INDEXER_KV_TRACE);
const directory = process.env.INDEXER_KV_DB;
const phase = process.env.INDEXER_KV_PHASE;
const now = process.hrtime.bigint;
const elapsed = start => Number(now() - start);
const report = {};
let started = now();
const db = phase === 'write' ? LiveDatabase.create(directory) : LiveDatabase.open(directory);
report.open_ns = elapsed(started);
try {
  if (phase === 'write') {
    started = now();
    for (const batch of batches) {
      db.commit(batch.map(([key, value]) => value === undefined ? {key} : {key, value}));
    }
    report.ingest_ns = elapsed(started);
    assert.equal(db.sequence(), BigInt(batches.length));
    report.committed_batches = batches.length;
    report.allocated_before_close = fs.readdirSync(directory).reduce((sum, name) => {
      const st = fs.lstatSync(path.join(directory, name));
      assert(st.isFile());
      return sum + st.blocks * 512;
    }, 0);
  } else if (phase === 'maintenance') {
    const before = db.sequence();
    started = now();
    db.checkpoint();
    report.maintenance_ns = elapsed(started);
    assert.equal(db.sequence(), before);
  } else {
    verifyReads({
      getSync: key => db.get(key),
      *getRange({start, end, reverse = false, exclusiveStart = false, inclusiveEnd = false, limit = Infinity} = {}) {
        let lower = reverse ? end : start;
        let upper = reverse ? start : end;
        let excludeLower = reverse ? !inclusiveEnd : exclusiveStart;
        let includeUpper = reverse ? !exclusiveStart : inclusiveEnd;
        while (limit > 0) {
          const count = Math.min(limit, 256);
          const page = db.range({
            start:lower, end:upper, startExclusive:excludeLower, endInclusive:includeUpper,
            reverse, limit:count,
          });
          yield* page;
          if (page.length < count) return;
          limit -= page.length;
          const last = page.at(-1).key;
          if (reverse) { upper = last; includeUpper = false; }
          else { lower = last; excludeLower = true; }
        }
      },
    }, expected, rows, report);
  }
} finally {
  started = now();
  db.close();
  report.close_ns = elapsed(started);
}
fs.writeFileSync(process.env.INDEXER_KV_REPORT, JSON.stringify(report));
