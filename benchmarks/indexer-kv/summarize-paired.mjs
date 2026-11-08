// Check retained paired evidence and summarize every round, including carry stalls.
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {gunzipSync} from 'node:zlib';

const paths = process.argv.slice(2);
if (!paths.length) throw Error('usage: node summarize-paired.mjs FILE.json[.gz] ...');
const median = xs => {
  const sorted = xs.toSorted((a, b) => a - b), i = Math.floor(sorted.length / 2);
  return (sorted[i] + sorted[Math.floor((sorted.length - 1) / 2)]) / 2;
};
for (const path of paths) {
  const contents = readFileSync(path);
  const x = JSON.parse(path.endsWith('.gz') ? gunzipSync(contents) : contents);
  assert(x.results.length && x.batches > 0 && x.expected_rows > 0);
  const stats = {};
  for (const kind of ['kasumi','rocks']) {
    const ns = [], after = [], before = [], opened = [], paid = [];
    for (const [i, round] of x.results.entries()) {
      assert.equal(round.round, i);
      const db = round.engines[kind];
      assert.equal(round.windows.reduce((n,w) => n + w.batches, 0), x.batches);
      assert.equal(round.windows.reduce((n,w) => n + w[kind + '_ns'], 0), db.ingest_ns);
      for (const phase of [db.reopened, db.after_maintenance_reopened]) {
        assert.equal(phase.rows, x.expected_rows);
        assert.equal(phase.reverse_rows, x.expected_rows);
        assert.equal(phase.state_sha256, x.expected_state_sha256);
      }
      ns.push(db.ingest_ns);
      before.push(db.after_close.allocated);
      after.push(db.after_maintenance.allocated);
      if (db.before_close) opened.push(db.before_close.allocated);
      if (db.write_close_ns !== undefined && db.maintenance_close_ns !== undefined)
        paid.push(db.ingest_ns + db.write_close_ns + db.maintenance_ns + db.maintenance_close_ns);
    }
    const rate = t => x.batches * 1e9 / t;
    stats[kind] = {median_blocks_s:median(ns.map(rate)), aggregate_blocks_s:rate(ns.reduce((a,b) => a+b)/ns.length),
      ...(paid.length === ns.length ? {aggregate_blocks_s_including_maintenance_and_closes:rate(paid.reduce((a,b) => a+b)/paid.length)} : {}),
      ...(opened.length === ns.length ? {median_allocated_before_close:median(opened)} : {}),
      median_allocated_after_close:median(before), median_allocated_after_compaction:median(after)};
  }
  const wins = x.results.filter(r => r.engines.kasumi.ingest_ns < r.engines.rocks.ingest_ns).length;
  console.log(JSON.stringify({path, rounds:x.results.length, blocks_per_sync:x.blocks_per_sync ?? 1, kasumi_won_rounds:wins, ...stats}, null, 2));
}
