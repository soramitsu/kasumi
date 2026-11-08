// Both JavaScript bindings replay and check the same byte buffers.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';

const now = process.hrtime.bigint;
const elapsed = start => Number(now() - start);

export function readTrace(path) {
  const batches = [];
  const expected = new Map();
  for (const line of fs.readFileSync(path, 'utf8').trimEnd().split('\n')) {
    const batch = [];
    for (const [action, hexKey, hexValue] of JSON.parse(line).ops) {
      const key = Buffer.from(hexKey, 'hex');
      if (action === 'put') {
        const value = Buffer.from(hexValue, 'hex');
        expected.set(hexKey, {key, value});
        batch.push([key, value]);
      } else {
        assert.equal(action, 'del');
        expected.delete(hexKey);
        batch.push([key]);
      }
    }
    batches.push(batch);
  }
  const rows = [...expected.values()].sort((a, b) => Buffer.compare(a.key, b.key));
  return {batches, expected, rows};
}

export function verifyReads(db, expected, rows, report) {
  let started = now();
  for (let i = 0; i < 1024; ++i) {
    const {key, value} = rows[(i * 197) % rows.length];
    assert(db.getSync(key).equals(value));
  }
  report.point_ns = elapsed(started);
  const width = Math.min(rows.length, 8);
  for (const reverse of [false, true]) {
    started = now();
    for (let i = 0; i < 64; ++i) {
      const first = (i * 197) % (rows.length - width + 1);
      let offset = 0;
      const options = {
        start: rows[first + (reverse ? width - 1 : 0)].key,
        end: rows[first + (reverse ? 0 : width - 1)].key, reverse,
        exclusiveStart:false, inclusiveEnd:true, limit:width,
      };
      for (const {key, value} of db.getRange(options)) {
        const want = rows[first + (reverse ? width - 1 - offset : offset)];
        assert(key.equals(want.key) && value.equals(want.value));
        ++offset;
      }
      assert.equal(offset, width);
    }
    report[reverse ? 'reverse_ns' : 'forward_ns'] = elapsed(started);
  }
  const lower = Buffer.from('x\0networkSnapshots\0y-t\0BLOCK\0');
  const upper = Buffer.from('x\0networkSnapshots\0y-t\0BLOCK\x01');
  const primary = Buffer.from('d\0networkSnapshots\0');
  const latest = rows.filter(row => row.key.subarray(0, lower.length).equals(lower)).reverse().slice(0, 24);
  if (latest.length) {
    const digest = createHash('sha256');
    const samples = [];
    started = now();
    for (let round = 0; round < 64; ++round) {
      const pageStart = now();
      let offset = 0;
      const options = {start:upper,end:lower,reverse:true,limit:24};
      for (const {key, value} of db.getRange(options)) {
        assert(key.equals(latest[offset].key) && value.equals(latest[offset].value));
        const documentKey = Buffer.concat([primary,key.subarray(key.lastIndexOf(0) + 1)]);
        const document = db.getSync(documentKey);
        assert(document.equals(expected.get(documentKey.toString('hex')).value));
        if (round === 0) {
          for (const bytes of [documentKey, document]) {
            const length = Buffer.alloc(4);
            length.writeUInt32BE(bytes.length);
            digest.update(length).update(bytes);
          }
        }
        ++offset;
      }
      assert.equal(offset, latest.length);
      samples.push(elapsed(pageStart));
    }
    const total = elapsed(started);
    samples.sort((a,b) => a-b);
    report.latest_blocks = {ns:total,pages:samples.length,p50_ns:samples[31],p95_ns:samples[60],documents_per_page:latest.length,
      page_sha256:digest.digest('hex')};
  } else report.latest_blocks = null;
  let pos = 0;
  for (const {key, value} of db.getRange()) {
    assert(key.equals(rows[pos].key) && value.equals(rows[pos].value));
    ++pos;
  }
  assert.equal(pos, rows.length);
  report.verified_rows = pos;
}
