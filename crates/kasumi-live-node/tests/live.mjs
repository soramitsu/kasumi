import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import test from 'node:test';

const addon = resolve(process.env.KASUMI_LIVE_ADDON ?? 'target/release/kasumi_live_node.node');
const { LiveDatabase } = createRequire(import.meta.url)(addon);
const buf = (value) => Buffer.from(value);
const empty = Buffer.alloc(0);

function fixture(t) {
  const directory = mkdtempSync(join(tmpdir(), 'kasumi-live-node-'));
  t.after(() => rmSync(directory, { recursive: true, force: true }));
  return join(directory, 'db');
}

test('durable ordered binary batches, bounded ranges, snapshot inputs and exclusive reopen', (t) => {
  const path = fixture(t);
  const db = LiveDatabase.create(path);
  t.after(() => db.close());
  assert.equal(db.sequence(), 0n);
  assert.throws(() => LiveDatabase.open(path));
  assert.equal(db.commit([
    { key: empty, value: empty },
    { key: buf([0]), value: buf([1]) },
    { key: buf([0, 255]), value: buf([2]) },
    { key: buf([255]), value: buf([3]) },
    { key: buf([0]) },
    { key: buf([0]), value: empty },
    { key: buf([254]) },
  ]), 1n);
  assert.deepEqual(db.get(empty), empty);
  assert.equal(db.get(buf([254])), null);
  const all = db.range({ limit: 4 });
  assert.deepEqual(all.map((row) => row.key), [empty, buf([0]), buf([0, 255]), buf([255])]);
  assert.deepEqual(all.map((row) => row.value), [empty, empty, buf([2]), buf([3])]);
  assert.deepEqual(db.range({ limit: 2, start: buf([0]), end: buf([255]), reverse: true }),
    [all[2], all[1]]);
  assert.deepEqual(db.range({ limit: 3, start: buf([0]), startExclusive: true, end: buf([255]), endInclusive: true }),
    [all[2], all[3]]);
  assert.deepEqual(db.range({ limit: 0 }), []);
  for (const limit of [-1, 1.5, 4097, NaN, Infinity]) assert.throws(() => db.range({ limit }));
  assert.throws(() => db.commit([{ key: buf([1]), value: buf('partial') }, { key: buf([2]), value: 'not binary' }]));
  assert.equal(db.get(buf([1])), null);
  assert.equal(db.sequence(), 1n);
  assert.throws(() => db.commit(Array(65_537)), /too many operations/);
  const original = buf('original');
  const entry = { get key() { original.fill(0xff); return buf('later'); }, value: empty };
  db.commit([{ key: buf('first'), value: original }, entry]);
  assert.deepEqual(db.get(buf('first')), buf('original'));
  db.checkpoint();
  db.close();
  db.close();
  assert.throws(() => db.get(empty), /closed/);
  const reopened = LiveDatabase.open(path);
  try {
    assert.equal(reopened.sequence(), 2n);
    assert.deepEqual(reopened.get(empty), empty);
    assert.deepEqual(reopened.get(buf('first')), buf('original'));
    assert.equal(reopened.commit([{ key: empty }]), 3n);
    assert.equal(reopened.get(empty), null);
  } finally {
    reopened.close();
  }
});

test('acknowledged WAL survives SIGKILL without an orderly close or checkpoint', (t) => {
  const path = fixture(t);
  const worker = spawnSync(process.execPath, ['-e', `
    const { LiveDatabase } = require(process.argv[1]);
    const db = LiveDatabase.create(process.argv[2]);
    const seq = db.commit([{ key: Buffer.from([0,255]), value: Buffer.from([0,128]) }]);
    if (seq !== 1n) process.exit(91);
    process.kill(process.pid, 'SIGKILL');
  `, addon, path], { timeout: 30_000, encoding: 'utf8' });
  assert.ifError(worker.error);
  assert.equal(worker.signal, 'SIGKILL', worker.stderr);
  const recovered = LiveDatabase.open(path);
  try {
    assert.equal(recovered.sequence(), 1n);
    assert.deepEqual(recovered.get(buf([0, 255])), buf([0, 128]));
    assert.equal(recovered.commit([{ key: buf([1]), value: empty }]), 2n);
  } finally {
    recovered.close();
  }
});

test('large eager ranges fail before returning a partial page, then bounded reads succeed', (t) => {
  const db = LiveDatabase.create(fixture(t));
  t.after(() => db.close());
  const value = Buffer.alloc(32 << 20, 7);
  db.commit([{ key: buf('a'), value }]);
  db.commit([{ key: buf('b'), value }]);
  assert.throws(() => db.range({ limit: 2 }), /range exceeds 64 MiB/);
  for (const reverse of [true, false]) {
    const [row] = db.range({ limit: 1, reverse });
    assert.deepEqual(row.key, buf(reverse ? 'b' : 'a'));
    assert.equal(row.value.length, value.length);
    assert.equal(row.value[0], 7);
  }
});
