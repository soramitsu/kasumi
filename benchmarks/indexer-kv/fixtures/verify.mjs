// Offline integrity and workload-shape check for the committed Polkaswap fixture.
// Optionally pass a built indexer release to verify its actual document codec.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { gunzipSync } from 'node:zlib';

const release = process.argv[2];
const codec = release && await import(pathToFileURL(resolve(release, 'dist/src/repository/rocksdb-document.js')));
const unpack = release && createRequire(resolve(release, 'package.json'))('msgpackr').unpack;
const bytes = gunzipSync(readFileSync(new URL('./network-blocks-28280001-28284096.jsonl.gz', import.meta.url)));
const rows = bytes.toString('utf8').trimEnd().split('\n');
assert.equal(createHash('sha256').update(bytes).digest('hex'), '7dc977b532aafb42ae07c4c9aa006cc56bb90ae04110f66daef4ea7e342b43dd');
assert.equal(rows.length, 4096);
const state = new Map();
const counterValues = n => n < 128 ? Buffer.from([n]) : n < 256 ? Buffer.from([0xcc, n]) : Buffer.from([0xcd, n >> 8, n & 255]);
const hex = text => Buffer.from(text).toString('hex');
const timestampIndex = 'x\0networkSnapshots\0y-t\0BLOCK\0';
const primaryPrefix = 'd\0networkSnapshots\0';
const counters = ['m\0count\0networkSnapshots', ...['y-t', 'y-b'].map(k => 'm\0indexCount\0networkSnapshots\0' + k + '\0BLOCK')];
for (const [i, row] of rows.entries()) {
  const { ops } = JSON.parse(row);
  assert.equal(ops.length, 7);
  const height = 28280001 + i;
  const id = 'block-' + height;
  assert.equal(ops[0][1], hex(primaryPrefix + id));
  for (const [j, prefix] of ['x\0networkSnapshots\0t\0', timestampIndex, 'x\0networkSnapshots\0y-b\0BLOCK\0'].entries()) {
    const [, key, value] = ops[1 + j];
    assert(key.startsWith(hex(prefix)) && key.endsWith(hex('\0' + id)));
    assert.equal(value, '01');
  }
  for (const [j, key] of counters.entries()) {
    assert.deepEqual(ops[4 + j], ['put', hex(key), counterValues(i + 1).toString('hex')]);
  }
  if (codec) {
    const stored = unpack(Buffer.from(ops[0][2], 'hex'));
    const doc = codec.decodeRocksDocument('networkSnapshots', id, stored, 3);
    assert.equal(doc.blockHeight, height);
    assert.equal(doc.data.type, 'BLOCK');
    assert.equal(stored[0], 2);
    assert.deepEqual(codec.encodeRocksDocument(doc, 'brotli'), stored);
  }
  for (const [action, key, value] of ops) {
    assert.equal(action, 'put');
    state.set(key, value);
  }
}
// Length-prefixed binary key/value pairs: no ambiguity at record boundaries.
function digest(entries) {
  const hash = createHash('sha256');
  const size = Buffer.alloc(4);
  for (const pair of entries) for (const item of pair) {
    const data = Buffer.from(item, 'hex');
    size.writeUInt32BE(data.length);
    hash.update(size).update(data);
  }
  return hash.digest('hex');
}
const sorted = [...state.keys()].sort();
assert.equal(sorted.length, 16387);
assert.equal(digest(sorted.map(key => [key, state.get(key)])), '927fa30fb0f6f25c6d60817c53af531d8b93833da091982dd291ca72a6c8d605');
const newest = sorted.filter(key => key.startsWith(hex(timestampIndex))).reverse().slice(0, 32).map(key => {
  const suffix = Buffer.from(key, 'hex').toString().split('\0').at(-1);
  const primary = hex(primaryPrefix + suffix);
  assert(state.has(primary));
  return [primary, state.get(primary)];
});
assert.equal(digest(newest), 'b33a04eeb4b43e9d6199679d62523cc2e78fc79a7f625cecdff8991fff80d8c7');
console.log('Verified 4,096 batches, 16,387 final keys and newest 32 documents.' +
  (codec ? ' The production Brotli option leaves every document unchanged.' : ''));
