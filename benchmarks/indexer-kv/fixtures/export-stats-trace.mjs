// Export a BLOCK history slice from an indexer's RocksDB in native read-only mode.
// stdout is JSONL: one insertion transaction per finalized block in an initially empty slice.
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { once } from 'node:events';
import { createRequire } from 'node:module';

const [release, databasePath, firstArg, countArg] = process.argv.slice(2);
const first = Number(firstArg);
const count = Number(countArg);
if (!release || !databasePath || !Number.isSafeInteger(first) || first < 1 ||
    !Number.isSafeInteger(count) || count < 1 || count > 100_000 || !Number.isSafeInteger(first + count)) {
  throw Error('Usage: node export-stats-trace.mjs INDEXER_RELEASE ROCKSDB_DIRECTORY FIRST_HEIGHT COUNT (1..100000)');
}
const require = createRequire(pathToFileURL(resolve(release, 'package.json')));
const { pack } = require('msgpackr');
// Load the same ESM edition as the repository. Loading both native entry points installs duplicate hooks.
const { RocksDatabase } = await import(pathToFileURL(resolve(require.resolve('@harperfast/rocksdb-js'), '../index.mjs')));
const { decodeRocksDocument } = await import(pathToFileURL(resolve(release, 'dist/src/repository/rocksdb-document.js')));
const { rocksCompactIndexKeysForDocument } = await import(pathToFileURL(resolve(release, 'dist/src/repository/rocksdb.js')));
const db = RocksDatabase.open(resolve(databasePath), { readOnly: true });
const collection = 'networkSnapshots';
const fields = new Set(('type accounts transactions fees liquidityUSD poolLiquidityUSD orderBookLiquidityUSD volumeUSD swaps ' +
  'activePools activeOrderBooks listedAssets bridgeIncomingTransactions bridgeOutgoingTransactions accountCountAvailable id timestamp blockHeight').split(' '));

function keyHex(key) {
  const encoded = db.store.encodeKey(key);
  return encoded.subarray(0, encoded.end).toString('hex');
}

function storedPut(key) {
  const encoded = db.getBinarySync(key);
  if (!Buffer.isBuffer(encoded) || !encoded.length) throw Error('Expected an existing encoded network snapshot or index entry');
  return ['put', keyHex(key), encoded.toString('hex')];
}

try {
  const version = db.getSync(['m', 'metadata', 'rocksdbFormatVersion']);
  if (version !== 2 && version !== 3) throw Error('Unsupported source format');
  let lastTime = 0;
  for (let i = 0; i < count; i++) {
    const height = first + i;
    const id = 'block-' + height;
    const key = ['d', collection, id];
    const doc = decodeRocksDocument(collection, id, db.getSync(key), version);
    if (doc?.blockHeight !== height || doc.data.type !== 'BLOCK' || !Number.isSafeInteger(doc.timestamp) ||
        doc.timestamp < lastTime || Object.entries(doc.data).some(([k, v]) =>
          !fields.has(k) || (v !== null && !['number', 'string', 'boolean'].includes(typeof v)))) {
      throw Error('Missing or unexpected BLOCK snapshot at height ' + height);
    }
    lastTime = doc.timestamp;
    const indexes = rocksCompactIndexKeysForDocument(doc);
    if (indexes.length !== 3 || indexes.some(k => k[0] !== 'x' || k[1] !== collection || k.at(-1) !== id)) {
      throw Error('Unexpected network snapshot index layout');
    }
    const ops = [storedPut(key), ...indexes.map(storedPut)];
    // Count keys belong to this isolated slice; production totals include earlier and other snapshot types.
    // Encode only the counter value. The native store encoder may return a reusable buffer.
    const countValue = Buffer.from(pack(i + 1)).toString('hex');
    if (countValue.length > 10 || db.store.decodeValue(Buffer.from(countValue, 'hex')) !== i + 1) {
      throw Error('Unexpected integer encoding');
    }
    for (const counter of [['m','count',collection], ['m','indexCount',collection,'y-t','BLOCK'],
                           ['m','indexCount',collection,'y-b','BLOCK']]) {
      ops.push(['put', keyHex(counter), countValue]);
    }
    if (!process.stdout.write(JSON.stringify({ ops }) + '\n')) await once(process.stdout, 'drain');
  }
} finally {
  await db.close();
}
