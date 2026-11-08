// Offline integration: actual indexer GraphQL resolver, query planner, row decoder
// and checked-in wallet queries. Only the physical read binding differs.
import assert from 'node:assert/strict';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import {createRequire} from 'node:module';
import os from 'node:os';
import path from 'node:path';
import {pathToFileURL} from 'node:url';
import {gunzipSync} from 'node:zlib';

const [releaseArg, addonArg, mode, blocksArg = '4096', roundsArg = '1', ...extra] = process.argv.slice(2);
const upsert = mode === '--upsert';
const blockCount = Number(blocksArg), rounds = Number(roundsArg);
assert(Number.isSafeInteger(blockCount) && blockCount >= 1 && blockCount <= 4096);
assert(Number.isSafeInteger(rounds) && rounds >= 1 && rounds <= 100);
if (mode && !upsert) throw Error('unrecognized application replay mode');
if (!releaseArg || !addonArg || extra.length) throw Error('usage: application-stats.mjs BUILT_INDEXER_RELEASE KASUMI_ADDON [--upsert [BLOCKS [ROUNDS]]]');
const release = fs.realpathSync(releaseArg);
const addon = fs.realpathSync(addonArg);
const dep = createRequire(path.join(release, 'package.json'));
const moduleAt = name => import(pathToFileURL(path.join(release, 'dist', name)));
const {graphql} = dep('graphql');
const {unpack, Encoder} = dep('msgpackr');
const {toBufferKey, fromBufferKey} = dep('ordered-binary');
const {LiveDatabase} = dep(addon);
const {RocksRepository} = await moduleAt('src/repository/rocksdb.js');
const {decodeRocksDocument} = await moduleAt('src/repository/rocksdb-document.js');
const {createSchema} = await moduleAt('src/graphql/resolvers.js');
const {PINNED_NETWORK_VOLUME_QUERIES} = await moduleAt('tests/pinned-network-volume-fixture.js');
// Load the same ESM class imported by the release's RocksRepository constructor.
const rocksPackage = path.resolve(path.dirname(dep.resolve('@harperfast/rocksdb-js')), '..');
const rocksEntry = JSON.parse(fs.readFileSync(path.join(rocksPackage, 'package.json'))).exports['.'].import;
const {RocksDatabase} = await import(pathToFileURL(path.join(rocksPackage, rocksEntry)));
const sha = data => createHash('sha256').update(data).digest('hex');
const fixture = gunzipSync(fs.readFileSync(new URL('./fixtures/network-blocks-28280001-28284096.jsonl.gz', import.meta.url)));
const traceDigest = sha(fixture);
assert.equal(traceDigest, '7dc977b532aafb42ae07c4c9aa006cc56bb90ae04110f66daef4ea7e342b43dd');
const fixtureLines = fixture.toString('utf8').trimEnd().split('\n');
assert.equal(fixtureLines.length, 4096);
const batches = fixtureLines.slice(0, blockCount).map(line => JSON.parse(line).ops.map(([op, key, value]) => {
  assert.equal(op, 'put');
  return {key:Buffer.from(key, 'hex'), value:Buffer.from(value, 'hex')};
}));
assert.equal(batches.length, blockCount);
const docs = batches.map(([{key, value}], i) => {
  const [kind, collection, id] = fromBufferKey(key);
  assert.deepEqual([kind, collection, id], ['d', 'networkSnapshots', 'block-' + (28280001 + i)]);
  return decodeRocksDocument(collection, id, unpack(value), 3);
});
const queries = PINNED_NETWORK_VOLUME_QUERIES.filter(query => query.type === 'BLOCK' && query.positiveOnly);
assert.deepEqual(queries.map(query => query.metric).sort(), ['fees', 'volumeUSD']);
for (const query of queries) assert.equal(sha(query.query), query.querySha256);

const rawOptions = {keyEncoding:'binary', encoding:'binary', disableWAL:false};
const settings = directory => ({
  rocksdbPath:directory, rocksdbParallelism:1, rocksdbEnableStats:false,
  rocksdbBlockCacheMb:8, rocksdbWriteBufferManagerMb:16, rocksdbDocumentCompression:'brotli',
  rocksdbWatchQueueMax:64, rocksdbQueryMaxScannedRows:100_000,
  rocksdbDocumentCacheMax:0, rocksdbDocumentCacheMaxBytes:0,
});

async function seed(rocksDir, liveDir) {
  // Obtain the exact current format/index metadata from the real empty
  // repository. No recovery-admission or entitlement records are fabricated.
  const bootstrap = new RocksRepository(settings(rocksDir));
  try { await bootstrap.prepare(); } finally { await bootstrap.close(); }
  const rocks = RocksDatabase.open(rocksDir, rawOptions);
  try {
    const live = LiveDatabase.create(liveDir);
    try {
      const metadata = Array.from(rocks.getRange(), ({key, value}) => ({key:Buffer.from(key), value:Buffer.from(value)}));
      assert(metadata.length > 0 && metadata.every(({key}) => fromBufferKey(key)[0] === 'm'));
      live.commit(metadata);
      for (let i = 0; i < batches.length; i += 64) {
        const group = batches.slice(i, i + 64);
        for (const batch of group) {
          rocks.transactionSync(tx => { for (const {key, value} of batch) tx.putSync(key, value); });
        }
        live.commitGroup(group);
      }
      rocks.flushSync();
      rocks.compactSync();
      live.checkpoint();
    } finally { live.close(); }
  } finally { rocks.close(); }
}

// This read-only view implements the physical methods reached by this real
// repository query, including its preparation/metadata checks. Unknown methods
// fail instead of falling back to RocksDB or an in-memory copy of the fixture.
function physicalReads(db, evidence) {
  let open = true;
  return {
    close() { db.close(); open = false; },
    isOpen() { return open; },
    getSync(key) {
      const value = db.get(toBufferKey(key));
      if (key[0] === 'd' && key[1] === 'networkSnapshots' && value !== null) evidence.primaryReads++;
      return value === null ? undefined : unpack(value);
    },
    *getRange({start, end, reverse = false, exclusiveStart = false, inclusiveEnd = false, values = true, limit = Infinity, ...other} = {}) {
      assert.deepEqual(Object.keys(other), [], 'unexpected repository range options');
      const lower = reverse ? end : start, upper = reverse ? start : end;
      const options = {reverse, start:lower && Buffer.from(toBufferKey(lower)), end:upper && Buffer.from(toBufferKey(upper)),
        startExclusive:reverse ? !inclusiveEnd : exclusiveStart, endInclusive:reverse ? !exclusiveStart : inclusiveEnd};
      while (limit > 0) {
        const count = Math.min(limit, 128);
        const rows = db.range({...options, limit:count});
        for (const row of rows) {
          const key = fromBufferKey(row.key);
          if (reverse && key[0] === 'x' && key[1] === 'networkSnapshots') evidence.reverseIndexRows++;
          yield {key, value:values ? unpack(row.value) : undefined};
        }
        if (rows.length < count) return;
        limit -= count;
        const last = rows.at(-1).key;
        if (reverse) { options.end = last; options.endInclusive = false; }
        else { options.start = last; options.startExclusive = true; }
      }
    },
  };
}

function openWithBinding(directory, readOnly, binding) {
  const nativeOpen = RocksDatabase.open;
  let intercepted = false;
  // Inject only during synchronous construction. The repository, codecs,
  // metadata gates, query planner and GraphQL schema execute unmodified.
  RocksDatabase.open = (requested, options) => {
    assert.equal(requested, directory);
    assert.equal(options.readOnly, readOnly);
    assert.equal(intercepted, false);
    intercepted = true;
    return binding(requested, options, nativeOpen.bind(RocksDatabase));
  };
  try {
    const repository = new RocksRepository(settings(directory), {readOnly});
    assert(intercepted, 'indexer did not use the injected physical binding');
    return repository;
  } finally { RocksDatabase.open = nativeOpen; }
}

function openKasumiRepository(directory, evidence) {
  return openWithBinding(directory, true, () => physicalReads(LiveDatabase.open(directory), evidence));
}

async function queryBackend(repository, evidence) {
  try {
    await repository.prepare();
    const schema = createSchema();
    const outcomes = {};
    for (const entry of queries) {
      const before = evidence && {...evidence};
      const variables = {after:null, type:'BLOCK', from:docs.at(-1).timestamp, to:docs[0].timestamp};
      const response = await graphql({schema, source:entry.query, variableValues:variables, contextValue:{repository}});
      assert.equal(response.errors, undefined, JSON.stringify(response.errors));
      const data = JSON.parse(JSON.stringify(response.data.data));
      const actual = data.edges.map(({node}) => [node.timestamp, String(node[entry.metric])]);
      // Expect all positive decimal values, ordered from latest to earliest,
      // independently of either query path. No floating-point amount conversion.
      const expected = docs.filter(doc => {
        const raw = String(doc.data[entry.metric]);
        assert(/^\d+(?:\.\d+)?$/.test(raw), 'unexpected unsigned decimal field');
        return /[1-9]/.test(raw);
      }).sort((a, b) => b.timestamp - a.timestamp).map(doc => [doc.timestamp, String(doc.data[entry.metric])]);
      if (blockCount === 4096) assert.equal(expected.length, entry.metric === 'fees' ? 7 : 1);
      assert.deepEqual(actual, expected, entry.operation);
      assert.equal(data.pageInfo.hasNextPage, false);
      if (evidence) {
        assert(evidence.primaryReads > before.primaryReads, 'Kasumi did not hydrate documents for this query');
        assert(evidence.reverseIndexRows > before.reverseIndexRows, 'Kasumi did not traverse its descending secondary index');
      }
      outcomes[entry.operation] = {query_sha256:entry.querySha256, rows:actual.length, response_sha256:sha(JSON.stringify(data))};
    }
    return outcomes;
  } finally { await repository.close(); }
}

const trial = fs.mkdtempSync(path.join(os.tmpdir(), 'kasumi-application-stats-'));
try {
  const rocks = path.join(trial, 'rocks');
  const live = path.join(trial, 'kasumi');
  async function verify(rocksDir, liveDir) {
    const reference = await queryBackend(RocksRepository.openReadOnly(settings(rocksDir)));
    const evidence = {primaryReads:0, reverseIndexRows:0};
    const candidate = await queryBackend(openKasumiRepository(liveDir, evidence), evidence);
    assert.deepEqual(candidate, reference);
    return {verified:candidate, kasumi_reads:evidence};
  }
  let outcome;
  if (upsert) {
    const {measureUpserts} = await import('./application-upsert.mjs');
    outcome = await measureUpserts({trial, rounds, docs, batches, RocksDatabase, LiveDatabase,
      Encoder, unpack, toBufferKey, settings, physicalReads, openWithBinding, verify, dep});
  } else {
    await seed(rocks, live);
    outcome = await verify(rocks, live);
  }
  const modules = Object.fromEntries(['src/graphql/resolvers.js','src/repository/rocksdb.js','src/repository/rocksdb-document.js']
    .map(name => [name, sha(fs.readFileSync(path.join(release, 'dist', name)))]));
  const versions = {};
  for (const name of ['@harperfast/rocksdb-js','graphql','msgpackr','ordered-binary']) {
    let dir = path.dirname(dep.resolve(name));
    while (dir !== path.dirname(dir)) {
      const pkgFile = path.join(dir, 'package.json');
      if (fs.existsSync(pkgFile)) {
        const pkg = JSON.parse(fs.readFileSync(pkgFile));
        if (pkg.name === name) {
          versions[name] = pkg.version;
          if (pkg.rocksdb) versions.rocksdb = pkg.rocksdb.version;
          break;
        }
      }
      dir = path.dirname(dir);
    }
    assert(versions[name], 'missing version of ' + name);
  }
  const rocksAddon = Object.keys(dep.cache).find(file => path.basename(file) === 'rocksdb-js.node');
  assert(rocksAddon, 'installed Rocks native library not identified');
  const driver = Object.fromEntries(['application-stats.mjs','application-upsert.mjs','rocks-durable.mjs','sync.c']
    .map(name => [name, sha(fs.readFileSync(new URL(name, import.meta.url)))]));
  console.log(JSON.stringify({node:process.version, node_abi:process.versions.modules, platform:process.platform, arch:process.arch,
    versions, rocks_addon_sha256:sha(fs.readFileSync(rocksAddon)), driver, trace_sha256:traceDigest, addon_sha256:sha(fs.readFileSync(addon)), modules,
    blocks:batches.length, ...outcome}, null, 2));
} finally { fs.rmSync(trial, {recursive:true, force:true}); }
