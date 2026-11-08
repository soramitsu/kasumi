// Opt-in physical transaction adapter for the BLOCK document integration runner.
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {durableRocksWriter} from './rocks-durable.mjs';

function loadSync(trial, dep) {
  const out = process.env.INDEXER_KV_SYNC ? fs.realpathSync(process.env.INDEXER_KV_SYNC) : path.join(trial, 'sync.node');
  const headers = process.env.NODE_INCLUDE || path.resolve(path.dirname(process.execPath), '../include/node');
  if (!process.env.INDEXER_KV_SYNC) execFileSync(process.env.CC || 'cc', ['-O2','-shared','-fPIC',...(process.platform === 'darwin' ? ['-undefined','dynamic_lookup'] : []),
    '-I',headers,fileURLToPath(new URL('./sync.c', import.meta.url)), '-o',out]);
  return {syncFile:dep(out), digest:createHash('sha256').update(fs.readFileSync(out)).digest('hex')};
}

function allocated(directory) {
  let bytes = 0;
  for (const name of fs.readdirSync(directory, {recursive:true})) {
    const stat = fs.lstatSync(path.join(directory, name));
    if (stat.isFile()) bytes += stat.blocks * 512;
  }
  return bytes;
}

function stageTransactions(db, reads, encoder, toBufferKey, unpack, receipts) {
  return {...reads,
    // Setup calls flush after confirming its maintenance scan. Every actual
    // mutation already awaited a durable commit.
    async flush() {},
    async transaction(callback) {
      const operations = [];
      const pending = new Map();
      let bytes = 0;
      function stage(key, value) {
        const id = key.toString('hex');
        bytes += key.length + (value?.length ?? 0);
        if (operations.length >= 65_536 || bytes > (64 << 20)) throw Error('repository transaction exceeded adapter limits');
        operations.push(value === undefined ? {key} : {key,value});
        pending.set(id, value);
      }
      const result = await callback({
        getSync(key) {
          const id = toBufferKey(key).toString('hex');
          if (!pending.has(id)) return reads.getSync(key);
          const value = pending.get(id);
          return value === undefined ? undefined : unpack(value);
        },
        getRange(options) {
          assert.equal(operations.length, 0, 'this fixture has no transactional scans after a staged mutation');
          return reads.getRange(options);
        },
        async put(key, value) {
          // The installed binding requests a reusable MessagePack buffer and
          // passes only its encoded [start,end) region to the native store.
          const data = encoder.encode(value, 1536);
          stage(Buffer.from(toBufferKey(key)), Buffer.from(data.subarray(data.start, data.end)));
        },
        async remove(key) { stage(Buffer.from(toBufferKey(key)), undefined); },
      });
      // A failed callback discards the staged changes. Each upsertMany call
      // contributes one accepted sequence, irrespective of its mutation count.
      if (operations.length) {
        db.commit(operations);
        receipts.commits++;
        receipts.mutations += operations.length;
      }
      return result;
    },
  };
}

function verifyRaw(rocks, live, expected, unpack) {
  const hash = createHash('sha256');
  const cursor = rocks.getRange()[Symbol.iterator]();
  let start, rows = 0, payloads = 0;
  do {
    const page = live.range({start, startExclusive:start !== undefined, limit:256});
    for (const row of page) {
      const reference = cursor.next();
      assert(!reference.done && row.key.equals(reference.value.key), 'physical key mismatch');
      assert(row.value.equals(reference.value.value), 'backend physical value mismatch');
      const fixtureValue = expected.get(row.key.toString('hex'));
      if (fixtureValue !== undefined) {
        // Fresh production writes may encode the same MessagePack object with
        // different record-table bytes. Validate the source value as decoded.
        assert.deepEqual(unpack(row.value), unpack(fixtureValue), 'application value differs from fixture');
        payloads++;
      }
      for (const bytes of [row.key, row.value]) {
        const length = Buffer.allocUnsafe(4);
        length.writeUInt32BE(bytes.length);
        hash.update(length).update(bytes);
      }
      rows++;
    }
    start = page.length === 256 ? page.at(-1).key : undefined;
  } while (start !== undefined);
  assert(cursor.next().done, 'extra Rocks rows');
  assert.equal(payloads, expected.size);
  return {physical_rows:rows, fixture_rows:payloads, state_sha256:hash.digest('hex')};
}

export async function measureUpserts({trial, rounds, docs, batches, RocksDatabase, LiveDatabase, Encoder, unpack,
  toBufferKey, physicalReads, openWithBinding, verify, dep}) {
  const {syncFile, digest} = loadSync(trial, dep);
  const now = process.hrtime.bigint;
  const elapsed = start => Number(now() - start);
  const expected = new Map();
  for (const batch of batches) for (const {key, value} of batch) expected.set(key.toString('hex'), value);
  const results = [];
  for (let round = 0; round < rounds; round++) {
    const dir = path.join(trial, 'round-' + round);
    fs.mkdirSync(dir);
    const rocksPath = path.join(dir, 'rocks'), livePath = path.join(dir, 'live');
    const live = LiveDatabase.create(livePath);
    let rawRocks, durable;
    let rocksCommits = 0;
    const receipts = {commits:0, mutations:0};
    const evidence = {primaryReads:0, reverseIndexRows:0};
    const rocksRepo = openWithBinding(rocksPath, false, (requested, options, nativeOpen) => {
      rawRocks = nativeOpen(requested, options);
      const transaction = rawRocks.transaction.bind(rawRocks);
      rawRocks.transaction = async (...args) => {
        const result = await transaction(...args);
        if (durable) { durable.confirm(); rocksCommits++; }
        return result;
      };
      return rawRocks;
    });
    const liveRepo = openWithBinding(livePath, false, () => stageTransactions(live,
      physicalReads(live, evidence), new Encoder({copyBuffers:true, freezeData:false}), toBufferKey, unpack, receipts));
    const windows = [], ingest = {kasumi:0, rocks:0};
    const writerClose = {}, beforeClose = {};
    try {
      await rocksRepo.prepare();
      await liveRepo.prepare();
      const initial = {...receipts};
      durable = durableRocksWriter(rawRocks, rocksPath, syncFile);
      for (let start = 0; start < docs.length; start += 64) {
        const end = Math.min(start + 64, docs.length);
        const order = (round + windows.length) % 2 === 0 ? ['kasumi','rocks'] : ['rocks','kasumi'];
        const window = {start, blocks:end - start, order};
        for (const kind of order) {
          const repo = kind === 'kasumi' ? liveRepo : rocksRepo;
          const begin = process.hrtime.bigint();
          for (let i = start; i < end; i++) await repo.upsertMany([docs[i]]);
          window[kind + '_ns'] = Number(process.hrtime.bigint() - begin);
          ingest[kind] += window[kind + '_ns'];
        }
        windows.push(window);
      }
      durable.verify();
      assert.equal(rocksCommits, docs.length);
      assert.equal(receipts.commits - initial.commits, docs.length);
      assert.equal(receipts.mutations - initial.mutations, batches.reduce((n,b) => n + b.length, 0));
      beforeClose.kasumi = allocated(livePath);
      beforeClose.rocks = allocated(rocksPath);
    } finally {
      let started = now();
      durable?.close();
      await rocksRepo.close();
      writerClose.rocks = elapsed(started);
      started = now();
      await liveRepo.close();
      writerClose.kasumi = elapsed(started);
    }
    const afterIngest = {kasumi:allocated(livePath), rocks:allocated(rocksPath)};
    const rawOptions = {encoding:'binary', keyEncoding:'binary', disableWAL:false};
    const maintenance = {};
    for (const kind of ['rocks','kasumi']) {
      const begin = now();
      const db = kind === 'rocks' ? RocksDatabase.open(rocksPath, rawOptions) : LiveDatabase.open(livePath);
      const openNs = elapsed(begin);
      let started = now(), compactNs, closeNs;
      try {
        if (kind === 'rocks') { db.flushSync(); db.compactSync(); } else db.checkpoint();
        compactNs = elapsed(started);
      } finally {
        started = now();
        db.close();
        closeNs = elapsed(started);
      }
      maintenance[kind] = {open_ns:openNs, compact_ns:compactNs, close_ns:closeNs, total_ns:elapsed(begin)};
    }
    const afterMaintenance = {kasumi:allocated(livePath), rocks:allocated(rocksPath)};
    const reopenedRocks = RocksDatabase.open(rocksPath, {...rawOptions, readOnly:true});
    const reopenedLive = LiveDatabase.open(livePath);
    let raw;
    try { raw = verifyRaw(reopenedRocks, reopenedLive, expected, unpack); }
    finally { reopenedRocks.close(); reopenedLive.close(); }
    const paid = Object.fromEntries(['rocks','kasumi'].map(kind =>
      [kind, ingest[kind] + writerClose[kind] + maintenance[kind].total_ns]));
    results.push({round, commits_per_backend:rocksCommits, windows, ingest_ns:ingest,
      writer_close_ns:writerClose, maintenance, paid_ns:paid, allocated_before_close:beforeClose,
      allocated_after_ingest:afterIngest, allocated_after_maintenance:afterMaintenance,
      ...raw, ...await verify(rocksPath, livePath)});
    fs.rmSync(dir, {recursive:true});
  }
  return {rounds:results, sync_addon_sha256:digest};
}
