// The installed JS binding uses asynchronous device durability by default.
// Keep the same synchronous WAL contract for both benchmark drivers.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

export function durableRocksWriter(db, dbPath, syncFile) {
  const walName = () => {
    const files = fs.readdirSync(dbPath).filter(name => /^[0-9]+\.log$/.test(name));
    assert.equal(files.length, 1, 'workload must fit within a single active WAL');
    return files[0];
  };
  // The package uses RocksDB's default manual_wal_flush=false. Its JS commit does not
  // request WriteOptions.sync. Persist initialization, then sync the same published WAL
  // after each acknowledged transaction. Reject rollover and buffered/missing writes.
  const originalWal = walName();
  for (const name of fs.readdirSync(dbPath)) {
    const entry = path.join(dbPath, name);
    if (fs.statSync(entry).isFile()) {
      const fd = fs.openSync(entry, 'r+');
      try { syncFile(fd); } finally { fs.closeSync(fd); }
    }
  }
  const dir = fs.openSync(dbPath, 'r');
  try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
  const wal = fs.openSync(path.join(dbPath, originalWal), 'r+');
  let size;
  try { size = fs.fstatSync(wal).size; }
  catch (error) { fs.closeSync(wal); throw error; }
  function append(batch) {
    db.transactionSync(tx => {
      for (const [key, value] of batch) {
        if (value === undefined) tx.removeSync(key);
        else tx.putSync(key, value);
      }
    });
  }
  function confirm() {
    syncFile(wal);
    const next = fs.fstatSync(wal).size;
    assert(next > size, 'buffered, missing or rotated WAL write');
    size = next;
  }
  return {
    commit(batch) { append(batch); confirm(); },
    // Each original block remains a separate RocksDB transaction. As with Kasumi,
    // all blocks are ready up front and none is acknowledged until this barrier.
    commitGroup(group) {
      for (const batch of group) append(batch);
      if (group.length) confirm();
    },
    verify() { assert.equal(walName(), originalWal, 'active WAL changed during the run'); },
    close() { fs.closeSync(wal); },
  };
}
