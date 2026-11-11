# Kasumi live database for Node.js

The addon supports Linux and macOS and opens the native Kasumi live database on a local filesystem. One handle holds its exclusive writer lock. Each successful commit durably appends one ordered batch. Calls run synchronously, so an indexer can own the database from a dedicated Node.js worker.

## Build and load

From the Kasumi workspace root, build the native library for the same operating system and architecture as Node.js. The binding uses Node-API level 6.

```sh
cargo build --locked --release -p kasumi-live-node
# macOS
cp target/release/libkasumi_live_node.dylib target/release/kasumi_live_node.node
# Linux
# cp target/release/libkasumi_live_node.so target/release/kasumi_live_node.node
node --test crates/kasumi-live-node/tests/live.mjs
```

Load the unpacked file by its absolute path with CommonJS `require`, or use `createRequire(import.meta.url)` in an ES module. The test also accepts an absolute addon path through `KASUMI_LIVE_ADDON`.

```js
const { LiveDatabase } = require('/absolute/path/to/kasumi_live_node.node');
const db = LiveDatabase.create('/absolute/path/to/new-database');
try {
  const key = Buffer.from([0x00, 0xff]);
  const sequence = db.commit([{ key, value: Buffer.alloc(0) }]);
  const value = db.get(key);
  const rows = db.range({ start: key, limit: 100, reverse: true });
  db.commit([{ key }]);
  db.checkpoint();
} finally {
  db.close();
}
```

On macOS, a release build can produce an addon the loader refuses with
`mis-aligned LINKEDIT string pool`: Xcode's `strip`, which a release build
runs by default, can leave the symbol string table unaligned. Build with
`--config 'profile.release.strip="none"'` added to the command above if
`require` fails that way. Linux builds are unaffected.

New directories use a 4 MiB write buffer budget by default. Pass a byte count as
`LiveDatabase.create(path, bytes)` (512 KiB through 16 MiB) to trade memory,
WAL size and recovery time for less frequent inline merge work. The budget
survives reopen and does not change when a commit becomes durable.

Pass `"zstd"` as a third argument, `LiveDatabase.create(path, bytes, "zstd")`,
to write Zstandard blocks instead of LZ4 (`undefined` for `bytes` keeps the
default buffer). The database is smaller on disk, by about half for text that
LZ4 cannot shorten, and takes more CPU to write and to read blocks that are
not cached. The choice is persisted, `blockCodec()` returns `"lz4"` or
`"zstd"`, and a Zstandard database needs this version of the addon or later.
See the [engine notes](../kasumi-frozen-run/README.md#smaller-files-with-zstandard-blocks)
for measurements and the format.

Use `LiveDatabase.open(path)` to reopen an existing database. Both `sequence()` and `commit(ops)` return a JavaScript `bigint`. A mutation with a Buffer value inserts or replaces that key; omitting the value deletes it. Duplicate keys follow array order. A read returns a Buffer or `null` for a missing key. All binary inputs require ordinary ArrayBuffer backing. Copy shared data into a private Buffer before calling the addon. Zero-length keys and values round-trip. An empty batch advances the sequence.

`range({ limit, start?, end?, startExclusive?, endInclusive?, reverse? })` returns an array of `{key, value}`. Buffer bounds describe ascending lexicographic key space in both directions. The default includes `start` and excludes `end`. The limit must be an integer from 0 through 4,096. A result above 64 MiB of combined key and value bytes throws. Use a smaller limit and resume a forward page with `startExclusive: true` on its last key, or a reverse page with `end` on its last key.

`getInto(key, destination)` returns the stored byte length or `null` when the key is absent. It copies a complete value into the destination when it fits, leaving the remainder untouched. A short destination stays unchanged so callers can retry with a larger Buffer. Consumers that reuse the destination must copy any decoded binary fields they retain.

For bulk iteration, `rangePacked(options)` applies the same bounds and returns one stable Buffer. Each row contains a four-byte unsigned big-endian key length, the key, a four-byte unsigned big-endian value length, and the value. An empty page has zero bytes. The 64 MiB limit includes the length fields. Returned point values and pages retain their contents across subsequent reads, commits and close.

A batch accepts up to 65,536 operations and 64 MiB of encoded data. Each key can occupy up to 4 KiB, each value up to 32 MiB. An error after a physical write may leave the complete batch recoverable. Close and reopen the database, then inspect the recovered sequence and data before retrying. Closing releases the lock and can be repeated.

For independent blocks already available together, `commitGroup([ops1, ops2, ...])` returns a `bigint[]` of consecutive sequences after a shared WAL flush. Each block retains its own atomic frame. A crash before acknowledgement may leave any complete prefix recoverable. Reopen and inspect `sequence()` before resuming intake. An empty group returns `[]`; empty blocks within a group advance the sequence.

A group accepts up to 64 blocks. Multi-block groups share a 512 KiB budget counting 128 bytes per frame, 256 bytes per operation, and all key and value bytes. A single-block group accepts the ordinary batch limits. Checkpoints can require additional synchronization when a group reaches the checkpoint threshold.
