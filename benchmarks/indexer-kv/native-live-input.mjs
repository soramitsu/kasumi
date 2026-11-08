// Materialize the exact puts, deletes and final rows for the native RocksDB control.
import fs from 'node:fs';
import path from 'node:path';

function u32(value) {
  const buffer = Buffer.alloc(4);
  buffer.writeUInt32BE(value);
  return buffer;
}

export function prepareNativeInput(blocks, directory) {
  const state = new Map();
  const batchFile = path.join(directory, 'rocks-live-batches.bin');
  const rowsFile = path.join(directory, 'rocks-live-rows.bin');
  const encoded = [];
  for (const {ops} of blocks) {
    encoded.push(u32(ops.length));
    for (const [action, hexKey, hexValue] of ops) {
      const key = Buffer.from(hexKey, 'hex');
      encoded.push(Buffer.from(action === 'put' ? 'P' : 'D'), u32(key.length), key);
      if (action === 'put') {
        const value = Buffer.from(hexValue, 'hex');
        encoded.push(u32(value.length), value);
        state.set(hexKey, value);
      } else {
        state.delete(hexKey);
      }
    }
  }
  fs.writeFileSync(batchFile, Buffer.concat(encoded), {flag:'wx'});
  const rows = [];
  for (const hex of [...state.keys()].sort()) {
    const key = Buffer.from(hex, 'hex');
    const value = state.get(hex);
    rows.push(u32(key.length), key, u32(value.length), value);
  }
  fs.writeFileSync(rowsFile, Buffer.concat(rows), {flag:'wx'});
  return {rows:rowsFile, batches:batchFile};
}
